/*
 * UAV side (ESP32) -- PUF chaos encryption of 128x128 grayscale frames, ESP-NOW link.
 * Needs puf_chaos.h in the same folder.  USB serial -> laptop running uav_webcam_responder.py.
 *
 * What this board does
 *   SESSION_INIT  : gets (challenge C, nonce N) from the base over the air, computes R = PUF(C),
 *                   derives the session state/key from R xor N, replies SESSION_ACK
 *   CMD (capture) : asks the laptop for a raw frame (0x01 on USB), encrypts it in place with
 *                   the PUF chaos cipher, sends the ciphertext to the base
 *   USB enrollment: enroll.py sends 0xE1 0x4F + a 16-byte challenge over the USB cable and gets
 *                   "PUFRESP:<hex>" back. The response R is NEVER sent over the radio.
 *
 * Packets (ESP-NOW, max 250 bytes). All start with [type][txn].
 *   CMD           0x01 [txn][frame_id u32]
 *   SESSION_INIT  0x02 [txn][C 16][N 16]
 *   SESSION_ACK   0x03 [txn][status]          status 0 = ok
 *   START         0x10 [txn][len u32][crc32 u32][num_pkts u16][frame_id u32]   (crc is of the CIPHERTEXT)
 *   DATA          0x11 [txn][seq u16][n u8][payload <=240]
 *   ERR           0x20 [txn][code]
 *
 * NOTE: the PUF is EMULATED: R = HMAC-SHA256(secret, challenge), where 'secret' is a random
 *       128-bit value generated on first boot and kept in this board's flash (never printed or
 *       sent). Anyone who can dump the flash can read it; a real PUF has no stored secret.
 * NOTE: debug text must never contain byte 0x01 (it is the frame-request byte for the laptop).
 */

#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <esp_system.h>
#if __has_include(<esp_random.h>)
#include <esp_random.h>
#endif
#include <Preferences.h>
#include "puf_chaos.h"

// ===================== USER SETTINGS =====================
#define SERIAL_BAUD    921600   // must match uav_webcam_responder.py (--baud)
#define ESPNOW_CHANNEL 1        // must be identical on base and UAV
// MAC of the BASE board (we send to this)
static const uint8_t PEER_MAC[6] = {0xE0, 0x8C, 0xFE, 0xE6, 0x6C, 0x20};
// =========================================================

#define DATA_PAYLOAD   240
#define REQ_BYTE       0x01
#define CAM_TIMEOUT_MS 4000
#define APP_TRIES      10

enum : uint8_t { PKT_CMD = 0x01, PKT_SESSION_INIT = 0x02, PKT_SESSION_ACK = 0x03,
                 PKT_START = 0x10, PKT_DATA = 0x11, PKT_ERR = 0x20 };
enum : uint8_t { ERR_CAMERA = 1, ERR_TIMEOUT = 2, ERR_BAD_SIZE = 3, ERR_CRC = 4, ERR_NO_SESSION = 5 };

static uint8_t* imgBuf  = nullptr;     // plaintext in, ciphertext out (in place)
static uint8_t* workBuf = nullptr;
static uint8_t* ksBuf   = nullptr;
static pc::Session sess;
static Preferences prefs;
static uint8_t pufSecret[16];          // emulated-PUF secret (flash only, never output)
static uint8_t lastTxn = 0;
static bool haveTxn = false;

// ---------- receive ring (filled in the ESP-NOW callback, drained in loop) ----------
#define RING_SLOTS 16
struct Slot { uint8_t len; uint8_t data[250]; };
static Slot ring[RING_SLOTS];
static volatile uint8_t ringHead = 0, ringTail = 0;

void onRecv(const void* info, const uint8_t* data, int len) {
  (void)info;
  if (len <= 0 || len > 250) return;
  uint8_t next = (ringHead + 1) % RING_SLOTS;
  if (next == ringTail) return;
  memcpy(ring[ringHead].data, data, len);
  ring[ringHead].len = (uint8_t)len;
  ringHead = next;
}

bool ringPop(uint8_t* out, uint8_t& len) {
  if (ringTail == ringHead) return false;
  len = ring[ringTail].len;
  memcpy(out, ring[ringTail].data, len);
  ringTail = (ringTail + 1) % RING_SLOTS;
  return true;
}

// ---------- send status ----------
static volatile bool sendDone = false, sendOk = false;

void onSent(const void* info, esp_now_send_status_t status) {
  (void)info;
  sendOk = (status == ESP_NOW_SEND_SUCCESS);
  sendDone = true;
}

// ---------- helpers ----------
static inline void put16(uint8_t* p, uint16_t v) { p[0] = v & 0xFF; p[1] = v >> 8; }
static inline void put32(uint8_t* p, uint32_t v) {
  p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
}
static inline uint32_t get32(const uint8_t* p) { return pc::le32(p); }

uint32_t crc32_calc(const uint8_t* d, size_t n) {
  uint32_t c = 0xFFFFFFFFu;
  for (size_t i = 0; i < n; i++) {
    c ^= d[i];
    for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
  }
  return ~c;
}

void printHash(const char* label, const uint8_t* buf, size_t n) {
  uint8_t h[32];
  pc::sha256(buf, n, h);
  Serial.printf("[UAV] %s sha256: %02x%02x%02x%02x\n", label, h[0], h[1], h[2], h[3]);
}

// ---------- PUF (emulated) ----------
void randomBytes(uint8_t* out, size_t n) {
  for (size_t i = 0; i < n; i += 4) {
    uint32_t r = esp_random();                 // hardware RNG (true random while Wi-Fi is running)
    for (size_t k = 0; k < 4 && i + k < n; k++) out[i + k] = (uint8_t)(r >> (8 * k));
  }
}

// Load the secret from flash, or create it on the very first boot. Call after WiFi has started.
void loadOrCreateSecret() {
  prefs.begin("puf", false);
  if (prefs.getBytes("s", pufSecret, 16) != 16) {
    randomBytes(pufSecret, 16);
    prefs.putBytes("s", pufSecret, 16);
    Serial.println("[UAV] PUF secret: generated and stored (first boot). Existing enrollments are now invalid.");
  } else {
    Serial.println("[UAV] PUF secret: loaded from flash");
  }
}

void pufEmulated(const uint8_t chal[16], uint8_t resp[16]) {
  pc::puf_response(pufSecret, chal, resp);
}

// ---------- USB enrollment command:  0xE1 0x4F + 16-byte challenge  ->  "PUFRESP:<32 hex chars>" ----------
void handleUsbCommand() {
  static uint32_t firstSeen = 0;
  if (!Serial.available()) { firstSeen = 0; return; }
  if (Serial.peek() != 0xE1) { Serial.read(); firstSeen = 0; return; }       // discard noise
  if (firstSeen == 0) firstSeen = millis();
  if (Serial.available() < 18) {
    if (millis() - firstSeen > 500) { Serial.read(); firstSeen = 0; }         // incomplete command: drop
    return;
  }
  uint8_t b[18];
  Serial.readBytes(b, 18);
  firstSeen = 0;
  if (b[1] != 0x4F) return;
  uint8_t R[16];
  pufEmulated(b + 2, R);
  Serial.print("PUFRESP:");
  for (int i = 0; i < 16; i++) Serial.printf("%02x", R[i]);
  Serial.println();
}

// ---------- ESP-NOW send with delivery check + retries ----------
bool sendPacket(const uint8_t* pkt, size_t len, uint32_t& retries) {
  for (uint8_t a = 0; a < APP_TRIES; a++) {
    sendDone = false;
    if (esp_now_send(PEER_MAC, pkt, len) == ESP_OK) {
      uint32_t t0 = millis();
      while (!sendDone && (millis() - t0) < 100) yield();
      if (sendDone && sendOk) return true;
    }
    retries++;
    delay(2);
  }
  return false;
}

void sendError(uint8_t txn, uint8_t code) {
  uint8_t pkt[3] = {PKT_ERR, txn, code};
  uint32_t r = 0;
  sendPacket(pkt, 3, r);
}

// ---------- USB serial side (laptop webcam) ----------
bool readExact(uint8_t* dst, size_t n, uint32_t idleTimeoutMs) {
  size_t got = 0;
  uint32_t last = millis();
  while (got < n) {
    int avail = Serial.available();
    if (avail > 0) {
      size_t want = n - got;
      size_t take = (size_t)avail < want ? (size_t)avail : want;
      got += Serial.readBytes(dst + got, take);
      last = millis();
    } else {
      if (millis() - last > idleTimeoutMs) return false;
      delay(1);
    }
  }
  return true;
}

bool waitForHeader(uint32_t timeoutMs) {
  uint32_t t0 = millis();
  uint8_t prev = 0;
  while (millis() - t0 < timeoutMs) {
    if (Serial.available()) {
      uint8_t b = Serial.read();
      if (prev == 0xA5 && b == 0x5A) return true;
      prev = b;
    } else {
      delay(1);
    }
  }
  return false;
}

// raw 128x128 grayscale frame from the laptop: A5 5A | len(4) | crc32(4) | pixels
uint8_t requestFrame() {
  while (Serial.available()) Serial.read();
  Serial.write((uint8_t)REQ_BYTE);
  Serial.flush();
  if (!waitForHeader(CAM_TIMEOUT_MS)) return ERR_TIMEOUT;
  uint8_t h[8];
  if (!readExact(h, 8, 1000)) return ERR_TIMEOUT;
  uint32_t n = get32(h), crc = get32(h + 4);
  if (n == 0) return ERR_CAMERA;
  if (n != pc::IMG_BYTES) return ERR_BAD_SIZE;
  if (!readExact(imgBuf, n, 1500)) return ERR_TIMEOUT;
  if (crc32_calc(imgBuf, n) != crc) return ERR_CRC;
  return 0;
}

// ---------- send the (already encrypted) buffer ----------
bool sendImage(uint8_t txn, uint32_t frameId) {
  uint8_t pkt[250];
  uint32_t retries = 0;
  const uint32_t len = pc::IMG_BYTES;
  uint16_t numPkts = (len + DATA_PAYLOAD - 1) / DATA_PAYLOAD;
  uint32_t crc = crc32_calc(imgBuf, len);
  uint32_t t0 = millis();

  memset(pkt, 0, 16);
  pkt[0] = PKT_START; pkt[1] = txn;
  put32(pkt + 2, len);
  put32(pkt + 6, crc);
  put16(pkt + 10, numPkts);
  put32(pkt + 12, frameId);
  if (!sendPacket(pkt, 16, retries)) {
    Serial.println("[UAV] ABORT: START packet not delivered (base off / wrong MAC / different channel?)");
    return false;
  }
  for (uint16_t seq = 0; seq < numPkts; seq++) {
    uint32_t off = (uint32_t)seq * DATA_PAYLOAD;
    uint32_t left = len - off;
    uint8_t n = left > DATA_PAYLOAD ? DATA_PAYLOAD : (uint8_t)left;
    pkt[0] = PKT_DATA; pkt[1] = txn;
    put16(pkt + 2, seq);
    pkt[4] = n;
    memcpy(pkt + 5, imgBuf + off, n);
    if (!sendPacket(pkt, 5 + n, retries)) {
      Serial.printf("[UAV] ABORT: DATA packet %u/%u failed after %u tries\n", seq, numPkts, APP_TRIES);
      return false;
    }
  }
  uint32_t dt = millis() - t0;
  Serial.printf("[UAV] sent %lu cipher bytes in %u packets, %lu ms (%.1f kB/s), app retries: %lu\n",
                (unsigned long)len, numPkts, (unsigned long)dt,
                dt ? (len / 1.024f) / dt : 0.0f, (unsigned long)retries);
  return true;
}

// ---------- message handlers ----------
void handleSessionInit(const uint8_t* pkt, uint8_t len) {
  if (len < 34) return;
  uint8_t R[16];
  pufEmulated(pkt + 2, R);
  uint32_t t0 = micros();
  pc::session_derive(R, pkt + 18, sess);
  uint32_t dt = micros() - t0;
  uint8_t h[32];
  pc::sha256(sess.key, 16, h);
  Serial.printf("[UAV] session key derived in %lu us, key fingerprint %02x%02x%02x%02x\n",
                (unsigned long)dt, h[0], h[1], h[2], h[3]);
  uint8_t ack[3] = {PKT_SESSION_ACK, pkt[1], 0};
  uint32_t r = 0;
  sendPacket(ack, 3, r);
}

void handleCapture(const uint8_t* pkt, uint8_t len) {
  if (len < 6) return;
  uint8_t txn = pkt[1];
  uint32_t frameId = get32(pkt + 2);
  if (haveTxn && txn == lastTxn) { Serial.println("[UAV] duplicate capture command ignored"); return; }
  haveTxn = true; lastTxn = txn;

  if (!sess.valid) {
    Serial.println("[UAV] capture requested but no session is active");
    sendError(txn, ERR_NO_SESSION);
    return;
  }
  Serial.printf("[UAV] capture command (frame %lu) - requesting raw frame from laptop\n", (unsigned long)frameId);
  uint8_t err = requestFrame();
  if (err) {
    Serial.printf("[UAV] frame request failed, error %u (1=camera 2=timeout 3=bad size 4=crc)\n", err);
    sendError(txn, err);
    return;
  }
  printHash("plaintext", imgBuf, pc::IMG_BYTES);

  uint32_t t0 = micros();
  pc::encrypt(sess, frameId, imgBuf, imgBuf, workBuf, ksBuf);      // in place
  uint32_t te = micros() - t0;
  Serial.printf("[UAV] ENC_TIME_US %lu (frame %lu)\n", (unsigned long)te, (unsigned long)frameId);

  sendImage(txn, frameId);
  ringTail = ringHead;   // discard anything that arrived while busy
}

// ---------- Arduino ----------
void setup() {
  Serial.setRxBufferSize(24576);   // must be called before begin(); holds a whole 16 KB frame
  Serial.begin(SERIAL_BAUD);
  delay(1000);
  Serial.println();
  Serial.println("[UAV] boot (PUF chaos, ESP-NOW)");

  imgBuf  = (uint8_t*)malloc(pc::IMG_BYTES);
  workBuf = (uint8_t*)malloc(pc::IMG_BYTES);
  ksBuf   = (uint8_t*)malloc(pc::IMG_BYTES);
  if (!imgBuf || !workBuf || !ksBuf) {
    while (true) { Serial.println("[UAV] FATAL: cannot allocate buffers"); delay(1000); }
  }
  sess.valid = false;

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.disconnect();
  esp_wifi_set_channel(ESPNOW_CHANNEL, WIFI_SECOND_CHAN_NONE);
  if (esp_now_init() != ESP_OK) {
    while (true) { Serial.println("[UAV] FATAL: esp_now_init failed"); delay(1000); }
  }
  esp_now_register_send_cb((esp_now_send_cb_t)onSent);
  esp_now_register_recv_cb((esp_now_recv_cb_t)onRecv);
  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, PEER_MAC, 6);
  peer.channel = 0;
  peer.encrypt = false;
  if (esp_now_add_peer(&peer) != ESP_OK) {
    while (true) { Serial.println("[UAV] FATAL: could not add peer"); delay(1000); }
  }

  loadOrCreateSecret();            // after WiFi is up so the RNG has radio entropy

  Serial.print("[UAV] my MAC: ");
  Serial.println(WiFi.macAddress());
  Serial.printf("[UAV] cipher: %d Duffing maps, image %dx%d, heap free %lu bytes, sketch size %lu bytes\n",
                pc::NMAPS, pc::N, pc::N, (unsigned long)ESP.getFreeHeap(), (unsigned long)ESP.getSketchSize());
  Serial.printf("[UAV] ready on channel %d\n", ESPNOW_CHANNEL);
}

void loop() {
  handleUsbCommand();
  uint8_t pkt[250];
  uint8_t len;
  if (ringPop(pkt, len)) {
    if (len < 2) return;
    switch (pkt[0]) {
      case PKT_SESSION_INIT: handleSessionInit(pkt, len); break;
      case PKT_CMD:          handleCapture(pkt, len); break;
      default: break;
    }
  }
}
