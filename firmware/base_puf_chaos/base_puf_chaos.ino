/*
 * Base station (ESP32) -- PUF chaos decryption of 128x128 grayscale frames, ESP-NOW link.
 * Needs puf_chaos.h in the same folder.  USB serial -> laptop running base_receiver.py.
 *
 * Single-character commands from the laptop:
 *   P  + 32 bytes (challenge, response): store one challenge/response pair (CRP) in flash (NVS).
 *      Sent by enroll.py over the USB cable. The response R never goes over the radio.
 *   S  start a new session: pick an unused CRP, send (challenge, nonce) to the UAV, derive the key
 *   1  capture: ask the UAV for a frame, receive the ciphertext, decrypt it
 *   T  print status
 *   X  wipe the CRP table
 *
 * Output to the laptop (binary frames, everything else is plain debug text):
 *   "CIPHER_START\r\n" | len(4, LE) | bytes | "\r\n" "CIPHER_END\r\n"
 *   "PLAIN_START\r\n"  | len(4, LE) | bytes | "\r\n" "PLAIN_END\r\n"
 *
 * Packet layouts: see uav_puf_chaos.ino (must stay identical).
 *
 * NOTE: the PUF is EMULATED on the UAV (HMAC with a random secret kept in the UAV's flash).
 *       Enrollment is wired (enroll.py talks to both boards over USB), so R is never transmitted.
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
#define SERIAL_BAUD    921600   // must match base_receiver.py (--baud)
#define ESPNOW_CHANNEL 1        // must be identical on base and UAV
// MAC of the UAV board (we send to this)
static const uint8_t PEER_MAC[6] = {0xFC, 0xE8, 0xC0, 0xE1, 0xB2, 0xE8};
// =========================================================

#define DATA_PAYLOAD     240
#define MAX_CRP          40
#define CMD_TRIES        5
#define START_TIMEOUT_MS 12000  // webcam capture + encryption + first packet
#define DATA_TIMEOUT_MS  1500   // max silence between packets mid-transfer

enum : uint8_t { PKT_CMD = 0x01, PKT_SESSION_INIT = 0x02, PKT_SESSION_ACK = 0x03,
                 PKT_START = 0x10, PKT_DATA = 0x11, PKT_ERR = 0x20 };

static uint8_t* cipherBuf = nullptr;
static uint8_t* plainBuf  = nullptr;
static uint8_t* workBuf   = nullptr;
static uint8_t* ksBuf     = nullptr;
static pc::Session sess;
static Preferences prefs;
static uint8_t crpCount = 0, crpUsed = 0;
static uint8_t txnCounter = 0;
static uint32_t frameCounter = 0;

// ---------- receive ring ----------
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
static inline void put32(uint8_t* p, uint32_t v) {
  p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
}
static inline uint16_t get16(const uint8_t* p) { return (uint16_t)p[0] | ((uint16_t)p[1] << 8); }
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
  Serial.printf("[BASE] %s sha256: %02x%02x%02x%02x\n", label, h[0], h[1], h[2], h[3]);
}

void randomBytes(uint8_t* out, size_t n) {
  for (size_t i = 0; i < n; i += 4) {
    uint32_t r = esp_random();
    for (size_t k = 0; k < 4 && i + k < n; k++) out[i + k] = (uint8_t)(r >> (8 * k));
  }
}

bool sendPkt(const uint8_t* pkt, size_t len) {
  for (int i = 0; i < CMD_TRIES; i++) {
    sendDone = false;
    if (esp_now_send(PEER_MAC, pkt, len) == ESP_OK) {
      uint32_t t0 = millis();
      while (!sendDone && (millis() - t0) < 100) yield();
      if (sendDone && sendOk) return true;
    }
    delay(20);
  }
  return false;
}

bool waitFor(uint8_t type, uint8_t txn, uint32_t timeoutMs, uint8_t* out, uint8_t& len) {
  uint32_t t0 = millis();
  while (millis() - t0 < timeoutMs) {
    if (ringPop(out, len)) {
      if (len >= 2 && out[0] == type && out[1] == txn) return true;
    } else {
      yield();
    }
  }
  return false;
}

void forwardToLaptop(const char* tag, const uint8_t* buf, uint32_t len) {
  uint8_t lb[4];
  put32(lb, len);
  Serial.print(tag); Serial.println("_START");
  Serial.write(lb, 4);
  uint32_t off = 0;
  while (off < len) {
    uint32_t n = len - off;
    if (n > 1024) n = 1024;
    Serial.write(buf + off, n);
    off += n;
  }
  Serial.flush();
  Serial.println();
  Serial.print(tag); Serial.println("_END");
}

// ---------- CRP table in flash (NVS) ----------
void crpKey(char* out, char kind, uint8_t i) { snprintf(out, 8, "%c%u", kind, i); }

bool crpLoad(uint8_t i, uint8_t chal[16], uint8_t resp[16]) {
  char k[8];
  crpKey(k, 'c', i);
  if (prefs.getBytes(k, chal, 16) != 16) return false;
  crpKey(k, 'r', i);
  return prefs.getBytes(k, resp, 16) == 16;
}

void printStatus() {
  Serial.printf("[BASE] CRPs stored: %u, used: %u, unused: %u, session: %s, next frame id: %lu, heap free: %lu\n",
                crpCount, crpUsed, (unsigned)(crpCount - crpUsed), sess.valid ? "active" : "none",
                (unsigned long)frameCounter, (unsigned long)ESP.getFreeHeap());
}

// ---------- commands ----------
// Receives one CRP over USB: 32 bytes = challenge(16) + response(16)
void doStoreCrp() {
  uint8_t buf[32];
  size_t n = Serial.readBytes(buf, 32);
  if (n != 32) { Serial.println("[BASE] FAILED: incomplete CRP received over USB"); return; }
  if (crpCount >= MAX_CRP) { Serial.println("[BASE] FAILED: CRP table full"); return; }
  char k[8];
  crpKey(k, 'c', crpCount); prefs.putBytes(k, buf, 16);
  crpKey(k, 'r', crpCount); prefs.putBytes(k, buf + 16, 16);
  crpCount++;
  prefs.putUChar("n", crpCount);
  Serial.printf("[BASE] enrolled CRP #%u (stored: %u, unused: %u)\n", crpCount, crpCount, (unsigned)(crpCount - crpUsed));
}

void doSession() {
  if (crpUsed >= crpCount) { Serial.println("[BASE] no unused CRP left - run enroll.py first"); return; }
  uint8_t chal[16], R[16];
  if (!crpLoad(crpUsed, chal, R)) { Serial.println("[BASE] FAILED: CRP read error"); return; }
  uint8_t nonce[16], pkt[34], rp[250], rl;
  randomBytes(nonce, 16);
  uint8_t txn = ++txnCounter;
  pkt[0] = PKT_SESSION_INIT; pkt[1] = txn;
  memcpy(pkt + 2, chal, 16);
  memcpy(pkt + 18, nonce, 16);
  ringTail = ringHead;
  if (!sendPkt(pkt, 34)) { Serial.println("[BASE] FAILED: session request not delivered"); return; }
  if (!waitFor(PKT_SESSION_ACK, txn, 3000, rp, rl) || rl < 3 || rp[2] != 0) {
    Serial.println("[BASE] FAILED: UAV did not confirm the session");
    return;
  }
  uint32_t t0 = micros();
  pc::session_derive(R, nonce, sess);
  uint32_t dt = micros() - t0;
  crpUsed++;
  prefs.putUChar("u", crpUsed);          // a CRP is never used twice
  frameCounter = 0;
  uint8_t h[32];
  pc::sha256(sess.key, 16, h);
  Serial.printf("[BASE] session key derived in %lu us, key fingerprint %02x%02x%02x%02x (CRP #%u used)\n",
                (unsigned long)dt, h[0], h[1], h[2], h[3], crpUsed);
  Serial.println("[BASE] compare this fingerprint with the UAV's - they must match");
}

void receiveAndDecrypt(uint8_t txn) {
  uint8_t pkt[250];
  uint8_t plen;
  bool started = false;
  uint32_t totalLen = 0, expectCrc = 0, got = 0, dups = 0, frameId = 0;
  uint16_t numPkts = 0, expectSeq = 0;
  uint32_t tBegin = millis(), tLast = millis(), tFirst = 0;

  while (true) {
    if (ringPop(pkt, plen)) {
      tLast = millis();
      if (plen < 2 || pkt[1] != txn) continue;

      if (pkt[0] == PKT_ERR && plen >= 3) {
        Serial.printf("[BASE] UAV reported error code %u (1=camera 2=timeout 3=bad size 4=crc 5=no session)\n", pkt[2]);
        return;
      }
      if (pkt[0] == PKT_START && plen >= 16) {
        if (started) continue;
        totalLen  = get32(pkt + 2);
        expectCrc = get32(pkt + 6);
        numPkts   = get16(pkt + 10);
        frameId   = get32(pkt + 12);
        if (totalLen != pc::IMG_BYTES) {
          Serial.printf("[BASE] FAILED: unexpected image length %lu\n", (unsigned long)totalLen);
          return;
        }
        started = true; got = 0; expectSeq = 0; tFirst = millis();
        continue;
      }
      if (pkt[0] == PKT_DATA && started && plen >= 5) {
        uint16_t seq = get16(pkt + 2);
        uint8_t n = pkt[4];
        if (n > DATA_PAYLOAD || plen < 5 + n) { Serial.println("[BASE] FAILED: corrupt DATA packet"); return; }
        if (seq == expectSeq) {
          if (got + n > totalLen) { Serial.println("[BASE] FAILED: data exceeds announced length"); return; }
          memcpy(cipherBuf + got, pkt + 5, n);
          got += n;
          expectSeq++;
          if (got == totalLen) break;
        } else if (seq < expectSeq) {
          dups++;
        } else {
          Serial.printf("[BASE] FAILED: gap in sequence (expected %u, got %u)\n", expectSeq, seq);
          return;
        }
      }
    } else {
      uint32_t limit = started ? DATA_TIMEOUT_MS : START_TIMEOUT_MS;
      if (millis() - tLast > limit) {
        if (started)
          Serial.printf("[BASE] FAILED: transfer stalled at %lu/%lu bytes (packet %u/%u)\n",
                        (unsigned long)got, (unsigned long)totalLen, expectSeq, numPkts);
        else
          Serial.println("[BASE] FAILED: no response from UAV (timeout)");
        return;
      }
      yield();
    }
  }

  uint32_t dt = millis() - tFirst;
  uint32_t crc = crc32_calc(cipherBuf, totalLen);
  if (expectSeq != numPkts || crc != expectCrc) {
    Serial.printf("[BASE] FAILED: link integrity check (pkts %u/%u, crc %08lX vs %08lX)\n",
                  expectSeq, numPkts, (unsigned long)crc, (unsigned long)expectCrc);
    return;
  }
  Serial.printf("[BASE] cipher received: %lu bytes, %u packets, %lu ms (%.1f kB/s), dup pkts: %lu, frame %lu\n",
                (unsigned long)totalLen, numPkts, (unsigned long)dt,
                dt ? (totalLen / 1.024f) / dt : 0.0f, (unsigned long)dups, (unsigned long)frameId);

  uint32_t t0 = micros();
  pc::decrypt(sess, frameId, cipherBuf, plainBuf, workBuf, ksBuf);
  uint32_t td = micros() - t0;
  Serial.printf("[BASE] DEC_TIME_US %lu (frame %lu)\n", (unsigned long)td, (unsigned long)frameId);
  printHash("decrypted plaintext", plainBuf, pc::IMG_BYTES);
  Serial.printf("[BASE] total %lu ms\n", (unsigned long)(millis() - tBegin));

  forwardToLaptop("CIPHER", cipherBuf, pc::IMG_BYTES);
  forwardToLaptop("PLAIN", plainBuf, pc::IMG_BYTES);
}

void doCapture() {
  if (!sess.valid) { Serial.println("[BASE] no active session - press S first"); return; }
  uint8_t txn = ++txnCounter;
  uint32_t fid = frameCounter++;
  uint8_t pkt[6];
  pkt[0] = PKT_CMD; pkt[1] = txn;
  put32(pkt + 2, fid);
  ringTail = ringHead;
  Serial.printf("[BASE] sending capture command (frame %lu)\n", (unsigned long)fid);
  if (!sendPkt(pkt, 6)) { Serial.println("[BASE] FAILED: command not delivered (UAV off? wrong MAC? different channel?)"); return; }
  Serial.println("[BASE] command delivered, waiting for image...");
  receiveAndDecrypt(txn);
  ringTail = ringHead;
}

// ---------- Arduino ----------
void setup() {
  Serial.begin(SERIAL_BAUD);
  Serial.setTimeout(2000);
  delay(1000);
  Serial.println();
  Serial.println("[BASE] boot (PUF chaos, ESP-NOW)");

  cipherBuf = (uint8_t*)malloc(pc::IMG_BYTES);
  plainBuf  = (uint8_t*)malloc(pc::IMG_BYTES);
  workBuf   = (uint8_t*)malloc(pc::IMG_BYTES);
  ksBuf     = (uint8_t*)malloc(pc::IMG_BYTES);
  if (!cipherBuf || !plainBuf || !workBuf || !ksBuf) {
    while (true) { Serial.println("[BASE] FATAL: cannot allocate buffers"); delay(1000); }
  }
  sess.valid = false;

  prefs.begin("crp", false);
  crpCount = prefs.getUChar("n", 0);
  crpUsed  = prefs.getUChar("u", 0);

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.disconnect();
  esp_wifi_set_channel(ESPNOW_CHANNEL, WIFI_SECOND_CHAN_NONE);
  if (esp_now_init() != ESP_OK) {
    while (true) { Serial.println("[BASE] FATAL: esp_now_init failed"); delay(1000); }
  }
  esp_now_register_send_cb((esp_now_send_cb_t)onSent);
  esp_now_register_recv_cb((esp_now_recv_cb_t)onRecv);
  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, PEER_MAC, 6);
  peer.channel = 0;
  peer.encrypt = false;
  if (esp_now_add_peer(&peer) != ESP_OK) {
    while (true) { Serial.println("[BASE] FATAL: could not add peer"); delay(1000); }
  }

  Serial.print("[BASE] my MAC: ");
  Serial.println(WiFi.macAddress());
  Serial.printf("[BASE] cipher: %d Duffing maps, image %dx%d\n", pc::NMAPS, pc::N, pc::N);
  printStatus();
  Serial.printf("[BASE] ready on channel %d. Commands: S=session 1=capture T=status X=wipe (enroll with enroll.py)\n", ESPNOW_CHANNEL);
}

void loop() {
  if (Serial.available()) {
    char c = Serial.read();
    switch (c) {
      case 'P': doStoreCrp(); break;
      case 'S': doSession(); break;
      case '1': doCapture(); break;
      case 'T': printStatus(); break;
      case 'X':
        prefs.clear(); crpCount = 0; crpUsed = 0; sess.valid = false;
        Serial.println("[BASE] CRP table wiped, session cleared");
        break;
      default: break;
    }
  }
}
