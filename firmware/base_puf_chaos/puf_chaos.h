/*
 * puf_chaos.h  --  PUF-seeded Duffing-map image cipher (fixed-point, integer only)
 *
 * Pure C++ with no Arduino dependency, so the SAME file is used:
 *   - on the UAV ESP32 (encrypt)
 *   - on the base ESP32 (derive key + decrypt)
 *   - on a PC for testing (g++), where it is checked bit-for-bit against puf_chaos_ref.py
 *
 * Pipeline (matches the handover, Phase 3-4, with one change explained below):
 *   seed  = R xor Nonce                      (R = PUF response, Nonce = public per-session)
 *   state = initial conditions of a BANK of NMAPS Duffing maps, taken from SHA-256(seed||i),
 *           then warm-up (discard transient)
 *   K     = 16 bytes quantised from the post-warm-up orbit           (session key)
 *   per frame f:
 *       re-key the map from (state, K, f), warm up, then draw
 *         - Arnold parameters (p, q, r) and two IV bytes
 *         - 128*128 keystream bytes
 *       encrypt = Arnold cat-map permutation  ->  forward chained diffusion  ->  backward chained diffusion
 *
 * WHY A BANK OF MAPS: measured on this exact fixed-point map, one Q4.28 Duffing map collapses
 * onto its attractor and reaches only ~2^26 distinct post-warm-up states (birthday-collision
 * estimate, see tests/diag_state_space.cpp). A single map therefore gives a ~2^26 key space no
 * matter how long the seed is. NMAPS independent maps multiply the state space (~2^26.4 each),
 * so NMAPS=5 gives ~2^132. The keystream byte is the XOR of the bytes of all maps.
 *
 * Fixed-point format: Q4.28 in int32 (1.0 = 1<<28), products done in int64.
 * Arithmetic right shift of negative values is assumed (true for gcc / xtensa / Python).
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace pc {

// ---------------------------------------------------------------- parameters
constexpr int      N          = 128;                 // image side, must be a power of two
constexpr size_t   IMG_BYTES  = (size_t)N * N;       // 16384 (8-bit grayscale)
constexpr int      FRAC       = 28;                  // Q4.28
constexpr int32_t  DUF_A      = 738197504;           // 2.75 * 2^28
constexpr int32_t  DUF_B      = 53687091;            // round(0.2 * 2^28)
constexpr int32_t  ESC_LIMIT  = 3 << FRAC;           // |y| above this = orbit escaped the basin
constexpr int      NMAPS      = 5;                   // independent Duffing maps (1..8)
static_assert(NMAPS >= 1 && NMAPS <= 8, "NMAPS must be 1..8");
constexpr int      SESSION_WARMUP = 500;
constexpr int      FRAME_WARMUP   = 100;

// ---------------------------------------------------------------- SHA-256
static const uint32_t K256[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

inline void sha256_block(uint32_t h[8], const uint8_t* p) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++)
    w[i] = ((uint32_t)p[4*i] << 24) | ((uint32_t)p[4*i+1] << 16) | ((uint32_t)p[4*i+2] << 8) | p[4*i+3];
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
    uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
    w[i] = w[i-16] + s0 + w[i-7] + s1;
  }
  uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
  for (int i = 0; i < 64; i++) {
    uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t t1 = hh + S1 + ch + K256[i] + w[i];
    uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = S0 + mj;
    hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

inline void sha256(const uint8_t* data, size_t n, uint8_t out[32]) {
  uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  size_t i = 0;
  while (n - i >= 64) { sha256_block(h, data + i); i += 64; }
  uint8_t blk[64];
  size_t rem = n - i;
  memcpy(blk, data + i, rem);
  blk[rem++] = 0x80;
  if (rem > 56) { memset(blk + rem, 0, 64 - rem); sha256_block(h, blk); rem = 0; }
  memset(blk + rem, 0, 56 - rem);
  uint64_t bits = (uint64_t)n * 8;
  for (int k = 0; k < 8; k++) blk[56 + k] = (uint8_t)(bits >> (56 - 8 * k));
  sha256_block(h, blk);
  for (int k = 0; k < 8; k++) {
    out[4*k] = h[k] >> 24; out[4*k+1] = h[k] >> 16; out[4*k+2] = h[k] >> 8; out[4*k+3] = h[k];
  }
}

// ---------------------------------------------------------------- HMAC-SHA256
// key length must be <= 64 bytes, message length <= 64 bytes (enough for the PUF use below)
inline void hmac_sha256(const uint8_t* key, size_t klen, const uint8_t* msg, size_t mlen, uint8_t out[32]) {
  uint8_t pad[64 + 64], inner[32];
  memset(pad, 0x36, 64);
  for (size_t i = 0; i < klen; i++) pad[i] ^= key[i];
  memcpy(pad + 64, msg, mlen);
  sha256(pad, 64 + mlen, inner);
  memset(pad, 0x5c, 64);
  for (size_t i = 0; i < klen; i++) pad[i] ^= key[i];
  memcpy(pad + 64, inner, 32);
  sha256(pad, 64 + 32, out);
}

// ---------------------------------------------------------------- PUF emulation
// R = first 16 bytes of HMAC-SHA256( secret, "PUF-EMU-v2" || challenge ).
// 'secret' is a random 128-bit value that the UAV generates on first boot, keeps in its flash and
// never prints or transmits. It plays the role of the physical randomness of a real PUF.
// THIS IS AN EMULATION: a real PUF derives R from physical variation, cannot be read out of
// flash, and is noisy (needs error correction).
inline void puf_response(const uint8_t secret[16], const uint8_t chal[16], uint8_t resp[16]) {
  uint8_t msg[26], h[32];
  memcpy(msg, "PUF-EMU-v2", 10);
  memcpy(msg + 10, chal, 16);
  hmac_sha256(secret, 16, msg, 26, h);
  memcpy(resp, h, 16);
}

// ---------------------------------------------------------------- fixed-point Duffing map
struct Duffing { int32_t x, y; uint32_t recoveries; };

inline uint32_t mix32(uint32_t h) {
  h ^= h >> 16; h *= 0x85ebca6bu; h ^= h >> 13; h *= 0xc2b2ae35u; h ^= h >> 16;
  return h;
}

// Deterministic recovery if an orbit ever leaves the basin (never expected from the safe
// start region; the salt depends on the old state so different seeds still give different keys).
inline void duf_recover(Duffing& d) {
  uint32_t salt = (uint32_t)d.x ^ rotl32((uint32_t)d.y, 16) ^ (0x9e3779b9u * (d.recoveries + 1));
  d.recoveries++;
  d.x = (int32_t)mix32(salt) >> 4;            // [-0.5, 0.5)
  d.y = (int32_t)mix32(salt ^ 0xa5a5a5a5u) >> 4;
}

inline void duf_step(Duffing& d) {
  int64_t x = d.x, y = d.y;
  int64_t y2 = (y * y) >> FRAC;
  int64_t y3 = (y2 * y) >> FRAC;
  int64_t ny = (((int64_t)DUF_A * y) >> FRAC) - (((int64_t)DUF_B * x) >> FRAC) - y3;
  if (ny > ESC_LIMIT || ny < -(int64_t)ESC_LIMIT) { duf_recover(d); return; }
  d.x = (int32_t)y;
  d.y = (int32_t)ny;
}

// One output byte from the current state: middle fractional bits of y XOR bits of x.
inline uint8_t duf_byte(const Duffing& d) {
  return (uint8_t)(((uint32_t)d.y >> 13) ^ ((uint32_t)d.x >> 5));
}

// Bank of NMAPS maps stepped in lock-step; output byte = XOR of the per-map bytes.
struct Bank { Duffing m[NMAPS]; };

inline void bank_step(Bank& b) { for (int i = 0; i < NMAPS; i++) duf_step(b.m[i]); }
inline uint8_t bank_byte(const Bank& b) {
  uint8_t o = 0;
  for (int i = 0; i < NMAPS; i++) o ^= duf_byte(b.m[i]);
  return o;
}

// ---------------------------------------------------------------- session key derivation
struct Session {
  int32_t  x[NMAPS], y[NMAPS];   // bank state after key extraction
  uint8_t  key[16];              // session key K
  bool     valid;
};

inline uint32_t le32(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

inline void session_derive(const uint8_t R[16], const uint8_t Nonce[16], Session& s) {
  uint8_t buf[17], h[64];
  for (int i = 0; i < 16; i++) buf[i] = R[i] ^ Nonce[i];          // seed = R xor Nonce
  buf[16] = 0; sha256(buf, 17, h);                                 // expand the seed into 16 words
  buf[16] = 1; sha256(buf, 17, h + 32);
  Bank b;
  for (int i = 0; i < NMAPS; i++) {
    const uint8_t* w = h + 8 * i;                                  // 2 words (8 bytes) per map
    b.m[i].recoveries = 0;
    b.m[i].x = (int32_t)le32(w) >> 4;                              // Q4.28 in [-0.5, 0.5): inside the basin
    b.m[i].y = (int32_t)le32(w + 4) >> 4;
  }
  for (int i = 0; i < SESSION_WARMUP; i++) bank_step(b);
  for (int i = 0; i < 16; i++) { bank_step(b); s.key[i] = bank_byte(b); }
  for (int i = 0; i < NMAPS; i++) { s.x[i] = b.m[i].x; s.y[i] = b.m[i].y; }
  s.valid = true;
}

// ---------------------------------------------------------------- per-frame material
struct Material { int A, B, C, D; uint8_t iv0, iv1; uint8_t p, q; uint16_t r; };

inline void frame_init(const Session& s, uint32_t frame_id, Bank& b) {
  uint8_t buf[20], h[32];
  memcpy(buf, s.key, 16);
  buf[16] = frame_id; buf[17] = frame_id >> 8; buf[18] = frame_id >> 16; buf[19] = frame_id >> 24;
  sha256(buf, 20, h);
  for (int i = 0; i < NMAPS; i++) {                                // tiny per-map perturbation; chaos amplifies it
    uint32_t p0 = (uint32_t)h[4 * i] | ((uint32_t)h[4 * i + 1] << 8);
    uint32_t p1 = (uint32_t)h[4 * i + 2] | ((uint32_t)h[4 * i + 3] << 8);
    b.m[i].x = s.x[i] ^ (int32_t)p0;
    b.m[i].y = s.y[i] ^ (int32_t)p1;
    b.m[i].recoveries = 0;
  }
  for (int i = 0; i < FRAME_WARMUP; i++) bank_step(b);
}

inline void gen_material(Bank& d, Material& m) {
  uint8_t b[8];
  for (int i = 0; i < 8; i++) { bank_step(d); b[i] = bank_byte(d); }
  m.p   = 1 + (b[0] % (N - 1));
  m.q   = 1 + (b[1] % (N - 1));
  m.r   = 1 + (b[2] | ((uint16_t)(b[3] & 1) << 8));        // 1..512
  m.iv0 = b[4];
  m.iv1 = b[5];
  // M = [[1,p],[q,pq+1]] (det 1), compute M^r mod N by repeated multiplication
  int p = m.p, q = m.q, pq1 = p * q + 1;
  int A = 1, B = 0, C = 0, D = 1;
  auto apply = [&]() {
    int nA = (A + p * C) & (N - 1), nB = (B + p * D) & (N - 1);
    int nC = (q * A + pq1 * C) & (N - 1), nD = (q * B + pq1 * D) & (N - 1);
    A = nA; B = nB; C = nC; D = nD;
  };
  for (int i = 0; i < m.r; i++) apply();
  for (int guard = 0; guard < 64 && (B == 0 || C == 0); guard++) apply();   // avoid degenerate permutations
  m.A = A; m.B = B; m.C = C; m.D = D;
}

// ---------------------------------------------------------------- encrypt / decrypt
// 'in' and 'out' may be the same buffer. 'work' and 'ks' are IMG_BYTES scratch buffers each.
inline void encrypt(const Session& s, uint32_t frame_id, const uint8_t* in, uint8_t* out,
                    uint8_t* work, uint8_t* ks) {
  Bank d; Material m;
  frame_init(s, frame_id, d);
  gen_material(d, m);
  for (size_t i = 0; i < IMG_BYTES; i++) { bank_step(d); ks[i] = bank_byte(d); }

  // 1) Arnold cat-map permutation:  (x,y) -> (A x + B y, C x + D y) mod N
  for (int y = 0; y < N; y++)
    for (int x = 0; x < N; x++) {
      int nx = (m.A * x + m.B * y) & (N - 1);
      int ny = (m.C * x + m.D * y) & (N - 1);
      work[ny * N + nx] = in[y * N + x];
    }
  // 2) forward chained diffusion
  uint8_t prev = m.iv0;
  for (size_t i = 0; i < IMG_BYTES; i++) {
    uint8_t t = (uint8_t)((work[i] + ks[i]) & 0xFF) ^ prev;
    work[i] = t; prev = t;
  }
  // 3) backward chained diffusion (uses the keystream in reverse order)
  prev = m.iv1;
  for (size_t i = IMG_BYTES; i-- > 0;) {
    uint8_t c = (uint8_t)((work[i] + ks[IMG_BYTES - 1 - i]) & 0xFF) ^ prev;
    out[i] = c; prev = c;
  }
}

inline void decrypt(const Session& s, uint32_t frame_id, const uint8_t* in, uint8_t* out,
                    uint8_t* work, uint8_t* ks) {
  Bank d; Material m;
  frame_init(s, frame_id, d);
  gen_material(d, m);
  for (size_t i = 0; i < IMG_BYTES; i++) { bank_step(d); ks[i] = bank_byte(d); }

  // undo backward pass
  for (size_t i = 0; i < IMG_BYTES; i++) {
    uint8_t next = (i == IMG_BYTES - 1) ? m.iv1 : in[i + 1];
    work[i] = (uint8_t)((in[i] ^ next) - ks[IMG_BYTES - 1 - i]);
  }
  // undo forward pass (in place, from the end so work[i-1] is still the original t[i-1])
  for (size_t i = IMG_BYTES; i-- > 0;) {
    uint8_t prev = (i == 0) ? m.iv0 : work[i - 1];
    work[i] = (uint8_t)((work[i] ^ prev) - ks[i]);
  }
  // inverse permutation:  x = D x' - B y',  y = -C x' + A y'  (mod N)
  for (int yp = 0; yp < N; yp++)
    for (int xp = 0; xp < N; xp++) {
      int x = (m.D * xp - m.B * yp) & (N - 1);
      int y = (-m.C * xp + m.A * yp) & (N - 1);
      out[y * N + x] = work[yp * N + xp];
    }
}

}  // namespace pc
