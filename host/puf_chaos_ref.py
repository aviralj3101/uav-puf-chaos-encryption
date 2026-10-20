#!/usr/bin/env python3
"""
puf_chaos_ref.py -- bit-exact Python reference of the PUF chaos cipher in puf_chaos.h

Use it to
  * cross-check the ESP32 firmware (same inputs -> same ciphertext),
  * encrypt/decrypt standard test images on the PC for the comparison study,
  * run a self-test:   python puf_chaos_ref.py selftest

Python's >> on negative ints is an arithmetic shift, matching gcc/xtensa, so the
fixed-point maths here is identical to the C++ version.
"""
import argparse
import hashlib
import hmac
import sys

import numpy as np

N = 128
IMG_BYTES = N * N
FRAC = 28
DUF_A = 738197504          # 2.75 * 2^28
DUF_B = 53687091           # round(0.2 * 2^28)
ESC_LIMIT = 3 << FRAC
NMAPS = 5
SESSION_WARMUP = 500
FRAME_WARMUP = 100
M32 = 0xFFFFFFFF


def s32(v):
    """Wrap an int to signed 32-bit (what a C int32_t cast does)."""
    v &= M32
    return v - (1 << 32) if v & 0x80000000 else v


def rotl32(x, n):
    x &= M32
    return ((x << n) | (x >> (32 - n))) & M32


def mix32(h):
    h &= M32
    h ^= h >> 16
    h = (h * 0x85ebca6b) & M32
    h ^= h >> 13
    h = (h * 0xc2b2ae35) & M32
    h ^= h >> 16
    return h


def sha256(b):
    return hashlib.sha256(bytes(b)).digest()


def puf_response(secret16, chal16):
    return hmac.new(bytes(secret16), b"PUF-EMU-v2" + bytes(chal16), hashlib.sha256).digest()[:16]


class Duffing:
    def __init__(self, x=0, y=0):
        self.x, self.y, self.recoveries = x, y, 0

    def recover(self):
        salt = ((self.x & M32) ^ rotl32(self.y & M32, 16) ^ ((0x9e3779b9 * (self.recoveries + 1)) & M32)) & M32
        self.recoveries += 1
        self.x = s32(mix32(salt)) >> 4
        self.y = s32(mix32(salt ^ 0xa5a5a5a5)) >> 4

    def step(self):
        x, y = self.x, self.y
        y2 = (y * y) >> FRAC
        y3 = (y2 * y) >> FRAC
        ny = ((DUF_A * y) >> FRAC) - ((DUF_B * x) >> FRAC) - y3
        if ny > ESC_LIMIT or ny < -ESC_LIMIT:
            self.recover()
            return
        self.x, self.y = y, ny

    def byte(self):
        return (((self.y & M32) >> 13) ^ ((self.x & M32) >> 5)) & 0xFF


class Session:
    def __init__(self):
        self.x = [0] * NMAPS
        self.y = [0] * NMAPS
        self.key = b""


def bank_step(bank):
    for d in bank:
        d.step()


def bank_byte(bank):
    o = 0
    for d in bank:
        o ^= d.byte()
    return o


def session_derive(R, nonce):
    seed = bytes(a ^ b for a, b in zip(R, nonce))
    h = sha256(seed + b"\x00") + sha256(seed + b"\x01")
    bank = []
    for i in range(NMAPS):
        w = h[8 * i:8 * i + 8]
        bank.append(Duffing(s32(int.from_bytes(w[0:4], "little")) >> 4,
                            s32(int.from_bytes(w[4:8], "little")) >> 4))
    for _ in range(SESSION_WARMUP):
        bank_step(bank)
    key = bytearray()
    for _ in range(16):
        bank_step(bank)
        key.append(bank_byte(bank))
    s = Session()
    s.x = [d.x for d in bank]
    s.y = [d.y for d in bank]
    s.key = bytes(key)
    return s


def frame_init(s, frame_id):
    h = sha256(s.key + frame_id.to_bytes(4, "little"))
    bank = []
    for i in range(NMAPS):
        p0 = h[4 * i] | (h[4 * i + 1] << 8)
        p1 = h[4 * i + 2] | (h[4 * i + 3] << 8)
        bank.append(Duffing(s32((s.x[i] & M32) ^ p0), s32((s.y[i] & M32) ^ p1)))
    for _ in range(FRAME_WARMUP):
        bank_step(bank)
    return bank


def gen_material(bank):
    b = []
    for _ in range(8):
        bank_step(bank)
        b.append(bank_byte(bank))
    p = 1 + (b[0] % (N - 1))
    q = 1 + (b[1] % (N - 1))
    r = 1 + (b[2] | ((b[3] & 1) << 8))
    iv0, iv1 = b[4], b[5]
    pq1 = p * q + 1
    A, B, C, D = 1, 0, 0, 1

    def apply(A, B, C, D):
        return ((A + p * C) & (N - 1), (B + p * D) & (N - 1),
                (q * A + pq1 * C) & (N - 1), (q * B + pq1 * D) & (N - 1))

    for _ in range(r):
        A, B, C, D = apply(A, B, C, D)
    guard = 0
    while guard < 64 and (B == 0 or C == 0):
        A, B, C, D = apply(A, B, C, D)
        guard += 1
    return dict(A=A, B=B, C=C, D=D, iv0=iv0, iv1=iv1, p=p, q=q, r=r)


def keystream(bank):
    ks = np.empty(IMG_BYTES, dtype=np.uint8)
    for i in range(IMG_BYTES):
        bank_step(bank)
        ks[i] = bank_byte(bank)
    return ks


def _perm_index(A, B, C, D):
    y, x = np.divmod(np.arange(IMG_BYTES), N)
    nx = (A * x + B * y) & (N - 1)
    ny = (C * x + D * y) & (N - 1)
    return ny * N + nx          # destination index for each source pixel


def encrypt(s, frame_id, plain):
    plain = np.asarray(plain, dtype=np.uint8).reshape(-1)
    assert plain.size == IMG_BYTES
    d = frame_init(s, frame_id)
    m = gen_material(d)
    ks = keystream(d)
    work = np.empty(IMG_BYTES, dtype=np.uint8)
    work[_perm_index(m["A"], m["B"], m["C"], m["D"])] = plain
    prev = m["iv0"]
    for i in range(IMG_BYTES):                       # forward chained diffusion
        t = ((int(work[i]) + int(ks[i])) & 0xFF) ^ prev
        work[i] = t
        prev = t
    out = np.empty(IMG_BYTES, dtype=np.uint8)
    prev = m["iv1"]
    for i in range(IMG_BYTES - 1, -1, -1):           # backward chained diffusion
        c = ((int(work[i]) + int(ks[IMG_BYTES - 1 - i])) & 0xFF) ^ prev
        out[i] = c
        prev = c
    return out


def decrypt(s, frame_id, cipher):
    cipher = np.asarray(cipher, dtype=np.uint8).reshape(-1)
    assert cipher.size == IMG_BYTES
    d = frame_init(s, frame_id)
    m = gen_material(d)
    ks = keystream(d)
    work = np.empty(IMG_BYTES, dtype=np.uint8)
    for i in range(IMG_BYTES):
        nxt = m["iv1"] if i == IMG_BYTES - 1 else int(cipher[i + 1])
        work[i] = ((int(cipher[i]) ^ nxt) - int(ks[IMG_BYTES - 1 - i])) & 0xFF
    for i in range(IMG_BYTES - 1, -1, -1):
        prev = m["iv0"] if i == 0 else int(work[i - 1])
        work[i] = ((int(work[i]) ^ prev) - int(ks[i])) & 0xFF
    idx = _perm_index(m["A"], m["B"], m["C"], m["D"])
    return work[idx]                                 # plain[src] = work[dst(src)]


def load_gray128(path):
    import cv2
    img = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        sys.exit(f"cannot read {path}")
    h, w = img.shape
    s = min(h, w)
    img = img[(h - s) // 2:(h - s) // 2 + s, (w - s) // 2:(w - s) // 2 + s]
    return cv2.resize(img, (N, N), interpolation=cv2.INTER_AREA)


def entropy(a):
    c = np.bincount(np.asarray(a, dtype=np.uint8).reshape(-1), minlength=256).astype(float)
    p = c[c > 0] / c.sum()
    return float(-(p * np.log2(p)).sum())


def selftest():
    secret = bytes(range(0x10, 0x20))
    chal = bytes(range(16))
    nonce = bytes(range(100, 116))
    R = puf_response(secret, chal)
    s = session_derive(R, nonce)
    print("R   :", R.hex())
    print("K   :", s.key.hex())
    print("fp  :", sha256(s.key)[:4].hex())
    img = (np.add.outer(np.arange(N), np.arange(N)) * 255 // (2 * N - 2)).astype(np.uint8)   # gradient test image
    c = encrypt(s, 7, img)
    print("cipher sha256:", sha256(c.tobytes()).hex())
    ok = np.array_equal(decrypt(s, 7, c), img.reshape(-1))
    print("round-trip   :", "OK" if ok else "FAILED")
    print("entropy plain/cipher: %.4f / %.4f" % (entropy(img), entropy(c)))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    e = sub.add_parser("encrypt", help="encrypt an image file (any format) to 128x128 gray cipher .png/.bin")
    e.add_argument("image")
    e.add_argument("--secret", default=bytes(range(0x10, 0x20)).hex(), help="16-byte hex PUF secret (test value)")
    e.add_argument("--challenge", default=bytes(range(16)).hex())
    e.add_argument("--nonce", default=bytes(range(100, 116)).hex())
    e.add_argument("--frame", type=int, default=0)
    e.add_argument("--out", default="cipher.png")
    args = ap.parse_args()
    if args.cmd == "selftest":
        sys.exit(selftest())
    import cv2
    R = puf_response(bytes.fromhex(args.secret), bytes.fromhex(args.challenge))
    s = session_derive(R, bytes.fromhex(args.nonce))
    c = encrypt(s, args.frame, load_gray128(args.image))
    cv2.imwrite(args.out, c.reshape(N, N))
    print("wrote", args.out)


if __name__ == "__main__":
    main()
