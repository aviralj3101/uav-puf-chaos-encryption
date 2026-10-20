#!/usr/bin/env python3
"""
Base-station laptop script for the PUF chaos system.

Commands (type then Enter):
    s        start a new session (uses one unused CRP, derives the session key on both boards)
    Enter    capture one frame   (or  c)
    t        show status of the base board
    x        wipe the CRP table on the base board
    q        quit

Before the first run, enroll challenge/response pairs over USB (this script and the UAV script
must NOT be running):   python enroll.py --uav-port COM7 --base-port COM10 --count 10
Then here:   s   ->   (Enter) (Enter) ...

For every capture it saves, in ./captures/ :
    capture_NNN_cipher.png / .bin   the encrypted frame as it crossed the air
    capture_NNN_plain.png           the frame decrypted by the base ESP32
and prints entropy and a short SHA-256 of the plaintext (compare it with the UAV and responder lines).

Install:  pip install pyserial opencv-python numpy
Run:      python base_receiver.py --port COM10
"""

import argparse
import hashlib
import os
import sys
import threading
import time

import cv2
import numpy as np
import serial

# ===================== USER SETTINGS (can also be passed as arguments) =====================
DEFAULT_PORT = "COM10"       # <-- the BASE ESP32's COM port
DEFAULT_BAUD = 921600        # must match SERIAL_BAUD in base_puf_chaos.ino
DEFAULT_OUTDIR = "captures"
# ===========================================================================================

N = 128
IMG_BYTES = N * N
MARKERS = {b"CIPHER_START": "cipher", b"PLAIN_START": "plain"}

state = {"t_trigger": 0.0, "count": 0, "cipher": None}


def entropy(a):
    c = np.bincount(np.frombuffer(a, dtype=np.uint8), minlength=256).astype(float)
    p = c[c > 0] / c.sum()
    return float(-(p * np.log2(p)).sum())


def h_corr(a):
    """Horizontal adjacent-pixel correlation."""
    img = np.frombuffer(a, dtype=np.uint8).reshape(N, N).astype(float)
    x, y = img[:, :-1].ravel(), img[:, 1:].ravel()
    if x.std() == 0 or y.std() == 0:
        return float("nan")
    return float(np.corrcoef(x, y)[0, 1])


def read_exact(ser, n, timeout=20.0):
    buf = bytearray()
    deadline = time.time() + timeout
    while len(buf) < n and time.time() < deadline:
        buf.extend(ser.read(n - len(buf)))
    return bytes(buf)


def save_pair(cipher, plain, outdir):
    state["count"] += 1
    base = os.path.join(outdir, f"capture_{state['count']:03d}")
    with open(base + "_cipher.bin", "wb") as f:
        f.write(cipher)
    cv2.imwrite(base + "_cipher.png", np.frombuffer(cipher, np.uint8).reshape(N, N))
    cv2.imwrite(base + "_plain.png", np.frombuffer(plain, np.uint8).reshape(N, N))
    rtt = time.time() - state["t_trigger"] if state["t_trigger"] else 0.0
    print(f"[PC] saved {base}_cipher.png / _plain.png")
    print(f"[PC] plaintext sha256 {hashlib.sha256(plain).hexdigest()[:8]} | "
          f"entropy plain {entropy(plain):.4f} cipher {entropy(cipher):.4f} | "
          f"h-corr plain {h_corr(plain):.4f} cipher {h_corr(cipher):.4f} | "
          f"trigger-to-file {rtt:.2f} s")


def handle_frame(kind, data, outdir):
    if kind == "cipher":
        state["cipher"] = data
    else:
        cipher, state["cipher"] = state["cipher"], None
        if cipher is None:
            print("[PC] plain image arrived without a cipher image - not saved")
        else:
            save_pair(cipher, data, outdir)


def reader(ser, outdir, stop):
    pending = b""
    while not stop.is_set():
        try:
            chunk = ser.readline()
        except serial.SerialException as e:
            print(f"[PC] serial error: {e}")
            stop.set()
            return
        if not chunk:
            continue
        pending += chunk
        if not pending.endswith(b"\n"):
            continue
        line = pending.strip()
        pending = b""

        if line in MARKERS:
            hdr = read_exact(ser, 4)
            if len(hdr) < 4:
                print("[PC] image header incomplete")
                continue
            length = int.from_bytes(hdr, "little")
            data = read_exact(ser, length)
            if len(data) != length or length != IMG_BYTES:
                print(f"[PC] image incomplete or wrong size: got {len(data)} of {length} bytes")
                continue
            handle_frame(MARKERS[line], data, outdir)
        elif line.endswith(b"_END") and line.split(b"_")[0] in (b"CIPHER", b"PLAIN"):
            pass
        elif line:
            print(line.decode(errors="replace"))


def main():
    ap = argparse.ArgumentParser(description="Base station for the PUF chaos system")
    ap.add_argument("--port", default=DEFAULT_PORT)
    ap.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    ap.add_argument("--outdir", default=DEFAULT_OUTDIR)
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    ser = serial.Serial()
    ser.port = args.port
    ser.baudrate = args.baud
    ser.timeout = 1
    ser.dtr = False              # avoid resetting the ESP32 on connect (some boards reset anyway)
    ser.rts = False
    try:
        ser.open()
    except serial.SerialException as e:
        sys.exit(f"Could not open {args.port}: {e}\n(Close the Arduino Serial Monitor / other programs using it.)")
    time.sleep(2)                # give the ESP32 time to boot if it did reset
    ser.reset_input_buffer()
    print(f"[PC] connected to {args.port} @ {args.baud}, saving to ./{args.outdir}/")
    print("[PC] commands: s=session  Enter=capture  t=status  x=wipe CRPs  q=quit  (enroll first with enroll.py)")

    stop = threading.Event()
    threading.Thread(target=reader, args=(ser, args.outdir, stop), daemon=True).start()
    ser.write(b"T")

    try:
        while not stop.is_set():
            cmd = input("> ").strip().lower()
            if cmd == "q":
                break
            elif cmd == "s":
                ser.write(b"S")
            elif cmd in ("", "c"):
                state["t_trigger"] = time.time()
                ser.write(b"1")
            elif cmd == "t":
                ser.write(b"T")
            elif cmd == "x":
                ser.write(b"X")
            else:
                print("[PC] unknown command")
            time.sleep(0.1)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        stop.set()
        time.sleep(0.2)
        ser.close()
        print("[PC] closed.")


if __name__ == "__main__":
    main()
