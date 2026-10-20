#!/usr/bin/env python3
"""
UAV-side laptop script: stands in for the camera.

Listens on the UAV ESP32's USB serial port. Whenever it sees the request byte 0x01 it
produces ONE 128x128 8-bit grayscale frame and replies with

    0xA5 0x5A | length (4 bytes LE) | crc32 (4 bytes LE) | 16384 raw pixel bytes

(length 0 means "camera failed"). Every other byte coming from the ESP32 is printed as text.

Frame source (pick one):
    (default)        laptop webcam
    --image  FILE    always send this image                 (e.g. Lena, for the comparison tests)
    --image-dir DIR  send the images in DIR one per request, cycling through them

Every frame that is sent is also saved to ./sent_frames/ so the decrypted result can be compared.

Install:  pip install pyserial opencv-python numpy
Run:      python uav_webcam_responder.py --port COM7
"""

import argparse
import hashlib
import os
import struct
import sys
import time
import zlib

import cv2
import numpy as np
import serial

# ===================== USER SETTINGS (can also be passed as arguments) =====================
DEFAULT_PORT = "COM7"        # <-- the UAV ESP32's COM port
DEFAULT_BAUD = 921600        # must match SERIAL_BAUD in uav_puf_chaos.ino
DEFAULT_CAM = 0              # webcam index (try 1 if 0 is the wrong camera)
# ===========================================================================================

REQ_BYTE = 0x01
MAGIC = b"\xA5\x5A"
N = 128
IMG_EXT = (".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".pgm")


def to_gray128(img):
    """Any BGR/gray image -> centre-cropped square -> 128x128 uint8 grayscale."""
    if img.ndim == 3:
        img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    h, w = img.shape
    s = min(h, w)
    y0, x0 = (h - s) // 2, (w - s) // 2
    img = img[y0:y0 + s, x0:x0 + s]
    return cv2.resize(img, (N, N), interpolation=cv2.INTER_AREA)


class WebcamSource:
    def __init__(self, index):
        backend = cv2.CAP_DSHOW if os.name == "nt" else cv2.CAP_ANY
        self.cap = cv2.VideoCapture(index, backend)
        if not self.cap.isOpened():
            raise RuntimeError(f"could not open webcam index {index} (close other apps using it, or try --cam 1)")
        self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
        self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
        self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
        for _ in range(10):                      # let auto-exposure settle
            self.cap.read()
        self.name = f"webcam {index}"

    def next(self):
        frame = None
        for _ in range(3):                       # skip buffered frames to get a fresh one
            ok, f = self.cap.read()
            if ok:
                frame = f
        return None if frame is None else to_gray128(frame)

    def close(self):
        self.cap.release()


class FileSource:
    def __init__(self, paths):
        self.paths = paths
        self.i = 0
        self.name = f"{len(paths)} image file(s)"

    def next(self):
        p = self.paths[self.i % len(self.paths)]
        self.i += 1
        img = cv2.imread(p, cv2.IMREAD_UNCHANGED)
        if img is None:
            print(f"[PC] cannot read {p}")
            return None
        print(f"[PC] using {os.path.basename(p)}")
        return to_gray128(img)

    def close(self):
        pass


def build_frame(gray):
    """Header + raw pixels for a 128x128 uint8 array (None -> error frame)."""
    if gray is None:
        return MAGIC + struct.pack("<II", 0, 0)
    raw = np.ascontiguousarray(gray, dtype=np.uint8).tobytes()
    assert len(raw) == N * N
    return MAGIC + struct.pack("<II", len(raw), zlib.crc32(raw) & 0xFFFFFFFF) + raw


def serve_request(ser, source, outdir, counter):
    t0 = time.time()
    gray = source.next()
    ser.write(build_frame(gray))
    ser.flush()
    if gray is None:
        print("[PC] capture failed - sent error frame")
        return
    counter[0] += 1
    cv2.imwrite(os.path.join(outdir, f"sent_{counter[0]:03d}.png"), gray)
    h = hashlib.sha256(gray.tobytes()).hexdigest()[:8]
    print(f"[PC] frame #{counter[0]} sent ({N * N} bytes), plaintext sha256 {h}, {(time.time() - t0) * 1000:.0f} ms")


def main():
    ap = argparse.ArgumentParser(description="Frame source for the UAV ESP32")
    ap.add_argument("--port", default=DEFAULT_PORT)
    ap.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    ap.add_argument("--cam", type=int, default=DEFAULT_CAM)
    ap.add_argument("--image", help="always send this image file")
    ap.add_argument("--image-dir", help="send the images of this folder one per request (cycling)")
    ap.add_argument("--outdir", default="sent_frames")
    args = ap.parse_args()

    try:
        if args.image:
            source = FileSource([args.image])
        elif args.image_dir:
            paths = sorted(os.path.join(args.image_dir, f) for f in os.listdir(args.image_dir)
                           if f.lower().endswith(IMG_EXT))
            if not paths:
                sys.exit(f"no images found in {args.image_dir}")
            source = FileSource(paths)
        else:
            source = WebcamSource(args.cam)
    except RuntimeError as e:
        sys.exit(str(e))
    os.makedirs(args.outdir, exist_ok=True)
    print(f"[PC] frame source: {source.name} ({N}x{N} grayscale)")

    ser = serial.Serial()
    ser.port = args.port
    ser.baudrate = args.baud
    ser.timeout = 0.1
    ser.write_timeout = 10
    ser.dtr = False              # avoid resetting the ESP32 on connect (some boards reset anyway)
    ser.rts = False
    try:
        ser.open()
    except serial.SerialException as e:
        sys.exit(f"Could not open {args.port}: {e}\n(Close the Arduino Serial Monitor / other programs using it.)")
    print(f"[PC] listening on {args.port} @ {args.baud}. Ctrl+C to quit.")

    counter = [0]
    line = bytearray()
    try:
        while True:
            data = ser.read(max(1, ser.in_waiting))
            for b in data:
                if b == REQ_BYTE:
                    serve_request(ser, source, args.outdir, counter)
                elif b == 0x0A:
                    text = line.decode(errors="replace").strip()
                    if text:
                        print(text)
                    line.clear()
                else:
                    line.append(b)
    except KeyboardInterrupt:
        print("\n[PC] stopped.")
    finally:
        ser.close()
        source.close()


if __name__ == "__main__":
    main()
