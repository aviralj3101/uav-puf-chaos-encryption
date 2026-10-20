#!/usr/bin/env python3
"""
Wired enrollment for the PUF chaos system. Run this ONCE (and again whenever the base runs out of
unused pairs), with both boards plugged into this laptop and the other two scripts NOT running
(they would be holding the COM ports).

For each pair it
    1. makes a random 16-byte challenge C,
    2. sends C to the UAV over the UAV's USB cable and reads back the PUF response R,
    3. sends (C, R) to the base over the base's USB cable, which stores it in its flash.

R only ever travels over the two USB cables. It is never transmitted by radio and never written
to disk or printed by this script.

Install:  pip install pyserial
Run:      python enroll.py --uav-port COM7 --base-port COM10 --count 10
"""

import argparse
import os
import sys
import time

import serial

# ===================== USER SETTINGS (can also be passed as arguments) =====================
DEFAULT_UAV_PORT = "COM7"
DEFAULT_BASE_PORT = "COM10"
DEFAULT_BAUD = 921600        # must match SERIAL_BAUD in both firmwares
# ===========================================================================================

UAV_CMD = b"\xE1\x4F"        # command header understood by the UAV firmware


def open_port(port, baud):
    ser = serial.Serial()
    ser.port = port
    ser.baudrate = baud
    ser.timeout = 0.2
    ser.write_timeout = 5
    ser.dtr = False          # avoid resetting the ESP32 on connect (some boards reset anyway)
    ser.rts = False
    ser.open()
    return ser


def read_until(ser, predicate, timeout):
    """Read lines until predicate(line_text) is true; return that line or None on timeout."""
    deadline = time.time() + timeout
    buf = b""
    while time.time() < deadline:
        chunk = ser.readline()
        if not chunk:
            continue
        buf += chunk
        if not buf.endswith(b"\n"):
            continue
        text = buf.decode(errors="replace").strip()
        buf = b""
        if predicate(text):
            return text
    return None


def get_response(uav, challenge):
    uav.reset_input_buffer()
    uav.write(UAV_CMD + challenge)
    uav.flush()
    line = read_until(uav, lambda t: "PUFRESP:" in t, 3.0)
    if line is None:
        return None
    hexpart = line.split("PUFRESP:", 1)[1].strip()
    try:
        r = bytes.fromhex(hexpart)
    except ValueError:
        return None
    return r if len(r) == 16 else None


def store_pair(base, challenge, response):
    base.reset_input_buffer()
    base.write(b"P" + challenge + response)
    base.flush()
    return read_until(base, lambda t: "enrolled CRP" in t or "FAILED" in t, 4.0)


def enroll(uav, base, count, log=print):
    ok = 0
    for i in range(count):
        challenge = os.urandom(16)
        r = get_response(uav, challenge)
        if r is None:
            log(f"[{i + 1}/{count}] no valid response from the UAV (check the port and that the UAV firmware is running)")
            break
        result = store_pair(base, challenge, r)
        if result is None or "FAILED" in result:
            log(f"[{i + 1}/{count}] the base did not confirm: {result}")
            break
        log(f"[{i + 1}/{count}] {result}")
        ok += 1
    return ok


def main():
    ap = argparse.ArgumentParser(description="Wired CRP enrollment")
    ap.add_argument("--uav-port", default=DEFAULT_UAV_PORT)
    ap.add_argument("--base-port", default=DEFAULT_BASE_PORT)
    ap.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    ap.add_argument("--count", type=int, default=10, help="number of pairs to enroll (base holds at most 40)")
    args = ap.parse_args()

    try:
        uav = open_port(args.uav_port, args.baud)
        base = open_port(args.base_port, args.baud)
    except serial.SerialException as e:
        sys.exit(f"Could not open a port: {e}\n(Close the Arduino Serial Monitor and the other scripts.)")
    time.sleep(2)            # give the boards time to boot if opening the port reset them
    uav.reset_input_buffer()
    base.reset_input_buffer()

    ok = enroll(uav, base, args.count)
    print(f"enrolled {ok} of {args.count} pairs")
    base.write(b"T")
    line = read_until(base, lambda t: "CRPs stored" in t, 2.0)
    if line:
        print(line)
    uav.close()
    base.close()
    sys.exit(0 if ok == args.count else 1)


if __name__ == "__main__":
    main()
