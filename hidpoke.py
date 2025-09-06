#!/usr/bin/env python3
import os, fcntl, array, sys, argparse

HIDIOCSFEATURE = 0xC0094806

def pad(pkt, rid=0x00):
    return [rid] + pkt + [0x00] * (65 - len(pkt) - 1)

def send(fd, pkt, rid=0x00):
    buf = array.array("B", pad(pkt, rid))
    fcntl.ioctl(fd, HIDIOCSFEATURE, buf, True)

def monocolor(fd, r, g, b):
    print("[*] Sending monocolor sequence...")

    # Step 1: Select static effect mode (effect ID 1)
    send(fd, [0x16, 0x00, 0x01])
    print("[+] Effect selected: static")

    # Step 2: Set parameters (speed=0, direction=0, brightness=255 at byte 5)
    send(fd, [0x14, 0x01, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00])
    print("[+] Params set: brightness=255")

    # Step 3: Set global color (non-indexed)
    send(fd, [0x08, 0x00, r, g, b, 0x00, 0x00, 0x00])
    print(f"[+] Color set: R={r} G={g} B={b}")

    # Step 4: Commit changes
    send(fd, [0x1A, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01])
    print("[+] Commit sent")

def main():
    parser = argparse.ArgumentParser(description="Send monocolor lighting packet to HID device")
    parser.add_argument("r", type=int, help="Red value (0–255)")
    parser.add_argument("g", type=int, help="Green value (0–255)")
    parser.add_argument("b", type=int, help="Blue value (0–255)")
    parser.add_argument("--hidraw", default="/dev/hidraw0", help="Path to HID device (e.g. /dev/hidraw1)")
    parser.add_argument("--report-id", type=lambda x: int(x, 0), default=0x00, help="Report ID (default: 0x00)")
    args = parser.parse_args()

    r, g, b = (args.r & 0xFF, args.g & 0xFF, args.b & 0xFF)

    try:
        fd = os.open(args.hidraw, os.O_RDWR)
    except OSError as e:
        print(f"[!] Failed to open {args.hidraw}: {e}")
        sys.exit(1)

    try:
        monocolor(fd, r, g, b)
    finally:
        os.close(fd)

if __name__ == "__main__":
    main()
