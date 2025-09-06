#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
kbctrl - Linux HID Interface for Uniwill/Tongfang Keyboards
===========================================================

Overview
--------
Command-line utility for controlling Uniwill/Tongfang keyboard backlights
via /dev/hidraw (no vendor driver needed). Uses only stdlib.

Key points:
- We talk HID "feature reports" directly (ioctl HIDIOCSFEATURE).
- Packets are 65 bytes total: 1-byte report ID + 64-byte payload (we pad).
- Different "families" control different functions:
  * 0x14 → static mono color
  * 0x09 → brightness (percent)
  * 0x1A → commit/apply
  * 0x16 → effect selector (future work)
  * 0x08 → per-key/per-segment control (future work)

This file embeds a small amount of protocol lore derived from Windows
USB captures (USBPcap) and live hardware experiments.

Why this revision?
------------------
Two earlier paths conflicted:
- “Brightness baked into 0x14” (looked plausible, caused color drift/purple)
- A separate 0x09 family that cleanly takes an integer percent (0..100)

Packet captures + your sanity scripts show the truth: **mono color** is
`14 01 01 RR GG BB 00 00`, and **brightness** lives in `09 02 <percent>…`.
We now implement both exactly that way.
"""

import argparse, os, fcntl, array, time, json, select

# =====================
# HID backend
# =====================

HIDIOCSFEATURE = 0xC0094806  # ioctl: send HID feature report (Linux)

# Config directory (next to this script). Stores last color, last VID/PID.
PROFILE_DIR = os.path.join(os.path.dirname(__file__), "kbctrlprofiles")
CONFIG_PATH = os.path.join(PROFILE_DIR, "last_color.json")
os.makedirs(PROFILE_DIR, exist_ok=True)

# Default IDs frequently seen on Uniwill/Tongfang/ITE devices
DEFAULTVID = "048D"
DEFAULTPID = "6006"

# =====================
# Logging (colorized, aligned labels)
# =====================

COLORS = {
    "INFO":    "\033[94m",  # blue
    "WARN":    "\033[93m",  # yellow
    "ERROR":   "\033[91m",  # red
    "DEBUG":   "\033[90m",  # grey
    "SUCCESS": "\033[92m",  # green
}
RESET = "\033[0m"
QUIET = False

def log(label, msg, level="INFO"):
    """Print a color-coded log message with aligned 10-char label."""
    global QUIET
    if QUIET and level.upper() in ("INFO", "DEBUG"):
        return
    color = COLORS.get(level.upper(), "")
    label_fmt = f"[{label:<10}]"
    print(f"{color}{label_fmt} {msg}{RESET}")

def log_info(label, msg):    log(label, msg, "INFO")
def log_warn(label, msg):    log(label, msg, "WARN")
def log_error(label, msg):   log(label, msg, "ERROR")
def log_debug(label, msg):   log(label, msg, "DEBUG")
def log_success(label, msg): log(label, msg, "SUCCESS")

# =====================
# Config helpers (color + device)
# =====================

def _load_config():
    try:
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def _save_config(cfg):
    os.makedirs(PROFILE_DIR, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)

def save_last_color(r, g, b):
    cfg = _load_config()
    cfg["last_color"] = [int(r), int(g), int(b)]
    _save_config(cfg)

def load_last_color():
    return _load_config().get("last_color", [255, 255, 255])

def supports_truecolor(): # much needed
    """
    Detect whether the terminal likely supports truecolor (24-bit ANSI colors).
    Strategy:
      1. Check $COLORTERM for 'truecolor' or '24bit'
      2. If running inside dumb/no-tty, assume False
      3. Otherwise, optimistic True (most modern terminals handle it)
    """
    colorterm = os.environ.get("COLORTERM", "").lower()
    term = os.environ.get("TERM", "").lower()

    if "truecolor" in colorterm or "24bit" in colorterm:
        return True
    if term in ("dumb", "") or not sys.stdout.isatty():
        return False
    # Heuristic: assume yes if TERM is xterm-256color or better
    if "256color" in term or "xterm" in term:
        return True
    return False


def rgb_preview(r, g, b):
    """Return a colored block if truecolor is supported, else plain [R,G,B]."""
    if supports_truecolor():
        return f"\033[48;2;{r};{g};{b}m   \033[0m"
    else:
        return f"[{r},{g},{b}]"


# =====================
# Device autodetection (VID/PID-cached + fallback)
# =====================

KNOWN_DEVICES = [
    ("048D", "6006"),  # ITE Tech (common)
    ("093A", "0255"),  # Uniwill (seen in your logs)
]

def find_hidraw_by_vid_pid(vid, pid, max_devices=20):
    """
    Scan /sys/class/hidraw/*/device/uevent for a device matching VID/PID.
    We compare against a canonical 'hid_id=0003:vvvvvvvv:pppppppp' line.
    """
    vid_padded = f"{int(vid, 16):08x}"
    pid_padded = f"{int(pid, 16):08x}"
    target = f"hid_id=0003:{vid_padded}:{pid_padded}"

    for i in range(max_devices):
        path = f"/sys/class/hidraw/hidraw{i}/device/uevent"
        log_info("scan", f"looking at {path}")
        try:
            with open(path, "r") as f:
                data = f.read().lower()
                log_debug(f"hidraw{i}", data.strip())
                if target in data:
                    log_success("success", f"enemy spotted: /dev/hidraw{i}")
                    return f"/dev/hidraw{i}"
        except FileNotFoundError:
            continue
    return None

def scan_all_candidates(max_devices=20):
    """Return [(path, uevent_text_lower)] for all hidraw candidates."""
    found = []
    for i in range(max_devices):
        path = f"/sys/class/hidraw/hidraw{i}/device/uevent"
        try:
            with open(path, "r") as f:
                found.append((f"/dev/hidraw{i}", f.read().strip().lower()))
        except FileNotFoundError:
            continue
    return found

def open_hidraw(dev=None):
    """
    Open a hidraw device with a pragmatic priority:
      1) explicit --device
      2) cached VID:PID from config
      3) known VID:PID candidates
      4) brute scan + user choice
    Caches last_vid/last_pid if a known/candidate path succeeds.
    """
    cfg = _load_config()

    if dev:
        log_info("config", f"Using explicit device: {dev}")
        return os.open(dev, os.O_RDWR)

    vid, pid = cfg.get("last_vid"), cfg.get("last_pid")
    if vid and pid:
        log_info("config", f"Trying cached VID:PID {vid}:{pid}")
        path = find_hidraw_by_vid_pid(vid, pid)
        if path:
            return os.open(path, os.O_RDWR)

    for vid, pid in KNOWN_DEVICES:
        log_info("config", f"Trying known VID:PID {vid}:{pid}")
        path = find_hidraw_by_vid_pid(vid, pid)
        if path:
            cfg["last_vid"], cfg["last_pid"] = vid, pid
            _save_config(cfg)
            return os.open(path, os.O_RDWR)

    log_warn("scan", "Brute scanning all hidraw devices...")
    candidates = scan_all_candidates()
    if not candidates:
        raise RuntimeError("No HID devices found.")

    print("Multiple candidate devices found:")
    for idx, (path, data) in enumerate(candidates):
        first = data.splitlines()[0] if data else ""
        print(f" [{idx}] {path}\n      {first}")

    choice = input(f"Select target [0-{len(candidates)-1}]: ")
    try:
        choice = int(choice)
        devpath, data = candidates[choice]
    except (ValueError, IndexError):
        raise RuntimeError("Invalid choice.")

    # Cache VID/PID if present
    for line in data.splitlines():
        if line.startswith("hid_id="):
            parts = line.split(":")
            if len(parts) >= 3:
                cfg["last_vid"], cfg["last_pid"] = parts[1], parts[2]
                _save_config(cfg)
                break

    return os.open(devpath, os.O_RDWR)

def close_hidraw(fd):
    os.close(fd)

def read_hidraw(dev=None, timeout=10):
    """
    Passive HID read (best-effort). Many Fn hotkeys are handled by the EC/firmware
    and may NOT traverse this HID interface—don’t be surprised by silence.
    """
    fd = open_hidraw(dev)
    start = time.time()
    while True:
        r, _, _ = select.select([fd], [], [], 0.5)
        if r:
            blob = os.read(fd, 65)
            if blob:
                hex_str = " ".join(f"{b:02X}" for b in blob)
                log_info("sniff", f"Packet: {hex_str}")
        if time.time() - start > timeout:
            break
    close_hidraw(fd)

# =====================
# Helpers: packing & I/O
# =====================

def pad(pkt):
    """Pad a payload to a 65-byte feature report (0x00 report ID + 64 payload)."""
    return [0x00] + pkt + [0x00] * (65 - 1 - len(pkt))

def send(fd, pkt, label="SEND"):
    """
    Send a raw feature report and log the exact bytes we emitted.
    (This is our single choke-point—great place to instrument later.)
    """
    buf = array.array('B', pad(pkt))
    hex_str = " ".join(f"{b:02X}" for b in pkt)
    log_debug(label, f"Packet: {hex_str}")
    fcntl.ioctl(fd, HIDIOCSFEATURE, buf, True)

def parse_byte(p: str) -> int:
    """
    Accept 0xFF, bare hex 'FF', or decimal '255'.
    Useful for --packet convenience.
    """
    p = p.strip()
    if p.lower().startswith("0x"):
        return int(p, 16)
    if all(c in "0123456789abcdefABCDEF" for c in p):
        return int(p, 16)
    return int(p)

# =====================
# Packet builders (canonical)
# =====================
# Family 0x14 = static mono color.
# Windows-proven format: 14 01 01 RR GG BB 00 00
# Keep CLI RGB; do NOT secretly reorder (we already match RR GG BB).
def pkt_color(r, g, b):
    r, g, b = int(r) & 0xFF, int(g) & 0xFF, int(b) & 0xFF
    return [0x14, 0x01, 0x01, r, g, b, 0x00, 0x00]

# Family 0x09 = brightness percent (0..100).
# Windows app emits: 09 02 XX 00 00 00 00 00
def pkt_brightness_percent(percent):
    lv = max(0, min(100, int(percent)))
    return [0x09, 0x02, lv, 0x00, 0x00, 0x00, 0x00, 0x00]

# Family 0x1A = commit/apply changes (empirically needed on this unit).
def pkt_commit():
    return [0x1A, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01]

# ---- Historical / DO NOT USE path (kept for RE notes) -----------------------
# Some older guesses embedded “brightness” inside 0x14. It caused drift/purple.
# Leaving the function as a reminder + for controlled experiments only.
def _pkt_color_with_brightness_legacy(r, g, b, brightness):
    return [0x14, 0x01, 0x01, int(brightness) & 0xFF, 0x00,
            int(r) & 0xFF, int(g) & 0xFF, int(b) & 0xFF]

def pkt_effect(effect_id):
    """
    Effect selection packet (family 0x16).
    effect_id: integer (0–255)
    """
    return [0x16, 0x00, effect_id & 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00]

def pkt_select_custom():
    # 0x16 family, effect_id=0x00 observed before per-key traffic
    return [0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

def pkt_params_perkey():
    # 0x14 family params observed right before per-key writes
    return [0x14, 0x01, 0x03, 0x04, 0xFF, 0xFF, 0x71, 0x00]

def pkt_perkey(index, r, g, b, enabled=1):
    # 08 02 [index] [R] [G] [B] 00 [enabled]
    return [0x08, 0x02, index & 0xFF, r & 0xFF, g & 0xFF,
            b & 0xFF, 0x00, 0x01 if enabled else 0x00]


# ---------------------------------------------------------------------------

# =====================
# Commands
# =====================

def cmd_raw(args):
    """
    Send an arbitrary packet (danger zone; perfect for RE).
    Example:
      kbctrl raw --packet "14 01 01 FF 00 00 00 00" --commit
    """
    parts = [p.strip() for p in args.packet.replace(",", " ").split()]
    pkt = [parse_byte(p) for p in parts if p]
    if not pkt:
        log_error("raw", "no bytes parsed")
        return
    fd = open_hidraw(dev=args.device)
    try:
        send(fd, pkt, label="raw-packet")
        if args.commit:
            send(fd, pkt_commit(), label="commit")
    finally:
        close_hidraw(fd)
    log_success("+", f"sent raw packet: {pkt}")

def cmd_color(args):
    """Set a static monocolor (RGB) at full brightness."""
    fd = open_hidraw(dev=args.device)
    r, g, b = [int(x) for x in args.color.split(",")]
    send(fd, pkt_color(r, g, b), label="color")
    send(fd, pkt_commit(), label="commit")
    close_hidraw(fd)
    save_last_color(r, g, b)
    preview = rgb_preview(r, g, b)
    log_success("+", f"Monocolor set to {r},{g},{b} {preview}")


def cmd_brightness(args):
    """Adjust brightness while preserving the last color."""
    fd = open_hidraw(dev=args.device)
    r, g, b = load_last_color()
    send(fd, pkt_color_with_brightness(r, g, b, args.level), label="color+brightness")
    send(fd, pkt_commit(), label="commit")
    close_hidraw(fd)
    save_last_color(r, g, b)
    preview = rgb_preview(r, g, b)
    log_success("+", f"Brightness set to {args.level} with color {r},{g},{b} {preview}")

def cmd_reset_rainbow(args):
    fd = open_hidraw()

    # Step 1: Select custom mode
    send(fd, pkt_select_custom(), label="select-custom")

    # Step 2: Send per-key params (optional but observed before per-key writes)
  #  send(fd, pkt_params_perkey(), label="perkey-params")

    # Step 3: Apply a static color (e.g., white)
    send(fd, pkt_color(255, 255, 255), label="static-white")

    # Step 4: Commit the change
    send(fd, pkt_commit(), label="commit")

    close_hidraw(fd)




def cmd_fnf8(args):
    """
    Simulate the typical three-step brightness cycle: 0% → 50% → 100%.
    Firmware hotkey on your unit seems EC-routed; we emulate user intent here.
    """
    fd = open_hidraw(dev=args.device)
    try:
        for lv in [0, 50, 100]:
            send(fd, pkt_brightness_percent(lv), label="brightness")
            send(fd, pkt_commit(), label="commit")
            log_success("+", f"Brightness {lv}%")
            time.sleep(1)
    finally:
        close_hidraw(fd)

def cmd_debug(args):
    """Emit a known-good example packet (useful for eyeballing)."""
    pkt = pkt_color(255, 0, 0)
    hex_str = " ".join(f"{b:02X}" for b in pkt)
    log_info("debug", f"Mono-color (red) packet: {hex_str}")


def cmd_sniff(args):
    """Sniff HID traffic for a short window (best-effort)."""
    read_hidraw(dev=args.device, timeout=args.timeout)

def cmd_sweep(args):
    """
    Coarse sanity sweep to verify channel mapping on a new device.
    Round-labeled: payload then commit → pause.
    """
    fd = open_hidraw(dev=args.device)
    rounds = []

    # R-only sweep
    for val in [0, 64, 128, 192, 255]:
        rounds.append(("R-sweep", pkt_color(val, 0, 0)))

    # G-only sweep
    for val in [0, 64, 128, 192, 255]:
        rounds.append(("G-sweep", pkt_color(0, val, 0)))

    # B-only sweep
    for val in [0, 64, 128, 192, 255]:
        rounds.append(("B-sweep", pkt_color(0, 0, val)))

    # Flags nibble exploration (kept as a playground; effects may key off it)
    for flag in range(0, 6):
        pkt = [0x14, 0x01, 0x01, 0xFF, 0xFF, 0xFF, flag & 0xFF, 0x00]
        rounds.append((f"flag-{flag}", pkt))

    # Execute all rounds with explicit round labeling
    round_num = 1
    for label, pkt in rounds:
        log_info(f"round {round_num}", label)
        log_debug("payload", " ".join(f"{b:02X}" for b in pkt))
        send(fd, pkt, label="payload")
        send(fd, pkt_commit(), label="commit")
        time.sleep(args.delay)
        round_num += 1

    close_hidraw(fd)
    log_success("+", "Sweep complete. Check which packets matched expected colors.")

def cmd_effect_sweep(args):
    """
    Sweep through effect IDs to build an effect map.
    - Sends effect packet
    - Sends commit
    - Waits delay between rounds
    """
    fd = open_hidraw(dev=args.device)
    round_num = 1
    for effect_id in range(args.start, args.end + 1):
        pkt = pkt_effect(effect_id)
        log_info(f"round {round_num}", f"Effect ID {effect_id}")
        log_debug("payload", " ".join(f"{b:02X}" for b in pkt))
        send(fd, pkt, label="effect")
        send(fd, pkt_commit(), label="commit")
        time.sleep(args.delay)
        round_num += 1

    close_hidraw(fd)
    log_success("+", "Effect sweep complete. Note visible effects per ID.")

def cmd_key_sweep(args):
    """Interactive per-key index → label mapper."""
    import yaml

    fd = open_hidraw(dev=args.device)

    # parse background color
    bg_r, bg_g, bg_b = [int(x) for x in args.background.split(",")]

    # set solid background first
    send(fd, pkt_color(bg_r, bg_g, bg_b), label="background")
    send(fd, pkt_commit(), label="commit")

    keymap = {}
    try:
        for idx in range(0x00, 0x40):  # adjust upper bound if more indices exist
            # highlight this index in bright red
            pkt_on  = [0x08, 0x02, idx, 0xFF, 0x00, 0x00, 0x00, 0x01]
            pkt_off = [0x08, 0x02, idx, 0x00, 0x00, 0x00, 0x00, 0x00]

            send(fd, pkt_on,  label=f"perkey-{idx:02X}")
            send(fd, pkt_commit(), label="commit")

            label = input(f"Index 0x{idx:02X} → label? ")
            if label.strip():
                keymap[f"0x{idx:02X}"] = label.strip()

            # turn highlight back off → restore background
            send(fd, pkt_off, label="perkey-off")
            send(fd, pkt_commit(), label="commit")

    finally:
        close_hidraw(fd)

    with open(args.output, "w") as f:
        yaml.safe_dump(keymap, f, sort_keys=True)
    log_success("+", f"Saved mapping to {args.output}")


# =====================
# Main CLI
# =====================

def main():
    global QUIET
    p = argparse.ArgumentParser(
        prog="kbctrl",
        description="Uniwill/Tongfang keyboard control (Linux HID)"
    )
    p.add_argument("--device", help="Manual HID device path (e.g. /dev/hidraw1)")
    p.add_argument("--quiet", action="store_true", help="Suppress info/debug logs")

    sub = p.add_subparsers()

    # Raw packet sender
    sr = sub.add_parser("raw", help="Send a custom raw packet")
    sr.add_argument("--packet", required=True, help="e.g. '14 01 01 FF 00 00 00 00'")
    sr.add_argument("--commit", action="store_true", help="Send commit after")
    sr.set_defaults(func=cmd_raw)

    ks = sub.add_parser("key-sweep", help="Interactive per-key index > label mapper")
    ks.add_argument("--indices", help="comma-separated indices (hex or dec); default 0-127", default="")
    ks.add_argument("--delay", type=float, default=0.6, help="pause between highlights")
    ks.add_argument("--outfile", default="keymap.yaml", help="where to write YAML")
    ks.add_argument("--background", help="R,G,B backdrop during sweep (default 0,0,255)")
    ks.set_defaults(func=cmd_key_sweep)

    rr = sub.add_parser("reset-rainbow", help="Reset keyboard to rainbow effect")
    rr.set_defaults(func=cmd_reset_rainbow)



    # Sniffer (may remain quiet if firmware handles hotkeys in EC)
    ss = sub.add_parser("sniff", help="Sniff raw HID packets (try pressing hotkeys)")
    ss.add_argument("--timeout", type=int, default=10, help="Seconds to listen")
    ss.set_defaults(func=cmd_sniff)

    # High-level commands
    sc = sub.add_parser("color", help="Set monocolor")
    sc.add_argument("--color", required=True, help="R,G,B (0..255)")
    sc.set_defaults(func=cmd_color)

    sb = sub.add_parser("brightness", help="Set brightness percent (0..100)")
    sb.add_argument("--level", type=int, required=True)
    sb.set_defaults(func=cmd_brightness)

    sf = sub.add_parser("fnf8", help="Cycle brightness 0%% -> 50 >- 100%%")
    sf.set_defaults(func=cmd_fnf8)

    sd = sub.add_parser("debug", help="Show example packet")
    sd.set_defaults(func=cmd_debug)

    # Sweep utility
    sw = sub.add_parser("sweep", help="Coarse RGB sweep to sanity-check channel mapping")
    sw.add_argument("--delay", type=float, default=0.5, help="Pause between rounds (s)")
    sw.set_defaults(func=cmd_sweep)

    args = p.parse_args()
    QUIET = args.quiet

    if hasattr(args, "func"):
        args.func(args)
    else:
        p.print_help()

if __name__ == "__main__":
    main()


# =====================
# Rosetta Stone (quick reference)
# =====================
"""
Packet format: [Family] [Sub-ID] [Param] [Payload...]

0x14 - Static Color
  14 01 01 RR GG BB 00 00   → Set monocolor (Windows-confirmed)
  (CLI takes RGB; we place RR GG BB as-is.)

0x09 - Brightness (percent)
  09 02 XX 00 00 00 00 00   → XX in 0..100 (0%, 50%, 100% observed)

0x1A - Commit
  1A 00 01 04 00 00 00 01   → Apply staged changes

0x08 - Per-key/segment (to map later)
  08 02 01 0A 64 08 00 01   → Mode/config kick-off observed
  (Actual RGB map likely bulk/interrupt OUT, not 8B feature frames.)

0x16 - Effect selector (to map later)
  16 00 EFFECT_ID 00 00 00 00 00   → Needs controlled capture

Notes:
- Commit appears required on this unit (even if Windows app sometimes omits).
- Fn+F8 brightness on Linux may be EC-handled; HID sniff may show nothing.
"""
