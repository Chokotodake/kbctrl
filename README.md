# kbctrl
kbctrl: Linux HID controller for Uniwill/Tongfang RGB keyboards
right now it's in a very basic state. do not expect this to work
kbctrl — Hiatus Notes
Current State

Core CLI implemented
color → static RGB (mono color).
brightness → percent (0–100).
fnf8 → 0% → 50% → 100% cycle.
sweep → RGB sweep & flag testing.
effect-sweep (partial) → iterates effect IDs.
solid → force a solid fill of one RGB.
reset-rainbow → quick restore to rainbow effect.
key-sweep → interactive per-key index → YAML map builder.

Packet families confirmed
0x14 → static mono color, and also parameter/config commands.
0x09 → brightness percent.
0x1A → commit/apply changes.
0x16 → effect selector (IDs ~0x00–0x15 known).
0x08 → per-key or per-segment control.
Working HID I/O
/dev/hidrawN auto-detect + VID/PID cache.
Feature reports padded to 65 bytes.
Logging with color + quiet flag.

Discoveries
Commit (0x1A) seems required after nearly every state change.
Rainbow = effect ID 0x05 (but exact behavior may vary by firmware).
Per-key lighting packets (0x08) exist, but still unclear if bulk/interrupt transfers are needed for full layouts.
Some captures show long URB_INTERRUPT out buffers with structured patterns → probably bulk per-key frame chunks.

TODO / Future Work
Per-Key Mapping
Build out full index → keymap YAML (A–Z, 0–9, F-keys, modifiers).
Verify whether per-key config is feature-report only or requires bulk writes.

Effects Catalog
Finish labeling 0x00–0x15 (gaming, wave, ripple, rain, sparks, aurora, etc.).
Document required parameters (speed, direction, colors).

Profiles
Reverse how “profiles” (default, custom, gaming) are switched.
Confirm if profile swap is effect vs. config param.

Bulk/Interrupt Writes
Decode those long 64-byte URB_INTERRUPT out frames in captures.
Hypothesis: they carry per-key color arrays, not just single-key indices.

Cross-Platform
Current impl = Linux (HIDIOCSFEATURE).
Could add Windows libusb or macOS HID driver later.

Polish
Clean YAML import/export for keymaps.
Better error handling + dry-run mode.
Maybe curses-based interactive tester.

Open Questions

Does Fn+F8 always bypass HID and go through EC firmware?
Is there a fixed upper bound on per-key indices (0x40? 0x80? 0x200+)?
Can static rainbow be re-emitted as a parameterized “effect” instead of hard-coded ID?
