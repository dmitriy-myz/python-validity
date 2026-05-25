# Match-on-Host (MoH) device support — 06cb:00a2

This document captures what's been reverse-engineered about Synaptics
**Metallica MOH** (USB ID `06cb:00a2`) and the workflow that gets
enrollment + matching working on Linux.

## TL;DR

- The chip's **storage path accepts any well-framed 23136-byte template**.
  It does not validate the content.
- The chip's **matcher works with templates captured by the Windows DLL.**
  We can replay a captured 4705 wire payload from a Wine session onto a
  Linux device and the chip will match a live finger against it.
- **Encryption is device-bound, not session-bound.** A template captured
  in one Wine session works for matching across reboots and Linux sessions
  on the same physical chip.
- **Pure host-side feature extraction does NOT work.** The 23 KB template
  body has entropy ~7.7 bits/byte (essentially random) and differs by 96%
  between two captures of the same finger. The chip's matcher expects
  bytes that have been processed by the Windows DLL's encryption layer.
- The workflow that *does* work today: **enroll once via Wine, persist
  the .bin file, replay onto Linux.**

## Why python-validity didn't support enrollment for this device

This driver was originally written for Match-on-Chip (MoC) Synaptics
sensors where the chip does its own feature extraction during enrollment.
The MoH sensors split the work: the chip captures images and matches
templates, but **the host (Windows DLL) does feature extraction and
encryption**. python-validity's `sensor.enroll()` flow calls
`enrollment_update_start` (opcode 0x68), which MoH chips reject with
`0x0401` (unsupported).

So enrollment on MoH cannot be implemented purely on the chip side. The
question becomes: can we either (a) replicate the DLL's host-side
processing, or (b) bypass it entirely by reusing pre-existing templates?
This work demonstrates (b) is viable.

## Wire format of a stored finger record

A finger record is sent with `0x47` (new_record) and these parameters:

```
opcode    0x47
parent    user dbid          (e.g. 5 or 6)
type      6                  (= finger record)
storage   3                  (StgWindsor dbid)
length    23136              (= 0x5a60)
data      23136 bytes        (the envelope below)
trailer   1 byte             (varies per template — captured per-record)
```

The 23136-byte data has this layout:

```
offset    size    description
0         2       u16  subtype          e.g. 0x00f7 (WINBIO_FINGER_UNSPECIFIED_POS_03)
2         2       u16  version          = 3
4         2       u16  payload_size     = 8 + ws_size + 32   (== 23096)
6         2       u16  trailing_size    = 32
8         2       u16  tlv1_tag         = 1
10        2       u16  tlv1_len         = ws_size            (== 23056)
12        4       u32  reserved         = 0
16        23056   working_state        encrypted feature data
23072     32      TemplateId            chip-side identifier (varies per enrollment)
23104     32      trailing zeros       padding
```

The **trailer byte** appended after the data isn't a fixed constant —
captured values include `0x11`, `0x86`, `0x70`, `0xa9`. It's per-record
metadata of unknown semantics; the chip wants whatever was captured.

## Things the chip checks (and doesn't)

The chip's storage path **does** check:
- Exact template size (23136 bytes)
- Envelope structural framing
- That `(parent_user, subtype)` is not already enrolled — duplicate
  enrollment returns `0x04c3`

The chip **does not** check:
- Working_state content (zeros, random bytes, anything works for storage)
- TID content
- Subtype value (any u16 is accepted)
- That data was actually captured by the chip itself

The chip's **matcher** does of course care about content — but it works
across sessions on the same chip, which is the load-bearing finding.

## Quirks we worked around

### `db_write_enable` size

The `db_write_enable` blob captured from Wine is 2736 bytes on the wire,
but the chip only wants its first 2693 bytes. The captured tail is from
Wine's TLS layer (HMAC + PKCS7 pad) and confuses the chip. python-validity
ships the truncated 2693-byte form in `validitysensor/blobs_a2.py`.

### TLS hwkey

Wine derives the TLS session keys using `product_name='VirtualBox'` and
`product_serial='0'`. On dev/test setups we force these via:

```python
# validitysensor/tls.py
product_name = 'VirtualBox'
product_serial = '0'
```

This matches the values used during the original wire-trace capture so
the chip's session keys derive the same way.

### Per-(user, subtype) deduplication

The chip rejects a second `0x47` write for the same `(parent_user_dbid,
subtype)` pair with `0x04c3`. To re-enroll a finger you must `del_record`
the existing one first, or use a different subtype.

## Identify-hash semantics

`sensor.identify()` returns `(usrid, subtype, hash)` where `hash` is **a
stable function of the matching stored template**:

- Same `hash` is returned every time *that enrollment* wins the match.
- Independent of who placed their finger (as long as the same stored
  enrollment is the best match).
- Independent of the parent user, the subtype value, or which Wine
  session originally captured the template.
- NOT the same as the TID at offset 23072 (that's a separate field).

This makes the hash a useful **per-enrollment stable identifier**.
Downstream code can use it as a user-bound auth primitive: link it to
account state, treat its return as proof that the right enrollment fired.

## Workflow

### Step 1 — Capture an enrollment via Wine on Windows

1. Run Synaptics' Windows installer under Wine, enroll a finger.
2. Capture the wire trace (the original work used a log of "To be
   encrypted" lines in `enroll-fresh.log` etc — any way to get the
   plaintext 4705 payload works).
3. Locate the `47 05 …` (or `47 06 …`) line — that's the new_record
   carrying the finger template.

### Step 2 — Extract the template bytes

```python
import struct
hex_str = "47 0500 0600 0300 605a f600 ..."   # the captured plaintext
wire = bytes.fromhex(hex_str.replace(" ", ""))

# Strip PKCS7 + TLS HMAC
pad_len = wire[-1]
appdata = wire[:-pad_len][:-32]

# Parse the 9-byte header
opc, parent, typ, storage, length = struct.unpack('<BHHHH', appdata[:9])
data    = appdata[9:9+length]            # 23136 bytes
trailer = appdata[9+length:]             # 1 byte (record-type marker)

with open('finger.bin', 'wb') as f: f.write(data)
with open('finger.trailer', 'wb') as f: f.write(trailer)
```

### Step 3 — Replay onto a Linux device (only if the chip was wiped)

In normal use you do NOT need this: the chip's flash holds the
enrollment across reboots, so just go to Step 4. This step is for
disaster recovery when the database was cleared by some chip reset.

```python
from struct import pack
from validitysensor.tls import tls
from validitysensor.flash import call_cleanups
from validitysensor.util import assert_status
from validitysensor.db import db
import validitysensor.blobs_a2 as blobs

data = open('finger.bin', 'rb').read()         # 23136 bytes
trailer = open('finger.trailer', 'rb').read()  # 1 byte
parent = 5                                      # the user's dbid

db.db_info()
assert_status(tls.cmd(blobs.db_write_enable))
try:
    msg = pack('<BHHHH', 0x47, parent, 6, 3, len(data)) + data + trailer
    assert_status(tls.cmd(msg))
finally:
    call_cleanups()
```

### Step 4 — Match a live finger

```python
print(sensor.identify(lambda e: print(f"retry: {e}")))
# (user_id, subtype, hash)
```

## Open questions

- **What is the WS encryption scheme?** Entropy ~7.7 bits/byte and 96%
  inter-capture diff strongly suggest AES or similar with a device-bound
  key. Reverse-engineering the DLL's encryption is the path to
  Linux-native enrollment. Until then, Wine is required for enrollment.

- **What determines the trailer byte?** Captured values vary
  (0x11, 0x70, 0x86, 0xa9). Probably a record-type or subtype marker the
  chip wants for some kind of internal indexing.

- **What's the structure of the stable anchors inside WS?** Diffing two
  captures of the same finger reveals 16-byte structured blocks at
  offsets 4845, 9433, 13973 carrying `0xfa = 250` (MAX_MINUTIAE) and a
  sequential index. These look like section headers but their semantics
  aren't fully understood.

## Debugging reference

### Error codes observed in this work

| Code     | Meaning                                                   | What to do |
|----------|-----------------------------------------------------------|------------|
| `0x0007` | Transient capture failure during `identify()`             | The `update_cb` retries automatically; no action |
| `0x0401` | Opcode not supported on this device                        | You called a MoC-only opcode (e.g. `enrollment_update_start` opcode 0x68) on a MoH chip |
| `0x0403` | Storage rejection — template framing/size wrong            | Re-check the 23136-byte envelope structure |
| `0x04b5` | Chip in bad state                                          | Re-enroll on Wine (see "Chip-state recovery" below) |
| `0x04c3` | Duplicate `(parent_user, subtype)` enrollment              | `del_record` the existing finger or use a different subtype |
| `0x04d7` | `db_write_enable` invalid                                  | Truncate the captured blob to 2693 bytes (strip trailing Wine TLS HMAC+pad) |

### Pitfalls

- **Don't call `sensor.match_finger()` directly.** It expects a captured
  image to already be in the chip's matcher buffer. Without that, the
  chip returns `05000b05db` ("Finger not recognized") and on some paths
  the USB device disconnects. Always go through `sensor.identify()`,
  which does `capture(IDENTIFY)` first.

- **Don't trust calibration after a USB disconnect.** If the chip got
  yanked mid-operation, the matcher state is unreliable until you
  re-enroll a finger via Wine. `open9x()` alone doesn't recover.

- **TLS hwkey must match the captured blobs.** `validitysensor/tls.py`
  derives session keys from `product_name` + `product_serial` read from
  `/sys/class/dmi/id/`. If the captured `db_write_enable` blob came from
  Wine running on a VBox VM (`product_name='VirtualBox'`,
  `product_serial='0'`), the same values must be in effect when you
  replay. For dev environments where the captured-blob path is hardcoded
  there's a forced override in `tls.py`.

### Wine enrollment-session opcode catalog

Observed in `enroll-fresh3.log` (a complete enrollment that added one
new finger). 142 wire commands total. Opcodes seen, in encounter order:

| Opcode + variant | Bytes/wire | Description |
|------------------|------------|-------------|
| `0x4603 00 9f`   | 48          | get_record_children of root 0x9f |
| `0x4904 00 98`   | 48          | get_record_value of dbid 0x98 |
| `0x4564`         | 48          | db_info (opcode 0x45) |
| `0x0278 ...`     | 13776       | Image transfer (one captured frame from chip → host) — 8 of these per enrollment |
| `0x49f0 ...`     | 48          | get_record_value (variant) |
| `0x0602 ...`     | 2736        | `db_write_enable` family (sender pads with 43 trailing TLS bytes we strip) |
| `0x4701 ...`     | 64          | new_record, parent=1 type=4 — creates `StgWindsor` storage record |
| `0x4706 ...`     | 23184       | new_record, parent=user type=6 — the finger template itself |
| `0x4707 ...`     | 64          | new_record, parent=7 type=8 — data record (e.g. identity name "Unicorn") |
| `0x4a00`, `0x4a05`, `0x4a06` | 128 | get_user variants |
| `0x4b00`, `0x4b03`, `0x4b04` | 64  | get_user_storage variants |
| `0x4c1b`, `0x4cc8`, `0x4c5c` | 80–256 | opcode 0x4c family (semantics unknown) |
| `0x4004`, `0x4006`, `0x5100`, `0x1aa9`, `0x3920`, `0x75d3`, `0x3f04`, `0x085c`, `0x0780`, `0x1400`, `0x4302` | 48–160 | other state-setup/teardown opcodes encountered, semantics not fully decoded |

For a fresh enroll-to-an-existing-user (`enroll-fresh.log`, 95 commands)
there's no `0x4701` (no storage creation) or `0x4707` (no identity
data record); just the image transfers + db_write_enable batch + `0x47`
finger record.

### Chip-state recovery

If you hit `0x04b5` (or any state where Wine-verbatim bytes also fail),
the chip's matcher state is gone. The only known recovery is to
**re-enroll the finger via Wine on Windows**: the Wine enrollment flow
performs whatever chip-side init steps put it back into a usable state.
Subsequent Linux operations work normally afterward.

## Files of interest

- `validitysensor/blobs_a2.py` — captured chip-state blobs (truncated)
- `validitysensor/moh_extract.py` — RE'd structure code (scaffold)
- `validitysensor/moh_opencv.py` — host-side OpenCV PoC (didn't work
  due to encryption — see Open questions)
- `dev/DLL-RE.md` — DLL function-by-function reverse-engineering notes
- `dev/bisect_ws.py` — bisection harness for chip-acceptance tests
- `dev/store_then_read.py` — chip-storage round-trip check
- `dev/map_template_layout.py` — diff/entropy analyzer for two captures
- `dev/compare_image_template.py` — image vs template overlap check
