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
- **The WS body is NOT encrypted.** It's plaintext signed-int32 feature
  data plus structural padding. The high entropy (~7.7 bits/byte) and the
  96% inter-capture byte diff both reflect natural variability of
  fingerprint feature extraction across slightly different image captures,
  not encryption. `db.dump_raw` returns the bytes verbatim.
- **The 32-byte TemplateId at offset 23072 is a self-MAC**, derived
  deterministically from the WS body via HMAC-SHA256 with K=SHA-256(WS).
  No device-bound secret is involved; anyone with the WS body can
  recompute the TID. See "TID derivation" below.
- **`sensor.identify()`'s hash output equals this TID** — the chip
  surfaces the matched record's TID as the 32-byte identifier in the
  return tuple. See "Identify-hash semantics".
- The workflow that works today: **enroll once via Wine, persist the
  .bin file, replay onto Linux.** Native Linux enrollment is now blocked
  only on producing a chip-acceptable WS body; the TID falls out of an
  11-line recipe (`validitysensor/moh_extract.compute_tid`).

## Why python-validity didn't support enrollment for this device

This driver was originally written for Match-on-Chip (MoC) Synaptics
sensors where the chip does its own feature extraction during enrollment.
The MoH sensors split the work: the chip captures images and matches
templates, but **the host (Windows DLL) does feature extraction and
template serialization**. python-validity's `sensor.enroll()` flow calls
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

The 23136-byte data has this layout (decoded from `sub_180036840` —
the DLL's envelope serializer):

```
offset    size    description
0         2       u16  subtype          e.g. 0x00f7 (WINBIO_FINGER_UNSPECIFIED_POS_03)
2         2       u16  version          = 3
4         2       u16  payload_size     = 4 + ws_size + 4 + 32 (== 23096)
6         2       u16  trailing_size    = 32
8         2       u16  tlv1_tag         = 1
10        2       u16  tlv1_len         = ws_size              (== 23056)
12        23056   ws_body              chip-view "working state" buffer
                                       — TLV1 payload, plaintext feature data
23068     2       u16  tlv2_tag         = 2
23070     2       u16  tlv2_len         = 32                   (TID size)
23072     32      TemplateId            HMAC-SHA256 over ws_body (see below)
23104     32      trailing zeros        padding
```

Note: the **WS body starts at offset 12, not 16.** Older versions of
this doc described an 8-byte inner header followed by 4 reserved zeros
and a 23056-byte WS body at offset 16. That was wrong: the inner header
is 4 bytes (tag + len, no reserved field) and the WS body's own first
4 bytes are natural zeros — so the boundary is at offset 12. The
"reserved field" we previously documented is just the leading zeros of
the WS body itself. Similarly, the 4 bytes at envelope offset
23068..23072 are a **TLV2 header** (tag=2, len=32) introducing the TID,
not part of the WS body — older docs mistook them for "WS body tail".

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

`sensor.identify()` returns `(usrid, subtype, hash)` where `hash` is
**exactly the 32-byte TID stored at offset 23072..23104 of the matched
template** — i.e. the chip surfaces the matched record's TID as the
hash output.

Two empirical pairs confirm this (transcript L8999, L9554):

| Stored template     | TID at offset 23072..23104                  | `identify()` hash                            |
|---------------------|---------------------------------------------|----------------------------------------------|
| `fresh.bin`         | `f7a4f2af83682009e934a8668cc1ade8…c257ff`   | `f7a4f2af83682009e934a8668cc1ade8…c257ff`    |
| `fresh3.bin`        | `b89e852413091c002c76a278085cd985…365ff9`   | `b89e852413091c002c76a278085cd985…365ff9`    |

Properties that follow:

- Same `hash` is returned every time *that enrollment* wins the match,
  because the TID lives in the stored template and the chip just reads
  it back.
- Independent of who placed their finger (as long as the same stored
  enrollment is the best match).
- Independent of the parent user dbid and subtype byte under which the
  template is stored — those can be patched (see the
  `override_subtype` test) and the hash still equals the original
  TID.
- Different captures of the same finger produce *different* hashes,
  because each Wine enrollment session generates its own TID.

This makes the hash a useful **per-enrollment stable identifier**, but
*not* a tamper-evident auth primitive on its own: the TID is a
deterministic function of the stored WS body (see "TID derivation"
below), so anyone with the WS bytes can recompute it. The hash proves
"this enrollment matched", not "this enrollment came from a trusted
source." For auth, treat the hash as an opaque per-enrollment ID and
bind it to account state at enrollment time — don't trust the hash
alone as a signature.

## TID derivation

The 32-byte TemplateId stored at envelope offset 23072..23104 is a
**self-MAC**: HMAC-SHA256 with a key derived from the WS body itself.
Recipe verified end-to-end against `enroll-fresh.log` lines 1570→1583
and against the TID stored in every one of the 5 unique captured
templates we have:

```python
import hashlib, hmac

# ws_body = template[12:12+23056]  — the chip-view WS body, identical to
# the TLV1 payload the envelope serializer writes at envelope offsets
# 12..12+23056. Always begins with 4 natural-zero bytes.

K   = hashlib.sha256(ws_body).digest()
info = b"Template ID" + b"\x00" * 32                  # 43 bytes, literal
T1  = hmac.new(K, info,        hashlib.sha256).digest()
TID = hmac.new(K, T1 + info,   hashlib.sha256).digest()
```

Two things worth noting:

- **K is derived from the WS body itself**, so there is no device-bound
  or session-bound secret. Anyone with the WS body bytes can recompute
  the TID. Different captures of the same finger get different TIDs
  because the WS body itself varies (feature-extraction noise).
- **The `"Template ID"` literal is the DLL's domain-separation label.**
  Other records in the database probably use different labels with the
  same HMAC construction; we haven't traced them.

A reference implementation lives in
`validitysensor/moh_extract.compute_tid()`.

## Why the OpenCV PoC didn't match

The chip's storage path doesn't validate the TID (bisection confirms:
zero TID is accepted on write). But the **matcher** very likely
re-derives K and TID on the stored record as a structural integrity
check before running comparison — that's the cheapest way to detect a
truncated or corrupted WS body. An OpenCV-extracted template with the
wrong TID stores fine but never matches. The fix is to compute the TID
via `compute_tid(ws)` after building the WS body and write it into the
envelope at offset 23072.

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

- **How are the per-minutia descriptors computed and encoded?** This is
  the real blocker for native enrollment (revised — see "gdb-dump
  findings" below). The template is *descriptor-dominated*: the
  in-memory 32-byte minutia record holds only position/score metadata,
  none of which appears in the WS body. The bulk of the template is
  binary feature descriptors computed from image patches by stage 5
  (`sub_18000A5B0`). Reproducing the template therefore requires
  reproducing that descriptor algorithm, not just placing coordinates.

## gdb-dump findings (known-input correlation)

Frida can't attach to Wine (bootstrapper SIGSTOP), so `dev/gdb_dump.py`
captures the in-memory state instead. From one enrollment we dumped 8
per-frame minutia tables + the final WS body. Results:

- **In-memory 32-byte minutia record fully confirmed:** `active` (0/1),
  `flag9` = tile index (exactly 0..8), `x`/`y` = **raw image pixel
  coordinates** (range ~5..108, NOT scaled to 1126×671), `score_c` =
  ascending sort rank, `score_10` = quality score, `head[0:8]` = a u32
  in 0x4e530..0x4f4c0 (a buffer offset/pointer, not a coordinate).

- **None of those fields appear in the WS body.** 8-byte head substring:
  0/248. (x,y) / single-x bit search: random frequency only. So the
  template does NOT store the in-memory record — it stores something
  derived.

- **The template is descriptor-dominated.** The 32-byte record contains
  no descriptor; the binary feature descriptor (the high-entropy bulk of
  each template record) is computed from the image pixel patch around
  the minutia by stage 5 and lives only transiently in stream buffers.
  That's why the WS body is 7.86-bit entropy and why coordinates can't
  be found — the descriptors dominate and the positions (if present at
  all) are buried bits.

- **An enrollment accumulator sits between the orchestrator and the
  serializer.** Each frame's orchestrator produces ~132 active minutiae,
  but the template sections are (87,95,96,94)=372 — neither a single
  frame's count nor a clean multiple. So frames are merged/selected by a
  step we haven't hooked; the per-frame minutia table is not the direct
  serializer input.

Next instrumentation: `dev/gdb_dump.py` with `GDB_DUMP_STAGE5=1` hooks
stage 5 (`sub_18000A5B0`) and snapshots its working buffer before/after
each call, so the delta = the descriptor bytes produced for a known slot
range. That yields (minutia → descriptor) pairs directly, bypassing both
the accumulator and the template bit-layout problem.

## WS body layout (DECODED — live packer hook + codec RE)

**This supersedes the black-box "bit-packed stream" model below.** The WS
body is a **TLV (tag-length-value) container**, not a bit-packed stream.
Decoded by (a) reverse-engineering the host-side packer chain in the DLL
and (b) hooking the packer live via `dev/gdb_dump.py GDB_DUMP_PACKER=1`
and diffing the WS body before/after every frame.

### Host-side pipeline (see `dev/DLL-RE.md` for the function map)

The per-frame processor `sub_1800D89C0` (reached via the object's `+104`
function-pointer slot, dispatched by `sub_18009FD20`) does, per frame:

```
sub_180001A50(algo, &features, image, w, h, dpi=363, …)   IMAGE → features
  └─ sub_180004C10 → sub_18000AAB0   (Harris / NMS / BRIEF orchestrator)
sub_180002240(algo, ws_body, &stats, features, w, h)       features → WS TLV ★
  ├─ sub_180001FE0   builds 180-byte working records (45 dwords each);
  │     stats fields at record +0 (quality), +6/+10 (u16), +136 (coverage)
  │  └─ sub_180008F10   descriptor-write engine (writes section payload)
  ├─ sub_180003320   the enrollment ACCUMULATOR (persistent record stream;
  │     answers the old "accumulator between orchestrator and serializer")
  └─ sub_18005xx → sub_180006A80/B80/890   TLV codec (below)
```

Working dims: a `144×144` input is resampled to `round(8·144/10)=116×116`
(not 112); DPI is forced to **363**; bad-frame counter caps at **6**.

### TLV codec

`sub_180006A80` writes one record: header dword `tag | (len<<16)`
(u16 tag, u16 len, len rounded up to a multiple of 4), then memcpy of
`len` payload bytes (`sub_1800031E0`). `sub_180006890` is the keyed slot
manager — it finds/inserts by tag and shifts bytes (`sub_180006970`) to
grow a slot, so the container is keyed, not a flat append array. Thin
field wrappers: `sub_180005B70(v)` → `{tag=3, len=4, value=v}`;
`sub_1800056C0(buf,v)` → `{tag=v+3, payload=buf}`.

### Byte layout (validated against a live 8-frame enrollment)

```
WS body (23056 B = TLV1 payload at envelope offset 12):
  [0..4)    00 00 00 00              leading zeros (the K-derivation prefix)
  [4..8)    u32 total_size           running; final 23036
  [8..16)   06 02 05 00 02 00 08 01  fixed config block (constant across captures)
  [16..24)  accepted-frame id list   reverse order (e.g. 04 03 02 01 …)
  [24..44)  per-section count table   u32×N — minutiae per section, e.g. 89,91,97,92,96
  [44..~64) geometry/stats            7800 (0x1e78), 676 (0x2a4), signed deltas, 9279
  [~64.. ]  N sections, one per ACCEPTED frame, ~4540 B each:
              [u32 ordinal][u32 flags][TLV tag=5,len=4536][payload]
              payload: leading zeros, 0xfa(250) marker, dense descriptor bytes
  [23036..23056)  20-byte trailer (… 9a a2 a2 a3 a7 bf d2 d8 d9 da e0 00 00 00 01 00 04 00 …)
```

Empirical confirmation from the live capture (`/media/sf_vbox-rw/finger/
frida_dumps/packer_*`): the buffer persists across frames (append-only);
each ACCEPTED frame grows `size@+4` by exactly **4540** (4868→9408→13956
→18496→23036); REJECTED frames (quality gate `stats[7]=1`) add only 8
bytes (bump size + a reject counter + small marker). The per-section
count table `[89,91,97,92,96]` *is* the old "(87,95,96,94)=372" anchors.

### What this resolves and what remains

- **Resolved:** the WS container format, section framing, the count
  table, the accumulator, the working-record size (180 B), and why no
  coordinate appeared at a fixed stride (fields are tagged + the section
  payload is descriptor-dominated, not positional).
- **Remaining for native enrollment:** the *intra-section payload* —
  i.e. what `sub_180008F10` writes into each tag-5 section from the
  180-byte working records / features. This is still the descriptor
  algorithm. Next: decompile `sub_180008F10` and `sub_180006890`, and/or
  hook `sub_180008F10` (input = 180-B records, output = section payload)
  the same way we hooked the packer.

## WS body feature encoding (black-box findings — SUPERSEDED, kept for history)

> Superseded by "WS body layout (DECODED)" above. The conclusions here
> ("bit-packed, not TLV, 36-byte period") were wrong: they were a
> misreading of TLV-framed sections whose *payloads* are high-entropy
> descriptors. Retained because the entropy/correlation measurements
> themselves are still valid observations.

Everything recoverable from the output alone has been extracted. Summary
of what the feature sections (the high-entropy data between the section
anchors) actually are:

- **Bit-packed, NOT byte-aligned records.** Entropy ~7.86 bits/byte. No
  coordinate-range values (`x∈0..1126, y∈0..671` or `x,y∈0..112`) appear
  at any stride/offset under any width — so fields cross byte boundaries.
  The earlier "32-byte minutia records" idea is *wrong* for the WS body:
  reading the in-memory record's `flag9` byte (which must be 0..8) at a
  32-byte stride gives uniform 0..255, and x/y read as garbage int32.
  (The 32-byte layout is the chip's *in-memory* working format, decoded
  in `dev/DLL-RE.md`; it is serialized into this denser packed form.)

- **NOT an image at any dimension.** An adjacent-row-correlation sweep
  over 93,233 `(skip 0..700, width 4..136)` combinations peaks at only
  **0.485** (at width 36). A real 112×112 fingerprint frame scores
  **0.81** at its true width; zero WS-body combos exceed 0.5. The
  `end_ptr = 18496 = 136²` match is a coincidence — width 68 and 136
  both give ≈0 correlation, so the "68²/136² quadrant grid" idea is
  ruled out.

- **36-byte (288-bit) packing period.** Autocorrelation and the width
  sweep both peak on the 18-multiple family (18, 36, 54, 72, …), with
  36 strongest. So the fundamental packing unit is 144 bits and a record
  is plausibly two of them (36 bytes), though `section_size / count`
  (≈50) doesn't divide cleanly — the count→record mapping is unconfirmed.

- **Cleanest stream is mid-section.** Row correlation roughly doubles
  (0.23 → 0.485) once you skip past ~550 bytes into a section, i.e. past
  the header/prelude/trailer into the pure feature payload. Target that
  region for the Frida known-input correlation.

The remaining unknowns are the per-slot tail bytes, the header
configuration words, and the trailing feature/calibration region — all
of which are inside the bit-packed stream and not recoverable without
known inputs.

- **What determines the trailer byte?** Captured values vary
  (0x11, 0x70, 0x86, 0xa9). Probably a record-type or subtype marker the
  chip wants for some kind of internal indexing.

- **Why is the K-derivation input 23056 bytes from envelope offset 12
  (not 23056 from offset 16)?** The reserved u32 at offset 12..16 is
  always 0 in captures we've seen, so this doesn't currently affect
  the recipe — but if the chip ever puts a non-zero value there, the
  TID would change.

### Resolved

- ~~**What is the WS encryption scheme?**~~ Likely no symmetric
  encryption pass, but "plaintext signed-int feature data" was an
  over-claim that only held for the low-entropy *prelude* (WS 40..223,
  entropy 5.17, visible sign-extension). The main feature *sections* are
  **bit-packed high-entropy data** (entropy 7.86) — see "WS body feature
  encoding" above. The mild byte skew (0x44 over-represented ~3.5×, not
  the perfect uniformity of AES output) argues against encryption and
  for bit-packed binary descriptors. `db.dump_raw` returns the bytes
  verbatim and the TID self-MAC works on them, but neither proves the
  content is plaintext — only that storage is verbatim.

- ~~**How is the TID derived?**~~ HMAC-SHA256 chain over the WS body
  itself (see "TID derivation" above).

## Debugging reference

### Error codes observed in this work

| Code     | Meaning                                                   | What to do |
|----------|-----------------------------------------------------------|------------|
| `0x0007` | Transient capture failure during `identify()`             | The `update_cb` retries automatically; no action |
| `0x0401` | Opcode not supported on this device                        | You called a MoC-only opcode (e.g. `enrollment_update_start` opcode 0x68) on a MoH chip |
| `0x0403` | Storage rejection — template framing/size wrong            | Re-check the 23136-byte envelope structure |
| `0x04b3` | No such parent dbid                                        | The `parent` field of `0x47 new_record` references a user dbid that doesn't exist on the chip. Run `db.dump_all()` to see which user dbids are real, then resend with a valid parent. Don't diagnose record-content issues until parent existence is confirmed. |
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

Observed across three Wine enrollment captures of the same finger
(position `0xf6`):

| Log                  | Host→chip cmds | `0x47` records emitted |
|----------------------|----------------|------------------------|
| `enroll-fresh.log`   | 94             | finger(type=6) + identity(type=8) |
| `enroll-fresh2.log`  | 94             | finger(type=6) + identity(type=8) |
| `enroll-fresh3.log`  | 142            | **StgWindsor(type=4)** + finger(type=6) + identity(type=8) |

The structural difference between the 94-cmd and 142-cmd runs is the
**`StgWindsor` storage-creation record**, not the identity record —
all three runs emit an identity record, just under varying parent
dbids. fresh3.log is bigger because it's an *empty-database* enrollment:
the chip has no `StgWindsor` storage yet, so the Windows DLL creates one
first (plus extra surrounding `0x4c` / `0x4b` setup chatter).

Opcodes seen in fresh3.log, in encounter order:

| Opcode + variant | Bytes/wire | Description |
|------------------|------------|-------------|
| `0x4603 00 9f`   | 48          | get_record_children of root 0x9f |
| `0x4904 00 98`   | 48          | get_record_value of dbid 0x98 |
| `0x4564`         | 48          | db_info (opcode 0x45) |
| `0x0278 ...`     | 13776       | Image transfer (one captured frame from chip → host) — 8 of these per enrollment |
| `0x49f0 ...`     | 48          | get_record_value (variant) |
| `0x0602 ...`     | 2736        | `db_write_enable` family (sender pads with 43 trailing TLS bytes we strip) |
| `0x47` parent=1 type=4 | 64    | new_record — creates `StgWindsor` storage record (only when chip DB is empty; payload is the literal string `"StgWindsor\0"`) |
| `0x47` parent=user type=6 | 23184 | new_record — the finger template itself; followed on the wire by a 1-byte trailer (`0x86`/`0x70`/`0xa9` observed in these three captures, `0x11` in older `enroll.log`) |
| `0x47` parent=user' type=8 | 64 | new_record — identity data record (payload `02 01 08 00 "Unicorn\0"`). Parent dbid varies per session (5/6/7 across the three captures); appears in *every* enrollment regardless of fresh-DB status |
| `0x4a00`, `0x4a05`, `0x4a06` | 128 | get_user variants |
| `0x4b00`, `0x4b03`, `0x4b04` | 64  | get_user_storage variants |
| `0x4c1b`, `0x4cc8`, `0x4c5c` | 80–256 | opcode 0x4c family (semantics unknown) |
| `0x4004`, `0x4006`, `0x5100`, `0x1aa9`, `0x3920`, `0x75d3`, `0x3f04`, `0x085c`, `0x0780`, `0x1400`, `0x4302` | 48–160 | other state-setup/teardown opcodes encountered, semantics not fully decoded |

Comparing two captures of the same finger (`subtype=0xf6`) confirms the
encryption finding from the TL;DR: the finger-template payloads disagree
on ~96% of their bytes (fresh vs fresh2 = 96.4%, fresh vs fresh3 = 96.7%,
fresh2 vs fresh3 = 96.1%). The envelope header, the trailing 32 zero
bytes, and the `02 01 08 00 "Unicorn\0"` identity payload are byte-identical
across all three runs; only the 23056-byte working_state, the 32-byte TID,
and the 1-byte trailer change per capture.

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
