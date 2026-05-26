# Reverse-engineering `synaWudfBioUsb.dll` — image → template pipeline

Notes on the host-side feature-extraction code that the Synaptics Windows
driver runs to convert a captured fingerprint image into the encrypted
~23 KB template that ends up on the chip via `0x47 new_record`.

DLL inspected: **`synaWudfBioUsb.dll`** (Lenovo `n1cgn10w` build),
x86-64 PE. Disassembly via IDA Pro / objdump.

The work here is incomplete: about half the pipeline has been mapped
byte-exactly; the actual feature transforms are partially understood;
the **per-slot minutia tail bytes and the trailing feature/calibration
region of the WS body** are still un-decoded (see Open Questions). The
previously-listed "unknown encryption pass" turned out not to exist —
the WS body is plaintext signed-int feature data, and the high entropy
comes from the dynamic range of those values.

---

## High-level architecture

The DLL exposes two C++ extractor classes that share the WUDF biometric
plumbing but route differently for the two device families:

| Class           | Devices | Where features live |
|-----------------|---------|---------------------|
| `CEocMocEIV`    | Match-on-Chip Synaptics sensors | extracted **inside the chip** |
| `CEohMohEIV`    | Match-on-Host (06cb:00a2 etc.)   | extracted **in this DLL**, sent via 0x47 |

For the MoH path, the chip captures the image (~13 KB per frame on the
wire) and hands it back to the DLL. The DLL runs the feature-extraction
pipeline below, wraps the output in the chip's expected envelope, and
sends the result via `new_record`.

The MoH pipeline appears to be Synaptics' internal **`vcsmRidgeMatcher`**
algorithm: classical computer-vision keypoint detection plus binary
descriptors, with the assembled template authenticated by a self-MAC
TID (HMAC-SHA256 chained over the WS body — see TID-derivation notes
below). No symmetric encryption is applied to the WS body itself; the
only cipher in play is the TLS-layer AES-256-CBC wrapping the wire
record.

---

## Pipeline overview

```
                              [image]
                                 │
                                 ▼
       sub_180009F50 ─ pad with mid-gray border (4-edge aware)
                                 │
                                 ▼
       sub_180010050 ─ Sobel gradients Ix, Iy           ┐
       sub_18000FDF0 ─ horizontal pass                  │  classical
       sub_18000CE80 ─ Harris response Ixx·Iyy − Ixy²   │  CV
                                 │                       │
                                 ▼                       │
                       Non-max suppression               │
                       → top-N (≤250) keypoints          │
                                 │                       ┘
                                 ▼
       sub_18000E6B0 ─ choose 64 BRIEF test pairs (deterministic)
                                 │
                                 ▼
       per-keypoint BRIEF descriptor (64 bits)
       packed into 32-byte minutia records
                                 │
                                 ▼
       sub_18000AAB0 ─ 9-stage orchestrator (reshape, qsort, dedup)
                                 │
                                 ▼
       sub_1800E0A60 ─ TID = HMAC²-SHA256(K=SHA256(WS), "Template ID")
                       (calls sub_18004B710 multiple times)
                                 │
                                 ▼
       sub_180036840 ─ serialize envelope: 16-byte header,
                       23056-byte WS, 32-byte TID, 32 trailing zeros
                                 │
                                 ▼
                       23136-byte template
                                 │
                                 ▼
                       sent via 0x47 new_record
```

**No encryption pass is applied to the WS body.** The ~7.7 bits/byte
entropy of the stored template reflects the dynamic range of signed
int32 feature values (sign-extended small numbers fill the byte
distribution evenly), not encryption. The 96% inter-capture byte diff
is feature-extraction noise — slightly different image captures of the
same finger produce different minutiae, coordinates, scores, and
descriptors. See `dev/MOH.md` "TL;DR" and "TID derivation".

---

## Function reference

Addresses are from the Lenovo `n1cgn10w` build. Where we have a clean
Python port it lives in `validitysensor/moh_extract.py`.

### Outer flow / class machinery

| VA              | Role                                                  | Status |
|-----------------|-------------------------------------------------------|--------|
| `sub_180001A50` | `CEohMohEIV` feature-extract coordinator              | body decompiled |
| `sub_180004C10` | 250-slot context init + 9-tuple param block setup     | body decompiled |
| `sub_1800D89C0` | Session-buffer setup. Writes `0x4C4F4356` ("VCOL") magic at offset 0, version 8 at offset 4. Session header is 152 bytes; minutia table starts at session+152. | body decompiled |
| `sub_18001D130` | Provides `(this+24) == 101` to dispatch into MoH path  | body decompiled |
| `sub_18001E750` | Enrollment update wrapper. Calls feature-extract per frame; tracks "bad frame" counter (cap = 6). | body decompiled |
| `sub_18001F070` | Per-frame entry from the WUDF enrollment update FSM   | body decompiled |
| `sub_180031470` | Frame counter / "progress %" accessor                 | body decompiled |
| `sub_1800E0A60` | TID format selector wrapper (calls `sub_18004B710` then `sub_18004E640`) | body decompiled |
| `sub_180001010` | Algorithm-ready gate. Returns HRESULT 0x80000030/0x80000032/0x80000002 if not ready, else 1. Replicated in `moh_extract.py`. | DECODED |

### Image preprocessing (stage 0)

| VA              | Role                                                  | Status |
|-----------------|-------------------------------------------------------|--------|
| `sub_180009F50` | **Image padding.** Wraps the input image with mid-gray border (`0x800000` = 128.0 in 16.16 fixed-point). Border per edge is either `scale` or 0, depending on `edge_flags` from `sub_18000A8E0` (i.e. whether the patch touches the sensor boundary). | DECODED — `moh_extract.py:sub_180009F50` |
| `sub_18000A8E0` | **Edge-flag computer.** Given `(y, x, height, width)` returns 4 bytes `(top, bottom, left, right)` — 1 if that edge is at the sensor boundary, 0 otherwise. | DECODED — `moh_extract.py:sub_18000A8E0` |
| `sub_18000A910` | **Coordinate quantize-and-offset.** Sign-extending arithmetic shift trick: `((diff << 16) + (off & 0xFFFFFFFF)) >> 16`. Used to map coordinates between scales. | DECODED — `moh_extract.py:sub_18000A910` |

### Gradient / Harris response

| VA              | Role                                                  | Status |
|-----------------|-------------------------------------------------------|--------|
| `sub_180010050` | Sobel-style gradient (vertical pass / I_y)            | body present, not ported |
| `sub_18000FDF0` | Sobel-style gradient (horizontal pass / I_x)          | body present, not ported |
| `sub_18000CE80` | Harris-style response: computes `Ixx·Iyy − Ixy²` (no `−k·trace²` term seen) | body present, not ported |

### BRIEF descriptor selection

| VA              | Role                                                  | Status |
|-----------------|-------------------------------------------------------|--------|
| `sub_18000E6B0` | **BRIEF test selection.** Builds 162 candidate `(x1,y1,x2,y2)` test pairs across 3 grid resolutions (2x2, 3x3, 4x4 — pairs counts 6+36+120=162). Selects 64 tests deterministically using a 128-entry hardcoded LFSR-like seed table. First 6 always picked sequentially; remaining 58 picked by `seed[i] mod len(remaining)`. | DECODED — `moh_extract.py:sub_18000E6B0`, table is `BRIEF_SEED_TABLE` |

The 128 hardcoded seeds are the "learned" random walk that defines this
algorithm's specific test set. They are: 3382, 4039, 29605, 1734, 19683,
2304, 17019, 16644, 10030, ... (see `BRIEF_SEED_TABLE` in
`moh_extract.py` for the full list).

### 9-stage orchestrator `sub_18000AAB0`

Called once per frame. 478 lines of disassembly, 9 internal stages.
Parameter block from `sub_180004C10`:

```
{ f0=500 (COORD_SCALE), f4=250 (MAX_MINUTIAE),
  f8=10  (GRID_X),     fc=7   (GRID_Y),
  f10=1126 (X range), f14=671 (Y range),
  f18=16 (small block), f1c=128 (large block), f20=0 }
```

| Stage VA          | Stage name                              | Status |
|-------------------|-----------------------------------------|--------|
| `sub_180003320`   | stage 1 — stream-advance dispatcher     | calls `sub_1800032C0` (decoded); routes to primary/secondary cursor |
| `sub_180003460`   | stage 2 — stream descriptor builder. 0x30 bytes: u32 size, u64 base ptr, u64 cursor ptr, 24 zeros | DECODED |
| `sub_1800095C0`   | qsort (CRT generic) — invoked with the 4 comparators below | use Python `sorted()` |
| `sub_18000A4B0`   | stage 4 — two-stage glue: `sub_18000A1B0` (197 insn, structural) → `sub_18000F300` (94 insn, SIMD; per-feature work) | not ported |
| `sub_18000A5B0`   | stage 5 — 122 insns                     | not decompiled |
| `sub_18000A850`   | stage 6 — row-iteration loop. Calls `sub_1800031E0` (memcpy) per row; effectively an image blit with strides | DECODED — `moh_extract.py:stage_6_18000A850_row_loop` |
| `sub_18000A8E0`   | stage 7 — edge flags (already covered above) | DECODED |
| `sub_18000A910`   | stage 8 — coord quantize (already covered above) | DECODED |
| `sub_18000A960`   | stage 9 — 91 insns                      | not decompiled |

### qsort comparators (all operate on 32-byte minutia records)

All four were decoded; Python uses `sorted(key=...)` to reproduce each:

| VA              | Sort order                              | Python key                          |
|-----------------|-----------------------------------------|-------------------------------------|
| `sub_18000A7C0` | asc by `score_10` (int32 at +0x10)      | `cmp_score_10_asc`                  |
| `sub_18000A7E0` | asc by `active` then `score_10`         | `cmp_active_then_score_10`          |
| `sub_18000A810` | asc by `flag9` then **desc** by `score_10` | `cmp_flag9_then_score_10_desc`   |
| `sub_18000A940` | asc by `score_c` (int32 at +0x0C)       | `cmp_score_c_asc`                   |

### Minutia record (32 bytes)

Layout inferred from the qsort comparator field references:

```
offset  size  field           notes
0       8     head            (x, y, theta?, type? — bytes we didn't crack)
0x08    1     active          0/1 flag
0x09    1     flag9           0/1 flag
0x0A    2     pad             zero
0x0C    4     score_c         int32, signed (qsort key)
0x10    4     score_10        int32, signed (qsort key)
0x14    12    tail            unknown trailing fields
```

The 250-slot minutia table is at session+152 in the session buffer
(see `sub_1800D89C0`).

### Memory plumbing

| VA               | Role                                          | Status |
|------------------|-----------------------------------------------|--------|
| `sub_180003460`  | Stream descriptor builder (30 lines)          | DECODED |
| `sub_1800031E0`  | Custom memcpy with dword fast-path            | DECODED (Python: slice assign) |
| `sub_1800032C0`  | Stream descriptor advance with bounds check   | DECODED |

### Crypto / hashing

| VA               | Role                                          | Status |
|------------------|-----------------------------------------------|--------|
| `sub_18004B710`  | CryptHashData wrapper → SHA-256               | body decompiled |
| `sub_18004E640`  | Hash output format selector. Returns 32 (SHA-256), 20 (SHA-1), or 16 (MD5) depending on `select` arg | body decompiled |
| `sub_1800A4AD0`  | Probably CryptDecrypt/CryptDuplicateKey path — touches `bcrypt.dll`, key handles | not fully decompiled |

The 32-byte TID at template offset 23072 is a **two-iteration
HMAC-SHA256 chain** with a key derived from the WS body itself,
not plain SHA-256 of WS. `sub_1800E0A60` is the orchestrator;
`sub_18004B710` (the CryptHashData wrapper) is invoked multiple times
to compute K, then T1, then the final TID. Full recipe and reference
implementation: `dev/MOH.md` "TID derivation" and
`validitysensor/moh_extract.compute_tid()`.

### Envelope serialization (the final write step)

| VA               | Role                                                 | Status |
|------------------|------------------------------------------------------|--------|
| `sub_180036840`  | **Envelope serializer.** Byte-exact in Python. Layout: 16 byte outer/inner header, ws_size bytes, 32-byte TID, 32 trailing zeros. | DECODED (after iteration) — `moh_extract.py:_build_envelope` |
| `sub_18003D7C0`  | Caller pass-through; effectively identity            | DECODED — no-op |
| `sub_180036590`  | TLV-tag-1 writer used inside the envelope            | body decompiled |
| `sub_180031CD0`  | Caller of `sub_180036840`                            | body decompiled |

The byte-exact envelope structure (verified against a chip-accepted Wine
capture) is documented in `dev/MOH.md`. Briefly:

```
[0..16]   outer + inner header (subtype, version=3, payload_size,
          trailing=32, tlv1_tag=1, tlv1_len=ws_size, 4 reserved zeros)
[16..16+ws_size]  working_state — encrypted feature bytes
[..+32]           TemplateId
[..+32]           trailing zeros
total = 16 + ws_size + 32 + 32       (= 23136 when ws_size = 23056)
```

---

## Constants and magic values found

| Name                  | Value           | From                       |
|-----------------------|-----------------|----------------------------|
| `MAX_MINUTIAE`        | 250 (0xfa)      | `sub_180004C10` param block |
| `GRID_X` / `GRID_Y`   | 10 / 7          | `sub_180004C10` param block |
| `COORD_RANGE_X` / `_Y`| 1126 / 671      | `sub_180004C10` param block |
| `COORD_SCALE`         | 500             | `sub_180004C10` param block |
| `BLOCK_SIZE_SMALL`    | 16              | `sub_180004C10` param block |
| `BLOCK_SIZE_LARGE`    | 128             | `sub_180004C10` param block |
| `SENSOR_DPI`          | 363             | derived from MoH device specs |
| `SENSOR_W` / `SENSOR_H` | 112 / 112     | wire trace image size      |
| `MAX_BAD_FRAMES`      | 6               | `sub_1800D89C0` cap        |
| `MOH_MODE_FLAG`       | 101             | vtbl(this)[+24] dispatch   |
| `SESSION_MAGIC`       | 0x4C4F4356 ("VCOL") | `sub_1800D89C0`         |
| `SESSION_VERSION`     | 8               | `sub_1800D89C0`            |
| `SESSION_HEADER_LEN`  | 152             | `sub_1800D89C0`            |
| `PADDING_FILL_VALUE`  | 0x800000        | `sub_180009F50` (16.16 fp) |
| `BRIEF_SEED_TABLE`    | 128 u16 values  | hardcoded in `sub_18000E6B0` |

---

## What we proved at the protocol level (no DLL needed)

Detailed in `dev/MOH.md`. Summary:

- **Storage** path: chip stores any 23136-byte template with no content
  validation; only structure (size + envelope framing) is checked.
- **Match**: chip can match a Wine-captured template against a live finger
  *across reboots, across Linux sessions, regardless of which user the
  template is re-parented under or what subtype byte is patched into the
  header*. → encryption is **device-bound**, not session-bound.
- **Identify-hash**: stable per-enrollment ID, deterministic function of
  the stored WS bytes; useful as auth primitive.
- **Trailer byte**: appears after the data, outside the u16 length field.
  Varies per template (`0x11`, `0x70`, `0x86`, `0xa9` observed). Probably
  a record-type marker; semantics unknown.

---

## Open questions / dead ends

1. **What is the trailer byte?** Hash byte? Subtype-related? Per-record
   counter encoded in single byte? Captured values: `0x11`, `0x70`,
   `0x86`, `0xa9`.
2. **What do offsets 4845, 9433, 13973 in the WS actually represent?**
   Diffing two captures shows stable 16-byte structured anchors with a
   counter (6, 7) and constant `0xfa = 250`. Likely section headers
   for sub-blocks of feature data.
3. **The 4 high bytes of the minutia head** (offsets +0..+7) and the
   12 tail bytes (+0x14..+0x1f): probably (x, y, theta, type, quality)
   but exact layout not cracked.
4. **The trailing region of the WS body** (roughly offsets 8000..23052
   that we haven't mapped to minutia records). Plaintext, but its
   feature/calibration semantics aren't decoded. Without this region
   the OpenCV PoC produces WS bodies the chip won't match.

### Resolved (originally listed open questions, now answered)

- ~~**Where is the encryption step?**~~ There isn't one. The WS body is
  plaintext signed-int32 feature data, not encrypted. The Wine crypto
  trace (see `dev/MOH.md` "TID derivation") shows that the only
  symmetric encryption call covering the finger record is the TLS-layer
  AES-256-CBC wrap of the whole wire payload — which the chip's TLS
  endpoint decrypts, leaving the WS body in cleartext for storage.
  `db.dump_raw` returns the same bytes that went in, confirming verbatim
  storage. The high entropy reflects the dynamic range of signed-int
  feature values, not encryption.

- ~~**How is the 32-byte TID at offset 23072 derived?**~~ HMAC-SHA256
  chain with a self-derived key, decoded from `enroll-fresh.log` lines
  1570→1583:

  ```
  K   = SHA-256(reserved_u32 ‖ WS[:23052])
  T1  = HMAC-SHA256(K, "Template ID" ‖ 32×0x00)
  TID = HMAC-SHA256(K, T1 ‖ "Template ID" ‖ 32×0x00)
  ```

  No device-bound or session-bound secret. Reference implementation:
  `validitysensor/moh_extract.compute_tid()`. Verified end-to-end
  against fresh.bin's stored TID. The "host-derived vs chip-generated"
  hypothesis pair from the previous version of this question is
  resolved in favour of **host-derived** — the host computes the TID
  from the WS body and writes it into the envelope before sending.

---

## Files in this repo to look at

- `validitysensor/moh_extract.py` — Python ports of decoded functions:
  constants, qsort keys, Minutia struct, BRIEF seed table, envelope
  serializer, and `compute_tid()` (the verified HMAC-SHA256 chain).
- `validitysensor/moh_opencv.py` — OpenCV-based PoC (Sobel + Harris +
  BRIEF + envelope + compute_tid). Now produces structurally-valid
  envelopes with correct TIDs; the open question is whether the
  feature-extraction approximation is close enough to the DLL's that
  the chip's matcher accepts our minutiae. Test by running, storing,
  then identifying — see `dev/MOH.md` "Why the OpenCV PoC didn't match".
- `dev/MOH.md` — protocol-side findings, replay workflow, TID recipe.
