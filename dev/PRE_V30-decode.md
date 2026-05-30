# pre_v30 metadata — structural decode

Decoded from the gdb capture `ws_body_1780084103036_23056.bin` (2026-05-29)
via `dev/parse_ws_tlv.py`, using the TLV format reverse-engineered in
`dev/PACKER-sub_180002240.md`. The ws-body body (after the 24-byte fixed
header) is a **TLV stream**; the per-section "pre_v30" zones are TLV records,
not opaque bytes.

## Fixed header [0..64)  — mostly CONSTANT, copyable

| zone | bytes | status |
|---|---|---|
| `[0..4)` zeros | `00000000` | CONST |
| `[4..8)` size_u32 | `23036` (0x59fc) | CONST (formula, sub_180001750 id-6, n=5) |
| `[8..16)` config | `06 02 05 00 02 00 08 01` | CONST |
| `[16..24)` id | `04 03 02 01 00 00 00 00` | CONST (sub_1800066f0 from algo[0..2]) |
| `[24..40)` per_section_counts | 4×u32 = (82,76,83,90) | **VARIANT** (session accumulator, tag-0x6c family from algo+0x130..) |
| `[40..44)` sec5cnt+flags | `[86, 5, 1, 94]` | PARTIAL (byte0=86 = 5th count; 5=section count; rest flags) |
| `[44..64)` geometry_stats | 20 B (5×i32, signed) | **VARIANT** (unresolved; candidate: sub_180008980 quantized pose vector) |

## Per-section header = TLV stream

Each section `i` (0..4) is framed as:
```
[8 pose-lead bytes]               <- VARIANT (ascending; bd10 argsort permutation — NOT field quantiles)
[3 bytes 00 00 00]                <- gap/count (constant 0 here)
[TLV records that CHANGED]        <- locate-or-append: only re-emitted on change
[section-content marker]          <- tag = 4+i, len = 0x11b8 = 4536  (CONST structure)
  [8 zero bytes][count=0xfa=250]  <- CONST
  [250 × 18-byte v30 records]     <- CONTENT (the serialize_v30_section output)
```

**TLV metadata records observed (only emitted when the value changes):**

| section | records emitted | meaning |
|---|---|---|
| sec0 | (special 245-B global table — see below) | — |
| sec1 | `0x68=0`, `0x03=5`, `0x69=(112,112)`, `0x6b=5`, `0x6c=(0,0,1,3)` | full set first-set here |
| sec2 | (none) | nothing changed since sec1 |
| sec3 | `0x6a=3` | one delta |
| sec4 | (none) | — |
| tail | `0x01=0` (TERM) | stream terminator |

So the persistent TLV field state to reproduce: `0x03=0x6b=5` (section count),
`0x69=(112,112)` (geometry dims — likely fixed for this sensor), `0x68=0`,
`0x6c=(0,0,1,3)` (a small accumulator, **VARIANT**), `0x6a=3` (set at sec3,
**VARIANT**). Section-content tag = `4+i`; len/count/zeros are constants.

## What this means for a from-scratch template

- **CONST / copyable** (no derivation needed): the fixed header `[0..24)`,
  section-content markers (tag 4+i, len 0x11b8, the `00..00 fa` framing),
  `0x03/0x6b=5`, `0x69=(112,112)`, the `0x01` terminator. These are sensor/algo
  constants identical across enrollments.
- **VARIANT — still to derive** (isolated to specific fields now):
  1. **8 pose-lead bytes × 5 sections** — the bd10 argsort permutation. NOT a
     quantile of resp/x/y/etc. (tested, no match). Needs the `GDB_DUMP_POSE`
     capture (`*(obj+0)`/`*(obj+8)` before/after bd10 @0x18000522c) to see the
     source ranking vector.
  2. **geometry_stats `[44..64)`** (20 B / 5×i32 signed).
  3. **per_section_counts** (82,76,83,90,86) + **0x6c=(0,0,1,3)** + **0x6a=3** —
     session accumulators (tag-0x6c family, algo+0x130..); their derivation is
     the cross-frame consensus count, not a single-frame table count (tested).
  4. **sec0_pre `[64..309)`** (245 B) — the global section table. Its leads are
     NOT ascending (different structure from sec1-4); it holds per-section
     offset/POSE records. The largest single unknown.

## Tools / next

- `dev/parse_ws_tlv.py` — re-run on any captured ws_body.
- To finish the VARIANT zones: (a) the `GDB_DUMP_POSE` capture for the leads;
  (b) a **second** ws_body capture (different finger) to diff constant-vs-variant
  in `sec0_pre` and confirm `0x69=(112,112)` is fixed; (c) decode the sec0
  global-table writer. Most framing is now reproducible; only the pose/geometry/
  count derivations remain, and they're localized.

## sec0_pre — investigated via the packer_emit + pose capture (1780086xxx)

The 3rd gdb capture (`GDB_DUMP_PACKER_EMIT=1 GDB_DUMP_POSE=1`) produced per-codec
stream deltas + the bd10 argsort dumps. Findings:

- **Writer = `sub_1800051f0`** (the per-frame section-table emitter). Confirmed
  by the f0 stream delta: of the 9 emit-block calls, only `51f0` writes the
  section-table region (the `56c0` call writes the 4540-B v30 content; the
  setters write the small TLV records). `51f0` **overwrites `sec0_pre` IN PLACE**
  each selected frame (not append) — the TLV grow/shift path (`sub_180006a80`/
  `sub_180006970`).
- **Timing:** at f0 (1 section) `sec0_pre` is ~all-zero; the final head appears
  at **f5** (3rd selected frame) and the table grows through f7. Selected frames
  this capture: f0,f2,f5,f6,f7 (f1,f3,f4 rejected) — best-frame selection.
- **Structure:** `sec0_pre` = ~8 × 20-byte records of large Q16 fixed-point
  values (the **inter-section alignment transforms** the matcher `c6a0`/`bdf0`
  computes pairwise between sections) + zero pad + the section-0 content marker
  `04 00 b8 11` (`0x11b80004`) at +0xd8 + `00..00 fa` framing.
- **`pose obj[0x10] = N = section count`** (call0..4 → N = 1..5). The bd10
  argsort inside `51f0` sorts **section indices**: `arr0_after` = `[N-1..0]`
  (call4 → `04 03 02 01 00`, descending-convention). So that argsort orders the
  global table; it is NOT the source of the per-section 8-byte ascending leads.

**Implication.** `sec0_pre` is **derived multi-frame geometry** — the pairwise
section-alignment transforms. It only exists with ≥2 sections and its exact
bytes depend on the finger's cross-frame poses (via the `bdf0` Q16 transform
math). A single-frame native template has no inter-section poses, so this zone
is naturally near-empty (the f0/N=1 case). Current `native_template` copies it
from the ref scaffold — fine for STORAGE; for MATCHING the chip scores the
per-section v30 records (which we build byte-exact), so `sec0_pre` matters only
for cross-section consistency.

**Still open:** (1) the per-section 8-byte ascending leads — NOT bd10 section
indices, NOT minutia quantiles; source still unidentified (a different argsort
or per-section signature). (2) Full byte-derivation of the `sec0_pre` Q16
records needs the `bdf0` pairwise-transform math decoded. (3) the session
accumulator counts (`0x6c`, per_section_counts).
