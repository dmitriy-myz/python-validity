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
