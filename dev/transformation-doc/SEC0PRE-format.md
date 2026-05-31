# sec0_pre format — GROUND TRUTH from gdb capture (2026-05-31)

Captured the `sub_1800051f0` (sec0_pre serializer) inputs during a real Wine
enrollment via the new `GDB_DUMP_SEC0PRE` hook. This is the authoritative
structure of the inter-frame geometry that goes into `sec0_pre`.

## Capture
- Hook: `Sec0PreEntryBP` on `sub_1800051f0` (dev/gdb_dump.py, `GDB_DUMP_SEC0PRE=1`).
- Enroll: Wine log `1780253459.log` (5 sections), dumps in
  `/media/sf_vbox-rw/finger/frida_dumps/sec0pre_{obj,leads,blob,table}_*`.
- 5 calls (idx1..idx5, one per section commit). Per call the obj at rcx holds:
  - `*(obj+0)` = **leads** (N bytes), `*(obj+8)` = **blob** (N×u32),
    `obj[0x10]` = N (table dimension), `obj[0x11]` = flag, `*(obj+0x18)` =
    **transform table** (N row-ptrs → N×20-byte records).

## The transform table (THE key structure)
Full **N×N symmetric pairwise** table, 20-byte records `[x:u8][y:u8][2 pad][a:i32][b:i32][tx:i32][ty:i32]` (Q16, R=[[a,−b],[b,a]]). Index = `row*N + col`:
- **Diagonal** `[i][i]` = identity sentinel `{a=0x10000,b=0,tx=0,ty=0}`, anchor `(0,255)` (0xff = unmatched).
- **`table[i][j]` (i<j)** = forward rigid transform aligning section i→j.
- **`table[j][i]`** = its inverse (CONFIRMED: e.g. `(0,1) rot+1.31 t(−6.58,−3.55)` ↔ `(1,0) rot−1.31 t(+6.67,+3.40)`).
- Built incrementally: when committing section idx, the table is `(idx−1)×(idx−1)` of the prior sections (call04/idx5 → full 4×4 = 16 recs). Example call04 transforms (sections 0–3), all small (±1.5°, ±31px):
  ```
  (0,1) +1.31 (−6.58,−3.55)   (0,2) +1.24 (−1.51,+21.28)  (0,3) +1.49 (+15.79,−9.12)
  (1,2) −0.10 (+4.89,+25.26)  (1,3) +0.00 (+21.96,−5.36)   (2,3) +0.32 (+17.37,−30.93)
  + inverses on the lower triangle; identity on diagonal.
  ```
- Record anchor `(x,y)` for non-identity recs is >112 (e.g. 185,165,154,156,140) — NOT an image coord; likely a representative/centroid point in a scaled frame. (Semantics TBD; probably not load-bearing for the matcher.)

## leads + blob
- **leads** = a descending index permutation of length N: `[3,2,1,0]` at the final call. Per [[ws-pose-leads]] it's an argsort permutation (sub_18000bd10), NOT scores. It orders the sections by the blob scores.
- **blob** = per-section u32 values (the argsort keys / quality scores): final call `[0x54000000, 0x5C000000, 0x5C000000, 0x5A000000, 0x57000000]` (look like floats/fixed-point quality; source = sub_180008980 pose quality, `[rec+0x38]`).

## DEFINITIVE SERIALIZATION — BYTE-EXACT VERIFIED (2026-05-31)
Decoded `sub_1800051f0` (disasm `/tmp/func_1800051f0.S`) + helpers and verified the
full byte layout against the stored template in `1780253459.log` (5 sections). The
framed `sec0_pre` region (`template[24:292]`, 268 B) is:

```
[u16 type=2][u16 size]            # stream header (sub_1800069e0); size patched at the very end
leads:  N  bytes                  # obj+0  — reverse-index [N-1..0]
blob:   N  u32 (LE)               # obj+8  — per-section quality (q<<24)
N:      1 byte                    # obj[0x10] (= #sections / matrix dim; written from dl AT ENTRY,
                                  #   so the gdb hook's hdr[0x10] is the STALE pre-write value)
flag:   1 byte                    # obj[0x11]  (observed = 1)
matrix: upper-triangle table[i][j] for j>i, row-major, 18 bytes each:
          [x:u8][y:u8][a:i32][b:i32][tx:i32][ty:i32]   (drops the in-mem +2/+3 pad)
<zero pad to `size` bytes, counted from AFTER the 4-byte header>
```

- **`size` = reservation formula** `(((N//2)*5)*4 + 4)*N + ((N+3)&~3) + 0x24` (= 264 for N=5),
  NOT the content length (207). Appends increment a running size; the tail patch overwrites it
  with the formula. Measured from after the header → lands the next-section marker exactly at +292.
- **leads = reverse-index `[N-1..0]`, independent of blob.** `sub_18000bd10` identity-inits
  `leads[i]=i`, builds N `(key=0, idx=i)` pairs, `qsort`s with comparator `sub_18000b1f0`
  (`return b-a`, descending; tie-break descending by idx). All keys 0 → deterministic reverse order.
  (The captured leads dump `[3,2,1,0]` was the STALE pre-`bd10` buffer; bd10 regenerates at serialize.)
- **only the strict UPPER triangle is emitted** (loop skips `j==i`; inner `j` runs `i+1..N-1`).
  The in-memory table is full N×N (forward `table[i][j]`, inverse `table[j][i]`) but the lower
  triangle + diagonal are NOT serialized.
- Append helpers: `sub_1800064d0`=u32 LE, `sub_180006510`=u8, `sub_180006550`=N bytes — all LE,
  confirmed by the byte-exact decode.

**Serializer + parser: `dev/sec0pre_serialize.py`** — `serialize_sec0pre(N, transforms, blob, flag)`
round-trips the stored template byte-for-byte (`__main__` asserts `template[24:292] == output`).
The lone approximate field for SYNTHESIS is `blob` (per-section quality, source `sub_180008980`
`[rec+0x38]`); leads ignores it and the matcher uses the matrix transforms, so it is likely
non-load-bearing.

## What this unblocks + what remains
We now have the EXACT in-memory structure. To build a byte-faithful sec0_pre:
1. **Nail the serialization** (in-memory N×N table → the `sec0_pre` byte stream): map the captured `call04` table to the stored template's sec0_pre bytes (extract template from `1780253459.log`'s `0x47 typ=6` record; the naive 18-byte scan in `decode_sec0_pre.py` is unreliable across the leads/blob boundary — use the capture as the oracle). Determine exact record order (upper+lower triangle? row-major?), leads/blob placement, TLV framing.
2. **Build the serializer** (inverse of the above) + the per-section pre_v30 for sections 1..4.
3. **Compute transforms for our frames**: `geom_register` (dev/sec0pre_register.py) — VALIDATE it reproduces the captured DLL transforms for THIS enroll's frames (log 1780253459 images via extract_log_images); they're small consecutive-frame alignments so it should be close. blob/leads: compute section quality + argsort.
4. Assemble mode-B 5-section template, test `--match`.

Note: orientation bug already fixed (feature frame must NOT be transposed; identity gives 242-250/250 keypoint overlap — commit 53c762e). Chip matching is geometric (positional Hough sub_18000c6a0), so close transforms + correct positions should suffice.

## TRANSFORM GENERATION — geometric methods CANNOT reproduce the DLL (2026-05-31)
Validated `geom_register` (and identity-seeded ICP) against the captured ground truth
for enroll 1780253459 (5 sections, source frames mapped {0,4,5,6,7}→sec{0..4}, our
pipeline reproduces their keypoints 238-248/250 exact-xy):

- **The captured transforms are GLOBALLY SELF-CONSISTENT**: `table[i][j] ==
  compose(table[0][j], inv(table[0][i]))` to within **1.1px / 0.6°** (triangle
  1→2→3 vs 1→3 to 0.3px). ⇒ the DLL registers everything to a reference frame and
  composes (the `sub_180008160` path); we'd only need `table[0][j]` (4 transforms),
  the rest derive by composition.
- **But we cannot find `table[0][j]` geometrically.** `geom_register` overlap-max
  reproduces only 1/10 (it locks onto a DIFFERENT high-overlap alignment); ICP from
  identity collapses to t≈0. Cause: the quasi-periodic ridge pattern admits MANY
  high-overlap rigid alignments (the clouds overlap both at identity AND at the DLL's
  real ±20-36px motion). Only the DLL's descriptor correspondences (the decoded
  model-fitter `sub_1800046e0`) disambiguate which ridge maps to which.
- Our v30 **positions are byte-exact** but **descriptors are near-random vs the DLL's**
  (median Hamming ~49) — the E090 descriptor path needs F250-enhanced input which
  `extract_frame_native` does not reproduce from a raw log frame. The matcher is
  positional (sub_18000c6a0: "a cell holds a count, not a descriptor"), so this is
  likely irrelevant — the diagnostic template tests exactly that.

**Diagnostic templates** (`dev/build_diagnostic_template.py`): T0 = exact DLL template
(positive control); T1 = OUR v30 for the mapped frames + the DLL's BYTE-EXACT sec0_pre/
leads/blob/framing (TID recomputed). If the chip matches T1, then sec0_pre transform
GENERATION is the SOLE remaining from-scratch blocker. PATHS to generate transforms:
(a) gdb-capture the registration during a Wine enroll (README 6-bp plan) for byte-exact
ground truth; (b) port the descriptor-correspondence model-fitter (needs F250-correct
descriptors too); (c) test whether a self-consistent geometric set suffices on chip.
