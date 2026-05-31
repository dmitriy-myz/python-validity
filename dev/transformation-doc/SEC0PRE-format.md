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

## What this unblocks + what remains
We now have the EXACT in-memory structure. To build a byte-faithful sec0_pre:
1. **Nail the serialization** (in-memory N×N table → the `sec0_pre` byte stream): map the captured `call04` table to the stored template's sec0_pre bytes (extract template from `1780253459.log`'s `0x47 typ=6` record; the naive 18-byte scan in `decode_sec0_pre.py` is unreliable across the leads/blob boundary — use the capture as the oracle). Determine exact record order (upper+lower triangle? row-major?), leads/blob placement, TLV framing.
2. **Build the serializer** (inverse of the above) + the per-section pre_v30 for sections 1..4.
3. **Compute transforms for our frames**: `geom_register` (dev/sec0pre_register.py) — VALIDATE it reproduces the captured DLL transforms for THIS enroll's frames (log 1780253459 images via extract_log_images); they're small consecutive-frame alignments so it should be close. blob/leads: compute section quality + argsort.
4. Assemble mode-B 5-section template, test `--match`.

Note: orientation bug already fixed (feature frame must NOT be transposed; identity gives 242-250/250 keypoint overlap — commit 53c762e). Chip matching is geometric (positional Hough sub_18000c6a0), so close transforms + correct positions should suffice.
