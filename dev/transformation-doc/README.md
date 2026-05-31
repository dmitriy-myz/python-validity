# sec0_pre frame-registration — reverse-engineering index

These docs decode the `syna.dll` (06cb:00a2) code path that produces the **sec0_pre
inter-frame rigid transforms** of a fingerprint enrollment template — the Q16 (16.16)
similarity transforms `{a, b, tx, ty}` that align each captured frame to the others.

One `func_<addr>.md` per function. Two ROOT entry points:

- **`sub_1800046e0`** — per-minutia / per-frame-pair **model-fitter**: a RANSAC + LSQ-refit
  loop over keypoint correspondences that fits the best Q16 similarity transform between two frames.
- **`sub_1800082a0`** — top-level **frame-registration orchestrator** (per-frame geometry /
  match-consistency): allocates scratch, registers the base frame, then drives the
  candidate-build → reproject/score/commit loop that writes the transforms into the sec0_pre table.

---

## Call tree

Shared leaves are written out once at their first occurrence and elsewhere shown as
`↻ sub_<addr>` (see its first appearance / its own doc).

```
sub_1800046e0 — RANSAC Q16 similarity transform fitter (frame registration)
├── sub_180003320 — byte-stream range-view clone + slice re-anchor
│   └── sub_1800032c0 — aligned-buffer cursor / struct initializer
├── sub_180003880 — keypoint partition + descriptor correspondence builder
│   ├── ↻ sub_180003320
│   └── sub_180003640 — descriptor nearest-neighbour matcher / correspondence builder
│       └── sub_1800034e0 — Hamming distance (XOR + popcount-LUT)
├── sub_1800043d0 — per-frame feature-pipeline orchestrator
│   ├── ↻ sub_180003320
│   ├── sub_180003ac0 — box-list label-map rasterizer
│   │   ├── sub_1800031c0 — guarded count-checked thunk (→ sub_1800e0a60)
│   │   └── sub_180003a00 — clipped box fill into byte image buffer
│   ├── sub_1800041d0 — transform-and-sample correspondence builder
│   │   ├── sub_180003150 — atan2(y,x) quadrant resolver, Q16 radians
│   │   │   └── sub_1800030a0 — fixed-point atan2 (vector angle, first-quadrant core)
│   │   ├── sub_180003490 — min angular distance on 180° ring
│   │   ├── ↻ sub_1800034e0
│   │   └── sub_180006bc0 — apply Q16 rigid 2D transform to a point
│   ├── sub_180004060 — paired orientation-difference scorer
│   │   └── sub_180004010 — angle-fold weighted accumulator
│   ├── sub_180003b50 — keypoint coverage-grid binning / occupancy histogram
│   │   ├── ↻ sub_1800031c0
│   │   ├── ↻ sub_180003a00
│   │   └── sub_1800095c0 — generic qsort (median-of-3) [+ comparator sub_180003480]
│   └── sub_180003ea0 — byte-array statistics (sum / filtered-avg / median / avg)
│       ├── sub_180003d30 — correspondence-table init (index/payload + sparse maps)
│       └── ↻ sub_1800095c0
├── sub_180004620 — circular angular distance mod 180
├── sub_180004680 — rigid-transform plausibility predicate (accept/reject gate)
├── sub_180007480 — RANSAC 2-point similarity estimator + LSQ refit
│   ├── sub_180007390 — 4-int32 compute-and-pack wrapper
│   │   └── sub_180006e10 — 2-point rigid (scale=1) Q16 transform solver
│   │       └── sub_180003060 — integer square root (radix-4 isqrt)
│   ├── sub_180007450 — Q16 rigid/similarity transform of a point (wrapper)
│   │   └── ↻ sub_180006bc0
│   └── sub_1800073f0 — similarity-transform out-struct packer wrapper
│       └── sub_180006f20 — 2D similarity (rigid+scale) fit (Procrustes/Kabsch, Q16)
│           ├── ↻ sub_180003060
│           └── sub_180006c40 — 2D vector normalize to Q16 unit vector
│               └── ↻ sub_180003060
└── ↻ sub_1800095c0

sub_1800082a0 — top-level frame-registration orchestrator
├── sub_18000b400 — two-byte unsigned range/bounds predicate (30<x, y≤55)
├── sub_18000b3d0 — byte-range validity predicate (30<x, y≤49)
├── ↻ sub_180003320
├── sub_180007fe0 — frame-slot init / bookkeeping
│   └── ↻ sub_1800031c0
├── ↻ sub_1800031c0
├── ↻ sub_180003ac0
├── ↻ sub_1800041d0
├── sub_180004190 — scatter-mark presence byte-map from index list
├── sub_1800077d0 — candidate-correspondence builder (ROI-gate + per-pair compose)
│   ├── ↻ sub_180003320
│   ├── sub_18000b3f0 — struct-field unpacking thunk → sub_18000b3d0
│   │   └── ↻ sub_18000b3d0
│   └── sub_180006cc0 — rigid similarity composition (B∘A) + rotation renorm
│       └── ↻ sub_180006c40
├── sub_180007b30 — per-candidate frame-pair evaluator + sec0_pre geometry commit loop
│   ├── ↻ sub_180006cc0
│   ├── sub_180006470 — guarded TLV-section dispatcher
│   │   ├── sub_180006320 — TLV section loader / frame-geometry record fetcher
│   │   │   ├── sub_180005930 — keypoint/geometry record deserializer
│   │   │   │   ├── sub_1800065e0 — stream read_u8
│   │   │   │   │   └── sub_1800031e0 — inlined memcpy block copy
│   │   │   │   └── sub_180006610 — counted byte-buffer append loop
│   │   │   │       └── ↻ sub_1800031e0
│   │   │   ├── sub_180005c60 — tag-0x69 TLV field writer
│   │   │   │   ├── sub_1800065b0 — stream u32 element mover
│   │   │   │   │   └── ↻ sub_1800031e0
│   │   │   │   └── sub_180006890 — guarded record-forwarder / dispatcher
│   │   │   │       ├── sub_180006680 — 24-byte range/handle struct initializer
│   │   │   │       └── sub_180006800 — recursive ordered-container lookup (find by key)
│   │   │   │           └── sub_1800067a0 — TLV cursor advance (span/iterator step)
│   │   │   │               └── ↻ sub_180006680
│   │   │   └── ↻ sub_180006890
│   │   └── ↻ sub_180006890
│   ├── ↻ sub_1800041d0
│   ├── ↻ sub_180003ea0
│   ├── ↻ sub_180004060
│   ├── sub_18000b3d0 ↻
│   ├── ↻ sub_180004190
│   └── sub_1800db580 — __security_check_cookie (stack canary)
├── ↻ sub_1800031e0
└── sub_180008160 — pairwise frame-correspondence loop (composes Q16 rigid transforms)
    ├── ↻ sub_180006cc0
    ├── ↻ sub_18000b3f0
    └── sub_18000b420 — Q16 transform identity-check predicate ({0x10000,0,0,0}?)
```

External callees referenced but not documented here: `sub_1800e0a60` (CRT memset),
`sub_1800db580` (`__security_check_cookie`), comparators `sub_180003480` / `sub_180004600`.

---

## All functions

| addr | name | role (short) | xform math | conf | doc |
|------|------|--------------|:--------:|:----:|-----|
| 0x1800046e0 | RANSAC Q16 similarity fitter | **ROOT** — fit best frame-pair transform via RANSAC + inlier refit | ✅ | high | [func_1800046e0.md](func_1800046e0.md) |
| 0x1800082a0 | frame-registration orchestrator | **ROOT** — drive candidate-build → score → commit into sec0_pre | ✅ | high | [func_1800082a0.md](func_1800082a0.md) |
| 0x180003060 | integer square root | radix-4 isqrt(uint32) | ❌ | high | [func_180003060.md](func_180003060.md) |
| 0x1800030a0 | fixed-point atan2 (core) | first-quadrant angle, 1136 units/deg | ✅ | high | [func_1800030a0.md](func_1800030a0.md) |
| 0x180003150 | atan2(y,x) Q16 radians | quadrant resolver → [0,2π) Q16 | ✅ | high | [func_180003150.md](func_180003150.md) |
| 0x1800031c0 | guarded count-checked thunk | count>0 ⇒ forward to sub_1800e0a60 | ❌ | high | [func_1800031c0.md](func_1800031c0.md) |
| 0x1800031e0 | inlined memcpy block copy | dword fast / byte slow copy | ❌ | high | [func_1800031e0.md](func_1800031e0.md) |
| 0x1800032c0 | aligned-buffer cursor init | round (begin+n) to 8B, init 0x30 struct | ❌ | high | [func_1800032c0.md](func_1800032c0.md) |
| 0x180003320 | stream range-view clone | copy 48B descriptor + re-anchor slice | ❌ | high | [func_180003320.md](func_180003320.md) |
| 0x180003490 | min angular dist (180° ring) | orientation diff folded 0..90 | ✅ | high | [func_180003490.md](func_180003490.md) |
| 0x1800034e0 | Hamming distance | XOR + 256-entry popcount LUT | ❌ | high | [func_1800034e0.md](func_1800034e0.md) |
| 0x180003640 | descriptor NN matcher | Lowe-ratio + spatial gates → correspondences | ✅ | high | [func_180003640.md](func_180003640.md) |
| 0x180003880 | kp partition + matcher | edge/interior split, runs matcher twice | ❌ | high | [func_180003880.md](func_180003880.md) |
| 0x180003a00 | clipped box fill | memset rectangle into byte image | ❌ | high | [func_180003a00.md](func_180003a00.md) |
| 0x180003ac0 | label-map rasterizer | stamp ±2 squares of record-index | ❌ | high | [func_180003ac0.md](func_180003ac0.md) |
| 0x180003b50 | coverage-grid binning | occupancy histogram → coverage level | ❌ | high | [func_180003b50.md](func_180003b50.md) |
| 0x180003d30 | correspondence-table init | index/payload tables + sparse maps | ❌ | high | [func_180003d30.md](func_180003d30.md) |
| 0x180003ea0 | byte-array statistics | sum / filtered-avg / median / avg | ❌ | high | [func_180003ea0.md](func_180003ea0.md) |
| 0x180004010 | angle-fold accumulator | fold to [0,45], 3 accumulators | ❌ | high | [func_180004010.md](func_180004010.md) |
| 0x180004060 | orientation-diff scorer | per-elem folded angle + scaled score | ❌ | high | [func_180004060.md](func_180004060.md) |
| 0x180004190 | scatter-mark presence map | dst[src[i]]=1 occupancy table | ❌ | high | [func_180004190.md](func_180004190.md) |
| 0x1800041d0 | transform-and-sample builder | reproject kps, sample labelmap, score | ✅ | medium | [func_1800041d0.md](func_1800041d0.md) |
| 0x1800043d0 | feature-pipeline orchestrator | thread dims+scratch through 6 stages | ❌ | high | [func_1800043d0.md](func_1800043d0.md) |
| 0x180004620 | circular angular dist mod 180 | min of two %180 reductions | ✅ | high | [func_180004620.md](func_180004620.md) |
| 0x180004680 | transform plausibility predicate | accept/reject Q16 transform by bounds | ✅ | high | [func_180004680.md](func_180004680.md) |
| 0x180005930 | kp/geometry deserializer | parse stream into geometry struct | ❌ | high | [func_180005930.md](func_180005930.md) |
| 0x180005c60 | tag-0x69 TLV field writer | append two u32 into 0x69 field | ❌ | high | [func_180005c60.md](func_180005c60.md) |
| 0x180006320 | TLV section loader | fetch frame-geometry record from blob | ❌ | high | [func_180006320.md](func_180006320.md) |
| 0x180006470 | guarded TLV-section dispatcher | probe tag id+4, dispatch worker | ❌ | high | [func_180006470.md](func_180006470.md) |
| 0x1800065b0 | stream u32 element mover | get/put 4 bytes, len+=4 | ❌ | high | [func_1800065b0.md](func_1800065b0.md) |
| 0x1800065e0 | stream read_u8 | read 1 byte, cursor+=1 | ❌ | high | [func_1800065e0.md](func_1800065e0.md) |
| 0x180006610 | counted byte append loop | vector push-back of N bytes | ❌ | high | [func_180006610.md](func_180006610.md) |
| 0x180006680 | 24-byte range struct init | {begin,end,flags} + tag wrapper | ❌ | high | [func_180006680.md](func_180006680.md) |
| 0x1800067a0 | TLV cursor advance | step to next TLV record span | ❌ | high | [func_1800067a0.md](func_1800067a0.md) |
| 0x180006800 | ordered-container lookup | recursive find by u16 key | ❌ | high | [func_180006800.md](func_180006800.md) |
| 0x180006890 | guarded record-forwarder | fetch 24B record, forward to lookup | ❌ | high | [func_180006890.md](func_180006890.md) |
| 0x180006bc0 | apply Q16 rigid transform | out = R·in + t, +0x8000 round, >>16 | ✅ | high | [func_180006bc0.md](func_180006bc0.md) |
| 0x180006c40 | normalize to Q16 unit vector | (cos·65536, sin·65536) via isqrt | ✅ | high | [func_180006c40.md](func_180006c40.md) |
| 0x180006cc0 | similarity composition B∘A | compose two Q16 transforms + renorm | ✅ | high | [func_180006cc0.md](func_180006cc0.md) |
| 0x180006e10 | 2-point rigid solver | solve {a,b,tx,ty} from one segment pair | ✅ | high | [func_180006e10.md](func_180006e10.md) |
| 0x180006f20 | similarity fit (Procrustes/Kabsch) | closed-form R,t over N point pairs | ✅ | medium | [func_180006f20.md](func_180006f20.md) |
| 0x180007390 | 4-int32 compute-and-pack | glue: sub_180006e10 → 16B out struct | ❌ | high | [func_180007390.md](func_180007390.md) |
| 0x1800073f0 | out-struct packer wrapper | sub_180006f20 → 16B sec0_pre out | ✅ | high | [func_1800073f0.md](func_1800073f0.md) |
| 0x180007450 | apply Q16 transform (wrapper) | unpack Point2i+xform → sub_180006bc0 | ✅ | high | [func_180007450.md](func_180007450.md) |
| 0x180007480 | RANSAC 2-point + LSQ refit | minimal-fit + inlier count + consensus refit | ✅ | high | [func_180007480.md](func_180007480.md) |
| 0x1800077d0 | candidate-correspondence builder | ROI-gate + per-pair compose, emit pairs | ✅ | medium | [func_1800077d0.md](func_1800077d0.md) |
| 0x180007b30 | frame-pair evaluator + commit | score reprojections, commit transform to sec0_pre | ✅ | high | [func_180007b30.md](func_180007b30.md) |
| 0x180007fe0 | frame-slot init / bookkeeping | zero flags, seed -1 arrays, copy header | ❌ | high | [func_180007fe0.md](func_180007fe0.md) |
| 0x180008160 | pairwise frame-corr loop | propagate Q16 transforms across same-tile frames | ✅ | medium | [func_180008160.md](func_180008160.md) |
| 0x1800095c0 | generic qsort (median-of-3) | MSVC CRT qsort copy | ❌ | high | [func_1800095c0.md](func_1800095c0.md) |
| 0x18000b3d0 | byte-range validity predicate | 30<x AND y≤49 | ❌ | high | [func_18000b3d0.md](func_18000b3d0.md) |
| 0x18000b3f0 | struct-field unpack thunk | load rec[0],rec[1] → sub_18000b3d0 | ❌ | high | [func_18000b3f0.md](func_18000b3f0.md) |
| 0x18000b400 | two-byte range predicate | 30<x AND y≤55 | ❌ | high | [func_18000b400.md](func_18000b400.md) |
| 0x18000b420 | Q16 identity-check predicate | is xform != {0x10000,0,0,0}? | ✅ | high | [func_18000b420.md](func_18000b420.md) |

---

## Where the transform math lives

Study these `is_transform_math=true` functions in this order to understand how the
frame-registration transforms are actually computed. Everything else is plumbing,
serialization, gating, or scoring around this core.

**Tier 0 — fixed-point primitives** (the Q16 conventions everything else assumes):
1. `sub_180003060` *(not flagged, but foundational)* — integer sqrt; the magnitude
   denominator used by every normalize/solve step.
2. `sub_180006bc0` — **apply** a Q16 transform to a point: `out = R·in + t`,
   `R=[[a,-b],[b,a]]`, `+0x8000` round, signed `>>16`. This is the canonical Q16 layout
   `{a@0, b@4, tx@8, ty@c}` and rounding rule the whole subsystem obeys.
3. `sub_180006c40` — normalize a 2D vector to a Q16 unit vector `(cos·65536, sin·65536)`;
   how rotation pairs get snapped back onto the unit circle after any arithmetic.

**Tier 1 — angle helpers** (orientation scoring; feeds match-consistency, not the transform itself):
4. `sub_1800030a0` → `sub_180003150` — fixed-point atan2 core, then the quadrant resolver
   that yields Q16 radians; used when reprojected keypoint orientations are compared.
5. `sub_180003490`, `sub_180004620` — min angular distance on the 180° orientation ring;
   the residual metric for ridge-orientation agreement.

**Tier 2 — solving a single transform** (closed-form estimators):
6. `sub_180006e10` — minimal **2-point** rigid (scale=1) solver: derive `{a,b,tx,ty}` from
   one segment correspondence. This is the RANSAC hypothesis generator.
7. `sub_180006f20` — closed-form **N-point** similarity (Procrustes/Kabsch) fit: centroids →
   cross-covariance → isqrt-normalized cos/sin → `a,b,tx,ty`. This is the LSQ refit over inliers.
8. `sub_1800073f0` / `sub_180007450` — thin Q16 wrappers that pack `sub_180006f20`'s output
   into the 16-byte sec0_pre struct and apply transforms to points; read for the exact field packing.

**Tier 3 — composing & validating transforms**:
9. `sub_180006cc0` — compose two Q16 similarities `B∘A` (`R_out=R_B·R_A`, `t_out=t_B+R_B·t_A`)
   then renormalize the rotation. This is how a frame's pose is chained with a measured pairwise transform.
10. `sub_180004680` — plausibility gate: reject transforms whose translation / rotation /
    scale-error exceed fixed bounds (4096==1.0 in Q12). The accept/reject predicate.
11. `sub_18000b420` — identity check `{0x10000,0,0,0}`; distinguishes "already aligned" frames.

**Tier 4 — the loops that drive the above on real correspondences**:
12. `sub_1800041d0` — reproject keypoints through a candidate Q16 transform and sample the
    label-map to build descriptor/orientation residual arrays (the per-hypothesis scoring data).
13. `sub_180007480` — **RANSAC 2-point estimator + LSQ refit** (calls 6,7,8,2): the inner
    fit engine invoked by the model-fitter root.
14. `sub_1800077d0` — candidate-correspondence builder: ROI-gates keypoint pairs and composes
    each frame transform with the keypoint's embedded pose (calls 9).
15. `sub_180008160` — pairwise propagation loop: spreads rigid alignments across all frames that
    observed the same tile (calls 9).
16. `sub_1800046e0` *(ROOT)* — the full RANSAC fitter that ties 13 + scoring (`sub_1800043d0`) +
    the gate (10) into one frame-pair transform.
17. `sub_180007b30` *(under ROOT `sub_1800082a0`)* — the evaluator that scores reprojections and
    **commits** the accepted 16-byte transform into the sec0_pre-bound master geometry array.

---

## Suggested gdb capture plan

Goal: capture ground truth `input frames → output sec0_pre transforms` during a Wine enroll,
to verify a Python port. Run under the Wine gdb harness only (Frida does not work under Wine):

```
GDB_DUMP_<HOOK>=1 gdb -p <WINE_PID> -x dev/gdb_dump.py
```

Six breakpoints, ordered outer→inner, each pulled from the function's own doc. Capturing
the boundary of `sub_180007b30`'s commit step plus the two inner estimators is sufficient to
pin every transform written to the template.

1. **`break *0x180008341`** (`sub_1800082a0` entry gate) — dump `cl`/`dl` status bytes and the
   frame count, plus `*(int)(rdi)`/`*(int)(rdi+4)` = `w`/`h` at `0x180008634`. Establishes
   *which frames* and *what image dims* enter the registration. (func_1800082a0.md hooks #1, #5.)
2. **`break *0x1800088ae`** (`sub_180007b30` entry, the per-candidate evaluator + commit — highest
   priority) — dump the candidate index and the two input transforms about to be composed. This is
   the outer boundary of every transform that lands in sec0_pre. (func_1800082a0.md hook #9.)
3. **`break *0x180007c32`** then **`*0x180007c37`** (`sub_180006cc0` compose, inside `sub_180007b30`)
   — dump the two 16-byte input transforms, then the 16 composed bytes at `[rsp+0xb0]`. Captures
   the chained pose before scoring. (func_180007b30.md hooks #2, #3.)
4. **`break *0x180007480`** region: **`break *0x180006f3b`** (`sub_180006f20` entry) — dump `N` and the
   two point arrays (`x/8wd` each), then **`*0x180007259`** (S_c/S_s accumulators) and **`*0x180007346`**
   (success path). This is the LSQ similarity fit that produces a refined `{a,b,tx,ty}`. (func_180006f20.md
   hooks #1, #3, #8.)
5. **`break *0x180006e10`** (entry) and its `call 0x180003060` isqrt site — dump the single segment
   pair in, and `{a,b,tx,ty}` out. This is the RANSAC minimal hypothesis; cross-checks the 2-point
   solver against the refit. (func_180006e10.md; func_180007480.md hook on the minimal-fit call.)
6. **`break *0x180007eb7`** (`sub_180007b30` record-write) then **`*0x180007f59`** (COMMIT) — dump the
   target master-geom record (`$rsi + $rcx*4`) and confirm `used_flags[idx]=1`. This is the *output*:
   the 16-byte transform as actually stored in the sec0_pre table, plus the accepted-index list at
   `0x1800088f9` (`sub_180008160` final lists). (func_180007b30.md hooks #9, #11; func_1800082a0.md hook #11.)

Cross-check sequence for the port: (1) frame set + dims → (3) composed input transform →
(5)/(4) minimal-fit then LSQ-refit `{a,b,tx,ty}` → (2)→(6) the committed sec0_pre record.
Matching the output at hook 6 byte-exact against the captured chip template validates the port.
For sub-validation, the `sub_180006bc0` apply (`+0x8000`/`>>16`) and the popcount LUT at
`0x18011ebd0` are the two primitives most likely to diverge first.
