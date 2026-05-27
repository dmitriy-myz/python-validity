# Next RE session — plan (06cb:00a2 native enrollment)

Resume point for the one remaining blocker. Read `dev/MOH.md` and
`dev/DLL-RE.md` first; this file is the action plan, not the findings.

## Where we are (TL;DR)

The MoH template format is **fully reverse-engineered and validated**:

```
0x47 record → envelope → WS body (TLV container)
  ├─ header (size@4, config@8, frame-id list@16, count table@24, geometry@44)
  ├─ N per-frame sections (~4540 B): [pose-record table] + [v30 copied verbatim]
  │     v30 = [~17B lead-in] + 250 × 18-byte records + [~16B trailer]
  │     record = [x:u8][y:u8][128-bit binary descriptor:16B]
  └─ TID (HMAC-SHA256 chain over WS body)
```

We can build chip-storable templates (`moh_opencv.extract_template(img,
reference_template=...)`), and a rebuilt-from-real template **matches** a
live finger (the `control` variant in `dev/splice_experiment.py`), proving
every structural layer + the store/TID path is correct.

## The single blocker (CORRECTED — no enhancement wall)

The **descriptor is load-bearing** (proven: `zero_desc` and `our_desc`
variants both fail to match; only real descriptors match). The earlier
"ridge-enhancement wall" was **WRONG** — there is no enhancement. The
detector input is just an **image tile**:

```
working image (112²)
  → 3×3 grid of 57×57 TILES (step h/3=37, overlap 20, mid-gray pad)   ← sub_18000A850 blit
  → per tile: img×1024; DoH (Q12) on the tile                          ← sub_18000A1B0 / sub_18000CE80
  → merge keypoints; quantize tile-local→global coords                 ← sub_18000A910 (DECODED)
  → per-keypoint 128-bit descriptor                                    ← sub_18000A5B0 (stage 5) — UNKNOWN
  → 250 minutiae → v30
```

Proven: each captured `gradin` == a 57×57 tile of `extract_image` at
**corr 1.000**. So the whole detector input is reproducible (plain tiling).
The only remaining unknown is the **descriptor algorithm** = stage 5
`sub_18000A5B0` (plus making the DoH exact, now easy since the input is a
known tile). This is ordinary decompilable RE, **not a wall**.

## Goal & validation gate

**Goal:** reproduce, per 57×57 image tile, the DoH keypoints and their
128-bit descriptors so `our_desc` matches. (Enhancement is NOT needed — the
tile is the detector input, confirmed corr 1.000.)

**Pass/fail gate (already built):** `dev/splice_experiment.py` `our_desc`
variant (real coords + OUR descriptor computed via the reproduced pipeline)
must **match** on `identify()`. That is the definition of done for the
descriptor. Intermediate gate: `dev/diff_v30.py compare_gradin` corr → ~1.0.

## IMPLEMENTATION ROADMAP (resume here — RE structure complete)

Native module started: `validitysensor/moh_native.py`. Stage status + the
exact leaves left to port bit-exact (validate each vs the dumps in
`$FRIDA_DUMP_DIR` via `dev/diff_v30.py`):

| stage | status | remaining leaves (decompile + port) |
|-------|--------|--------------------------------------|
| tiling | ✅ byte-exact (`tile_image`) | — |
| gradient/DoH | ✅ FULLY decoded (disasm) — see DLL-RE.md "Gradient kernel chain" | PORT: Gaussian smooth (shift 12) + 3-tap [1,0,-1]/[1,3.33,1] planes (shift 10) + `sub_18000CC20` buffer/scale wiring; validate vs captured `harris_*` planes |
| DoH `Ixy` | ✅ explained: `[1,0,-1]_x ⊗ [1,0,-1]_y`, per-tap >>10 in both passes | (port, same as above) |
| keypoints (NMS) | ✅ decoded — `sub_18000CF90`: 8-nbr NMS + thresh([+0x20],[+0x24]) + dist-dedup | port + validate kp coords |
| orientation | algo decoded (`sub_18000D920`) | atan2 leaves `sub_1800030A0`, `sub_180003150`; peak `sub_18000D850`; weights `dword_180120C00` (dumped) |
| descriptor | algo decoded (`sub_18000E090`) | bit-pack `sub_18000DF20`; DoH context `sub_18000C920`; BRIEF pairs from `sub_18000E6B0` (`BRIEF_SEED_TABLE`) |
| assemble v30 | format known (`build_v30_record`) | wire stages → 250 records → splice/TID (have) |

Validation gates: `compare_harris` (DoH), `decode_records` (v30 layout),
`splice_experiment.py` `our_desc` must `identify()`-match (final). Pull the
`.rdata` tables with IDA (manual file-offset math proved unreliable). The
work is bounded (~8 small leaves) but methodical; do it offline against the
captured dumps, not as a live function-by-function chain.

## (older) STATUS: RE COMPLETE — now an implementation task

Every stage from raw frame → `v30` is decoded as classical CV with known
tables (see `dev/DLL-RE.md` "Descriptor algorithm — FULLY DECODED"). No
unknowns remain to reverse; what's left is **porting + bit-exact validation**:

1. **Tiling**: 3×3 grid of 57×57 tiles (step `h/3`=37, overlap 20, mid-gray
   128 pad). `sub_18000A850` blit + `sub_180009F50` pad (both DECODED).
2. **DoH per tile** (Q12): `(Ixx>>12)(Iyy>>12) − (Ixy>>12)²` on `tile<<10`,
   gradients via Sobel-like `sub_18000FDF0`/`180010050` (need exact kernel),
   NMS → keypoints. Validate vs captured `harris_resp`/`gradin`.
3. **Orientation** (`sub_18000D920`): radius-6 Gaussian-weighted gradient
   histogram (42 bins, table `dword_180120C00` dumped) → orientation+quality.
4. **Oriented BRIEF** (`sub_18000E090`): rotate by orientation (cos/sin
   `·65536`), block-aggregate gradients, apply BRIEF pairs (`sub_18000E6B0` /
   `BRIEF_SEED_TABLE`) → 128-bit descriptor.
5. **Assemble** `v30` ([x][y][16B desc] ×250), splice via the existing
   `moh_opencv` path, recompute TID. **Validate**: `dev/splice_experiment.py`
   `our_desc` variant must match on `identify()`.

Validate each stage against the captured dumps (`compare_harris`,
`compare_gradin`, `decode_records`) before chaining. Tables to pull from the
DLL: `dword_180120C00` (file 0x11f800); cos/sin are `round(cos/sin(deg)·65536)`;
BRIEF pairs from `sub_18000E6B0`. Exact Sobel kernel: decompile
`sub_18000FDF0`/`sub_180010050` if step-2 byte-match falls short.

## (historical) Attack plan — superseded by the status above

1. **DONE — there is no enhancement; the input is a tile.** `sub_18000AAB0`
   (decompiled) tiles the working image 3×3 and runs the DoH detector
   (`sub_18000A4B0`→`sub_18000A1B0`) per 57×57 tile (`sub_18000A850` blit +
   mid-gray pad). `gradin` == an `extract_image` tile at corr 1.000.

2. **Decompile stage 5 `sub_18000A5B0`** — the per-keypoint descriptor (the
   real remaining unknown). It's called in the orchestrator's second 9-tile
   pass: `sub_18000A5B0(v85 tile, a2 ctx, w, h, …, a7 params)`. Read how it
   turns a keypoint + its tile image into the 128-bit descriptor (binary
   tests? sampling pattern? `sub_18000E6B0` BRIEF-select is partly decoded
   but for 64 not 128 tests). Validate bit-exactly against captured `v30`
   descriptors for the same image.

3. **Make the DoH exact** (now easy — input is a known tile): port tiling +
   `img×1024` + DoH (Q12, `Lxx·Lyy−Lxy²`) and match `harris_resp` byte-exact,
   then keypoints byte-exact.

2. **Bisect the transform with intermediate hooks.** We already capture the
   final enhanced image (`GDB_DUMP_GRADIN`, `sub_18000FDF0`'s RCX). Add hooks
   on the stage outputs *before* it — after padding, after downsample, after
   each enhancement pass — to get (input → output) image pairs per stage.
   Add these to `dev/gdb_dump.py` following the existing hook pattern.

3. **Identify each stage from its pairs.** Likely components (fingerprint
   enhancement canon): (a) downsample kernel (112→57; find exact filter),
   (b) **orientation-field estimation**, (c) **oriented/Gabor bandpass
   filtering** along the ridge orientation, possibly (d) frequency/contrast
   normalization. For each, correlate candidate operators (cv2 / numpy)
   against the captured stage output until corr ≈ 1.0.

4. **Port + chain in `moh_opencv`.** Implement each stage; validate against
   captured intermediates, then the full enhancement against `gradin`
   (compare_gradin corr → ~1.0), then DoH against `harris_resp`.

5. **Descriptor binary tests.** With the enhanced image + DoH keypoints,
   reproduce the **128-bit** descriptor: confirm the binary-test pattern
   (`sub_18000E6B0` is partly decoded — `BRIEF_SEED_TABLE`, 162 candidates,
   but for **128** tests not 64) and the sampling geometry/scale. Validate
   bit-exactly against captured `v30` descriptors (same image).

6. **Validate end-to-end** via the `our_desc` then `our_both` splice variants.

## Tools available (all in `dev/`, on branch `moh-opencv-poc`)

- `gdb_dump.py` — 6 hooks: `GDB_DUMP_{PACKER,DESC,BLOB,EXTRACT,HARRIS,GRADIN}=1`.
  Run on the Wine host: `gdb -p <WUDFHost PID> -x dev/gdb_dump.py`, then a full
  enrollment. Dumps land in `$FRIDA_DUMP_DIR` (the captures used the VBox share
  `/media/sf_vbox-rw/finger/frida_dumps`). Add the stage-output hooks here.
- `diff_v30.py` — loads (image→v30) pairs, `decode_records()`, recall metrics,
  `compare_harris`, `compare_gradin`. The grind dashboard.
- `splice_experiment.py` — the isolation/validation harness.
- DLL + IDA db at `/media/sf_vbox-rw/finger/` (`synaWudfBioUsb.{dll,i64}`),
  image base 0x180000000, IDA demo at `~/idademo-7.5`. `objdump` works for raw
  disasm.

## Key facts to carry in

- Working resolution **57×57** (not 112/116); DoH terms are **Q12** (`>>12`);
  enhanced image is **Q10** (`×1024`, range [0,255·1024]).
- 250 minutiae/frame; descriptor mean popcount ~64/128 (balanced binary).
- Reference templates: `wine_finger_fresh.bin` (matches the live finger),
  `wine_finger_data*.bin`. v30 regions in it: offsets 309/4913/9453/13993.
- Hardware/Wine are intermittent; capture in batches. ptrace_scope may need
  `sudo sysctl kernel.yama.ptrace_scope=0`.

## Honest effort note

This is the proprietary fingerprint enhancement core — orientation estimation
+ oriented filtering, bit-exact. It is a large, open-ended effort with no
guarantee of a clean closed form, and small errors cascade through
DoH→keypoints→descriptor where the matcher is unforgiving. The
**Wine-enroll → replay** path (dev/MOH.md "Workflow") works today and is the
pragmatic alternative if this stalls.
