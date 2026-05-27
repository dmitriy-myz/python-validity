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

## The single blocker

The **descriptor is load-bearing** (proven: `zero_desc` and `our_desc`
variants both fail to match; only real descriptors match). The descriptor is
the output of:

```
raw 112² frame
  → [RIDGE ENHANCEMENT]            ← THE WALL: a content transform, not
  → enhanced 57² image (Q10)          recoverable from endpoints (corr ~0 vs
  → Determinant-of-Hessian (Q12)      resized raw; rotation/ECC registration
  → keypoints + 128-bit descriptor    fails). Decoded everything downstream.
```

So native enrollment requires reproducing the **enhancement front-end**
inside `sub_180001A50` (between its input image and the gradient stage
`sub_18000FDF0`), bit-exactly. This is the whole task below.

## Goal & validation gate

**Goal:** produce, from a raw 112² frame, the enhanced 57² image such that
`Lxx·Lyy − Lxy²` (Q12) on it reproduces the DLL's `harris_resp`, and the
resulting 128-bit descriptors match.

**Pass/fail gate (already built):** `dev/splice_experiment.py` `our_desc`
variant (real coords + OUR descriptor computed via the reproduced pipeline)
must **match** on `identify()`. That is the definition of done for the
descriptor. Intermediate gate: `dev/diff_v30.py compare_gradin` corr → ~1.0.

## Attack plan (ordered)

1. **PARTLY DONE (detector decoded; enhancement still upstream).** From the
   Hex-Rays of `sub_18000A1B0` + `sub_18000F250`:
   - `sub_18000F250` = gradients (`sub_1800101C0`) + DoH (`sub_18000CE80`)
     with a `>>6/<<6` Q-scale wrapper; it does NOT enhance.
   - `sub_18000A1B0` pads its input (`sub_180009F50`, border only) → `v41`,
     and `gradin = v41 >> 6`. So **its input `a2` is already the enhanced,
     downsampled ~57² image.**
   - ⇒ the enhancement + 112→57 downsample are UPSTREAM in the orchestrator
     `sub_18000AAB0` (stage-4 `sub_18000A1B0` is reached via dispatcher
     `sub_18000A4B0`). My earlier "enhancement = sub_18000D920/E090" was a
     bad-disasm-range artifact — discard it.
   - NEXT: get the Hex-Rays of `sub_18000AAB0` (or `sub_18000A4B0`) and walk
     its early stages to find where raw 112² → enhanced ~57². OR bracket
     empirically: hook `sub_18000A1B0` entry (dump a2) and the orchestrator
     input, and bisect. (`sub_18000C920` builds the DoH context that feeds
     `sub_18000CE80`'s a5 — may matter for the response, check it too.)

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
