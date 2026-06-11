# MoH native pipeline — float-math rewrite (experiment)

**Date:** 2026-06-11
**Branch:** `moh-native-float-experiment` (off `moh-native-remove-unused`)
**Goal:** Replace the bit-exact x86 fixed-point emulation in
`validitysensor/moh_native.py` with readable native Python/NumPy float math,
to empirically test whether a **non-byte-exact** template still enrolls and
matches on the 06cb:00a2 sensor.

## Motivation

`moh_native.py` reproduces the Windows DLL's image→v30 feature pipeline
byte-for-byte. That fidelity is carried by ~hundreds of lines of x86
emulation: the `_s32`/`_sar32`/`_imul32`/`_idiv32` 32-bit-truncation
wrappers, magic-constant `atan2`/`exp`/division polynomials, and Q-format
shift juggling. The hypothesis under test: the on-chip matcher (Hough
geometric voting, relative-argmax, **no fixed threshold** — see memory
`moh_matcher`) tolerates small numeric drift, so a clean float pipeline
that is *algorithmically* the same will still match.

## Scope

### Unchanged (byte-format / data — NOT asm)
`compute_tid`, `_build_envelope`, `serialize_v30_section`,
`merge_tile_kps_to_global`, `patch_pre_v30_near_identity`,
`_load_ws_scaffold`, `native_template`, `extract_frame_native`
orchestration, tiling (`tile_image`/`tile_origin`/`tile_size`), and the data
tables `GAUSS_Q`, `AGGR_TABLE`/`BRIEF_TABLE` (from `blobs_a2`).

Public symbols imported by production code keep their signatures:
`extract_frame_native`, `_load_ws_scaffold`, `NATIVE_WS_V30_REGIONS`,
`patch_pre_v30_near_identity`, `serialize_v30_section`, `V30_DESC_LEN`,
`compute_tid`, `_build_envelope`, `native_template`.

### Rewritten to native float math
| Stage | From | To |
|---|---|---|
| Gaussian kernel | `gauss_tap`+`EXP_TABLE`, `build_gaussian` shift-magic | real `exp(-x²/2σ²)`, unity-normalized |
| 3-tap deriv/smooth | `build_3tap` magic `0xd55`/`0x2aaa` | `[1,0,-1]` central diff, `[1,2,1]/4` smooth |
| Separable conv | `_conv_axis` per-tap `>>shift` | float NumPy convolution |
| DoH response | `>>12` Q-juggling | float `Ixx·Iyy − Ixy²`, scaled by `RESP_SCALE` |
| Subpix | `_solve_2x2_d4c0` Cramer/SAR | `numpy.linalg.solve` 2×2 |
| Orientation | `_fast_atan2`/`_precise_atan2`/`_angle_to_bin` | `math.atan2`, `bin = angle·42/2π` |
| Descriptor | `_s32` Q16 cos/sin, NEG-then-SAR | float `cos/sin`, plain sums |
| Helpers/tables | `_s32/_sar32/_imul32/_idiv32`, `EXP_TABLE`, `COS_Q16/SIN_Q16` | deleted |

### Deleted (dead RE scaffold, not imported anywhere)
`Minutia`, `FrameContext`, `orchestrate`, `extract_features`,
`EnrollmentSession`, the `stage_*` `NotImplementedError` stubs,
`sub_180003460`/`sub_18000A8E0`/`sub_18000A910`/`sub_180001010`/
`sub_1800031E0`/`sub_1800032C0`/`sub_180009F50`/`sub_18000E6B0`,
`BRIEF_SEED_TABLE`, the qsort `cmp_*` helpers. Keep only `compute_tid` and
`_build_envelope` from that block.

## Response-scale preservation

NMS uses **absolute** thresholds (`t_lo=671`, `t_hi=168`) tuned to the
fixed-point response magnitude. Tracing the original gains analytically:
`resp_original ≈ 16 · (Ixx·Iyy − Ixy²)` of the doubly-smoothed image in
natural units. Rather than re-derive every per-pass gain by hand, we
**calibrate one constant** `RESP_SCALE`: compute the native response and the
original response on the same synthetic tiles and set `RESP_SCALE` so their
magnitudes match (median + max). The constant is then frozen and `t_lo`/`t_hi`
are kept. If hardware shows a very different keypoint count, `t_lo`/`t_hi`
become the tuning knob.

## Validation (no hardware required for these)
1. Calibration: native vs original `doh()` response stats agree within a few
   percent after `RESP_SCALE` (one-off script using `git show` of the
   original).
2. Import smoke test of `validitysensor.moh_native` + `moh_enrollment`.
3. End-to-end `extract_frame_native` and `native_template` run on a synthetic
   112×112 frame; envelope is 23136 bytes; TID recomputes.

Hardware enroll/match (`enroll_moh_chip.py --match`) is the actual experiment
the user runs.
