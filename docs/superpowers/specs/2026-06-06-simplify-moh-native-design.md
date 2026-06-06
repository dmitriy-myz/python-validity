# Decode & simplify `validitysensor/moh_native.py`

**Date:** 2026-06-06
**Branch:** `moh-enrollment-refactor`
**Status:** design approved, pending implementation plan

## Problem

`validitysensor/moh_native.py` (1742 lines) is the byte-exact host-side port of
the 06cb:00a2 DLL's image→v30 feature pipeline. Large parts are written in an
asm-translation style that is hard to read:

- Fixed-point wrappers `_s32` / `_sar32` / `_imul32` / `_idiv32` applied at
  nearly every arithmetic step, e.g. `dxx = _sar32(_s32(L + R - 2 * cV), 2)`.
- Register-machine variable names (`eax`, `ecx`, `edx`, `r8d`, `r9d`, `r10d`,
  `r11d`) in the atan2 trio (`_fast_atan2`, `_precise_atan2`, `_angle_to_bin`).
- A ~580-line "formerly moh_extract.py" RE scaffold (lines ~1162–1742) that is
  explicitly documented as retained RE documentation; only `compute_tid` and
  `_build_envelope` from it are used in production.

The goal is readable, idiomatic Python ("simple python commands instead of
asm-style") **without changing a single output byte** of the chip-accepted
template, plus removal of dead code.

## Non-negotiable contract: byte-identical output

The output of `native_template()` is the exact buffer the chip ingests (cmd
0x47). Therefore **a byte-identical envelope ⇒ identical behavior on
hardware** — there is no hidden state. This makes byte-diffing the *complete*
correctness proof; hardware re-verification becomes optional
(belt-and-suspenders only).

The contract for this refactor is: for every input, the new module produces the
**literally identical bytes** the frozen original produces — verified at three
granularities (end-to-end, per-stage, and full-domain arithmetic fuzz).

## Public API surface (must not change)

External importers and the symbols they pull (verified by grep over
`validitysensor/` + `scripts/`):

- `validitysensor/moh_enrollment.py`:
  `extract_frame_native`, `_load_ws_scaffold`, `NATIVE_WS_V30_REGIONS`,
  `patch_pre_v30_near_identity`, `serialize_v30_section`, `V30_DESC_LEN`,
  `compute_tid`, `_build_envelope`
- `scripts/enroll_moh_chip.py`:
  `native_template`, `extract_frame_native`

All nine symbols must continue to resolve and behave identically. Everything
else in the module is internal and free to rewrite, rename, or delete.

`blobs_a2` provides `BRIEF_TABLE`, `AGGR_TABLE`, `build_ws_scaffold` — consumed
lazily by the module; unaffected.

## Safety net (built FIRST, before any edit to `moh_native.py`)

### 1. Frozen oracle
Copy today's `validitysensor/moh_native.py` verbatim to
`tests/_moh_native_frozen.py`, with a header comment marking it the byte-exact
oracle (not for production import). This is the single source of truth for
"current behavior". **Kept permanently** as a regression guard (user decision)
so the live module can never silently drift from the chip-accepted bytes.

### 2. Golden / characterization test
`tests/test_moh_native_golden.py` — runnable both as a plain script
(`./.venv-poc/bin/python tests/test_moh_native_golden.py`, exit non-zero on
failure) and under pytest if present. It imports BOTH the frozen oracle and the
live `moh_native` and asserts they agree on:

- **End-to-end (the contract):** a set of deterministic seeded 112×112 Q16
  images (mid-gray = 0x800000 base + seeded structure chosen to yield many
  keypoints and wide value ranges). For each image:
  - `extract_frame_native(img)` equal field-for-field (gx, gy, orient_q16,
    descriptor bytes), and
  - `native_template(img)` envelope **byte-identical** (compare full bytes).
- **Per-stage:** on the same images — `presmooth`, `cc20_planes`/`doh` (resp
  arrays via `np.array_equal`), `nms` (kp lists), `subpix_refine_kp`,
  `orient_d920`, `descriptor_gradient` (gradX/gradY arrays), `desc_sample_rotate`,
  `desc_aggregate`, `brief_pack`.
- **Differential fuzz of the arithmetic helpers** over the **full i32 domain,
  including overflow-inducing values** (seeded RNG, ~1e6 samples each):
  `_s32`, `_sar32`, `_imul32`, `_idiv32`, `gauss_tap`, `build_gaussian`,
  `build_3tap`, `_solve_2x2_d4c0`, `_fast_atan2`, `_precise_atan2`,
  `_angle_to_bin`. This is what *licenses removing a wrapper*: a simplified
  expression is only adopted if it reproduces the oracle across this domain.
  It closes the overflow gap that a sample-image-only golden test cannot.

The test must pass with the **unmodified** module first (sanity: oracle ≡
itself) before any simplification begins.

## Simplification rules (mechanical, per-call-site, test-gated)

Apply only changes the safety net proves byte-identical. Decision per pattern:

- `_sar32(_s32(EXPR), n)` → `EXPR >> n` **iff** fuzz + per-stage golden prove
  `EXPR` stays within i32 across realistic ranges. Otherwise retain a single
  clearly-named helper `sar32(x, n)`.
- `_imul32(a, b)` → `a * b` **iff** the product is proven within i32 on real
  inputs. Otherwise retain `mul32(a, b)` — here the 32-bit truncation IS the
  behavior (e.g. `cos_q * gx8` in `desc_sample_rotate`).
- `_idiv32(a, b)` → `trunc_div(a, b)`, one clearly-named trunc-toward-zero
  helper. **Never** bare `//` (Python floors; the DLL truncates toward zero,
  which differs for negative operands). Call sites: `build_gaussian`,
  `build_3tap`, `_solve_2x2_d4c0`.
- atan2 trio (`_fast_atan2`, `_precise_atan2`, `_angle_to_bin`): keep the exact
  polynomial and magic constants (load-bearing); rename register variables to
  meaningful names; add docstrings explaining the algorithm (fixed-point atan2 =
  cubic-poly arctan on [0,1] with quadrant folding; `_angle_to_bin` = signed
  divide-by-9830 via reciprocal-multiply). Arithmetic frozen.
- `desc_sample_rotate`: remove the redundant inner `_s32` redefinition; use the
  module-level helpers consistently.
- Already-clean functions (`tile_image`, `nms`, `merge_tile_kps_to_global`,
  `serialize_v30_section`, `find_v30_regions`, `compute_tid`, `_build_envelope`,
  the numpy convolutions) get only light comment/name touch-ups.

Naming: retained fixed-point helpers get intent-revealing names (`s32`/`trunc32`,
`sar32`, `mul32`, `trunc_div`) with a short module-level docstring block
explaining the fixed-point conventions once, rather than re-deriving them inline.

## Deletions

- The "formerly moh_extract.py" scaffold (lines ~1162–1742) **except**
  `compute_tid`, `_build_envelope`, and `_TID_INFO`, which move up into the
  active module. Removed: `MAX_MINUTIAE`/`GRID_X`/... tuning constants block,
  `Minutia`, `FrameContext`, the `cmp_*` comparators, all `sub_XXXXXXXX`
  functions, `stage_*` stubs, `orchestrate`, `extract_features`,
  `_serialize_for_hash`, `EnrollmentSession`, `BRIEF_SEED_TABLE`,
  `PADDING_FILL_VALUE`, `sub_180009F50`, `sub_18000E6B0`. (Recoverable from git
  history if ever needed for RE.)
- Dead active-half helpers (zero callers anywhere): `build_v30`,
  `subpix_refine_kps`, `tile_origin_yx`, `_rotate_sample_pair`.

## Done criteria

1. `tests/test_moh_native_golden.py` passes: new ≡ frozen oracle at all three
   granularities (end-to-end byte-identical envelope, per-stage equal,
   full-domain fuzz equal).
2. The nine externally-imported symbols still resolve and behave identically;
   `moh_enrollment.py` and `scripts/enroll_moh_chip.py` import without change.
3. No `sub_XXXXXXXX` names and no register-style variables remain in the active
   module; the file is substantially shorter.
4. (Optional, user-run) `scripts/enroll_moh_chip.py --dry-run` produces an
   envelope byte-identical to a pre-refactor run — already implied by (1).

## Risks & mitigation

- **A removed wrapper mattered on an untested value.** Mitigated by full-i32
  differential fuzz (incl. overflow values), not just sample-image golden. When
  fuzz shows any divergence, the wrapper is kept.
- **The oracle duplicates the old asm-style file.** Acceptable: it lives in
  `tests/`, is never imported by production, and serves as a permanent
  regression guard pinning the live module to chip-accepted bytes forever.
- **Hidden coupling via internal helper removal.** Mitigated by the grep-proven
  zero-caller check before each deletion and by the per-stage golden assertions.

## Out of scope

- Algorithmic changes, performance tuning, or "fixing" anything in the pipeline.
- The remaining RE work (e.g. the cull stage / matching gate) — untouched.
- `moh_enrollment.py`, `blobs_a2.py`, `scripts/` — read-only references here.
