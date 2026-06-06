# Decode & Simplify `moh_native.py` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite the asm-translation style in `validitysensor/moh_native.py` into readable Python and delete dead code, producing **byte-identical** output for the production path.

**Architecture:** This is a *refactor under a characterization test*, not a feature. Task 1 builds the safety net (a frozen copy of the current module + a golden test that pins new ≡ frozen at end-to-end, per-stage, and full-i32 helper-fuzz granularity). Every later task is a transformation that **must keep the golden test green**. Because `native_template()` output is exactly what the chip ingests, byte-identical output is a complete correctness proof.

**Tech Stack:** Python 3, numpy. Run everything with the project venv `./.venv-poc/bin/python` (base `python3` lacks numpy). No pytest in the venv — the test is a self-contained script (also pytest-discoverable).

---

## TDD note for this plan

Pure TDD (write failing test → implement → green) applies to Task 1, which *creates* the test. Tasks 2–9 are refactors: the golden test is a **standing gate** that is green before and after each change. The "test" step in those tasks is "run the gate, confirm still green." If a change turns it red, the per-stage assertions name the offending stage — revert that one simplification to its wrapped form (the test is the arbiter of what is safe to drop) and re-run.

## File Structure

- **Create** `tests/_moh_native_frozen.py` — verbatim copy of the current `validitysensor/moh_native.py` (the byte-exact oracle), with its 3 relative `from .blobs_a2` imports rewritten to absolute. Never imported by production. Kept permanently as a regression guard.
- **Create** `tests/test_moh_native_golden.py` — the golden/characterization test (script + pytest-compatible).
- **Modify** `validitysensor/moh_native.py` — the live module being simplified.
- Read-only references (must keep importing cleanly): `validitysensor/moh_enrollment.py`, `scripts/enroll_moh_chip.py`, `validitysensor/blobs_a2.py`.

The 9 externally-imported symbols that must keep resolving identically: `extract_frame_native`, `native_template`, `compute_tid`, `_build_envelope`, `_load_ws_scaffold`, `NATIVE_WS_V30_REGIONS`, `patch_pre_v30_near_identity`, `serialize_v30_section`, `V30_DESC_LEN`.

---

### Task 1: Build the safety net (frozen oracle + golden test)

**Files:**
- Create: `tests/_moh_native_frozen.py`
- Create: `tests/test_moh_native_golden.py`

- [ ] **Step 1: Freeze the current module as the oracle**

```bash
cd /home/dev/projects/own/python-validity
cp validitysensor/moh_native.py tests/_moh_native_frozen.py
```

- [ ] **Step 2: Make the frozen oracle importable from outside the package**

The frozen copy has 3 relative imports (`from .blobs_a2 import ...`) that only resolve inside the `validitysensor` package. Rewrite them to absolute so the oracle can be loaded by file path. Apply these three exact edits to `tests/_moh_native_frozen.py` (do NOT touch anything else — the oracle's arithmetic must stay byte-for-byte identical):

```bash
cd /home/dev/projects/own/python-validity
sed -i 's/^        from \.blobs_a2 import BRIEF_TABLE/        from validitysensor.blobs_a2 import BRIEF_TABLE/' tests/_moh_native_frozen.py
sed -i 's/^        from \.blobs_a2 import AGGR_TABLE/        from validitysensor.blobs_a2 import AGGR_TABLE/'   tests/_moh_native_frozen.py
sed -i 's/^        from \.blobs_a2 import build_ws_scaffold/        from validitysensor.blobs_a2 import build_ws_scaffold/' tests/_moh_native_frozen.py
```

Add a one-line marker at the very top so nobody imports it in production:

Insert as the new line 1 of `tests/_moh_native_frozen.py`:
```python
# BYTE-EXACT ORACLE — frozen pre-refactor copy of moh_native.py. Test use only; never import in production. See docs/superpowers/plans/2026-06-06-simplify-moh-native.md
```

- [ ] **Step 3: Verify the 3 import rewrites landed and nothing else changed**

```bash
cd /home/dev/projects/own/python-validity
grep -n "from .blobs_a2\|from validitysensor.blobs_a2" tests/_moh_native_frozen.py
diff <(tail -n +2 tests/_moh_native_frozen.py) validitysensor/moh_native.py | grep -c '^[<>]'
```
Expected: the grep shows 3 lines all reading `from validitysensor.blobs_a2 import ...`; the diff count is `6` (exactly the 3 changed import lines, each a `<`/`>` pair) — confirming no other line differs.

- [ ] **Step 4: Write the golden test**

Create `tests/test_moh_native_golden.py`:

```python
#!/usr/bin/env python3
"""Golden characterization test for validitysensor/moh_native.py.

Pins the refactored module BYTE-FOR-BYTE to the frozen pre-refactor oracle
(tests/_moh_native_frozen.py). Run:

    ./.venv-poc/bin/python tests/test_moh_native_golden.py

Prints "ALL GOLDEN CHECKS PASSED" and exits 0 on success; non-zero on any
divergence. Also importable under pytest (functions are named test_*).
"""
import importlib.util
import os
import sys

import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from validitysensor import moh_native as live  # noqa: E402


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


frozen = _load("moh_native_frozen",
               os.path.join(REPO, "tests", "_moh_native_frozen.py"))


def make_images():
    """Deterministic 112x112 Q16 images (mid-gray = 0x800000 == 128<<16).
    Mix of seeded noise (wide value ranges) and synthetic ridges (stable
    keypoints that survive subpix and exercise orient+descriptor+e2e)."""
    imgs = []
    for s in range(4):
        a = np.random.default_rng(1000 + s).integers(0, 256, (112, 112)).astype(np.int32)
        imgs.append((f"noise{s}", a << 16))
    yy, xx = np.mgrid[0:112, 0:112]
    for k, (period, ang) in enumerate([(9, 0.3), (13, 1.1), (7, 2.0)]):
        c, sn = np.cos(ang), np.sin(ang)
        ridge = 128 + 90 * np.sin(2 * np.pi * (xx * c + yy * sn) / period)
        a = np.clip(ridge, 0, 255).astype(np.int32)
        imgs.append((f"ridge{k}", a << 16))
    return imgs


_IMAGES = make_images()


def test_extract_frame_native_e2e():
    for name, img in _IMAGES:
        assert live.extract_frame_native(img) == frozen.extract_frame_native(img), \
            f"extract_frame_native diverged on {name}"


def test_native_template_byte_identical():
    for name, img in _IMAGES:
        new = live.native_template(img)
        old = frozen.native_template(img)
        assert new == old, \
            f"native_template bytes diverged on {name} (len {len(new)} vs {len(old)})"


def test_stages_match():
    """Per-stage localization: run every stage on both modules with identical
    inputs and compare. Iterates ALL nms keypoints (not the global 250 cap),
    so it covers more than the e2e path alone."""
    for name, img in _IMAGES:
        img64 = np.asarray(img, dtype=np.int64)
        for (i, j, tile) in frozen.tile_image(img64):
            gxN, gyN = live.descriptor_gradient(tile)
            gxO, gyO = frozen.descriptor_gradient(tile)
            assert np.array_equal(gxN, gxO) and np.array_equal(gyN, gyO), \
                f"descriptor_gradient {name} tile {i},{j}"
            assert np.array_equal(live.presmooth(tile), frozen.presmooth(tile)), \
                f"presmooth {name} {i},{j}"
            rN = live.doh(tile >> 6)
            rO = frozen.doh(tile >> 6)
            for q in range(4):
                assert np.array_equal(rN[q], rO[q]), f"doh[{q}] {name} {i},{j}"
            resp = rO[3]
            kpsN = live.nms(resp)
            kpsO = frozen.nms(resp)
            assert kpsN == kpsO, f"nms {name} {i},{j}"
            for (sc, lx, ly) in kpsO:
                aN = live.subpix_refine_kp(resp, lx, ly)
                aO = frozen.subpix_refine_kp(resp, lx, ly)
                assert aN == aO, f"subpix {name} {i},{j} ({lx},{ly})"
                if aO is None:
                    continue
                sx, sy = aO
                assert live.orient_d920(gxO, gyO, sx, sy) == \
                    frozen.orient_d920(gxO, gyO, sx, sy), f"orient {name} {i},{j}"
                idx = frozen.orient_to_index(frozen.orient_d920(gxO, gyO, sx, sy)) % 360
                rgxN, rgyN = live.desc_sample_rotate(gxO, gyO, sx, sy, idx)
                rgxO, rgyO = frozen.desc_sample_rotate(gxO, gyO, sx, sy, idx)
                assert np.array_equal(rgxN, rgxO) and np.array_equal(rgyN, rgyO), \
                    f"desc_sample_rotate {name} {i},{j}"
                aggN = live.desc_aggregate(rgxO, rgyO, live._load_aggr_table(), live._WIN_SIZES)
                aggO = frozen.desc_aggregate(rgxO, rgyO, frozen._load_aggr_table(), frozen._WIN_SIZES)
                assert np.array_equal(aggN, aggO), f"desc_aggregate {name} {i},{j}"
                assert np.array_equal(live.brief_pack(aggO), frozen.brief_pack(aggO)), \
                    f"brief_pack {name} {i},{j}"


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {fn.__name__}: {e}")
    if failed:
        print(f"{failed} CHECK(S) FAILED")
        sys.exit(1)
    print("ALL GOLDEN CHECKS PASSED")


if __name__ == "__main__":
    _run_all()
```

- [ ] **Step 5: Run the golden test against the UNMODIFIED live module**

```bash
cd /home/dev/projects/own/python-validity
./.venv-poc/bin/python tests/test_moh_native_golden.py
```
Expected: `PASS test_extract_frame_native_e2e`, `PASS test_native_template_byte_identical`, `PASS test_stages_match`, then `ALL GOLDEN CHECKS PASSED`, exit 0. (live and frozen are the same code here, so this validates the harness wiring: image generation, both imports, every stage call.)

- [ ] **Step 6: Commit**

```bash
cd /home/dev/projects/own/python-validity
git add tests/_moh_native_frozen.py tests/test_moh_native_golden.py
git commit -m "test: golden characterization harness pinning moh_native to frozen oracle

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git push
```

---

### Task 2: Delete dead code (scaffold + dead helpers)

**Files:**
- Modify: `validitysensor/moh_native.py`

This removes the unused "formerly moh_extract.py" scaffold (keeping only `_TID_INFO`, `compute_tid`, `_build_envelope`) and four dead helpers in the active half. Behavior-preserving (nothing live calls the removed symbols — verified by grep).

- [ ] **Step 1: Preserve the three kept definitions verbatim**

Do NOT retype these — open `validitysensor/moh_native.py` and copy the three blocks out exactly as they currently are, so you can paste them back after the bulk delete:
- `_TID_INFO = b'Template ID' ...` plus its `assert len(_TID_INFO) == 43` (currently ~lines 1705–1706).
- `def compute_tid(ws_body: bytes) -> bytes:` ... through its `return hmac.new(...)` (currently ~lines 1709–1741).
- `def _build_envelope(subtype: int, ws_body: bytes, template_id: bytes, version: int = 3) -> bytes:` ... through its `return bytes(buf)` (currently ~lines 1639–1698).

- [ ] **Step 2: Delete the entire lower scaffold, re-add the three kept blocks**

Replace everything from the banner line
```
# ══════════════════════════════════════════════════════════════════════
# Host-side feature-extraction pipeline (formerly moh_extract.py)
```
to the end of the file with a new "envelope + TID" section containing ONLY the three preserved blocks. The new tail of the file is:

```python
# ─── Envelope + TemplateId (the only survivors of the moh_extract port) ──────
# These two functions are the host-side serializer used by native_template()
# above and by moh_enrollment.py. Everything else from the former
# moh_extract.py scaffold was RE documentation and has been removed
# (recoverable from git history).

def _build_envelope(subtype: int, ws_body: bytes, template_id: bytes,
                    version: int = 3) -> bytes:
    <<paste the preserved _build_envelope body verbatim>>


# ─── TID derivation (sub_1800E0A60 → sub_18004B710 chain) ───────────────
_TID_INFO = b'Template ID' + b'\x00' * 32
assert len(_TID_INFO) == 43


def compute_tid(ws_body: bytes) -> bytes:
    <<paste the preserved compute_tid body verbatim>>
```

Keep the module's existing `import hashlib`, `import hmac`, `from struct import pack, unpack` at the top — `compute_tid`/`_build_envelope` still need them. (The `dataclass`/`field`/`List`/`Optional`/`Tuple` typing imports are now unused; remove them in Task 9's cleanup.)

- [ ] **Step 3: Delete the four dead helpers in the active half**

Remove these complete function definitions (each confirmed to have zero callers anywhere):
- `def build_v30(global_kps, max_records=250, tag=4, body_len=4533):` ... through its `return header + bytes(body)`, plus its preceding comment block describing the standalone v30 buffer.
- `def subpix_refine_kps(resp, kps, scale_shift=0):` ... through its `return out`.
- `def tile_origin_yx(i, j, h, w):` ... through its `return tile_origin(i, j, h, w)`.
- `def _rotate_sample_pair(gx, gy, cos_q16, sin_q16):` ... through its `return np.int32(rgx), np.int32(rgy)`.

- [ ] **Step 4: Confirm the removed symbols are gone and nothing references them**

```bash
cd /home/dev/projects/own/python-validity
grep -nE "^(class |def )(Minutia|FrameContext|EnrollmentSession|orchestrate|extract_features|_serialize_for_hash|sub_[0-9A-Fa-f]+|stage_[0-9]|cmp_)" validitysensor/moh_native.py
grep -nE "^def (build_v30|subpix_refine_kps|tile_origin_yx|_rotate_sample_pair)\b" validitysensor/moh_native.py
grep -rnE "\b(build_v30|subpix_refine_kps|tile_origin_yx|_rotate_sample_pair|Minutia|FrameContext|EnrollmentSession|orchestrate|extract_features)\b" validitysensor/ scripts/ | grep -v "moh_native.py:"
```
Expected: all three greps print nothing (no scaffold defs remain, no dead-helper defs remain, no external references exist).

- [ ] **Step 5: Run the golden test**

```bash
cd /home/dev/projects/own/python-validity
./.venv-poc/bin/python tests/test_moh_native_golden.py
```
Expected: `ALL GOLDEN CHECKS PASSED`, exit 0. (Deleted symbols are never exercised; `native_template`'s byte-identical envelope confirms `compute_tid`/`_build_envelope` still work after relocation.)

- [ ] **Step 6: Confirm consumers still import**

```bash
cd /home/dev/projects/own/python-validity
./.venv-poc/bin/python -c "from validitysensor import moh_enrollment; import ast; ast.parse(open('scripts/enroll_moh_chip.py').read()); print('imports OK')"
```
Expected: `imports OK` (importing `moh_enrollment` triggers the `from .moh_native import (...)` of all 9 symbols — wait, that import is inside a function in moh_enrollment; instead verify the symbols resolve directly):

```bash
cd /home/dev/projects/own/python-validity
./.venv-poc/bin/python -c "from validitysensor.moh_native import extract_frame_native, native_template, compute_tid, _build_envelope, _load_ws_scaffold, NATIVE_WS_V30_REGIONS, patch_pre_v30_near_identity, serialize_v30_section, V30_DESC_LEN; print('9 symbols OK')"
```
Expected: `9 symbols OK`.

- [ ] **Step 7: Commit**

```bash
cd /home/dev/projects/own/python-validity
git add validitysensor/moh_native.py
git commit -m "refactor(moh_native): delete unused moh_extract RE scaffold + dead helpers

Removes Minutia/FrameContext/orchestrate/EnrollmentSession/sub_* scaffold
(kept compute_tid + _build_envelope) and dead build_v30/subpix_refine_kps/
tile_origin_yx/_rotate_sample_pair. Golden test green.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git push
```

---

### Task 3: Introduce named fixed-point helpers + add the helper-fuzz gate

**Files:**
- Modify: `validitysensor/moh_native.py:149-163` (the `_M32`/`_s32`/`_sar32`/`_idiv32`/`_imul32` block)
- Modify: `tests/test_moh_native_golden.py` (append `test_helper_fuzz`)

- [ ] **Step 1: Add intent-revealing helpers; keep old names as aliases**

Replace the current helper block (the `_M32 = (1 << 32)` ... `_imul32` definitions) with:

```python
# ─── 32-bit fixed-point helpers (x86 imul/sar/idiv semantics) ────────────────
# The DLL does all detector math in signed 32-bit registers. These four helpers
# reproduce that exactly; they are load-bearing only where an intermediate can
# exceed 32 bits (a multiply, or a sum/shift of large response values). Where a
# value provably fits in i32, call sites use plain Python `*`/`>>` instead.
_M32 = 1 << 32


def s32(x):
    """Truncate to signed 32-bit (wrap like an x86 register)."""
    x &= _M32 - 1
    return x - _M32 if x & 0x80000000 else x


def sar32(x, n):
    """Arithmetic right shift of a signed-32-bit value (x86 SAR).
    Equivalent to the old `_sar32(_s32(EXPR), n)` — the inner truncation is
    folded in, so `sar32(EXPR, n)` replaces that whole nested form."""
    return s32(s32(x) >> n)


def mul32(a, b):
    """Low 32 bits of a signed 32-bit product (x86 IMUL r32, r32). Differs from
    plain `a*b` only when the true product overflows i32 — that truncation is
    the behavior, so keep mul32 wherever overflow is possible."""
    return s32(s32(a) * s32(b))


def trunc_div(a, b):
    """Signed division truncating toward zero (x86 IDIV). NOT Python `//`,
    which floors toward -inf and differs for mixed-sign operands."""
    a, b = s32(a), s32(b)
    q = abs(a) // abs(b)
    return -q if (a < 0) ^ (b < 0) else q


# Legacy aliases — removed in the final cleanup task once all call sites migrate.
_s32, _sar32, _imul32, _idiv32 = s32, sar32, mul32, trunc_div
```

- [ ] **Step 2: Append the full-domain helper fuzz to the golden test**

Add this function to `tests/test_moh_native_golden.py` (anywhere above `_run_all`; the runner auto-discovers `test_*`):

```python
def _i32_samples(n, seed):
    rng = np.random.default_rng(seed)
    big = rng.integers(-(1 << 31), 1 << 31, size=n, dtype=np.int64)
    small = rng.integers(-(1 << 16), 1 << 16, size=n, dtype=np.int64)
    edge = np.array([0, 1, -1, (1 << 31) - 1, -(1 << 31), 1 << 30, -(1 << 30),
                     0x800000, -0x800000], dtype=np.int64)
    return np.concatenate([big, small, edge]).tolist()


def test_helper_fuzz():
    """Prove the RETAINED helpers are byte-exact vs the oracle over the full
    i32 domain (incl. overflow), so any call site using them is safe at any
    range. This is the defense-in-depth behind dropping wrappers elsewhere."""
    xs = _i32_samples(40000, 1)
    ys = _i32_samples(40000, 2)
    shifts = [0, 1, 2, 4, 6, 8, 12, 15, 24]
    for k, x in enumerate(xs):
        assert live.s32(x) == frozen._s32(x), f"s32({x})"
        assert live.sar32(x, shifts[k % len(shifts)]) == \
            frozen._sar32(x, shifts[k % len(shifts)]), f"sar32({x})"
    for a, b in zip(xs, ys):
        assert live.mul32(a, b) == frozen._imul32(a, b), f"mul32({a},{b})"
        if frozen._s32(b) != 0:
            assert live.trunc_div(a, b) == frozen._idiv32(a, b), f"trunc_div({a},{b})"
    # atan2 trio — this is where 32-bit overflow actually bites
    for gy, gx in zip(ys, xs):
        assert live._fast_atan2(gy, gx) == frozen._fast_atan2(gy, gx), f"fast_atan2({gy},{gx})"
        assert live._precise_atan2(gx, gy) == frozen._precise_atan2(gx, gy), f"precise_atan2({gx},{gy})"
    for a in _i32_samples(15000, 3):
        assert live._angle_to_bin(a) == frozen._angle_to_bin(a), f"angle_to_bin({a})"
    # kernel builders + Cramer solver over their plausible domains
    for nn in range(2, 16):
        assert live.build_gaussian(nn) == frozen.build_gaussian(nn), f"build_gaussian({nn})"
        assert live.build_3tap(nn, True) == frozen.build_3tap(nn, True)
        assert live.build_3tap(nn, False) == frozen.build_3tap(nn, False)
    rng = np.random.default_rng(7)
    for _ in range(4000):
        coeffs = rng.integers(-(1 << 20), 1 << 20, size=6).tolist()
        assert live._solve_2x2_d4c0(coeffs) == frozen._solve_2x2_d4c0(coeffs), f"solve {coeffs}"
```

- [ ] **Step 3: Run the golden test (now includes fuzz)**

```bash
cd /home/dev/projects/own/python-validity
./.venv-poc/bin/python tests/test_moh_native_golden.py
```
Expected: all four checks `PASS`, including `PASS test_helper_fuzz`, then `ALL GOLDEN CHECKS PASSED`. (The new helpers have identical bodies to the originals, so fuzz passes; aliases keep every existing call site working.)

- [ ] **Step 4: Commit**

```bash
cd /home/dev/projects/own/python-validity
git add validitysensor/moh_native.py tests/test_moh_native_golden.py
git commit -m "refactor(moh_native): add named fixed-point helpers (s32/sar32/mul32/trunc_div) + full-i32 fuzz gate

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git push
```

---

### Task 4: Simplify the kernel builders

**Files:**
- Modify: `validitysensor/moh_native.py` — `gauss_tap`, `build_gaussian`, `build_3tap`

Pattern applied: collapse `_sar32(_s32(EXPR), n)` → `sar32(EXPR, n)` (the inner `_s32` is folded into `sar32`); use `trunc_div` for signed divides (it applies `s32` to its numerator internally, so `0xe0000000` is still treated as negative); rename locals.

- [ ] **Step 1: Replace the three functions**

```python
def gauss_tap(coef, x):
    """One Gaussian tap = EXP_TABLE[quantized -coef*x^2]  (sub_18000FEC0)."""
    t = sar32(coef * x, 2)
    t = sar32(t * x, 8)
    q = (t * 0x51eb851f) >> 35      # signed reciprocal-multiply (divide by ~12.8)
    if q < 0:
        q += 1                       # floor -> truncate toward zero
    i = -(q >> 13)
    return int(EXP_TABLE[min(max(i, 0), len(EXP_TABLE) - 1)])


def build_gaussian(n):
    """Normalized 1-D Gaussian (size n) -> [(offset, tap_Q12)]  (sub_18000FF00)."""
    sigma = sar32(0x26600 * n + 0x59acd, 10)
    coef = trunc_div(0xe0000000, sigma * sigma)     # 0xe0000000 is negative as i32
    taps, total = [], 0
    for i in range(n):
        t = sar32(gauss_tap(coef, 512 * (2 * i - n + 1)), 4)
        taps.append(t)
        total += t
    norm = sar32(trunc_div(0x40000000, total), 3)
    half = n // 2
    return [(i - half, sar32(t * norm, 15)) for i, t in enumerate(taps)]


def build_3tap(scale, deriv):
    """Sparse 3-point kernel at offsets +/-scale  (sub_180010280).
    deriv -> [1024, 0, -1024]; smooth -> [c, round(c*3.33), c]."""
    if deriv:
        return [(-scale, 1024), (0, 0), (scale, -1024)]
    c = trunc_div(0x100000, scale * 0x2aaa)
    mid = sar32(c * 0xd55 + (1 << 9), 10)
    return [(-scale, c), (0, mid), (scale, c)]
```

- [ ] **Step 2: Run the golden test**

```bash
cd /home/dev/projects/own/python-validity
./.venv-poc/bin/python tests/test_moh_native_golden.py
```
Expected: `ALL GOLDEN CHECKS PASSED`. `test_helper_fuzz` exercises `build_gaussian`/`build_3tap` directly; `test_stages_match` exercises `gauss_tap` via `presmooth`/`descriptor_gradient`. If RED: the named assertion identifies the function — restore the wrapped form (`_sar32(_s32(...), n)`) on the offending line and re-run.

- [ ] **Step 3: Commit**

```bash
cd /home/dev/projects/own/python-validity
git add validitysensor/moh_native.py
git commit -m "refactor(moh_native): simplify kernel builders (gauss_tap/build_gaussian/build_3tap)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git push
```

---

### Task 5: Simplify the subpixel solver + refiner

**Files:**
- Modify: `validitysensor/moh_native.py` — `_solve_2x2_d4c0`, `subpix_refine_kp`

Pattern: `_sar32(_s32(X), n)` → `sar32(X, n)`; `_imul32` → `mul32` (products of i32 response values overflow — keep); `_idiv32` → `trunc_div`; `_s32(int(resp[...]))` → `s32(int(resp[...]))` (response values are i64 and DO overflow i32 — keep the truncation); rename `L/R/T/B/cV/TL...` to words.

- [ ] **Step 1: Replace both functions**

```python
def _solve_2x2_d4c0(coeffs):
    """Cramer 2x2 solver -> (dx, dy) or None on singular Hessian (sub_18000D4C0).
    coeffs = [a, b, c, d, e, f] (i32 each)."""
    a, b, c, d, e, f = (sar32(v, 4) for v in coeffs)
    det_pos = sar32(mul32(a, d) - mul32(b, c), 7)
    det_neg = sar32(mul32(b, c) - mul32(a, d), 7)
    if det_pos == 0 or det_neg == 0:
        return None
    num_x = mul32(d, e) - mul32(f, c)
    num_y = mul32(b, e) - mul32(f, a)
    return trunc_div(num_x, det_pos), trunc_div(num_y, det_neg)


def subpix_refine_kp(resp, x_int, y_int, scale_shift=0):
    """Subpixel-refine one integer keypoint via Hessian-Newton (sub_18000D5D0).
    Returns (x_q16, y_q16), or None if the keypoint should be culled (singular
    system, or |delta| > 1 px). scale_shift = ctx[+0x50]+0x60 (0 on 06cb:00a2)."""
    h, w = resp.shape
    if not (1 <= x_int <= w - 2 and 1 <= y_int <= h - 2):
        return None
    center = s32(int(resp[y_int,     x_int]))
    left   = s32(int(resp[y_int,     x_int - 1]))
    right  = s32(int(resp[y_int,     x_int + 1]))
    top    = s32(int(resp[y_int - 1, x_int]))
    bottom = s32(int(resp[y_int + 1, x_int]))
    tl     = s32(int(resp[y_int - 1, x_int - 1]))
    tr     = s32(int(resp[y_int - 1, x_int + 1]))
    bl     = s32(int(resp[y_int + 1, x_int - 1]))
    br     = s32(int(resp[y_int + 1, x_int + 1]))
    dxx = sar32(left + right - 2 * center, 2)
    dyy = sar32(top + bottom - 2 * center, 2)
    dxy = sar32(sar32(br + tl, 2) - sar32(bl + tr, 2), 2)
    dx_neg = sar32(-sar32(right - left, 1), 2)
    dy_neg = sar32(-sar32(bottom - top, 1), 2)
    delta = _solve_2x2_d4c0([dxx, dxy, dxy, dyy, dx_neg, dy_neg])
    if delta is None:
        return None
    dx, dy = delta
    if not (-0x80 <= dx <= 0x80 and -0x80 <= dy <= 0x80):
        return None
    scale_mul = 1 << scale_shift
    x_q16 = (((x_int << 7) + dx) << 9) * scale_mul
    y_q16 = (((y_int << 7) + dy) << 9) * scale_mul
    return x_q16, y_q16
```

- [ ] **Step 2: Run the golden test**

```bash
cd /home/dev/projects/own/python-validity
./.venv-poc/bin/python tests/test_moh_native_golden.py
```
Expected: `ALL GOLDEN CHECKS PASSED`. `test_stages_match` calls `subpix_refine_kp` on every nms keypoint of every tile; `test_helper_fuzz` fuzzes `_solve_2x2_d4c0`. If RED on `subpix ...`: restore the `_sar32(_s32(...))` nesting on the named line.

- [ ] **Step 3: Commit**

```bash
cd /home/dev/projects/own/python-validity
git add validitysensor/moh_native.py
git commit -m "refactor(moh_native): simplify subpix solver + refiner (named coords, folded wrappers)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git push
```

---

### Task 6: De-asm the atan2 trio (rename registers, keep arithmetic)

**Files:**
- Modify: `validitysensor/moh_native.py` — `_fast_atan2`, `_precise_atan2`, `_angle_to_bin`

These keep the exact polynomial and magic constants (load-bearing); only the register variables (`eax`/`ecx`/`edx`/`r8d`/`r9d`/`r10d`/`r11d`) become meaningful names, plus docstrings. Function names are unchanged (the test pins them).

- [ ] **Step 1: Replace the three functions**

```python
def _fast_atan2(gy_in, gx_in):
    """Fixed-point atan2 (sub_1800030A0). Args are (y, x). Returns an angle on
    a ~2*pi*65086 full-circle scale. Method: evaluate a cubic-polynomial arctan
    on the (smaller/larger) magnitude ratio in [0, 1], then fold by octant and
    quadrant using the sign branches."""
    gx = s32(gx_in)
    gy = s32(gy_in)
    abs_gx = gx if gx > 0 else s32(-gx)
    abs_gy = gy if gy > 0 else s32(-gy)
    small, large = (abs_gx, abs_gy) if abs_gx < abs_gy else (abs_gy, abs_gx)
    large = s32(large + 1)
    small = s32(small << 8)
    if large == 0:
        return 0
    q = abs(small) // abs(large)
    ratio = s32(-q if (small < 0) ^ (large < 0) else q)
    ratio = s32(ratio << 8)
    t = sar32(ratio, 4)                # arctan argument
    t2 = sar32(ratio, 6)
    t2 = mul32(t2, t2)
    t2 = sar32(sar32(t2, 4), 4)        # t^2 in the polynomial's working scale
    poly = sar32(mul32(t2, 0xFFFFF5D7), 12); poly = s32(poly + 0x23A7)
    poly = sar32(mul32(poly, t2), 12);       poly = s32(poly - 0x4AAC)
    poly = sar32(mul32(poly, t2), 12);       poly = s32(poly + 0xE522)
    angle = sar32(mul32(poly, t), 6)
    if abs_gx < abs_gy:                # reflect across the 45-degree octant line
        angle = s32(0x5A0000 - angle)
    if gx < 0:                         # x-quadrant fold
        angle = s32(0xB40000 - angle)
    if gy < 0:                         # y-quadrant fold
        angle = s32(0x1680000 - angle)
    angle = sar32(angle, 8)
    angle = mul32(angle, 0x47)         # rescale into the cos/sin table's units
    return sar32(angle, 4)


def _precise_atan2(gx, gy):
    """4-quadrant atan2 in [0, 2*pi*65536) (sub_180003150). 0x3243F = pi*65536,
    0x6487E ~= 2*pi*65536. Returns the orient_q16 stored at kp[+0xc]."""
    gx = s32(gx)
    gy = s32(gy)
    if gx >= 0:
        return _fast_atan2(gy, gx) if gy >= 0 else s32(0x6487E - _fast_atan2(-gy, gx))
    if gy >= 0:
        return s32(0x3243F - _fast_atan2(gy, -gx))
    return s32(0x3243F + _fast_atan2(-gy, -gx))


def _angle_to_bin(ang):
    """bin ~= angle / 9830, truncating toward zero, via a signed reciprocal-
    multiply (DLL: `imul 0x6AAAAABD; sar edx,24; add sign-bit`)."""
    shifted = s32((s32(ang) << 12) & 0xFFFFFFFF)
    hi = (s32(shifted) * 0x6AAAAABD >> 32) & 0xFFFFFFFF   # high 32 bits of the product
    if hi & 0x80000000:
        hi -= 0x100000000
    b = sar32(hi, 24)
    return s32(b + (1 if b < 0 else 0))
```

- [ ] **Step 2: Run the golden test**

```bash
cd /home/dev/projects/own/python-validity
./.venv-poc/bin/python tests/test_moh_native_golden.py
```
Expected: `ALL GOLDEN CHECKS PASSED`. `test_helper_fuzz` fuzzes all three over the full i32 domain (incl. overflow); `test_stages_match` exercises them via `orient_d920`/`desc_sample_rotate`. A rename slip surfaces immediately as `FAIL test_helper_fuzz: fast_atan2(...)`.

- [ ] **Step 3: Commit**

```bash
cd /home/dev/projects/own/python-validity
git add validitysensor/moh_native.py
git commit -m "refactor(moh_native): de-asm atan2 trio (meaningful names + docstrings, arithmetic frozen)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git push
```

---

### Task 7: Simplify the orientation pass

**Files:**
- Modify: `validitysensor/moh_native.py` — `orient_d920`

Pattern: `_imul32` → `mul32` (grad*weight overflows — keep), `_sar32` → `sar32`, `_s32` → `s32`. Structure/comments preserved.

- [ ] **Step 1: Replace the function body's arithmetic helper calls**

```python
def orient_d920(gradX, gradY, subpix_x_q16, subpix_y_q16):
    """Dominant-gradient orientation, byte-exact reproduction of sub_18000D920's
    kp[+0xc] orient_q16. gradX/gradY are the i32 first-derivative buffers; the
    subpix coords are kp[+0x14,+0x18] in Q16. Returns the i32 orient_q16."""
    W = gradX.shape[1]
    H = gradX.shape[0]
    cx = (subpix_x_q16 + 0x8000) >> 16     # rounded, not truncated
    cy = (subpix_y_q16 + 0x8000) >> 16
    H_gx = [0] * 42
    H_gy = [0] * 42
    for dy in range(-6, 7):
        for dx in range(-6, 7):
            if dy * dy + dx * dx >= 36:     # circular mask, radius 6
                continue
            y = cy + dy
            x = cx + dx
            if not (0 <= y < H and 0 <= x < W):
                continue
            weight = int(GAUSS_Q[abs(dy), abs(dx)])
            ggx = sar32(mul32(s32(int(gradX[y, x])) >> 10, weight), 4)
            ggy = sar32(mul32(s32(int(gradY[y, x])) >> 10, weight), 4)
            b = _angle_to_bin(_fast_atan2(ggy, ggx))
            for k in range(7):              # 7-bin smear: bin-6 .. bin
                sb = (b + 36 + k) % 42
                H_gx[sb] = s32(H_gx[sb] + ggx)
                H_gy[sb] = s32(H_gy[sb] + ggy)
    maxbin = 0
    maxmag = 0
    for i in range(42):
        a = sar32(H_gx[i], 13)
        b = sar32(H_gy[i], 13)
        m = s32(mul32(a, a) + mul32(b, b))
        if m > maxmag:
            maxmag = m
            maxbin = i
    return _precise_atan2(sar32(H_gx[maxbin], 10), sar32(H_gy[maxbin], 10))
```

- [ ] **Step 2: Run the golden test**

```bash
cd /home/dev/projects/own/python-validity
./.venv-poc/bin/python tests/test_moh_native_golden.py
```
Expected: `ALL GOLDEN CHECKS PASSED`. `test_stages_match` compares `orient_d920` on every surviving keypoint; `test_extract_frame_native_e2e` compares the resulting `orient_q16` field. If RED on `orient ...`: a wrapper was over-dropped — restore `mul32`/`s32` on the named line.

- [ ] **Step 3: Commit**

```bash
cd /home/dev/projects/own/python-validity
git add validitysensor/moh_native.py
git commit -m "refactor(moh_native): simplify orient_d920 helper calls (named vars, mul32 kept on grad*weight)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git push
```

---

### Task 8: Simplify the descriptor rotate/sample stage

**Files:**
- Modify: `validitysensor/moh_native.py` — `desc_sample_rotate`

Remove the function-local `_s32` redefinition (use the module `s32`), name variables, and preserve the exact NEG-then-SAR ordering on the rotated_gy term (the original comment warns `(-v)>>8 != -(v>>8)`). `desc_aggregate` is already clean numpy — leave it (light comment only if desired).

- [ ] **Step 1: Replace `desc_sample_rotate`**

```python
def desc_sample_rotate(grad_x, grad_y, subpix_x_q16, subpix_y_q16, orient_idx,
                       N=7):
    """E090 rotation+sampling (stage 1). Returns two int32 arrays of length
    (2N+2)^2 (256 for N=7): the rotated_gx/rotated_gy buffers the aggregation
    stage sums over.

    Storage is COLUMN-MAJOR (xL outer, yL inner): index = (xL+N)*(2N+2)+(yL+N).
    Out-of-bounds samples read mid-gray (0x800000). The rotated_gy term mirrors
    the DLL's `NEG ecx; SAR ecx,8` (e413/e415): negate the full product FIRST,
    then arithmetic-shift, which differs from -(v>>8) by one for non-multiples
    of 256 — so it is reproduced exactly here."""
    stride = grad_x.shape[1]
    height = grad_x.shape[0]
    cos_q = int(COS_Q16[orient_idx])
    sin_q = int(SIN_Q16[orient_idx])
    span = 2 * N + 2                                   # = 16 for N=7
    rgx = np.zeros(span * span, dtype=np.int64)
    rgy = np.zeros(span * span, dtype=np.int64)

    for xi in range(span):                             # outer = xL
        xL = xi - N
        for yi in range(span):                         # inner = yL
            yL = yi - N
            px = (subpix_x_q16 + xL * cos_q - yL * sin_q + 0x8000) >> 16
            py = (subpix_y_q16 + xL * sin_q + yL * cos_q + 0x8000) >> 16
            if 0 <= px < stride and 0 <= py < height:
                gx = int(grad_x[py, px])
                gy = int(grad_y[py, px])
            else:
                gx = gy = 0x800000
            gx8 = gx >> 8
            gy8 = gy >> 8
            rx = (s32(cos_q * gx8) >> 8) + (s32(sin_q * gy8) >> 8)
            ry = (s32(cos_q * gy8) >> 8) + (s32(-(sin_q * gx8)) >> 8)
            idx = xi * span + yi
            rgx[idx] = s32(rx)
            rgy[idx] = s32(ry)
    return rgx.astype(np.int32), rgy.astype(np.int32)
```

- [ ] **Step 2: Run the golden test**

```bash
cd /home/dev/projects/own/python-validity
./.venv-poc/bin/python tests/test_moh_native_golden.py
```
Expected: `ALL GOLDEN CHECKS PASSED`. `test_stages_match` compares `desc_sample_rotate` arrays per keypoint; e2e compares the final descriptor bytes. If RED on `desc_sample_rotate ...`: the `ry` NEG-then-SAR form was altered — restore `(s32(-(sin_q * gx8)) >> 8)` exactly.

- [ ] **Step 3: Commit**

```bash
cd /home/dev/projects/own/python-validity
git add validitysensor/moh_native.py
git commit -m "refactor(moh_native): simplify desc_sample_rotate (drop local _s32 dup, name vars; keep NEG-then-SAR)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git push
```

---

### Task 9: Remove legacy aliases + final cleanup and verification

**Files:**
- Modify: `validitysensor/moh_native.py`

- [ ] **Step 1: Confirm no remaining users of the legacy alias names**

```bash
cd /home/dev/projects/own/python-validity
grep -nE "\b_s32\b|\b_sar32\b|\b_imul32\b|\b_idiv32\b" validitysensor/moh_native.py
```
Expected: only the alias-definition line `_s32, _sar32, _imul32, _idiv32 = s32, sar32, mul32, trunc_div`. If any other line matches, migrate it to the new name first (and re-run the golden test) before deleting the aliases.

- [ ] **Step 2: Delete the alias line and prune now-unused imports**

Remove the line:
```python
# Legacy aliases — removed in the final cleanup task once all call sites migrate.
_s32, _sar32, _imul32, _idiv32 = s32, sar32, mul32, trunc_div
```
Then prune the top-of-file imports that the deleted scaffold used. Check each before removing:

```bash
cd /home/dev/projects/own/python-validity
grep -nE "\bdataclass\b|\bfield\b|\bList\b|\bOptional\b|\bTuple\b|\bunpack\b" validitysensor/moh_native.py
```
For any of `dataclass`, `field`, `List`, `Optional`, `Tuple`, `unpack` that now appear ONLY on their import line, remove them from the imports. (Keep `pack` — `_build_envelope` uses it. Keep `numpy`, `hashlib`, `hmac`, `logging`.) Update the imports to exactly what remains used, e.g.:
```python
from struct import pack
```
(and drop `from dataclasses import dataclass, field` and the now-unused `typing` names entirely if unused).

- [ ] **Step 3: Run the golden test**

```bash
cd /home/dev/projects/own/python-validity
./.venv-poc/bin/python tests/test_moh_native_golden.py
```
Expected: `ALL GOLDEN CHECKS PASSED`.

- [ ] **Step 4: Final assertions — no asm-isms remain, API intact, file shrank, module imports clean**

```bash
cd /home/dev/projects/own/python-validity
echo "--- no sub_/register-style names remain ---"
grep -nE "\bsub_[0-9A-Fa-f]{6,}\b|\b(eax|ecx|edx|r8d|r9d|r10d|r11d|ecx_tan|buf20|buf28)\b" validitysensor/moh_native.py || echo "none (good)"
echo "--- 9 exported symbols still resolve ---"
./.venv-poc/bin/python -c "from validitysensor.moh_native import extract_frame_native, native_template, compute_tid, _build_envelope, _load_ws_scaffold, NATIVE_WS_V30_REGIONS, patch_pre_v30_near_identity, serialize_v30_section, V30_DESC_LEN; print('9 symbols OK')"
echo "--- module byte-compiles ---"
./.venv-poc/bin/python -c "import py_compile; py_compile.compile('validitysensor/moh_native.py', doraise=True); print('compiles OK')"
echo "--- line count (was 1742) ---"
wc -l validitysensor/moh_native.py
```
Expected: `none (good)` (note: `sub_XXXX` references inside docstrings/comments are acceptable as RE provenance — the grep targets identifiers; if it matches only comment text, that is fine, judge by context), `9 symbols OK`, `compiles OK`, and a line count well below 1742 (roughly ~1050–1150 after deleting the ~580-line scaffold and dead helpers).

- [ ] **Step 5: Commit**

```bash
cd /home/dev/projects/own/python-validity
git add validitysensor/moh_native.py
git commit -m "refactor(moh_native): drop legacy fixed-point aliases + prune unused imports

moh_native.py is now plain readable Python with byte-identical output, pinned
by tests/test_moh_native_golden.py against the frozen oracle.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git push
```

- [ ] **Step 6 (optional, user-run on hardware): confirm a live enrollment still works**

Not required for correctness — the golden test already proves `native_template` output is byte-identical, and identical bytes enroll identically — but as belt-and-suspenders the user may run:
```bash
sudo ./.venv-poc/bin/python scripts/enroll_moh_chip.py --dry-run
```
Expected: writes `/tmp/native_envelope.bin`; its bytes match a pre-refactor dry-run for the same captured frame.

---

## Self-Review

**Spec coverage:**
- "byte-identical output" → Tasks 1 (e2e byte compare) + standing gate on every task. ✓
- "frozen oracle, kept permanently" → Task 1 (create) + never deleted. ✓
- "golden test: e2e + per-stage + full-i32 fuzz" → Task 1 (e2e + stages), Task 3 (fuzz). ✓
- "simplify where proven safe; keep truncation where overflow possible" → Tasks 4–8 each note which wrappers stay (mul32 on grad*weight, s32 on i64 response reads, NEG-then-SAR) vs collapse. ✓
- "_idiv32 never becomes bare //" → Task 3 defines `trunc_div`; Tasks 4–5 use it. ✓
- "rename register vars in atan2 trio, arithmetic frozen" → Task 6. ✓
- "delete scaffold except compute_tid/_build_envelope/_TID_INFO; delete build_v30/subpix_refine_kps/tile_origin_yx/_rotate_sample_pair" → Task 2. ✓
- "9 exported symbols unchanged" → verified in Tasks 2 and 9. ✓
- "no sub_XXXX names / register vars remain; file shorter" → Task 9 Step 4. ✓

**Placeholder scan:** The only `<<paste ...>>` markers are in Task 2, deliberately instructing the engineer to copy three unchanged blocks out of the current file rather than risk transcription errors — each is pinpointed by exact symbol name and first/last line. No TODO/TBD/"handle edge cases" remain.

**Type/name consistency:** Helper names `s32`/`sar32`/`mul32`/`trunc_div` are defined in Task 3 and used identically in Tasks 4–8. Stage function names (`presmooth`, `doh`, `nms`, `subpix_refine_kp`, `orient_d920`, `desc_sample_rotate`, `desc_aggregate`, `brief_pack`, `_fast_atan2`, `_precise_atan2`, `_angle_to_bin`) are never renamed, so the golden test references stay valid throughout. `_WIN_SIZES` and `_load_aggr_table` referenced in the test exist in the module.
