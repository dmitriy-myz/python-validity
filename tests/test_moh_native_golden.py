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
    # Register before exec_module: the frozen oracle defines an @dataclass with a
    # forward-reference annotation, and dataclasses looks the module up in
    # sys.modules during class construction. Without this the load raises
    # AttributeError on 'NoneType'. This is harness wiring only; it does not
    # affect the live-vs-frozen byte comparison.
    sys.modules[spec.name] = mod
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
            for (_sc, lx, ly) in kpsO:
                aN = live.subpix_refine_kp(resp, lx, ly)
                aO = frozen.subpix_refine_kp(resp, lx, ly)
                assert aN == aO, f"subpix {name} {i},{j} ({lx},{ly})"
                if aO is None:
                    continue
                sx, sy = aO
                oO = frozen.orient_d920(gxO, gyO, sx, sy)
                assert live.orient_d920(gxO, gyO, sx, sy) == oO, f"orient {name} {i},{j}"
                idx = frozen.orient_to_index(oO) % 360
                rgxN, rgyN = live.desc_sample_rotate(gxO, gyO, sx, sy, idx)
                rgxO, rgyO = frozen.desc_sample_rotate(gxO, gyO, sx, sy, idx)
                assert np.array_equal(rgxN, rgxO) and np.array_equal(rgyN, rgyO), \
                    f"desc_sample_rotate {name} {i},{j}"
                aggN = live.desc_aggregate(rgxO, rgyO, live._load_aggr_table(), live._WIN_SIZES)
                aggO = frozen.desc_aggregate(rgxO, rgyO, frozen._load_aggr_table(), frozen._WIN_SIZES)
                assert np.array_equal(aggN, aggO), f"desc_aggregate {name} {i},{j}"
                assert np.array_equal(live.brief_pack(aggO), frozen.brief_pack(aggO)), \
                    f"brief_pack {name} {i},{j}"


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


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS {fn.__name__}")
        except Exception as e:
            failed += 1
            print(f"  FAIL {fn.__name__}: {type(e).__name__}: {e}")
    if failed:
        print(f"{failed} CHECK(S) FAILED")
        sys.exit(1)
    print("ALL GOLDEN CHECKS PASSED")


if __name__ == "__main__":
    _run_all()
