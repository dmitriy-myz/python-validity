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
