#!/usr/bin/env python3
"""Verify native enrollment is REFERENCE-FREE and byte-faithful.

`native_template(image, reference_template=None)` must build a complete,
chip-shaped 23136-byte envelope using the baked-in WS-body scaffold
(validitysensor/native_ws_scaffold.bin) — NO captured reference template.

Checks (no hardware, no real finger needed):
  1. The baked scaffold is 23056 B and its 4 pinned v30 regions are zeroed.
  2. native_template(img, None) returns a well-formed 23136-B envelope whose
     framing (every byte OUTSIDE the 4 v30 record areas) is byte-identical to
     the genuine chip-accepted fresh.bin — i.e. we touch ONLY the v30 records.
  3. Each v30 region holds our 250×18 records (ours first, zero-padded).
  4. The envelope TID validates: compute_tid(ws_body) == envelope[23072:23104].
  5. Regression: passing reference_template=fresh.bin still works (find_v30_
     regions locates the same 4 regions; framing == fresh outside v30).
  6. Real-pipeline smoke test: a synthetic textured image runs end-to-end
     through native_template(img, None) and yields a valid envelope.

Run: ./.venv-poc/bin/python dev/verify_reference_free.py
"""
import os, sys, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np
from validitysensor import moh_native as M
from validitysensor.moh_native import (native_template, _load_ws_scaffold,
                                        NATIVE_WS_V30_REGIONS, serialize_v30_section)
from validitysensor.moh_extract import compute_tid
from validitysensor.moh_opencv import WS_SIZE, find_v30_regions

FRESH = "/media/sf_vbox-rw/finger/wine_finger_fresh.bin"
SPAN = 250 * 18   # 4500-byte v30 record area
fails = []


def check(cond, msg):
    print(("  OK  " if cond else " FAIL ") + msg)
    if not cond:
        fails.append(msg)


def framing_mask(ws):
    """ws bytes with the 4 v30 record areas zeroed (compare framing only)."""
    m = bytearray(ws)
    for base in NATIVE_WS_V30_REGIONS:
        for i in range(base, base + SPAN):
            m[i] = 0
    return bytes(m)


def fake_kps(n=200):
    """Deterministic stand-in for extract_frame_native — exercises the wiring
    without depending on a real image. (x, y, orient_q16, desc_16B)."""
    out = []
    for i in range(n):
        x = 3 + (i % 100)
        y = 3 + ((i * 7) % 100)
        desc = bytes(((i * 13 + j * 7) & 0xFF) for j in range(16))
        out.append((x, y, 0, desc))
    return out


def main():
    scaffold = _load_ws_scaffold()
    print(f"scaffold: {len(scaffold)}B  pinned v30 regions: {NATIVE_WS_V30_REGIONS}")

    # 1. scaffold shape + zeroed v30 areas
    check(len(scaffold) == WS_SIZE, f"scaffold is {WS_SIZE}B")
    for base in NATIVE_WS_V30_REGIONS:
        z = all(b == 0 for b in scaffold[base:base + SPAN])
        check(z, f"scaffold v30 region @{base} is zeroed ({SPAN}B)")

    fresh = open(FRESH, "rb").read()
    fresh_ws = fresh[12:12 + WS_SIZE]
    # scaffold framing must equal fresh framing (scaffold = fresh w/ v30 zeroed)
    check(framing_mask(scaffold) == framing_mask(fresh_ws),
          "scaffold framing == fresh.bin framing (outside v30)")

    # 2-4. reference-free build with deterministic kps
    recs = fake_kps(200)
    M.extract_frame_native = lambda *a, **k: recs   # monkeypatch the detector
    env = native_template(np.zeros((112, 112), dtype=np.int32), None)
    check(len(env) == 23136, f"reference-free envelope is 23136B (got {len(env)})")
    check(struct.unpack_from('<H', env, 2)[0] == 3, "version == 3")
    check(struct.unpack_from('<HH', env, 8) == (1, WS_SIZE), "TLV1 header (1, 23056)")

    ws = env[12:12 + WS_SIZE]
    # framing identical to fresh.bin outside v30 regions
    check(framing_mask(ws) == framing_mask(fresh_ws),
          "reference-free framing == fresh.bin (only v30 areas changed)")

    # each region carries OUR records (ours first, zero-padded)
    expect = serialize_v30_section([(x, y, d) for (x, y, _o, d) in recs])
    for base in NATIVE_WS_V30_REGIONS:
        check(ws[base:base + SPAN] == expect,
              f"region @{base} == our 250-slot v30 section")

    # TID validates
    off = 12 + WS_SIZE
    check(struct.unpack_from('<HH', env, off) == (2, 32), "TLV2 header (2, 32)")
    check(compute_tid(ws) == env[off + 4:off + 36], "envelope TID == compute_tid(ws)")

    # 5. regression — explicit reference still works
    env2 = native_template(np.zeros((112, 112), dtype=np.int32), fresh)
    ws2 = env2[12:12 + WS_SIZE]
    regions2 = find_v30_regions(fresh_ws)
    check(regions2 == list(NATIVE_WS_V30_REGIONS),
          f"find_v30_regions(fresh) == pinned offsets (got {regions2})")
    check(framing_mask(ws2) == framing_mask(fresh_ws),
          "ref-given framing == fresh.bin (regression)")
    check(compute_tid(ws2) == env2[off + 4:off + 36], "ref-given TID validates")

    # 6. real-pipeline smoke test (restore the real detector first)
    import importlib
    importlib.reload(M)
    from validitysensor.moh_native import native_template as nt_real
    rng = np.random.RandomState(1234)
    yy, xx = np.mgrid[0:112, 0:112]
    ridges = 128 + 70 * np.sin(xx / 3.0 + 2.0 * np.sin(yy / 9.0))
    img = np.clip(ridges + rng.randint(-12, 12, (112, 112)), 0, 255).astype(np.int32)
    img_q16 = img << 16
    env3 = nt_real(img_q16, None)
    n_rec0 = sum(1 for i in range(250)
                 if 0 < env3[12 + NATIVE_WS_V30_REGIONS[0] + i * 18] <= 112)
    check(len(env3) == 23136, f"real-pipeline reference-free envelope 23136B "
                              f"({n_rec0} kp records in section 0)")
    check(compute_tid(env3[12:12 + WS_SIZE]) == env3[off + 4:off + 36],
          "real-pipeline TID validates")

    print()
    if fails:
        print(f"=== {len(fails)} CHECK(S) FAILED ===")
        for f in fails:
            print("  -", f)
        return 1
    print("=== ALL CHECKS PASSED — native enrollment is reference-free ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
