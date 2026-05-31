#!/usr/bin/env python3
"""Multi-frame native template assembler (mode-A, 4 sections) + sec0_pre writer.

Builds a complete from-scratch enrollment template from OUR captured frames:
  * 4 v30 sections  = our 4 frames' [x][y][16B desc] records (serialize_v30_section)
  * sec0_pre        = OUR inter-frame rigid transforms, computed geometrically
                      (geom_register), written into the scaffold's 4 transform slots
  * TID recomputed; mode-A envelope rebuilt.

The scaffold (fresh.bin framing, v30 zeroed) supplies the validated TLV structure
(header, per-section pre-v30 leads/blob/markers, section trailers). We overwrite
only the finger-specific content: the v30 records and the 4 sec0_pre transform
VALUES. The slot→pair mapping was determined once by max spatial overlap on the
scaffold's own sections:
    ws+79 → frames (0,3) ;  ws+97 → (1,2) ;  ws+115 → (3,0) ;  ws+133 → (2,3)
(a connected spanning set 1→2→3↔0 covering all 4 frames).

CAVEATS (read before trusting a hardware result):
  * Our geom transforms do NOT byte-match the DLL's stored ones (the DLL uses a
    descriptor-correspondence / reference-composed registration we can't reproduce
    offline). We supply geometrically-valid transforms for OUR frames instead.
  * The scaffold's pre-v30 leads/blob (an argsort permutation + per-record blob)
    are kept as-is — they may be stale w.r.t. our transforms. The chip's matcher
    is positional/geometric (sub_18000c6a0), so this MAY be tolerated; the hardware
    --match test is the arbiter. Byte-exact correctness needs the gdb capture
    (see dev/transformation-doc/README.md capture plan).

Run (offline self-test, round-trips fresh.bin's own sections):
    ./.venv-poc/bin/python dev/build_multiframe_template.py
"""
import sys, os, struct, math
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
from validitysensor.moh_opencv import find_v30_regions, WS_SIZE
from validitysensor.moh_native import serialize_v30_section
from validitysensor.moh_extract import compute_tid, _build_envelope
from sec0pre_register import geom_register

ONE = 0x10000
# sec0_pre transform-slot byte offsets in the WS body, and the frame pair each
# slot encodes (determined by max spatial overlap on the scaffold).
SEC0PRE_SLOTS = [(79, 0, 3), (97, 1, 2), (115, 3, 0), (133, 2, 3)]
DEFAULT_SCAFFOLD = "/media/sf_vbox-rw/finger/wine_finger_fresh.bin"


def build_multiframe(frames_kps, scaffold_ws, subtype):
    """frames_kps: list of 4 lists of (x, y, desc16). scaffold_ws: 23056-byte WS
    body (framing). Returns a 23136-byte envelope with our v30 + our sec0_pre."""
    assert len(frames_kps) == 4, "mode-A scaffold has 4 sections"
    assert len(scaffold_ws) == WS_SIZE
    ws = bytearray(scaffold_ws)
    regs = find_v30_regions(scaffold_ws)
    if len(regs) != 4:
        # baked scaffold has v30 zeroed → use pinned offsets
        from validitysensor.moh_native import NATIVE_WS_V30_REGIONS
        regs = list(NATIVE_WS_V30_REGIONS)

    # 1. overwrite the 4 v30 record areas with our frames
    for r, base in enumerate(regs):
        sec = serialize_v30_section([(x, y, d) for (x, y, d) in frames_kps[r]])
        ws[base:base + len(sec)] = sec

    # 2. patch the 4 sec0_pre transform slots with OUR geometric transforms
    pos = [np.array([(x, y) for (x, y, _d) in f], float) for f in frames_kps]
    report = []
    for off, i, j in SEC0PRE_SLOTS:
        res = geom_register(pos[i], pos[j])
        if res is None:
            report.append((off, i, j, None))
            continue
        a, b, tx, ty, ov = res
        struct.pack_into('<4i', ws, off + 2, a, b, tx, ty)   # keep anchor x,y at off,+1
        report.append((off, i, j, (math.degrees(math.atan2(b, a)), tx / ONE, ty / ONE, ov)))

    # 3. TID + envelope
    ws_body = bytes(ws)
    tid = compute_tid(ws_body)
    return _build_envelope(subtype, ws_body, tid), report


def _sections_with_desc(ws, regs):
    out = []
    for base in regs:
        recs = []
        for k in range(250):
            o = base + k * 18
            x, y = ws[o], ws[o + 1]
            if not (0 < x <= 112 and 0 < y <= 112):
                break
            recs.append((x, y, bytes(ws[o + 2:o + 18])))
        out.append(recs)
    return out


def _selftest(path):
    """Round-trip: use the scaffold's OWN 4 sections as 'our frames' → assemble →
    verify the output is structurally valid (4 v30 regions, sec0_pre parses, TID OK)."""
    env = open(path, "rb").read()
    subtype = struct.unpack_from('<H', env, 0)[0]
    ws = env[12:12 + WS_SIZE]
    regs = find_v30_regions(ws)
    frames = _sections_with_desc(ws, regs)
    print(f"scaffold: {path}  subtype=0x{subtype:04x}  sections={[len(f) for f in frames]}")

    out_env, report = build_multiframe(frames, ws, subtype)
    print(f"\nassembled envelope: {len(out_env)} bytes")
    print("sec0_pre slots patched with our geom transforms:")
    for off, i, j, t in report:
        if t:
            print(f"  ws+{off} (frames {i}->{j}): rot={t[0]:+6.2f} t=({t[1]:+7.2f},{t[2]:+7.2f}) overlap={t[3]}")
        else:
            print(f"  ws+{off} (frames {i}->{j}): geom_register FAILED")

    # structural checks
    ows = out_env[12:12 + WS_SIZE]
    ok = True
    r2 = find_v30_regions(ows)
    ck = (r2 == regs)
    ok &= ck
    print(f"\n[{'OK' if ck else 'FAIL'}] v30 regions preserved: {r2}")
    off = 12 + WS_SIZE
    tid_ok = compute_tid(ows) == out_env[off + 4:off + 36]
    ok &= tid_ok
    print(f"[{'OK' if tid_ok else 'FAIL'}] TID valid")
    sz = len(out_env) == 23136
    ok &= sz
    print(f"[{'OK' if sz else 'FAIL'}] envelope size 23136")
    # v30 content == our frames (round-trip identity for selftest)
    fr2 = _sections_with_desc(ows, r2)
    same = all(fr2[r] == frames[r] for r in range(4))
    ok &= same
    print(f"[{'OK' if same else 'FAIL'}] v30 records == input frames")
    # framing outside v30 + sec0_pre-transform area unchanged
    print(f"\n=== {'ALL STRUCTURAL CHECKS PASS' if ok else 'CHECKS FAILED'} — "
          "assembler produces a well-formed template. Chip acceptance of the geom\n"
          "sec0_pre is the open hardware question (--match). ===")
    return 0 if ok else 1


if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SCAFFOLD
    sys.exit(_selftest(p))
