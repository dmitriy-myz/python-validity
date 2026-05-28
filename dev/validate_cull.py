"""Validate the A960 + 250-cap + tile_id re-sort port against the captured
2026-05-28 combined GDB session.

Approach: for each of the 9 frame-0 tiles, load nms_kp + nms_resp captures.
Simulate phases 1+2+3 of extract_frame_native (without descriptor gradients,
since we don't need them for the count check). Compare per-tile survivor
counts to actual orient_before subrun sizes [29, 27, 17, 33, 36, 33, 30, 26, 19].

This isolates the cull stage (A960 + cap + re-sort) from the upstream stages
(doh, nms, subpix) and the downstream stages (D920, E090).

Run:
  ./.venv-poc/bin/python dev/validate_cull.py
"""
import os, sys, glob, struct, re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from validitysensor.moh_native import (
    FRAME_KP_CAP, GRID, _a960_passes_global_edge, subpix_refine_kp,
    tile_origin,
)
import numpy as np

DUMP = os.environ.get('FRIDA_DUMP_DIR', '/media/sf_vbox-rw/finger/frida_dumps')
EXPECTED = [29, 27, 17, 33, 36, 33, 30, 26, 19]


def _shape(p):
    m = re.search(r'_(\d+)x(\d+)\.bin$', os.path.basename(p))
    return int(m.group(1)), int(m.group(2))


def _ts(p, k):
    m = re.search(rf'{k}_(\d+)_', os.path.basename(p))
    return int(m.group(1)) if m else 0


def _load_nms_kps(call_idx):
    p = glob.glob(os.path.join(DUMP, f'nms_kp_*_call{call_idx}_n*.bin'))[0]
    raw = open(p, 'rb').read()
    return [struct.unpack_from('<8i', raw, i * 32) for i in range(len(raw) // 32)]


def _load_nms_resp(call_idx):
    p = glob.glob(os.path.join(DUMP, f'nms_resp_*_call{call_idx}_*x*.bin'))[0]
    w, h = _shape(p)
    resp = np.frombuffer(open(p, 'rb').read(), dtype=np.int32).reshape(h, w)
    return resp, w, h


def main():
    pool = []   # list of (score, tile_id, ti, tj, sx_q16, sy_q16)
    h_frame = w_frame = 112  # 06cb:00a2 default

    print('Phase 1: per-tile NMS + subpix + A960 edge filter')
    for call_idx in range(9):
        i, j = divmod(call_idx, 3)
        resp, w, h = _load_nms_resp(call_idx)
        oy, ox = tile_origin(i, j, h_frame, w_frame)
        n_kept = n_culled_d5d0 = n_culled_a960 = 0
        cf90_records = _load_nms_kps(call_idx)
        for rec in cf90_records:
            score, x_int, y_int = rec[4], rec[5], rec[6]
            sub = subpix_refine_kp(resp, x_int, y_int)
            if sub is None:
                n_culled_d5d0 += 1
                continue
            sx_q16, sy_q16 = sub
            if not _a960_passes_global_edge(sx_q16, sy_q16, oy, ox, h_frame, w_frame):
                n_culled_a960 += 1
                continue
            pool.append((score, call_idx, i, j, sx_q16, sy_q16))
            n_kept += 1
        print(f'  Tile {call_idx} ({w}x{h}) origin=({oy},{ox}): '
              f'CF90={len(cf90_records)}  D5D0_cull={n_culled_d5d0}  '
              f'A960_cull={n_culled_a960}  pool+={n_kept}')

    print(f'\nPhase 2: global resp-desc sort + cap to {FRAME_KP_CAP}')
    pool.sort(key=lambda r: -r[0])
    pool = pool[:FRAME_KP_CAP]
    print(f'  Pool size after cap: {len(pool)}')

    print(f'\nPhase 3: re-sort by (tile_id ASC, resp DESC)')
    pool.sort(key=lambda r: (r[1], -r[0]))

    print(f'\nPer-tile survivor counts:')
    from collections import Counter
    per_tile = Counter(r[1] for r in pool)
    ok = True
    for ti in range(9):
        exp = EXPECTED[ti]
        got = per_tile.get(ti, 0)
        mark = 'OK' if got == exp else f'OFF by {got-exp:+d}'
        if got != exp:
            ok = False
        print(f'  Tile {ti}: predicted={got:3d}  actual={exp:3d}  {mark}')

    print(f'\n{"PASS" if ok else "DRIFT (likely subpix-edge wobble — see hypothesis)"}')


if __name__ == '__main__':
    main()
