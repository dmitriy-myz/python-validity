"""Per-kp subpix Q16 diff: my port's subpix vs captured orient_before.

Hypothesis being tested: 40 of 240 matched-gx descriptors differ. Likely
because subpix Q16 values diverge even when integer gx matches. This
script computes my port's subpix from scratch (doh + nms + subpix_refine)
on each captured F250 tile and compares to captured orient_before's
sx/sy at +0x14/+0x18.
"""
import os, sys, glob, struct, re
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from validitysensor.moh_native import (
    tile_origin, doh, nms, subpix_refine_kp, _a960_passes_global_edge,
)

DUMP = os.environ.get('FRIDA_DUMP_DIR', '/media/sf_vbox-rw/finger/frida_dumps')


def _shape(p):
    m = re.search(r'_(\d+)x(\d+)\.bin$', os.path.basename(p)); return int(m.group(1)), int(m.group(2))


def _ts(p, k):
    m = re.search(rf'{k}_(\d+)_', os.path.basename(p)); return int(m.group(1)) if m else 0


def main():
    # Tile ranges from gradstruct
    gs = sorted(glob.glob(os.path.join(DUMP, 'descbrief_gradstruct_*_t*_kp*.bin')),
                key=lambda p: int(re.search(r'_t(\d+)_', p).group(1)))
    tile_kp_starts = []
    for g in gs:
        m = re.search(r'_t(\d+)_kp(\d+)\.bin$', os.path.basename(g))
        tile_kp_starts.append((int(m.group(1)), int(m.group(2))))
    tile_kp_starts.sort(key=lambda x: x[1])
    tile_ranges = []
    for idx, (ti, ks) in enumerate(tile_kp_starts):
        end = tile_kp_starts[idx + 1][1] if idx + 1 < len(tile_kp_starts) else 250
        tile_ranges.append((ti, ks, end))

    # F250 tiles by tile_id
    f250 = {}
    for p in glob.glob(os.path.join(DUMP, 'f250_raw_tile_*_call*_*x*.bin')):
        ci = int(re.search(r'call(\d+)_', p).group(1))
        if ci < 9 and ci not in f250:
            w, h = _shape(p)
            f250[ci] = (np.frombuffer(open(p, 'rb').read(), dtype=np.int32).reshape(h, w), w, h)

    # Captured kp_before records (sx, sy, orient)
    kpb = {}
    for p in glob.glob(os.path.join(DUMP, 'descbrief_kp_before_*_kp*.bin')):
        kpi = int(re.search(r'_kp(\d+)\.bin$', os.path.basename(p)).group(1))
        if kpi < 250:
            d = open(p, 'rb').read()
            kpb[kpi] = {
                'orient': struct.unpack_from('<i', d, 0xc)[0],
                'sx': struct.unpack_from('<i', d, 0x14)[0],
                'sy': struct.unpack_from('<i', d, 0x18)[0],
                'tile_id': d[9],
            }

    # For each tile: compute my port's subpix for each NMS kp (after A960 + cap)
    print(f'{"tile":>4} {"cap_count":>9} {"my_after_A960":>13} {"sx_match":>9} {"sy_match":>9} {"sx_diff":>8} {"sy_diff":>8}')
    n_sx_diff_total = n_sy_diff_total = n_match_total = 0

    for ti, ks, ke in tile_ranges:
        tile, w, h = f250[ti]
        i, j = divmod(ti, 3)
        oy, ox = tile_origin(i, j, 112, 112)

        _, _, _, resp = doh(tile.astype(np.int64) >> 6)
        my_subpix = []  # list of (sx_q16, sy_q16, abs_resp)
        for score, lx, ly in nms(resp):
            r = subpix_refine_kp(resp, lx, ly)
            if r is None: continue
            sx, sy = r
            if not _a960_passes_global_edge(sx, sy, oy, ox, 112, 112):
                continue
            my_subpix.append((sx, sy, score))

        # Captured kps for this tile
        cap_in_tile = [(kpi, kpb[kpi]) for kpi in range(ks, ke)]

        # Match by exact (sx, sy) Q16
        my_xy = {(s[0], s[1]) for s in my_subpix}
        cap_xy = {(c[1]['sx'], c[1]['sy']) for c in cap_in_tile}
        common = my_xy & cap_xy
        only_mine = my_xy - cap_xy
        only_cap = cap_xy - my_xy

        n_match_total += len(common)
        n_sx_diff_total += len(only_mine)
        n_sy_diff_total += len(only_cap)
        print(f'  {ti:>4} {len(cap_in_tile):>9} {len(my_subpix):>13} {len(common):>9} {"":>9} {len(only_mine):>8} {len(only_cap):>8}')

        if only_mine or only_cap:
            print(f'    only_mine examples: {[(s[0]/65536, s[1]/65536) for s in list(only_mine)[:3]]}')
            print(f'    only_cap  examples: {[(s[0]/65536, s[1]/65536) for s in list(only_cap)[:3]]}')

    print(f'\nTotal subpix-Q16-exact matches: {n_match_total}')
    print(f'Only in my port: {n_sx_diff_total}')
    print(f'Only in capture: {n_sy_diff_total}')


if __name__ == '__main__':
    main()
