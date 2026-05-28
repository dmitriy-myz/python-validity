"""Full end-to-end diff: reconstruct image from F250 tiles, run my port's
extract_frame_native, and compare kp-by-kp against captured DLL output.

What we know already:
  - tile_image, doh, nms: byte-exact (verified in diff_wine_pipeline.py)
  - subpix_refine_kp: byte-exact for kept kps (1000/1000 in validate_subpix)
  - descriptor_gradient: byte-exact (verified in diff_descriptors.py)
  - orient_d920: byte-exact (verified in validate_d920)
  - _descriptor_at: byte-exact (verified in diff_descriptors.py)

What this script diffs:
  - my extract_frame_native(reconstructed_image) → 250 (gx, gy, orient, desc) tuples
  - captured (gx, gy, orient, desc) from descbrief_kp_before + descbrief_desc
  - byte-by-byte across both lists

Reports exactly which kps my port differs on.
"""
import os, sys, glob, struct, re
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from validitysensor.moh_native import (
    GRID, GRID_X, tile_origin, tile_size, extract_frame_native,
)

DUMP = os.environ.get('FRIDA_DUMP_DIR', '/media/sf_vbox-rw/finger/frida_dumps')


def _ts(p, k):
    m = re.search(rf'{k}_(\d+)_', os.path.basename(p)); return int(m.group(1)) if m else 0


def _shape(p):
    m = re.search(r'_(\d+)x(\d+)\.bin$', os.path.basename(p))
    return int(m.group(1)), int(m.group(2))


def load_frame0_f250_tiles():
    """Take the 9 oldest F250 raw_tile captures as frame-0 tiles."""
    all_f250 = sorted(glob.glob(os.path.join(DUMP, 'f250_raw_tile_*_call*_*x*.bin')),
                       key=lambda p: int(re.search(r'call(\d+)_', p).group(1)))
    out = {}
    for ci in range(9):
        # find by call index
        cand = [p for p in all_f250 if re.search(rf'_call0*{ci}_', p)]
        if not cand:
            print(f'WARN: no F250 raw_tile for call{ci}'); continue
        p = sorted(cand, key=lambda x: _ts(x, 'f250_raw_tile'))[0]
        i, j = divmod(ci, 3)
        w, h = _shape(p)
        out[(i, j)] = (np.frombuffer(open(p, 'rb').read(), dtype=np.int32).reshape(h, w), w, h)
    return out


def reconstruct_image(captured_tiles, h=112, w=112):
    img = np.full((h, w), 0x800000, dtype=np.int32)
    written = np.zeros((h, w), dtype=bool)
    for (i, j), (tile, tw, th) in captured_tiles.items():
        oy, ox = tile_origin(i, j, h, w)
        for ty in range(th):
            for tx in range(tw):
                ry, cx = oy + ty, ox + tx
                if 0 <= ry < h and 0 <= cx < w and not written[ry, cx]:
                    img[ry, cx] = tile[ty, tx]
                    written[ry, cx] = True
    if int(written.sum()) != h * w:
        print(f'WARN: only {int(written.sum())}/{h*w} pixels reconstructed')
    return img


def load_captured_kps():
    """Return list of (kpi, sx_q16, sy_q16, orient_q16, gx, gy, desc) for the
    first 250 kps from the capture."""
    kpb_paths = {int(re.search(r'_kp(\d+)\.bin$', os.path.basename(p)).group(1)): p
                 for p in glob.glob(os.path.join(DUMP, 'descbrief_kp_before_*_kp*.bin'))}
    desc_paths = {int(re.search(r'_kp(\d+)\.bin$', os.path.basename(p)).group(1)): p
                  for p in glob.glob(os.path.join(DUMP, 'descbrief_desc_*_kp*.bin'))}
    out = []
    for kpi in sorted(kpb_paths):
        if kpi >= 250: break
        if kpi not in desc_paths: continue
        kpb = open(kpb_paths[kpi], 'rb').read()
        orient = struct.unpack_from('<i', kpb, 0xc)[0]
        sx = struct.unpack_from('<i', kpb, 0x14)[0]
        sy = struct.unpack_from('<i', kpb, 0x18)[0]
        # descbrief kp record byte[+9] = tile_id
        tile_id = kpb[9]
        desc = open(desc_paths[kpi], 'rb').read()
        out.append({
            'kpi': kpi, 'tile_id': tile_id,
            'sx_q16': sx, 'sy_q16': sy, 'orient': orient, 'desc': desc,
        })
    return out


def main():
    captured_tiles = load_frame0_f250_tiles()
    print(f'Loaded {len(captured_tiles)} F250 tiles')
    img = reconstruct_image(captured_tiles)
    print(f'Reconstructed 112x112 image')

    print('\nRunning extract_frame_native on reconstructed image...')
    my_out = extract_frame_native(img.astype(np.int64))
    print(f'  My port: {len(my_out)} kps')

    cap = load_captured_kps()
    print(f'  Captured: {len(cap)} kps (first frame)')

    # Group cap by tile_id
    from collections import defaultdict
    cap_by_tile = defaultdict(list)
    for c in cap:
        cap_by_tile[c['tile_id']].append(c)

    # Group my_out by tile (we know merge_tile_kps_to_global preserves tile-order).
    # My output is (gx, gy, orient, desc) — no tile_id, but the order is per-tile.
    # We need to RECONSTRUCT my tile_id assignment based on gx, gy ranges.
    def my_tile_id(gx, gy):
        # tile origins are at (i*37-10, j*37-10), core region is [i*37, (i+1)*37)
        i = min(2, max(0, gy // 37))
        j = min(2, max(0, gx // 37))
        return i * 3 + j

    my_by_tile = defaultdict(list)
    for kp in my_out:
        gx, gy, orient, desc = kp
        my_by_tile[my_tile_id(gx, gy)].append({
            'gx': gx, 'gy': gy, 'orient': orient, 'desc': desc,
        })

    print(f'\nPer-tile counts:')
    print(f'  {"tile":>4} {"mine":>5} {"cap":>5}')
    for ti in range(9):
        print(f'  {ti:>4} {len(my_by_tile[ti]):>5} {len(cap_by_tile[ti]):>5}')

    # For each tile, sort cap by (sx, sy) and my by (gx, gy) - then match
    n_exact_xy = n_xy_diff = n_orient_diff = n_desc_diff = 0
    n_unmatched_mine = n_unmatched_cap = 0
    diffs = []
    for ti in range(9):
        i, j = divmod(ti, 3)
        oy, ox = tile_origin(i, j, 112, 112)
        # Convert cap's local subpix to global (gx, gy)
        cap_kps = []
        for c in cap_by_tile[ti]:
            gx = ((ox << 16) + c['sx_q16']) >> 16
            gy = ((oy << 16) + c['sy_q16']) >> 16
            cap_kps.append({**c, 'gx': gx, 'gy': gy})

        my_kps = my_by_tile[ti]

        # Match by (gx, gy) exact
        cap_idx = {(c['gx'], c['gy']): c for c in cap_kps}
        my_idx = {(m['gx'], m['gy']): m for m in my_kps}

        common = set(cap_idx) & set(my_idx)
        only_mine = set(my_idx) - set(cap_idx)
        only_cap = set(cap_idx) - set(my_idx)

        for xy in common:
            n_exact_xy += 1
            m, c = my_idx[xy], cap_idx[xy]
            if m['orient'] != c['orient']:
                n_orient_diff += 1
                diffs.append(('orient', ti, xy, m['orient'], c['orient']))
            if m['desc'] != c['desc']:
                n_desc_diff += 1
                if len([d for d in diffs if d[0] == 'desc']) < 5:
                    xor = bytes(a ^ b for a, b in zip(m['desc'], c['desc']))
                    n_bits = sum(bin(b).count('1') for b in xor)
                    diffs.append(('desc', ti, xy, n_bits, m['desc'].hex(), c['desc'].hex()))

        n_unmatched_mine += len(only_mine)
        n_unmatched_cap += len(only_cap)
        if only_mine or only_cap:
            if ti not in [t[1] for t in diffs if t[0] == 'set'][:9]:
                diffs.append(('set', ti, len(only_mine), len(only_cap),
                              sorted(only_mine)[:5], sorted(only_cap)[:5]))

    print(f'\n=== Summary ===')
    print(f'  Exact (gx, gy) matches: {n_exact_xy}')
    print(f'  Of which orient differs: {n_orient_diff}')
    print(f'  Of which desc differs:   {n_desc_diff}')
    print(f'  Unmatched (only in mine): {n_unmatched_mine}')
    print(f'  Unmatched (only in cap):  {n_unmatched_cap}')

    print(f'\n=== First few set diffs ===')
    for d in diffs[:9]:
        if d[0] == 'set':
            _, ti, n_mine, n_cap, sample_mine, sample_cap = d
            print(f'  tile {ti}: only_mine={n_mine} only_cap={n_cap}')
            print(f'    mine samples: {sample_mine}')
            print(f'    cap  samples: {sample_cap}')

    print(f'\n=== First few descriptor diffs (matching xy) ===')
    for d in diffs:
        if d[0] == 'desc':
            _, ti, xy, nbits, mine, cap = d
            print(f'  tile {ti} ({xy}): {nbits}/128 bits diff')
            print(f'    mine: {mine}')
            print(f'    cap:  {cap}')


if __name__ == '__main__':
    main()
