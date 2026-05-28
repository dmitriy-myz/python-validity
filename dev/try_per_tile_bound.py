"""Test hypothesis: DLL's per-tile bound is grid-cell partition with
tile-position-dependent tightening.

For each (gx, gy), assign tile via (i, j) = (gy // 37, gx // 37) clamped
to [0, 2]. Then check if the kp passes that tile's observed bound.

Observed bounds (from 9-frame Wine enrollment capture):
  tile (0,0): gx [3, 36], gy [3, 36]
  tile (0,1): gx [36, 73], gy [3, 36]
  tile (0,2): gx [73, 108], gy [3, 36]
  tile (1,0): gx [3, 36], gy [36, 73]
  tile (1,1): gx [36, 73], gy [36, 73]
  tile (1,2): gx [73, 108], gy [36, 73]
  tile (2,0): gx [3, 36], gy [73, 108]
  tile (2,1): gx [36, 72], gy [73, 108]   (gx -1 from 73)
  tile (2,2): gx [73, 108], gy [73, 101]   (gy -7 from 108) ← corner tightening

The corner tile 8 has gy max = 101 = oy + 37 (= step) where oy = 64. So
the rule might be: for tile (2, 2), gy < 102 = oy + step. Let's test.
"""
import os, sys, glob, struct, re
from collections import defaultdict
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import validitysensor.moh_native as mn
mn.RESP_CULL_THRESHOLD = 0
from validitysensor.moh_native import extract_frame_native, tile_origin

DUMP = os.environ.get('FRIDA_DUMP_DIR', '/media/sf_vbox-rw/finger/frida_dumps')

# Per-tile observed bounds (from find_edge_bound.py output)
PER_TILE_BOUND = {
    (0, 0): {'gx': (3, 36),   'gy': (3, 36)},
    (0, 1): {'gx': (36, 73),  'gy': (3, 36)},
    (0, 2): {'gx': (73, 108), 'gy': (3, 36)},
    (1, 0): {'gx': (3, 36),   'gy': (36, 73)},
    (1, 1): {'gx': (36, 73),  'gy': (36, 73)},
    (1, 2): {'gx': (73, 108), 'gy': (36, 73)},
    (2, 0): {'gx': (3, 36),   'gy': (73, 108)},
    (2, 1): {'gx': (36, 72),  'gy': (73, 108)},
    (2, 2): {'gx': (73, 108), 'gy': (73, 101)},  # corner: gy tighter
}


def assign_tile(gx, gy):
    """Determine tile (i, j) for a kp by gx/gy partition."""
    # Use boundary at 37, 74 (tile widths 37, 37, 38)
    if gx < 37:
        j = 0
    elif gx < 74:
        j = 1
    else:
        j = 2
    if gy < 37:
        i = 0
    elif gy < 74:
        i = 1
    else:
        i = 2
    return i, j


def passes_per_tile_bound(gx, gy):
    """Apply the per-tile observed bound."""
    ij = assign_tile(gx, gy)
    b = PER_TILE_BOUND[ij]
    return b['gx'][0] <= gx <= b['gx'][1] and b['gy'][0] <= gy <= b['gy'][1]


def load_dll_kps(path):
    raw = open(path, 'rb').read()
    out = set()
    for i in range(len(raw) // 32):
        f = struct.unpack_from('<8i', raw, i * 32)
        out.add((f[5], f[6]))
    return out


def _shape(p):
    m = re.search(r'_(\d+)x(\d+)\.bin$', os.path.basename(p))
    return int(m.group(1)), int(m.group(2))


def reconstruct_image(call_start, call_end, h=112, w=112):
    """Build 112×112 image from F250 detect-path tiles [call_start..call_start+9)."""
    img = np.full((h, w), 0x800000, dtype=np.int32)
    written = np.zeros((h, w), dtype=bool)
    for ci_global in range(call_start, call_start + 9):
        cands = glob.glob(os.path.join(DUMP, f'f250_raw_tile_*_call{ci_global:03d}_*x*.bin'))
        if not cands: return None
        p = cands[0]
        ci = ci_global % 9
        ii, jj = divmod(ci, 3)
        oy, ox = tile_origin(ii, jj, h, w)
        tw, th = _shape(p)
        tile = np.frombuffer(open(p, 'rb').read(), dtype=np.int32).reshape(th, tw)
        for ty in range(th):
            for tx in range(tw):
                ry, cx = oy + ty, ox + tx
                if 0 <= ry < h and 0 <= cx < w and not written[ry, cx]:
                    img[ry, cx] = tile[ty, tx]
                    written[ry, cx] = True
    return img


def main():
    mt_paths = sorted(glob.glob(os.path.join(DUMP, 'minutia_table_*.bin')))
    print(f'Testing per-tile bound against {len(mt_paths)} AAB0 invocations:')
    print()
    print(f'  {"AAB0":>5}  {"raw":>5}  {"bounded":>7}  {"DLL":>4}  {"common":>7}  {"only_mine":>10}  {"only_dll":>9}')
    for idx, mt in enumerate(mt_paths):
        dll = load_dll_kps(mt)
        img = reconstruct_image(idx * 18, idx * 18 + 9)
        if img is None:
            print(f'  AAB0 #{idx}: skip (no F250)'); continue
        my_out = extract_frame_native(img.astype(np.int64))
        my_xy = set((gx, gy) for gx, gy, _, _ in my_out)
        # Apply per-tile bound filter
        my_bounded = set(xy for xy in my_xy if passes_per_tile_bound(*xy))
        common = my_bounded & dll
        only_mine = my_bounded - dll
        only_dll = dll - my_bounded
        print(f'  {idx:>5}  {len(my_xy):>5}  {len(my_bounded):>7}  {len(dll):>4}'
              f'  {len(common):>7}  {len(only_mine):>10}  {len(only_dll):>9}')


if __name__ == '__main__':
    main()
