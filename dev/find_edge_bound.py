"""Find the per-tile edge bound rule DLL applies beyond A960's uniform (3, 109).

Hypothesis: for each tile (i, j) at position in the 3×3 grid, DLL applies
a position-dependent bound like
   3 <= gx < FRAME_W - some_margin(i, j)
   3 <= gy < FRAME_H - some_margin(i, j)

Strategy:
  1. Load all 9 minutia_tables from a Wine enrollment capture (2250 kps).
  2. For each kp, byte[+9] = tile_id 0..8 (= 3*i + j).
  3. Per (i, j), collect all (gx, gy) values observed across all 9 frames.
  4. Compute per-tile gx_min/max, gy_min/max.
  5. Look for a formula tile_size(i, j) -> bounds that fits all observations.

Run:
  ./.venv-poc/bin/python dev/find_edge_bound.py
"""
import os, sys, glob, struct, re
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

DUMP = os.environ.get('FRIDA_DUMP_DIR', '/media/sf_vbox-rw/finger/frida_dumps')


def main():
    paths = sorted(glob.glob(os.path.join(DUMP, 'minutia_table_*.bin')))
    print(f'Loaded {len(paths)} minutia_tables')

    # Collect (gx, gy) per tile_id across all frames
    per_tile = defaultdict(list)
    for p in paths:
        raw = open(p, 'rb').read()
        for i in range(len(raw) // 32):
            f = struct.unpack_from('<8i', raw, i * 32)
            gx, gy = f[5], f[6]
            tile_id = raw[i * 32 + 9]
            per_tile[tile_id].append((gx, gy))

    print('\nPer-tile (i, j) observed gx, gy ranges across all 9 frames:')
    print(f'  {"tile":>4} {"i":>2} {"j":>2} {"count":>6}   '
          f'{"gx_min":>7} {"gx_max":>7}  '
          f'{"gy_min":>7} {"gy_max":>7}')
    for tile_id in sorted(per_tile):
        kps = per_tile[tile_id]
        i, j = divmod(tile_id, 3)
        gxs = [kp[0] for kp in kps]
        gys = [kp[1] for kp in kps]
        print(f'  {tile_id:>4} {i:>2} {j:>2} {len(kps):>6}   '
              f'{min(gxs):>7} {max(gxs):>7}  '
              f'{min(gys):>7} {max(gys):>7}')

    print()
    print('Hypothesized bounds (assuming uniform A960 = [3, 108]):')
    print(f'  step = 37, GRID_X = 10, last-tile step = 38, last-tile size = 58')
    print()
    print('Natural NMS-derived bounds (= tile_origin + NMS_margin..NMS_margin_upper):')
    for tile_id in sorted(per_tile):
        i, j = divmod(tile_id, 3)
        step_y = 38 if i == 2 else 37
        step_x = 38 if j == 2 else 37
        oy = i * 37 - 10
        ox = j * 37 - 10
        # NMS keeps local x in [10, tile_w - 11]. tile_w = step_x + 20.
        # → local x in [10, step_x + 9]. Global x in [oy+10, oy+step_x+9] = [ox+10, ox+step_x+9]
        tw = step_x + 20
        th = step_y + 20
        gx_lo_nms = ox + 10        # = j*37
        gx_hi_nms = ox + tw - 11    # = ox + (step_x + 20) - 11 = ox + step_x + 9
        gy_lo_nms = oy + 10
        gy_hi_nms = oy + th - 11
        # The A960 uniform bound caps at [3, 108]
        gx_lo = max(3, gx_lo_nms)
        gx_hi = min(108, gx_hi_nms)
        gy_lo = max(3, gy_lo_nms)
        gy_hi = min(108, gy_hi_nms)
        # Observed ranges
        kps = per_tile[tile_id]
        gxs = [kp[0] for kp in kps]; gys = [kp[1] for kp in kps]
        obs_gx_lo, obs_gx_hi = min(gxs), max(gxs)
        obs_gy_lo, obs_gy_hi = min(gys), max(gys)
        # If observed lies INSIDE the natural NMS-derived bounds, no extra cull is needed
        gx_natural_ok = (obs_gx_lo >= gx_lo) and (obs_gx_hi <= gx_hi)
        gy_natural_ok = (obs_gy_lo >= gy_lo) and (obs_gy_hi <= gy_hi)
        msg_x = '' if gx_natural_ok else f' (TIGHTER than natural by {gx_lo-obs_gx_lo}..{gx_hi-obs_gx_hi})'
        msg_y = '' if gy_natural_ok else f' (TIGHTER than natural by {gy_lo-obs_gy_lo}..{gy_hi-obs_gy_hi})'
        print(f'  tile {tile_id} (i={i}, j={j}, tile {tw}x{th}):')
        print(f'    NMS-derived: gx in [{gx_lo_nms}, {gx_hi_nms}], gy in [{gy_lo_nms}, {gy_hi_nms}]')
        print(f'    A960-capped:  gx in [{gx_lo}, {gx_hi}], gy in [{gy_lo}, {gy_hi}]')
        print(f'    observed:    gx in [{obs_gx_lo}, {obs_gx_hi}]{msg_x}')
        print(f'                 gy in [{obs_gy_lo}, {obs_gy_hi}]{msg_y}')


if __name__ == '__main__':
    main()
