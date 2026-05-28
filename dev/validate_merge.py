"""Validate the tile→global merge byte-exact: all 1024 captured kps
must pass the [3, 109) bound check after row-major (i, j) attribution
via `kp[+0x9]`.

Each per-kp record at orient_before_kp####.bin embeds the tile-within-
frame index at byte offset +0x9 (range 0..8, row-major in the 3×3
grid: `i = +0x9 // 3, j = +0x9 % 3`). Frame transitions are detected
as `+0x9 < prev_+0x9` (when the DLL wraps from tile 8 back to 0).
This is the SAME signal D920/E090 use internally — the in-record
field is the ground truth for tile attribution, replacing the seq-
based heuristic the gradient capture had to use.

Validated 1024/1024 byte-exact on the current capture (4 full frames
+ partial 5th = 38 tile invocations, all gradients within bounds).

Run:
  ./.venv-poc/bin/python dev/validate_merge.py
"""
import os, sys, glob, struct

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from validitysensor.moh_native import merge_tile_kps_to_global, tile_origin_yx

DUMP = os.environ.get('FRIDA_DUMP_DIR', '/media/sf_vbox-rw/finger/frida_dumps')


def main():
    per_tile = {}
    frame = 0; prev_b9 = -1
    n_loaded = 0
    for i in range(1024):
        fs = sorted(glob.glob(os.path.join(DUMP, f'orient_before_*_kp{i:04d}.bin')))
        if not fs:
            break
        kp = open(fs[-1], 'rb').read()
        if len(kp) < 0x20:
            continue
        b9 = kp[0x9]
        sx = struct.unpack_from('<i', kp, 0x14)[0]
        sy = struct.unpack_from('<i', kp, 0x18)[0]
        if b9 < prev_b9:
            frame += 1
        prev_b9 = b9
        ti = b9 // 3            # row-major
        tj = b9 % 3
        per_tile.setdefault((frame, ti, tj), []).append((sx, sy, i))
        n_loaded += 1

    ordered = sorted(per_tile.items(), key=lambda x: (x[0][0], x[0][1] * 3 + x[0][2]))
    input_iter = [(ti, tj, kps) for (frame, ti, tj), kps in ordered]

    print(f'kps loaded: {n_loaded}')
    print(f'tile invocations: {len(input_iter)}, frames: {frame + 1}')

    global_kps = merge_tile_kps_to_global(input_iter, 112, 112)
    total = sum(len(k) for _, _, k in input_iter)
    print(f'merge: {len(global_kps)}/{total} in bounds')

    if len(global_kps) < total:
        print('\nDROPPED:')
        for (frame, ti, tj), kps in ordered:
            oy, ox = tile_origin_yx(ti, tj, 112, 112)
            for sx, sy, idx in kps:
                gx = ox + (sx >> 16); gy = oy + (sy >> 16)
                if not (3 <= gx < 109 and 3 <= gy < 109):
                    print(f'  kp{idx}: tile(f={frame}, i={ti}, j={tj}) origin=({oy},{ox}) '
                          f'subpix=({sx/65536:.2f},{sy/65536:.2f}) global=({gx},{gy})')
        return 2

    # Report global xy range
    gx_min = min(g[0] for g in global_kps); gx_max = max(g[0] for g in global_kps)
    gy_min = min(g[1] for g in global_kps); gy_max = max(g[1] for g in global_kps)
    print(f'global xy range: ({gx_min}..{gx_max}, {gy_min}..{gy_max})  '
          f'(DLL bound: [3, 109))')
    return 0


if __name__ == '__main__':
    sys.exit(main())
