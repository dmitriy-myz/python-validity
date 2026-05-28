"""Byte-diff my port's descriptor pipeline against captured DLL outputs.

Two stages we couldn't verify until now:
  1. descriptor_gradient(tile) vs captured descbrief_gradX/gradY (per tile)
  2. _descriptor_at(gradX, gradY, sx, sy, orient) vs captured descbrief_desc (per kp)

Inputs are the captured F250 raw tile (so we use the DLL's exact tile bytes)
and the captured kp record (subpix + orient straight from DLL).
"""
import os, sys, glob, struct, re
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from validitysensor.moh_native import (
    descriptor_gradient, orient_d920, _descriptor_at,
)

DUMP = os.environ.get('FRIDA_DUMP_DIR', '/media/sf_vbox-rw/finger/frida_dumps')


def _shape(path):
    m = re.search(r'_(\d+)x(\d+)\.bin$', os.path.basename(path))
    return int(m.group(1)), int(m.group(2))


def _ts(path, kind):
    m = re.search(rf'{kind}_(\d+)_', os.path.basename(path))
    return int(m.group(1)) if m else 0


def main():
    # Load per-tile gradstruct → kp range start mapping
    gs = sorted(glob.glob(os.path.join(DUMP, 'descbrief_gradstruct_*_t*_kp*.bin')),
                key=lambda p: int(re.search(r'_t(\d+)_', p).group(1)))
    if not gs:
        print('No descbrief_gradstruct_*.bin found'); return

    tiles = []
    for gp in gs:
        m = re.search(r'_t(\d+)_kp(\d+)\.bin$', os.path.basename(gp))
        ti, kp_start = int(m.group(1)), int(m.group(2))
        ts = _ts(gp, 'descbrief_gradstruct')
        tiles.append((ti, kp_start, ts, gp))
    print(f'Found {len(tiles)} per-tile gradients in this capture')

    # Pair gradient struct → (gradX, gradY, raw tile)
    gradX_paths = glob.glob(os.path.join(DUMP, 'descbrief_gradX_*_t*_kp*_*x*.bin'))
    gradY_paths = glob.glob(os.path.join(DUMP, 'descbrief_gradY_*_t*_kp*_*x*.bin'))
    f250_paths = glob.glob(os.path.join(DUMP, 'f250_raw_tile_*_call*_*x*.bin'))

    # Build (ti, kp_start) -> raw tile by matching gradX shape AND ts proximity
    print(f'\n=== Stage A: descriptor_gradient(F250_raw_tile) vs captured gradX/gradY ===')
    n_gx_diff_total = n_gy_diff_total = 0
    n_tiles_checked = 0
    tile_to_grad = {}
    for ti, kp_start, ts, gp in tiles[:9]:    # first frame
        # Match gradX/Y by ti tag
        gx = next((p for p in gradX_paths
                    if re.search(rf'_t{ti:02d}_kp{kp_start:04d}_', os.path.basename(p))), None)
        gy = next((p for p in gradY_paths
                    if re.search(rf'_t{ti:02d}_kp{kp_start:04d}_', os.path.basename(p))), None)
        if not (gx and gy):
            print(f'  tile {ti} kp_start={kp_start}: gradX or gradY not found'); continue
        w, h = _shape(gx)
        # Find the F250 raw tile of matching dim AND ts close to gradstruct's ts
        candidates = [(p, _ts(p, 'f250_raw_tile')) for p in f250_paths
                       if re.search(rf'_{w}x{h}\.bin$', os.path.basename(p))]
        candidates = [(p, t) for p, t in candidates if t <= ts]
        if not candidates:
            print(f'  tile {ti}: no F250 raw tile of {w}x{h}'); continue
        f250_path, _ = max(candidates, key=lambda c: c[1])

        tile_q16 = np.frombuffer(open(f250_path, 'rb').read(), dtype=np.int32).reshape(h, w)
        cap_gx = np.frombuffer(open(gx, 'rb').read(), dtype=np.int32).reshape(h, w)
        cap_gy = np.frombuffer(open(gy, 'rb').read(), dtype=np.int32).reshape(h, w)
        my_gx, my_gy = descriptor_gradient(tile_q16)
        my_gx = my_gx.astype(np.int32); my_gy = my_gy.astype(np.int32)

        diff_x = (my_gx != cap_gx)
        diff_y = (my_gy != cap_gy)
        nx, ny = int(diff_x.sum()), int(diff_y.sum())
        n_gx_diff_total += nx; n_gy_diff_total += ny
        n_tiles_checked += 1
        # Inner-region diffs (border 3)
        r = np.broadcast_to(np.arange(h)[:, None], (h, w))
        c = np.broadcast_to(np.arange(w)[None, :], (h, w))
        inner = (np.minimum(np.minimum(r, c), np.minimum(h-1-r, w-1-c)) >= 3)
        nxi, nyi = int((diff_x & inner).sum()), int((diff_y & inner).sum())
        print(f'  tile {ti} ({w}x{h}) kp_start={kp_start}: gradX diff={nx} (inner {nxi}); gradY diff={ny} (inner {nyi})')
        tile_to_grad[(ti, kp_start)] = (cap_gx, cap_gy, my_gx, my_gy)

    print(f'\n=== Stage B: my _descriptor_at(...) vs captured descbrief_desc ===')
    # For each descbrief_kp_before, run my port's descriptor pipeline and compare
    # the resulting 16-byte descriptor against descbrief_desc_kpXXXX.
    desc_paths = glob.glob(os.path.join(DUMP, 'descbrief_desc_*_kp*.bin'))
    kp_before_paths = glob.glob(os.path.join(DUMP, 'descbrief_kp_before_*_kp*.bin'))
    desc_by_kp = {int(re.search(r'_kp(\d+)\.bin$', os.path.basename(p)).group(1)): p
                  for p in desc_paths}
    kpb_by_kp = {int(re.search(r'_kp(\d+)\.bin$', os.path.basename(p)).group(1)): p
                 for p in kp_before_paths}

    # Use the per-tile gradient mapping. For kp i belonging to tile ti, range
    # [kp_start_ti, kp_start_{ti+1}).
    tiles_first_frame = sorted(tiles[:9], key=lambda t: t[1])
    tile_ranges = []
    for idx, (ti, ks, _, _) in enumerate(tiles_first_frame):
        end = tiles_first_frame[idx + 1][1] if idx + 1 < len(tiles_first_frame) else 250
        tile_ranges.append((ti, ks, end))
    print('  tile ranges:', tile_ranges)

    n_byte_exact = n_partial = n_total_wrong = 0
    n_checked = 0
    first_mismatches = []
    for kpi in sorted(desc_by_kp):
        if kpi not in kpb_by_kp: continue
        ti = None
        for t, ks, ke in tile_ranges:
            if ks <= kpi < ke:
                ti = t
                kp_start = ks
                break
        if ti is None: continue
        cap_gx, cap_gy, my_gx, my_gy = tile_to_grad[(ti, kp_start)]

        kpb = open(kpb_by_kp[kpi], 'rb').read()
        # kp record layout (64 bytes per descbrief): orient at +0xc, sx at +0x14, sy at +0x18
        orient = struct.unpack_from('<i', kpb, 0xc)[0]
        sx = struct.unpack_from('<i', kpb, 0x14)[0]
        sy = struct.unpack_from('<i', kpb, 0x18)[0]
        cap_desc = open(desc_by_kp[kpi], 'rb').read()

        # Use CAPTURED gradient (so we isolate the descriptor stage from gradient stage)
        my_desc = bytes(_descriptor_at(cap_gx, cap_gy, sx, sy, orient))
        n_checked += 1
        if my_desc == cap_desc:
            n_byte_exact += 1
        else:
            n_partial += 1
            if len(first_mismatches) < 5:
                # count bit differences
                xor = bytes(a ^ b for a, b in zip(my_desc, cap_desc))
                n_bit_diff = sum(bin(b).count('1') for b in xor)
                first_mismatches.append((kpi, ti, sx/65536, sy/65536, orient, n_bit_diff,
                                         my_desc.hex(), cap_desc.hex()))

    print(f'\n  Checked: {n_checked} kps')
    print(f'    byte-exact descriptor: {n_byte_exact}')
    print(f'    differing descriptor:  {n_partial}')
    if first_mismatches:
        print(f'\n  First 5 mismatches:')
        for kpi, ti, sx, sy, orient, nbits, mine, cap in first_mismatches:
            print(f'    kp{kpi:4d} tile{ti} ({sx:.2f},{sy:.2f}) orient={orient}: {nbits}/128 bits diff')
            print(f'      mine: {mine}')
            print(f'      cap:  {cap}')


if __name__ == '__main__':
    main()
