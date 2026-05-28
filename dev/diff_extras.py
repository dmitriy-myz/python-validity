"""For each tile, characterize the 253 'extra' kps my port keeps that DLL
drops. Compare their resp, subpix Δ, neighborhood, and position to the 250
captured kps to find the discriminating criterion.
"""
import os, sys, glob, struct, re
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from validitysensor.moh_native import (
    tile_origin, doh, nms, subpix_refine_kp, _a960_passes_global_edge,
    _solve_2x2_d4c0, _s32, _sar32,
)

DUMP = os.environ.get('FRIDA_DUMP_DIR', '/media/sf_vbox-rw/finger/frida_dumps')


def _shape(p):
    m = re.search(r'_(\d+)x(\d+)\.bin$', os.path.basename(p))
    return int(m.group(1)), int(m.group(2))


def main():
    gs = sorted(glob.glob(os.path.join(DUMP, 'descbrief_gradstruct_*_t*_kp*.bin')),
                key=lambda p: int(re.search(r'_t(\d+)_', p).group(1)))
    tile_ranges = []
    starts = sorted((int(re.search(r'_t(\d+)_', g).group(1)),
                     int(re.search(r'_kp(\d+)\.bin$', g).group(1))) for g in gs[:9])
    for idx, (ti, ks) in enumerate(starts):
        end = starts[idx + 1][1] if idx + 1 < len(starts) else 250
        tile_ranges.append((ti, ks, end))

    f250 = {}
    for p in glob.glob(os.path.join(DUMP, 'f250_raw_tile_*_call*_*x*.bin')):
        ci = int(re.search(r'call(\d+)_', p).group(1))
        if ci < 9 and ci not in f250:
            w, h = _shape(p)
            f250[ci] = (np.frombuffer(open(p, 'rb').read(), dtype=np.int32).reshape(h, w), w, h)

    # Cap kps: byte-exact Q16 positions
    kpb = {}
    for p in glob.glob(os.path.join(DUMP, 'descbrief_kp_before_*_kp*.bin')):
        kpi = int(re.search(r'_kp(\d+)\.bin$', os.path.basename(p)).group(1))
        if kpi < 250:
            d = open(p, 'rb').read()
            kpb[kpi] = {
                'sx': struct.unpack_from('<i', d, 0x14)[0],
                'sy': struct.unpack_from('<i', d, 0x18)[0],
                'tile_id': d[9],
            }

    print(f'{"ti":>3} {"cat":>6} {"resp":>8} {"sx":>7} {"sy":>7} {"x_int":>5} {"y_int":>5}'
          f' {"dxx":>7} {"dyy":>7} {"dxy":>7} {"detpos":>8}')
    for ti, ks, ke in tile_ranges[:3]:  # first 3 tiles for brevity
        tile, w, h = f250[ti]
        i, j = divmod(ti, 3)
        oy, ox = tile_origin(i, j, 112, 112)
        _, _, _, resp = doh(tile.astype(np.int64) >> 6)

        # cap kp set
        cap_xy = {(kpb[kpi]['sx'], kpb[kpi]['sy']) for kpi in range(ks, ke)}

        for score, lx, ly in nms(resp):
            r = subpix_refine_kp(resp, lx, ly)
            if r is None: continue
            sx, sy = r
            if not _a960_passes_global_edge(sx, sy, oy, ox, 112, 112):
                continue
            cat = 'CAP' if (sx, sy) in cap_xy else 'EXTRA'

            # Compute Hessian coeffs from raw resp values (re-do what D5D0 does)
            cV = _s32(int(resp[ly, lx])); L = _s32(int(resp[ly, lx-1]))
            R = _s32(int(resp[ly, lx+1])); T = _s32(int(resp[ly-1, lx]))
            B = _s32(int(resp[ly+1, lx])); TL = _s32(int(resp[ly-1, lx-1]))
            TR = _s32(int(resp[ly-1, lx+1])); BL = _s32(int(resp[ly+1, lx-1]))
            BR = _s32(int(resp[ly+1, lx+1]))
            dxx = _sar32(_s32(L + R - 2*cV), 2)
            dyy = _sar32(_s32(T + B - 2*cV), 2)
            dxy = _sar32(_s32(_sar32(_s32(BR+TL), 2) - _sar32(_s32(BL+TR), 2)), 2)
            # det
            from validitysensor.moh_native import _imul32
            a = _sar32(dxx, 4); b = _sar32(dxy, 4); c = _sar32(dxy, 4); d = _sar32(dyy, 4)
            det_pos = _sar32(_imul32(a, d) - _imul32(b, c), 7)

            print(f'  {ti:>3} {cat:>6} {score:>8} {sx/65536:>7.2f} {sy/65536:>7.2f} {lx:>5} {ly:>5}'
                  f' {dxx:>7} {dyy:>7} {dxy:>7} {det_pos:>8}')


if __name__ == '__main__':
    main()
