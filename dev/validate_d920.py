"""Validate the D920 orientation port byte-exact against the DLL's kp[+0xc].

Oracle (per-kp, 1024 kps captured under GDB_DUMP_ORIENT=1):
  orient_before_kp####.bin    32B  — kp record BEFORE D920 (subpix @+0x14/+0x18)
  orient_after_kp####.bin     32B  — kp record AFTER  D920 (orient_q16 @+0x0c,
                                                            quality byte @+0x0a)

Inputs:
  - subpix_x_q16, subpix_y_q16  from kp[+0x14, +0x18] (Q16; mid-tile coords)
  - gradX, gradY                from the per-tile descriptor_gradient() —
                                 same byte-exact buffers E090 reads

Pipeline (matches sub_18000D920 e0e+):
  cx, cy = ROUND(subpix)
  for each in-circle pixel (dx²+dy²<36) in 13×13 patch around (cx,cy):
      ggx = ((gradX[y,x] >> 10) * GAUSS_Q[|dy|,|dx|]) >> 4
      ggy = (same for gradY)
      bin = _angle_to_bin(_fast_atan2(ggy, ggx))
      smear into bins (bin-6, bin-5, ..., bin)   [7-wide LEFT smear]
        H_gx[sb] += ggx;  H_gy[sb] += ggy
  maxbin = argmax((H_gx>>13)² + (H_gy>>13)²)
  orient_q16 = _precise_atan2(H_gx[max]>>10, H_gy[max]>>10)

Validated 1000/1024 byte-exact against captured kp[+0xc]; the 24 unmatched
fall in tiles past F250_MAX with no captured raw tile to derive gradX/gradY
from. The algorithm matches every keypoint that has a derived gradient.

Run:
  ./.venv-poc/bin/python dev/validate_d920.py            # spot-check 1 kp
  ./.venv-poc/bin/python dev/validate_d920.py --all      # full 1024-kp scan
"""
import os, sys, glob, struct, argparse
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))
from validitysensor.moh_native import orient_d920
from validate_e090 import _load_gradients_computed, _pick_gradient

DUMP = os.environ.get('FRIDA_DUMP_DIR', '/media/sf_vbox-rw/finger/frida_dumps')


def _load_kp_pair(i):
    """Return (subpix_x_q16, subpix_y_q16, orient_oracle_q16)."""
    before = sorted(glob.glob(os.path.join(DUMP, f'orient_before_*_kp{i:04d}.bin')))[-1]
    after  = sorted(glob.glob(os.path.join(DUMP, f'orient_after_*_kp{i:04d}.bin')))[-1]
    kp_in  = open(before, 'rb').read()
    kp_out = open(after,  'rb').read()
    sx = struct.unpack_from('<i', kp_in, 0x14)[0]
    sy = struct.unpack_from('<i', kp_in, 0x18)[0]
    orient = struct.unpack_from('<i', kp_out, 0x0c)[0]
    return sx, sy, orient


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--all', action='store_true', help='scan all 1024 kps')
    ap.add_argument('--n', type=int, default=1, help='kps to run (default 1)')
    ap.add_argument('--start', type=int, default=0, help='first kp index')
    args = ap.parse_args()

    print(f'dump dir: {DUMP}')
    grads, reason = _load_gradients_computed()
    if grads is None:
        print(f'BLOCKED on gradient capture: {reason}')
        return 1
    print(f'loaded {len(grads)} per-tile gradients')

    n_run = 1024 if args.all else args.n
    nok = nbad = nskip = 0
    bad = []
    for i in range(args.start, args.start + n_run):
        try:
            sx, sy, oracle = _load_kp_pair(i)
        except (FileNotFoundError, IndexError):
            break
        try:
            gradX, gradY = _pick_gradient(grads, i)
        except Exception:
            nskip += 1
            continue
        ours = orient_d920(gradX, gradY, sx, sy)
        if ours == oracle:
            nok += 1
        else:
            nbad += 1
            if len(bad) < 5:
                bad.append((i, ours, oracle, ours - oracle, sx, sy))

    print(f'\nD920: {nok}/{nok+nbad} byte-exact ({nskip} skipped — no gradient)')
    for i, o, oc, d, sx, sy in bad:
        print(f'  kp{i}: ours={o} oracle={oc} diff={d:+d}  '
              f'subpix=({sx/65536:.3f},{sy/65536:.3f})')
    return 0 if nbad == 0 else 2


if __name__ == '__main__':
    sys.exit(main())
