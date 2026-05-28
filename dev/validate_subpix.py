"""Validate subpix_refine_kps() against captured orient_before Q16 coords.

Pipeline: f250_raw_tile (Q16) >> 6 → moh_native.doh() → resp → nms →
          subpix_refine_kps.
Oracle:   orient_before kp[+0x14]/[+0x18] = LOCAL Q16 coords (tile-local).

Tile pairing: f250 fires per tile (even tiles with 0 kps), but orient_before
only has runs for tiles with ≥1 kp. We reuse validate_e090's interior-gx
byte-exact matching to map each orient_before kp_start → f250_raw_tile_path.
"""
import glob
import os
import re
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from validitysensor import moh_native as M
import validate_e090 as VE

DUMP = os.environ.get('FRIDA_DUMP_DIR', '/media/sf_vbox-rw/finger/frida_dumps')


def _ts(p, prefix):
    """Extract the 13-digit ms timestamp from a dump filename."""
    m = re.search(rf'{prefix}_(\d{{13}})_', os.path.basename(p))
    return int(m.group(1)) if m else 0


def load_orient_before(idx):
    f = glob.glob(os.path.join(DUMP, f'orient_before_*_kp{idx:04d}.bin'))[0]
    return np.frombuffer(open(f, 'rb').read(), dtype=np.int32)


def load_orient_before_bytes(idx):
    f = glob.glob(os.path.join(DUMP, f'orient_before_*_kp{idx:04d}.bin'))[0]
    return open(f, 'rb').read()


def main():
    # 1) Pair each orient_before kp_start → f250_raw_tile via interior-gx
    #    byte-exact match (reuse validate_e090's logic, but track raw_path).
    captured, err = VE._load_gradients()
    if err:
        print('ERR:', err)
        return
    raws = sorted(glob.glob(os.path.join(DUMP, 'f250_raw_tile_*_call*_*x*.bin')),
                  key=lambda p: _ts(p, 'f250_raw_tile'))
    border = 3
    kp_start_to_raw = {}
    used = set()
    for kp_start, (cap_gx, _) in sorted(captured.items()):
        for idx, raw_path in enumerate(raws):
            if idx in used:
                continue
            dim = re.search(r'_(\d+)x(\d+)\.bin$', os.path.basename(raw_path))
            if not dim:
                continue
            w, h = int(dim.group(1)), int(dim.group(2))
            raw = np.frombuffer(open(raw_path, 'rb').read(),
                                dtype=np.int32).reshape(h, w)
            if raw.shape != cap_gx.shape:
                continue
            gx, _gy = M.descriptor_gradient(raw)
            if np.array_equal(gx[border:-border, border:-border],
                              cap_gx[border:-border, border:-border]):
                kp_start_to_raw[kp_start] = raw_path
                used.add(idx)
                break
    print(f'matched {len(kp_start_to_raw)} tile→kp_start via gx interior')

    # 2) Order tile_runs in orient_before. Each contiguous run (same +0x9)
    #    of kps corresponds to one E090 tile invocation.
    orient_files = sorted(glob.glob(os.path.join(DUMP, 'orient_before_*.bin')),
                          key=lambda p: int(re.search(r'_kp(\d{4})\.bin', p).group(1)))
    tile_runs = []
    cur_run = []
    cur_tid = None
    for i, f in enumerate(orient_files):
        tid = open(f, 'rb').read()[0x9]
        if cur_tid is None or tid == cur_tid:
            cur_run.append(i)
            cur_tid = tid
        else:
            tile_runs.append((cur_tid, cur_run))
            cur_run = [i]
            cur_tid = tid
    if cur_run:
        tile_runs.append((cur_tid, cur_run))

    # 3) Use kp_start (= first kp_idx in each run) to pick the matched raw_tile.
    total_match = 0
    total_kps = 0
    no_tile = 0
    no_predicted = 0
    for tid, kp_idxs in tile_runs:
        kp_start = kp_idxs[0]
        raw_path = kp_start_to_raw.get(kp_start)
        if raw_path is None:
            no_tile += len(kp_idxs)
            continue
        dim = re.search(r'_(\d+)x(\d+)\.bin$', os.path.basename(raw_path))
        w, h = int(dim.group(1)), int(dim.group(2))
        raw = np.fromfile(raw_path, dtype=np.int32).reshape(h, w)
        # F250's input is Q16 (mid-gray=0x800000); doh() expects Q10 → shift
        # by 6 to bring f250_raw_tile down to Q10.
        ixx, iyy, ixy, resp = M.doh((raw >> 6).astype(np.int64))
        kps = M.nms(resp)
        kps_q16 = M.subpix_refine_kps(resp, kps)
        pred_by_xy = {}
        for s, xq, yq in kps_q16:
            xi = (xq + 0x8000) >> 16
            yi = (yq + 0x8000) >> 16
            pred_by_xy[(xi, yi)] = (xq, yq)
        run_match = 0
        for ki in kp_idxs:
            rec = np.frombuffer(load_orient_before_bytes(ki), dtype=np.int32)
            ref_xq, ref_yq = int(rec[5]), int(rec[6])
            ref_xi = (ref_xq + 0x8000) >> 16
            ref_yi = (ref_yq + 0x8000) >> 16
            total_kps += 1
            if (ref_xi, ref_yi) in pred_by_xy:
                p_xq, p_yq = pred_by_xy[(ref_xi, ref_yi)]
                if p_xq == ref_xq and p_yq == ref_yq:
                    run_match += 1
                    total_match += 1
            else:
                no_predicted += 1
        # Only print mismatched runs.
        if run_match != len(kp_idxs):
            print(f'  kp_start={kp_start:>4} tid={tid}  '
                  f'{run_match}/{len(kp_idxs)} byte-exact')
    print(f'\nTOTAL byte-exact: {total_match}/{total_kps}')
    print(f'  no_tile (kp_start not gx-matched): {no_tile}')
    print(f'  no_predicted (NMS peak not at orient_before integer position): {no_predicted}')


if __name__ == '__main__':
    main()
