"""Validate the E090 oriented-BRIEF rotation+sampling+aggregation port
byte-exact against the DLL's captured 58-i32 BRIEF input buffer.

Oracle (per-kp, 1024 kps captured at TS prefix 1779951*):
  descbrief_kp_before_kp####.bin     64B  — kp record (orient_q16 @+0xc,
                                            subpix_x @+0x14, subpix_y @+0x18)
  descbrief_samples_kp####.bin     16KB  — [rsp+0x58] dump; first 58 i32 are
                                            the BRIEF input (rest zero-padded)

Needed (re-run enrollment with `GDB_DUMP_DESC_BRIEF=1`, hooks added in
dev/gdb_dump.py this session):
  descbrief_gradstruct_ctx000.bin  ≤64B — *(ctx[+0x50]): stride@+0, height@+4,
                                            gradX_ptr@+0x20, gradY_ptr@+0x28
  descbrief_gradX_ctx000_<W>x<H>.bin       i32 array, stride·height entries
  descbrief_gradY_ctx000_<W>x<H>.bin       i32 array, stride·height entries
  descbrief_aggrtbl_ctx000.bin    ≥348B — *(ctx[+0x60]): 29 entries × 12B
                                            (3 i32: size_idx, dy, dx)

Pipeline per kp (matches sub_18000E090 e0b1..e5c0):
  1. idx = trunc(orient_q16 · 180 / (π·65536))                       (mod 360)
  2. (rotated_gx, rotated_gy) = desc_sample_rotate(gradX, gradY,
                                                  subpix_x, subpix_y, idx, N=7)
  3. samples = desc_aggregate(rotated_gx, rotated_gy, aggr_table,
                              win_sizes=[7, 5, 3], N=7)
  4. assert samples == descbrief_samples_kp####.bin[:58]

Run:
  ./.venv-poc/bin/python dev/validate_e090.py            # check capture state,
                                                          # print first kp diff
  ./.venv-poc/bin/python dev/validate_e090.py --all      # full 1024-kp scan
"""
import os, sys, glob, struct, argparse
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from validitysensor.moh_native import (
    COS_Q16, SIN_Q16, orient_to_index, desc_sample_rotate, desc_aggregate,
)

DUMP = os.environ.get('FRIDA_DUMP_DIR', '/media/sf_vbox-rw/finger/frida_dumps')

# ─── small local table at [rsp+0x78..0x80] in E090 (from e1e1-e243) ──────
# [0]=ctx[+0x34]=7, [1]=trunc(((7·2.0)/3.0)+0.999999)=5, [2]=ctx[+0x34]/2=3.
# Verified disasm at e1ec (·2.0/3.0+0.999999) — constants from .rdata.
WIN_SIZES = [7, 5, 3]
N = 7


# ─── capture-file loaders ────────────────────────────────────────────────
# Each capture-file kind has its OWN ts_ms in the filename (kp_before is
# written ~3ms before samples for the same kp).  So we glob by kind+suffix
# and take the most recent match instead of pinning a single ts prefix.
def _glob_one(pat):
    fs = glob.glob(os.path.join(DUMP, pat))
    if not fs:
        return None
    fs.sort(key=os.path.getmtime, reverse=True)
    return fs[0]


def _load_kp(i):
    """Return (orient_q16, subpix_x_q16, subpix_y_q16) for kp #i."""
    p = _glob_one(f'descbrief_kp_before_*_kp{i:04d}.bin')
    if p is None:
        raise FileNotFoundError(f'descbrief_kp_before_*_kp{i:04d}.bin')
    with open(p, 'rb') as f:
        kp = f.read()
    return (struct.unpack_from('<i', kp, 0xc)[0],
            struct.unpack_from('<i', kp, 0x14)[0],
            struct.unpack_from('<i', kp, 0x18)[0])


def _load_samples(i):
    """Return the 58-i32 oracle (the actual BRIEF input buffer)."""
    p = _glob_one(f'descbrief_samples_*_kp{i:04d}.bin')
    if p is None:
        raise FileNotFoundError(f'descbrief_samples_*_kp{i:04d}.bin')
    with open(p, 'rb') as f:
        buf = f.read()
    return np.frombuffer(buf[:58 * 4], dtype=np.int32)


def _load_gradients():
    """Returns either:
      - dict (kp_start -> (gradX, gradY)) for the per-tile capture format
        `descbrief_gradstruct_<ts>_t<NN>_kp<####>.bin` (preferred — new hook
        in dev/gdb_dump.py), where kp_start is the first kp index this
        gradient applies to.  Resolve a kp's grad with `floor`-style lookup.
      - (None, reason) if no gradient capture is present.
    """
    import re
    new_gs = glob.glob(os.path.join(DUMP, 'descbrief_gradstruct_*_t*_kp*.bin'))
    if new_gs:
        out = {}
        for gs_path in new_gs:
            m = re.search(r'_t(\d+)_kp(\d+)\.bin$', os.path.basename(gs_path))
            if not m:
                continue
            kp_start = int(m.group(2))
            with open(gs_path, 'rb') as f:
                gs = f.read()
            stride = int.from_bytes(gs[0:4], 'little', signed=True)
            height = int.from_bytes(gs[4:8], 'little', signed=True)
            if not (0 < stride <= 512 and 0 < height <= 512):
                continue
            tag = re.search(r'(_t\d+_kp\d+)\.bin', os.path.basename(gs_path)).group(1)
            gx_path = _glob_one(f'descbrief_gradX_*{tag}_{stride}x{height}.bin')
            gy_path = _glob_one(f'descbrief_gradY_*{tag}_{stride}x{height}.bin')
            if gx_path is None or gy_path is None:
                continue
            gx = np.frombuffer(open(gx_path, 'rb').read(),
                               dtype=np.int32).reshape(height, stride).copy()
            gy = np.frombuffer(open(gy_path, 'rb').read(),
                               dtype=np.int32).reshape(height, stride).copy()
            out[kp_start] = (gx, gy)
        if out:
            return out, None
    # Fallback: legacy single-gradient capture (only tile 0 valid).
    legacy = _glob_one('descbrief_gradstruct_*ctx*.bin')
    if legacy is None:
        return None, ('descbrief_gradstruct_*.bin missing — re-run a capture '
                      'with GDB_DUMP_DESC_BRIEF=1 (updated dev/gdb_dump.py '
                      'now captures per-tile gradient buffers).')
    with open(legacy, 'rb') as f:
        gs = f.read()
    stride = int.from_bytes(gs[0:4], 'little', signed=True)
    height = int.from_bytes(gs[4:8], 'little', signed=True)
    gx_path = _glob_one(f'descbrief_gradX_*ctx*_{stride}x{height}.bin')
    gy_path = _glob_one(f'descbrief_gradY_*ctx*_{stride}x{height}.bin')
    if gx_path is None or gy_path is None:
        return None, (f'legacy descbrief_gradX/Y_*_{stride}x{height}.bin '
                      'missing alongside gradstruct.')
    gx = np.frombuffer(open(gx_path, 'rb').read(),
                       dtype=np.int32).reshape(height, stride).copy()
    gy = np.frombuffer(open(gy_path, 'rb').read(),
                       dtype=np.int32).reshape(height, stride).copy()
    return {0: (gx, gy)}, None


def _pick_gradient(grads_by_start, kp_idx):
    """Floor lookup: the largest kp_start <= kp_idx wins."""
    starts = sorted(grads_by_start.keys())
    pick = starts[0]
    for s in starts:
        if s <= kp_idx:
            pick = s
        else:
            break
    return grads_by_start[pick]


def _load_aggrtbl():
    """Returns the 29×3 i32 aggregation table (size_idx, dy, dx), or
    (None, reason) if not captured yet."""
    p = _glob_one('descbrief_aggrtbl_*ctx*.bin')
    if p is None:
        return None, ('descbrief_aggrtbl_*.bin missing — re-run a capture '
                      'with the updated hook to populate.')
    with open(p, 'rb') as f:
        buf = f.read()
    n = 29
    tbl = np.frombuffer(buf[:n * 12], dtype=np.int32).reshape(n, 3)
    return tbl, None


def _load_ctx_count():
    """ctx[+0x68] = number of aggregation positions (=29 expected)."""
    p = _glob_one('descbrief_ctx_*_ctx000.bin')
    if p is None:
        return 29
    with open(p, 'rb') as f:
        ctx = f.read()
    return struct.unpack_from('<i', ctx, 0x68)[0]


# ─── per-keypoint pipeline ───────────────────────────────────────────────
def run_one(gradX, gradY, aggr_table, orient_q16, sx_q16, sy_q16):
    """Reproduce the E090 stages 1+2 for one keypoint. Returns 58 i32."""
    idx = orient_to_index(orient_q16) % 360
    rgx, rgy = desc_sample_rotate(gradX, gradY, sx_q16, sy_q16, idx, N=N)
    return desc_aggregate(rgx, rgy, aggr_table, WIN_SIZES, N=N)


def diff(ours, oracle):
    """Return (n_mismatch, first_diff_idx_or_-1, ours, oracle).  Both are
    flat int32 arrays; ours==oracle iff every i32 matches."""
    ours = np.asarray(ours, dtype=np.int32)
    oracle = np.asarray(oracle, dtype=np.int32)
    mism = np.where(ours != oracle)[0]
    return len(mism), (mism[0] if len(mism) else -1), ours, oracle


# ─── CLI ─────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--all', action='store_true', help='scan all 1024 kps')
    ap.add_argument('--n', type=int, default=1, help='kps to run (default 1)')
    ap.add_argument('--start', type=int, default=0, help='first kp index')
    args = ap.parse_args()

    print(f'dump dir: {DUMP}')

    grads, reason = _load_gradients()
    if grads is None:
        print()
        print('=== BLOCKED — gradient buffer not yet captured ===')
        print(f'  {reason}')
        print()
        print('To unblock: re-run enrollment under Wine with the updated hook:')
        print('    gdb -p <wine-pid> -x dev/gdb_dump.py  '
              '(set GDB_DUMP_DESC_BRIEF=1 in env)')
        print('Until then we can\'t reproduce the per-pixel sampling step.')
        try:
            o = _load_samples(0)
            orient, sx, sy = _load_kp(0)
            print(f'\noracle kp0 ready: orient={orient}  subpix=({sx/65536:.2f},{sy/65536:.2f})')
            print(f'  first 16 i32 of 58-sample buf: {o[:16].tolist()}')
        except FileNotFoundError as e:
            print(f'\noracle missing too: {e}')
        return 1

    aggr_tbl, reason = _load_aggrtbl()
    if aggr_tbl is None:
        print(f'BLOCKED on aggregation table: {reason}')
        return 1

    n_pos = _load_ctx_count()
    sample_grad = next(iter(grads.values()))[0]
    print(f'gradient buffers: {len(grads)} tile(s) covering '
          f'kp_starts={sorted(grads.keys())[:10]}... '
          f'({sample_grad.shape[1]}×{sample_grad.shape[0]} each)')
    print(f'aggr_table: {aggr_tbl.shape}  ctx[+0x68]={n_pos} positions')
    if aggr_tbl.shape[0] < n_pos:
        print(f'WARN: aggr_tbl has {aggr_tbl.shape[0]} entries but ctx says {n_pos}')

    n_run = 1024 if args.all else args.n
    total = 0
    matched = 0
    first_bad = None
    for i in range(args.start, args.start + n_run):
        try:
            orient, sx, sy = _load_kp(i)
            oracle = _load_samples(i)
        except FileNotFoundError:
            break
        gradX, gradY = _pick_gradient(grads, i)
        ours = run_one(gradX, gradY, aggr_tbl[:n_pos], orient, sx, sy)
        n_mis, first_idx, ours_a, oracle_a = diff(ours, oracle)
        total += 1
        if n_mis == 0:
            matched += 1
        elif first_bad is None:
            first_bad = (i, n_mis, first_idx, ours_a, oracle_a, orient, sx, sy)

    print()
    print(f'matched {matched}/{total} keypoints byte-exact')
    if first_bad:
        i, n_mis, first_idx, ours_a, oracle_a, orient, sx, sy = first_bad
        print(f'\nfirst mismatch — kp{i}: {n_mis}/58 i32 differ; first @ idx {first_idx}')
        print(f'  kp inputs:  orient_q16={orient}  subpix=({sx/65536:.3f},{sy/65536:.3f})  '
              f'idx={orient_to_index(orient) % 360}')
        print(f'  ours[:16]:   {ours_a[:16].tolist()}')
        print(f'  oracle[:16]: {oracle_a[:16].tolist()}')

    return 0 if matched == total else 2


if __name__ == '__main__':
    sys.exit(main())
