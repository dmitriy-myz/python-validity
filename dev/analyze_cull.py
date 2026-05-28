"""Diagnose the ~50 kps/tile cull mismatch between CF90 (NMS exit) and D920
(orientation entry) using a combined GDB capture.

Capture needed (run once):
  GDB_DUMP_F250=1 GDB_DUMP_NMS=1 GDB_DUMP_ORIENT=1 gdb -p <WUDFHost> -x dev/gdb_dump.py

Two hypotheses (see memory `native-enrollment-status`):
  (A) doh() non-peak fidelity bug → port produces extra/different kps.
  (B) Missing cull stage between CF90 and D920 in the port.

Resolves both by:
  1. Per-tile byte-diff of doh(f250_raw_tile >> 6) vs captured nms_resp.
  2. Per-tile count of CF90 outputs (nms_kp file) vs D920 entries
     (orient_before kps bucketed by tile, detected from coord jumps).

Run:
  ./.venv-poc/bin/python dev/analyze_cull.py
"""
import os, sys, glob, re, struct
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from validitysensor.moh_native import doh

DUMP = os.environ.get('FRIDA_DUMP_DIR', '/media/sf_vbox-rw/finger/frida_dumps')


def _ts(path, prefix):
    m = re.search(rf'{prefix}_(\d{{13}})_', os.path.basename(path))
    return int(m.group(1)) if m else 0


def _load_i32(path, shape=None):
    a = np.frombuffer(open(path, 'rb').read(), dtype=np.int32)
    return a.reshape(shape) if shape else a


# ─── tile pairing ────────────────────────────────────────────────────────
# F250 fires per tile (every tile, every frame). NMS fires only for tiles
# that have a populated response (12 across the whole capture). For each
# nms_resp_callN_<W>x<H>.bin, the matching f250_raw_tile is the F250 call
# whose timestamp is the LARGEST < nms_resp's ts (i.e. fires just before).
def pair_nms_to_f250():
    nms_resps = sorted(glob.glob(os.path.join(DUMP, 'nms_resp_*_call*_*x*.bin')),
                       key=lambda p: _ts(p, 'nms_resp'))
    f250s = sorted(glob.glob(os.path.join(DUMP, 'f250_raw_tile_*_call*_*x*.bin')),
                   key=lambda p: _ts(p, 'f250_raw_tile'))
    pairs = []
    for nms in nms_resps:
        nms_ts = _ts(nms, 'nms_resp')
        m = re.search(r'call(\d+)_(\d+)x(\d+)\.bin$', os.path.basename(nms))
        call_idx, w, h = int(m.group(1)), int(m.group(2)), int(m.group(3))
        # Largest F250 ts strictly < nms_ts with matching shape.
        cand = [(p, _ts(p, 'f250_raw_tile')) for p in f250s
                if _ts(p, 'f250_raw_tile') < nms_ts
                and re.search(rf'_{w}x{h}\.bin$', os.path.basename(p))]
        if not cand:
            print(f'  WARN no F250 for nms call{call_idx}'); continue
        f250_path = max(cand, key=lambda t: t[1])[0]
        pairs.append((call_idx, w, h, f250_path, nms))
    return pairs


# ─── nms_kp ──────────────────────────────────────────────────────────────
def load_nms_kp_counts():
    """Per-call count from filename suffix _n<count>.bin."""
    counts = {}
    for p in glob.glob(os.path.join(DUMP, 'nms_kp_*_call*_n*.bin')):
        m = re.search(r'call(\d+)_n(\d+)\.bin$', os.path.basename(p))
        if m:
            counts[int(m.group(1))] = int(m.group(2))
    return counts


def load_nms_kps(call_idx):
    """Return list of (abs_resp, x_int, y_int) for nms_kp_call<idx>."""
    p = glob.glob(os.path.join(DUMP, f'nms_kp_*_call{call_idx}_n*.bin'))
    if not p:
        return []
    raw = open(p[0], 'rb').read()
    n = len(raw) // 32
    out = []
    for i in range(n):
        rec = struct.unpack_from('<8i', raw, i * 32)
        # Memory: [0,0,0,0, abs(resp), x, y, 0]
        out.append((rec[4], rec[5], rec[6]))
    return out


# ─── orient_before ───────────────────────────────────────────────────────
def load_orient_before_all():
    """Return list of (kp_idx, full_32B) sorted by kp index."""
    rec = []
    for p in glob.glob(os.path.join(DUMP, 'orient_before_*_kp*.bin')):
        m = re.search(r'_kp(\d{4})\.bin$', os.path.basename(p))
        if m:
            with open(p, 'rb') as f:
                rec.append((int(m.group(1)), f.read()))
    rec.sort()
    return rec


def orient_subpix_yx(rec_bytes):
    """Return (x_q16, y_q16) from kp record fields +0x14/+0x18."""
    return (struct.unpack_from('<i', rec_bytes, 0x14)[0],
            struct.unpack_from('<i', rec_bytes, 0x18)[0])


# ─── tile boundary detection in orient_before ────────────────────────────
def detect_tile_boundaries(all_orient):
    """Field 0 (offset 0x00) is a kp_array pointer that increments by exactly
    16B per kp within a tile. Any other delta = tile boundary."""
    import struct
    boundaries = [0]
    prev_f0 = None
    for i, (_, rec) in enumerate(all_orient):
        f0 = struct.unpack_from('<i', rec, 0)[0]
        if prev_f0 is not None and (f0 - prev_f0) != 16:
            boundaries.append(i)
        prev_f0 = f0
    boundaries.append(len(all_orient))
    return boundaries


def main():
    pairs = pair_nms_to_f250()
    nms_counts = load_nms_kp_counts()
    print(f'Found {len(pairs)} nms_resp/f250 pairs')
    print()

    # ─── Hypothesis A: doh() byte-diff per tile ──────────────────────────
    print('═' * 78)
    print('Hypothesis A — doh(f250>>6) vs captured nms_resp, byte-exact per tile')
    print('═' * 78)
    print(f'{"call":>4} {"w":>3} {"h":>3} {"diff_px":>8} {"diff%":>6}'
          f' {"max|Δ|":>10} {"first_diff":>14}')
    a_total_diff = 0
    a_total_px = 0
    for call_idx, w, h, f250_p, nms_p in pairs:
        raw = _load_i32(f250_p, (h, w))         # Q16
        oracle = _load_i32(nms_p, (h, w))       # DLL resp
        _, _, _, mine = doh(raw.astype(np.int64) >> 6)
        diff_mask = (mine.astype(np.int64) != oracle.astype(np.int64))
        n_diff = int(diff_mask.sum())
        a_total_diff += n_diff
        a_total_px += h * w
        if n_diff:
            delta = (mine.astype(np.int64) - oracle.astype(np.int64))[diff_mask]
            max_abs = int(np.abs(delta).max())
            ys, xs = np.where(diff_mask)
            first = f'({xs[0]},{ys[0]})'
        else:
            max_abs = 0
            first = '-'
        print(f'{call_idx:>4} {w:>3} {h:>3} {n_diff:>8} '
              f'{100*n_diff/(h*w):>5.1f}% {max_abs:>10} {first:>14}')
    print()
    print(f'  TOTAL diff pixels: {a_total_diff} / {a_total_px} '
          f'({100*a_total_diff/a_total_px:.2f}%)')
    print()

    # ─── Hypothesis B: CF90 output count vs D920 entry count per tile ────
    print('═' * 78)
    print('Hypothesis B — CF90 outputs (nms_kp count) vs D920 entries (orient_before)')
    print('═' * 78)
    all_orient = load_orient_before_all()
    print(f'  orient_before total kps: {len(all_orient)}')
    boundaries = detect_tile_boundaries(all_orient)
    print(f'  Detected {len(boundaries)-1} tile runs in orient_before (by y-drop)')
    print()
    # Per-tile-run sizes
    print(f'  Run sizes: {[boundaries[i+1]-boundaries[i] for i in range(len(boundaries)-1)]}')
    print()
    print(f'{"call":>4} {"CF90_out":>9} {"orient_run":>11} {"survival":>10}')
    # Match each NMS call (in order) to the next orient_before run.
    nms_calls = sorted(set(c for c, *_ in pairs))
    for j, call_idx in enumerate(nms_calls):
        cf90 = nms_counts.get(call_idx, -1)
        if j < len(boundaries) - 1:
            run = boundaries[j+1] - boundaries[j]
        else:
            run = -1
        pct = (100 * run / cf90) if cf90 > 0 and run >= 0 else 0
        print(f'{call_idx:>4} {cf90:>9} {run:>11} {pct:>9.1f}%')


if __name__ == '__main__':
    main()
