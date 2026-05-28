"""Where does doh(f250>>6) diverge from captured nms_resp? Bucket diff
pixels by distance-to-border to see whether the bug is purely border
(safe — NMS margin=10) or extends into the inner region (taints subpix).
"""
import os, sys, glob, re
import numpy as np
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from validitysensor.moh_native import doh

DUMP = os.environ.get('FRIDA_DUMP_DIR', '/media/sf_vbox-rw/finger/frida_dumps')


def _ts(p, pre):
    m = re.search(rf'{pre}_(\d+)_', os.path.basename(p)); return int(m.group(1)) if m else 0


def pair_nms_to_f250():
    nms = sorted(glob.glob(os.path.join(DUMP, 'nms_resp_*_call*_*x*.bin')),
                 key=lambda p: _ts(p, 'nms_resp'))
    f250 = sorted(glob.glob(os.path.join(DUMP, 'f250_raw_tile_*_call*_*x*.bin')),
                  key=lambda p: _ts(p, 'f250_raw_tile'))
    out = []
    for n in nms:
        nt = _ts(n, 'nms_resp')
        m = re.search(r'call(\d+)_(\d+)x(\d+)\.bin$', os.path.basename(n))
        ci, w, h = int(m.group(1)), int(m.group(2)), int(m.group(3))
        cand = [(p, _ts(p, 'f250_raw_tile')) for p in f250
                if _ts(p, 'f250_raw_tile') < nt
                and re.search(rf'_{w}x{h}\.bin$', os.path.basename(p))]
        out.append((ci, w, h, max(cand, key=lambda t: t[1])[0], n))
    return out


def per_border_dist_counts(diff_mask):
    h, w = diff_mask.shape
    rows = np.broadcast_to(np.arange(h)[:, None], (h, w))
    cols = np.broadcast_to(np.arange(w)[None, :], (h, w))
    dist = np.minimum(np.minimum(rows, cols),
                      np.minimum(h - 1 - rows, w - 1 - cols))
    out = []
    for d in range(11):
        if d < 10:
            band = (dist == d)
        else:
            band = (dist >= d)
        n_band = int(band.sum())
        n_diff = int((band & diff_mask).sum())
        out.append((d, n_band, n_diff))
    return out


def main():
    pairs = pair_nms_to_f250()
    print('Per-tile diff distribution by distance-to-border')
    print('(NMS margin=10 — diffs at dist>=10 reach NMS peaks; diffs <10 only matter for subpix neighborhoods on kps at margin edge)')
    print()
    aggregate = np.zeros(11, dtype=np.int64)
    aggregate_band = np.zeros(11, dtype=np.int64)
    for ci, w, h, f250_p, nms_p in pairs:
        raw = np.frombuffer(open(f250_p, 'rb').read(), dtype=np.int32).reshape(h, w)
        oracle = np.frombuffer(open(nms_p, 'rb').read(), dtype=np.int32).reshape(h, w)
        _, _, _, mine = doh(raw.astype(np.int64) >> 6)
        diff = (mine.astype(np.int64) != oracle.astype(np.int64))
        rows = per_border_dist_counts(diff)
        # Aggregate
        for d, nb, nd in rows:
            aggregate_band[d] += nb
            aggregate[d] += nd
        # Per-tile diff at >=10 (the danger zone)
        deep = sum(nd for d, _, nd in rows if d >= 10)
        deep_max = 0
        if deep:
            r = np.broadcast_to(np.arange(h)[:, None], (h, w))
            c = np.broadcast_to(np.arange(w)[None, :], (h, w))
            d10 = (np.minimum(np.minimum(r, c),
                              np.minimum(h - 1 - r, w - 1 - c)) >= 10)
            delta = (mine - oracle.astype(np.int64))[d10 & diff]
            deep_max = int(np.abs(delta).max()) if len(delta) else 0
        print(f'  call{ci:>2}  shape {w}x{h}  dist≥10 diffs: {deep:4d}  '
              f'max|Δ| in deep: {deep_max}')
    print()
    print('Aggregate across 12 tiles:')
    print(f'  {"dist":>4} {"band_px":>8} {"diff_px":>8} {"pct":>6}')
    for d in range(11):
        nb, nd = aggregate_band[d], aggregate[d]
        label = f'>={d}' if d == 10 else f'={d}'
        print(f'  {label:>4} {nb:>8} {nd:>8} {100*nd/max(nb,1):>5.1f}%')


if __name__ == '__main__':
    main()
