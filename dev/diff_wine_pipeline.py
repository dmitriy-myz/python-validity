"""End-to-end byte-diff: reconstruct the 112x112 image from captured F250
tiles (= what the DLL fed to sub_18000F250 at enrollment), run my port on
it, then diff at every stage against the captures.

What we diff (in order, stopping at the first divergence per kp):
  1. tile_image output vs captured F250 raw tiles  (per tile, byte-exact)
  2. doh resp vs captured nms_resp                  (per tile, byte-exact)
  3. nms kps vs captured nms_kp                     (per tile, set + order)
  4. subpix coords vs captured orient_before kp[+0x14, +0x18]
  5. A960 edge filter survivors
  6. global 250-cap survivors (per tile)
  7. orient_d920 vs captured orient_after kp[+0x0c]

Caveat: captured tiles span 9 F250 calls per frame, only 12 NMS calls total
across 9+3 = 2 frames. Frame 0 has all 9 tiles + NMS + orient_before/after,
so this is the diff target.

Run:
  ./.venv-poc/bin/python dev/diff_wine_pipeline.py
"""
import os, sys, glob, struct, re
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from validitysensor.moh_native import (
    GRID, GRID_X, FILL, FRAME_KP_CAP,
    tile_origin, tile_size, tile_image, doh, nms,
    subpix_refine_kp, orient_d920, descriptor_gradient,
    _a960_passes_global_edge, _descriptor_at,
)

DUMP = os.environ.get('FRIDA_DUMP_DIR', '/media/sf_vbox-rw/finger/frida_dumps')


def _ts(p, k):
    m = re.search(rf'{k}_(\d+)_', os.path.basename(p)); return int(m.group(1)) if m else 0


def load_frame0_tiles():
    """Return dict (i, j) -> (tile_q16 int32, w, h) for the 9 tiles of frame 0."""
    out = {}
    all_f250 = sorted(glob.glob(os.path.join(DUMP, 'f250_raw_tile_*_call*_*x*.bin')),
                       key=lambda p: _ts(p, 'f250_raw_tile'))
    # Frame 0 = the 9 tiles whose ts is just before the first NMS ts
    first_nms_ts = min(_ts(p, 'nms_resp') for p in glob.glob(
        os.path.join(DUMP, 'nms_resp_*_call0_*x*.bin')))
    # Take the 9 F250 calls just before first_nms_ts. Actually we want the 9 tiles
    # interleaved with NMS calls 0..8 — F250 fires per tile then NMS per tile.
    # Pair by call index: F250 call 000..008 = frame 0 tiles for (i,j) 0..8.
    for ci in range(9):
        i, j = divmod(ci, 3)
        p = glob.glob(os.path.join(DUMP, f'f250_raw_tile_*_call{ci:03d}_*x*.bin'))
        if not p:
            print(f'WARN: f250_raw_tile call{ci:03d} not found')
            continue
        p = p[0]
        m = re.search(r'_(\d+)x(\d+)\.bin$', os.path.basename(p))
        w, h = int(m.group(1)), int(m.group(2))
        tile = np.frombuffer(open(p, 'rb').read(), dtype=np.int32).reshape(h, w)
        out[(i, j)] = (tile.copy(), w, h)
    return out


def reconstruct_image(captured_tiles, h=112, w=112):
    """Reconstruct the 112x112 Q16 image by reading each frame pixel from
    the tile whose origin places it in the central (non-pad) region.

    Tile (i, j) origin = (i*37-10, j*37-10). The tile's central core (where
    the tile_image() blit actually copies image pixels, NOT padding) is
    tile-local indices [10, tile_h) x [10, tile_w). For frame pixel (r, c),
    the natural tile is (r // 37, c // 37) — that's the tile whose core
    region contains it.
    """
    img = np.full((h, w), 0x800000, dtype=np.int32)
    written = np.zeros((h, w), dtype=bool)
    for (i, j), (tile, tw, th) in captured_tiles.items():
        oy, ox = tile_origin(i, j, h, w)
        for ty in range(th):
            for tx in range(tw):
                ry = oy + ty
                cx = ox + tx
                if 0 <= ry < h and 0 <= cx < w:
                    if not written[ry, cx]:
                        img[ry, cx] = tile[ty, tx]
                        written[ry, cx] = True
    n_written = int(written.sum())
    assert n_written == h * w, f'only {n_written}/{h*w} pixels reconstructed'
    return img


def compare_tiles(reconstructed_img, captured_tiles):
    print('\n=== Stage 1: tile_image roundtrip ===')
    n_diff_total = 0
    for i, j, my_tile in tile_image(reconstructed_img):
        cap_tile, cw, ch = captured_tiles[(i, j)]
        if my_tile.shape != (ch, cw):
            print(f'  tile ({i},{j}): SHAPE MISMATCH mine={my_tile.shape} cap=({ch},{cw})')
            continue
        diff = (my_tile.astype(np.int32) != cap_tile)
        n_diff = int(diff.sum())
        n_diff_total += n_diff
        if n_diff:
            ys, xs = np.where(diff)
            d = (my_tile.astype(np.int64) - cap_tile.astype(np.int64))[diff]
            print(f'  tile ({i},{j}) {cw}x{ch}: {n_diff} diff px, max|Δ|={int(np.abs(d).max())}, first @ ({xs[0]},{ys[0]})')
        else:
            print(f'  tile ({i},{j}) {cw}x{ch}: byte-exact')
    print(f'  TOTAL diff pixels across 9 tiles: {n_diff_total}')
    return n_diff_total == 0


def compare_doh(captured_tiles):
    print('\n=== Stage 2: doh(tile>>6) vs captured nms_resp ===')
    n_diff_total = n_diff_inner = 0
    for ci in range(9):
        i, j = divmod(ci, 3)
        tile, w, h = captured_tiles[(i, j)]
        nms_resp_path = glob.glob(os.path.join(DUMP, f'nms_resp_*_call{ci}_*x*.bin'))[0]
        oracle = np.frombuffer(open(nms_resp_path, 'rb').read(), dtype=np.int32).reshape(h, w)
        _, _, _, mine = doh(tile.astype(np.int64) >> 6)
        diff = (mine.astype(np.int64) != oracle.astype(np.int64))
        n = int(diff.sum())
        # Inner region (dist >= 4) — what NMS+subpix actually touches
        r = np.broadcast_to(np.arange(h)[:, None], (h, w))
        c = np.broadcast_to(np.arange(w)[None, :], (h, w))
        inner = (np.minimum(np.minimum(r, c), np.minimum(h-1-r, w-1-c)) >= 4)
        n_inner = int((diff & inner).sum())
        n_diff_total += n
        n_diff_inner += n_inner
        print(f'  tile ({i},{j}) {w}x{h}: {n} diff px ({n_inner} in dist>=4 region)')
    print(f'  TOTAL: {n_diff_total} ({n_diff_inner} in NMS-eligible interior)')
    return n_diff_inner == 0


def load_nms_kp_records(call_idx):
    p = glob.glob(os.path.join(DUMP, f'nms_kp_*_call{call_idx}_n*.bin'))[0]
    raw = open(p, 'rb').read()
    return [struct.unpack_from('<8i', raw, i * 32) for i in range(len(raw) // 32)]


def compare_nms(captured_tiles):
    print('\n=== Stage 3: nms kps vs captured nms_kp ===')
    all_match = True
    for ci in range(9):
        i, j = divmod(ci, 3)
        tile, w, h = captured_tiles[(i, j)]
        _, _, _, resp = doh(tile.astype(np.int64) >> 6)
        my_kps = nms(resp)  # list of (score, x, y)
        cap = load_nms_kp_records(ci)
        cap_xy = [(r[5], r[6], r[4]) for r in cap]  # (x, y, score)
        my_xy = [(x, y, s) for (s, x, y) in my_kps]
        if len(my_xy) != len(cap_xy):
            print(f'  tile ({i},{j}) {w}x{h}: COUNT my={len(my_xy)} cap={len(cap_xy)}')
            all_match = False
            continue
        # Set compare (ignoring order)
        my_set = set((x, y, s) for (x, y, s) in my_xy)
        cap_set = set(cap_xy)
        if my_set != cap_set:
            extra_mine = my_set - cap_set
            extra_cap = cap_set - my_set
            print(f'  tile ({i},{j}): SET DIFF +mine={len(extra_mine)} +cap={len(extra_cap)}')
            for e in list(extra_mine)[:3]: print(f'    extra mine: {e}')
            for e in list(extra_cap)[:3]:  print(f'    extra cap:  {e}')
            all_match = False
            continue
        # Order compare
        if my_xy != cap_xy:
            n_order_diff = sum(1 for a, b in zip(my_xy, cap_xy) if a != b)
            print(f'  tile ({i},{j}): same set ({len(my_xy)} kps), {n_order_diff} order diffs')
        else:
            print(f'  tile ({i},{j}) {w}x{h}: byte-exact ({len(my_xy)} kps)')
    return all_match


def compare_subpix_and_orient(captured_tiles):
    print('\n=== Stage 4-7: subpix + A960 + cap + orient ===')
    # Load orient_before/after records (first 250 = frame 0)
    orient_kps = []
    for p in glob.glob(os.path.join(DUMP, 'orient_before_*_kp*.bin')):
        m = re.search(r'_kp(\d{4})\.bin$', os.path.basename(p))
        if m: orient_kps.append((int(m.group(1)), open(p,'rb').read()))
    orient_kps.sort()
    orient_after = {}
    for p in glob.glob(os.path.join(DUMP, 'orient_after_*_kp*.bin')):
        m = re.search(r'_kp(\d{4})\.bin$', os.path.basename(p))
        if m: orient_after[int(m.group(1))] = open(p, 'rb').read()

    # Per-tile subrun sizes (frame 0):
    SUBRUN = [29, 27, 17, 33, 36, 33, 30, 26, 19]
    cursor = 0
    cap_per_tile = {}  # tile_id -> list of (subpix_x_q16, subpix_y_q16, orient_q16, abs_resp)
    for ti, sz in enumerate(SUBRUN):
        cap_per_tile[ti] = []
        for j in range(cursor, cursor + sz):
            r = orient_kps[j][1]
            f0, _, _, _, resp, sx, sy, _ = struct.unpack_from('<8i', r, 0)
            after = orient_after.get(orient_kps[j][0])
            orient_q16 = struct.unpack_from('<i', after, 0x0c)[0] if after else None
            cap_per_tile[ti].append((sx, sy, orient_q16, resp))
        cursor += sz

    # Run my port through Phase 1+2+3 (cull) for each tile, comparing against
    # captured orient_before kp records.
    pool = []
    for ci in range(9):
        i, j = divmod(ci, 3)
        tile, w, h = captured_tiles[(i, j)]
        _, _, _, resp = doh(tile.astype(np.int64) >> 6)
        my_kps = nms(resp)
        oy, ox = tile_origin(i, j, 112, 112)
        n_after_subpix = n_after_a960 = 0
        for score, lx, ly in my_kps:
            r = subpix_refine_kp(resp, lx, ly)
            if r is None: continue
            sx, sy = r
            n_after_subpix += 1
            if not _a960_passes_global_edge(sx, sy, oy, ox, 112, 112):
                continue
            n_after_a960 += 1
            pool.append((score, ci, i, j, sx, sy))
        cap_count = SUBRUN[ci]
        print(f'  tile {ci}: nms={len(my_kps)} subpix_keep={n_after_subpix} a960_keep={n_after_a960}  (cap_final={cap_count})')

    # Global cap
    pool.sort(key=lambda r: -r[0])
    pool = pool[:FRAME_KP_CAP]
    pool.sort(key=lambda r: (r[1], -r[0]))

    print(f'\n  Phase 2+3: pool after cap = {len(pool)}')
    from collections import Counter
    per_tile_count = Counter(r[1] for r in pool)
    print('  Per-tile final counts (predicted vs actual):')
    for ti in range(9):
        pred = per_tile_count.get(ti, 0)
        act = SUBRUN[ti]
        flag = 'OK' if pred == act else f'OFF {pred-act:+d}'
        print(f'    tile {ti}: {pred:3d} / {act:3d}  {flag}')

    # Per-kp diff: match my pool kp to cap_per_tile by descending resp rank
    print('\n  Per-kp subpix diff (matching by rank within tile):')
    n_byte_exact = n_subpix_diff = n_orient_diff = 0
    n_total = 0
    for ti in range(9):
        cap_list = cap_per_tile[ti]
        my_list = [(r[4], r[5], r[0]) for r in pool if r[1] == ti]  # (sx, sy, score)
        # Both should be in resp-descending order within the tile
        for rank in range(min(len(cap_list), len(my_list))):
            c_sx, c_sy, c_orient, c_resp = cap_list[rank]
            m_sx, m_sy, m_resp = my_list[rank]
            n_total += 1
            if (c_sx, c_sy) == (m_sx, m_sy):
                # Subpix match — compute my orient and compare
                tile, w, h = captured_tiles[(divmod(ti, 3))]
                gradX, gradY = descriptor_gradient(tile.astype(np.int64))
                my_orient = orient_d920(gradX, gradY, m_sx, m_sy)
                if c_orient is None or my_orient == c_orient:
                    n_byte_exact += 1
                else:
                    n_orient_diff += 1
                    if n_orient_diff <= 3:
                        print(f'    tile {ti} rank {rank}: subpix exact ({m_sx},{m_sy}) but orient differs my={my_orient} cap={c_orient}')
            else:
                n_subpix_diff += 1
                # Global coords for both
                oy, ox = tile_origin(ti // 3, ti % 3, 112, 112)
                m_gx = ((ox << 16) + m_sx) >> 16
                m_gy = ((oy << 16) + m_sy) >> 16
                c_gx = ((ox << 16) + c_sx) >> 16
                c_gy = ((oy << 16) + c_sy) >> 16
                print(f'    tile {ti} rank {rank}: subpix mine=({m_sx/65536:.2f},{m_sy/65536:.2f}) gxy=({m_gx},{m_gy}) resp={m_resp}  '
                      f'cap=({c_sx/65536:.2f},{c_sy/65536:.2f}) gxy=({c_gx},{c_gy}) resp={c_resp}')

    print(f'\n  TOTAL kps compared: {n_total}')
    print(f'    byte-exact: {n_byte_exact}')
    print(f'    subpix diff: {n_subpix_diff}')
    print(f'    orient diff only: {n_orient_diff}')


def main():
    print('Loading frame-0 captures...')
    captured = load_frame0_tiles()
    print(f'  Got {len(captured)} tiles')
    for (i, j), (_, w, h) in sorted(captured.items()):
        print(f'    ({i},{j}): {w}x{h}')

    print('\nReconstructing 112x112 image from tiles...')
    img = reconstruct_image(captured, 112, 112)
    print(f'  Reconstructed image dtype={img.dtype} shape={img.shape} '
          f'min={img.min()} max={img.max()} mean={img.mean():.0f}')

    compare_tiles(img, captured)
    compare_doh(captured)
    compare_nms(captured)
    compare_subpix_and_orient(captured)


if __name__ == '__main__':
    main()
