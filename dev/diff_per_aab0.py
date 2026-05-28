"""Per-AAB0-invocation diff: pair each minutia_table with its 9 F250 tiles
(reconstruct the input image), run my port, byte-diff against DLL's output.

Each minutia_table_*.bin = 250 records × 32B = the kp_array at AAB0 exit
(= post-A810-sort + post-A5B0-coord-update). Record layout per memory:
  +0x00..+0x07  ?
  +0x08         byte: CF90 sign flag (Ixx<0 AND Iyy<0 → 0)
  +0x09         byte: tile_id (post-sort grouping)
  +0x0a..+0x0c  ?
  +0x0c         i32: orient_q16 (from D920)
  +0x10         i32: abs(resp)
  +0x14         i32: AT EXIT, INTEGER global gx (A5B0+A910 overwrote Q16 subpix)
  +0x18         i32: INTEGER global gy
  +0x1c..+0x1f  ?
"""
import os, sys, glob, struct, re
import numpy as np
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from validitysensor import moh_native
# Allow overriding the resp threshold via env (e.g. RESP_THRESHOLD=0 to disable)
if 'RESP_THRESHOLD' in os.environ:
    moh_native.RESP_CULL_THRESHOLD = int(os.environ['RESP_THRESHOLD'])
    print(f'[*] RESP_CULL_THRESHOLD overridden to {moh_native.RESP_CULL_THRESHOLD}')
from validitysensor.moh_native import extract_frame_native, tile_origin, orient_to_index

DUMP = os.environ.get('FRIDA_DUMP_DIR', '/media/sf_vbox-rw/finger/frida_dumps')


def _ts(p, k):
    m = re.search(rf'{k}_(\d+)_', os.path.basename(p))
    return int(m.group(1)) if m else 0


def _shape(p):
    m = re.search(r'_(\d+)x(\d+)\.bin$', os.path.basename(p))
    return int(m.group(1)), int(m.group(2))


def load_minutia_tables():
    """Return list of (ts, records[250]) sorted by ts."""
    paths = sorted(glob.glob(os.path.join(DUMP, 'minutia_table_*.bin')),
                    key=lambda p: _ts(p, 'minutia_table'))
    out = []
    for p in paths:
        raw = open(p, 'rb').read()
        ts = _ts(p, 'minutia_table')
        n = len(raw) // 32
        recs = []
        for i in range(n):
            f = struct.unpack_from('<8i', raw, i * 32)
            recs.append({'bytes': raw[i*32:(i+1)*32],
                         'f0': f[0], 'f1': f[1], 'f2': f[2], 'f3': f[3],
                         'orient': f[3], 'resp': f[4],
                         'gx': f[5], 'gy': f[6], 'f7': f[7],
                         'byte8': raw[i*32+8], 'byte9': raw[i*32+9]})
        out.append((ts, recs))
    return out


def group_f250_by_aab0(minutia_ts_list):
    """Group F250 captures by which AAB0 invocation they belong to.

    Each AAB0 fires 18 F250 calls: 9 for the detect-path (via A4B0 → A1B0
    → F250) then 9 for the descriptor-gradient path (via A5B0 → A1B0 →
    F250). Call indices are monotonic across the whole capture session,
    so AAB0 #N → call indices [18*N .. 18*N+17].

    The minutia_ts_list is just used to limit how many AAB0 groups we
    return (one per minutia_table). We trust the call-index math, not the
    timestamps, because timestamps spread out when the chip is idle but
    call indices are tight."""
    f250s = sorted(glob.glob(os.path.join(DUMP, 'f250_raw_tile_*_call*_*x*.bin')),
                   key=lambda p: int(re.search(r'call(\d+)_', p).group(1)))
    groups = [[] for _ in minutia_ts_list]
    for p in f250s:
        ci = int(re.search(r'call(\d+)_', os.path.basename(p)).group(1))
        aab0_idx = ci // 18
        if aab0_idx < len(groups):
            groups[aab0_idx].append(p)
    return groups


def reconstruct_image(f250_paths, h=112, w=112):
    """Take 9 tiles from a single AAB0 invocation (the FIRST 9 by call index
    are the detect-path; the next 9 are descriptor-path with same content
    but at different times). Build the 112x112 input image."""
    # Use only the DETECT-path tiles: call000..call008 of this AAB0.
    detect_paths = sorted(f250_paths, key=lambda p: int(re.search(r'call(\d+)_', p).group(1)))[:9]
    if len(detect_paths) < 9:
        return None, f'only {len(detect_paths)} detect tiles'
    img = np.full((h, w), 0x800000, dtype=np.int32)
    written = np.zeros((h, w), dtype=bool)
    for p in detect_paths:
        ci = int(re.search(r'call(\d+)_', p).group(1)) % 9
        i, j = divmod(ci, 3)
        oy, ox = tile_origin(i, j, h, w)
        tw, th = _shape(p)
        tile = np.frombuffer(open(p, 'rb').read(), dtype=np.int32).reshape(th, tw)
        for ty in range(th):
            for tx in range(tw):
                ry, cx = oy + ty, ox + tx
                if 0 <= ry < h and 0 <= cx < w and not written[ry, cx]:
                    img[ry, cx] = tile[ty, tx]
                    written[ry, cx] = True
    if int(written.sum()) != h * w:
        return img, f'partial reconstruction ({int(written.sum())}/{h*w})'
    return img, None


def diff_aab0(idx, ts, recs, f250_paths):
    """For one AAB0 invocation: run my port on its input image, compare."""
    img, warn = reconstruct_image(f250_paths)
    if img is None:
        print(f'  AAB0 #{idx} (ts={ts}): SKIP - {warn}')
        return
    if warn:
        print(f'  AAB0 #{idx} (ts={ts}): warn - {warn}')

    my_out = extract_frame_native(img.astype(np.int64))

    # Compare by (gx, gy) integer match.
    # DLL records at AAB0 exit have INTEGER gx, gy (A5B0+A910 overwrote
    # the Q16 subpix). Our port returns (gx, gy, orient, desc) already
    # with integer gx, gy.
    dll_xy = {(r['gx'], r['gy']): r for r in recs}
    my_xy = {(gx, gy): (gx, gy, o, d) for (gx, gy, o, d) in my_out}

    common = set(dll_xy) & set(my_xy)
    only_mine = set(my_xy) - set(dll_xy)
    only_dll = set(dll_xy) - set(my_xy)

    print(f'  AAB0 #{idx} (ts={ts}): my={len(my_out)} dll={len(recs)}'
          f'  common(gx,gy)={len(common)}  only_mine={len(only_mine)}'
          f'  only_dll={len(only_dll)}')

    if common:
        # Orient comparison at matched positions. DLL stores integer index
        # (0..179) at +0xc; our port returns orient_q16. Convert ours via
        # orient_to_index for the comparison.
        n_orient_match = 0
        orient_diffs = []
        for xy in common:
            my_idx = orient_to_index(my_xy[xy][2])
            dll_idx = dll_xy[xy]['orient']
            if my_idx == dll_idx:
                n_orient_match += 1
            else:
                orient_diffs.append((my_idx, dll_idx, my_idx - dll_idx))
        print(f'      orient INDEX exact at matched (gx,gy): {n_orient_match}/{len(common)}')
        if orient_diffs:
            small_diff = sum(1 for _, _, d in orient_diffs if abs(d) <= 1)
            print(f'        orient diff |Δ|<=1: {small_diff}/{len(orient_diffs)}')

    # Characterize the divergent kps
    if only_mine and idx <= 2:
        print(f'      only_mine sample (first 5):')
        for xy in list(only_mine)[:5]:
            _, _, orient, _ = my_xy[xy]
            print(f'        ({xy[0]}, {xy[1]}) orient_idx={orient_to_index(orient)}')
        print(f'      only_dll sample (first 5):')
        for xy in list(only_dll)[:5]:
            r = dll_xy[xy]
            print(f'        ({xy[0]}, {xy[1]}) orient_idx={r["orient"]} resp={r["resp"]} tile_id={r["byte9"]} sign={r["byte8"]}')


def main():
    mts = load_minutia_tables()
    print(f'Found {len(mts)} minutia_table dumps (= AAB0 invocations)')
    if not mts:
        return

    minutia_ts_list = [t for (t, _) in mts]
    f250_groups = group_f250_by_aab0(minutia_ts_list)
    print(f'F250 captures grouped by AAB0 (count per AAB0):')
    print(f'  {[len(g) for g in f250_groups]}')
    print()

    # Check first record of each minutia_table to verify gx/gy are integers
    print('Sample first record from each minutia_table:')
    for idx, (ts, recs) in enumerate(mts[:2]):
        r0 = recs[0]
        print(f'  #{idx} ts={ts}: gx={r0["gx"]} gy={r0["gy"]} orient={r0["orient"]} '
              f'resp={r0["resp"]} tile_id={r0["byte9"]} byte8={r0["byte8"]}')
    print()

    for idx, (ts, recs) in enumerate(mts):
        diff_aab0(idx, ts, recs, f250_groups[idx])


if __name__ == '__main__':
    main()
