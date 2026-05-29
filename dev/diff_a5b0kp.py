"""Diff A5B0 kp-array dumps (before/after each call) to discover whether
sub_18000A5B0 modifies or culls keypoints.

The hook (GDB_DUMP_A5B0_KP=1 in dev/gdb_dump.py) dumps:
  a5b0kp_before_<ts>_call<NN>_tile<T>_s<S>_e<E>_n<count>_ng<n_good>.bin
  a5b0kp_after_<ts>_call<NN>_tile<T>_s<S>_e<E>_n<count>_ng<n_good>.bin
each = count × 32 bytes (the full kp_array).

The `tile<T>` label in filenames is incorrect — it's [rsp+0x38] (= arg7 =
a config constant 10), not the tile_id. The actual tile_id at the call
is in r13; we don't have it here. But the (s, e) range is the per-tile
slice in the kp_array, and 9 consecutive calls = 1 frame (250 records).

Per kp the 32-byte record layout (from dev/MOH.md + memory):
  +0x00  qword  head/desc-buffer ptr (initialized by AAB0 right before
                this loop, may be overwritten by A5B0)
  +0x08  u8     flag (1 default, 0 if (Ixx<0 AND Iyy<0) — set by NMS)
  +0x09  u8     tile_id (0..8, row-major in 3×3 grid)
  +0x0a  u8     orient-quality
  +0x0b  u8     ?
  +0x0c  u32    orient_q16 (set by D920)
  +0x10  i32    response (resp)
  +0x14  u32    subpix_x_q16 (overwritten by post-A5B0 A910 with int gx,gy)
  +0x18  u32    subpix_y_q16
  +0x1c  u32    ?
"""
import glob
import os
import sys

DUMP_DIR = os.environ.get('FRIDA_DUMP_DIR', '/media/sf_vbox-rw/finger/frida_dumps')

FIELDS = [
    (0x00, 8, 'head'),
    (0x08, 1, 'flag8'),
    (0x09, 1, 'tile9'),
    (0x0a, 1, 'qual'),
    (0x0b, 1, 'b0b'),
    (0x0c, 4, 'orient'),
    (0x10, 4, 'resp'),
    (0x14, 4, 'sx'),
    (0x18, 4, 'sy'),
    (0x1c, 4, 'tail'),
]


def parse_meta(name):
    # a5b0kp_<before|after>_<ts>_call<NN>_tile<T>_s<S>_e<E>_n<count>_ng<ng>.bin
    base = os.path.basename(name).removesuffix('.bin')
    parts = base.split('_')
    # parts: [a5b0kp, before/after, ts, callNN, tileT, sS, eE, nN, ngNG]
    return {
        'when': parts[1],
        'ts': int(parts[2]),
        'call': int(parts[3][len('call'):]),
        'tile_label': int(parts[4][len('tile'):]),
        's': int(parts[5][len('s'):]),
        'e': int(parts[6][len('e'):]),
        'n': int(parts[7][len('n'):]),
        'ng': int(parts[8][len('ng'):]),
        'path': name,
    }


def pair_calls():
    befores = {parse_meta(p)['call']: p
               for p in glob.glob(os.path.join(DUMP_DIR, 'a5b0kp_before_*.bin'))}
    afters = {parse_meta(p)['call']: p
              for p in glob.glob(os.path.join(DUMP_DIR, 'a5b0kp_after_*.bin'))}
    common = sorted(set(befores) & set(afters))
    return [(c, befores[c], afters[c]) for c in common]


def diff_call(call, before_path, after_path):
    meta = parse_meta(before_path)
    s, e, n, ng = meta['s'], meta['e'], meta['n'], meta['ng']
    with open(before_path, 'rb') as f:
        before = f.read()
    with open(after_path, 'rb') as f:
        after = f.read()
    assert len(before) == len(after) == n * 32, \
        f'size mismatch: {len(before)} vs {len(after)} expected {n*32}'

    # per-kp diff
    per_kp_changed = []  # list of (kp_idx, byte_count_changed)
    field_changes = {f[2]: 0 for f in FIELDS}  # field_name -> kps_with_change_in_this_field
    for k in range(n):
        b = before[k*32:(k+1)*32]
        a = after[k*32:(k+1)*32]
        if b != a:
            ndiff = sum(1 for x, y in zip(b, a) if x != y)
            per_kp_changed.append((k, ndiff))
            for off, sz, name in FIELDS:
                if b[off:off+sz] != a[off:off+sz]:
                    field_changes[name] += 1

    in_range = sum(1 for k, _ in per_kp_changed if s <= k < e)
    out_range = sum(1 for k, _ in per_kp_changed if not (s <= k < e))
    print(f'call{call:02d}  s={s:3d} e={e:3d} (in-range={e-s})  '
          f'changed_kps={len(per_kp_changed)}  '
          f'in_range={in_range}  out_range={out_range}')
    nonzero_fields = [(n, c) for n, c in field_changes.items() if c]
    if nonzero_fields:
        flds = ' '.join(f'{n}={c}' for n, c in nonzero_fields)
        print(f'        fields:  {flds}')


def main():
    pairs = pair_calls()
    if not pairs:
        print(f'no paired dumps in {DUMP_DIR}')
        sys.exit(1)
    print(f'paired {len(pairs)} A5B0 calls')
    print()
    # column headers
    print('  call    range       changed=in+out   fields changed (kp-count)')
    print('  ----    -----       --------------   ------------------------')
    for call, b, a in pairs:
        diff_call(call, b, a)


if __name__ == '__main__':
    main()
