"""Inspect orient_before kp records to find the right tile-bucketing signal."""
import os, glob, struct, re
import numpy as np

DUMP = os.environ.get('FRIDA_DUMP_DIR', '/media/sf_vbox-rw/finger/frida_dumps')


def load_all():
    out = []
    for p in glob.glob(os.path.join(DUMP, 'orient_before_*_kp*.bin')):
        m = re.search(r'_kp(\d{4})\.bin$', os.path.basename(p))
        if m:
            out.append((int(m.group(1)), open(p, 'rb').read()))
    out.sort()
    return out


def main():
    kps = load_all()
    print(f'total orient_before: {len(kps)}\n')

    # Dump first 20 kps full i32 fields
    print('First 20 kps as 8×i32:')
    print(f'{"idx":>4} {"f0":>10} {"f1":>10} {"f2":>10} {"f3":>10} '
          f'{"resp":>10} {"x_q16":>10} {"y_q16":>10} {"f7":>10}')
    for i in range(min(20, len(kps))):
        kpi, raw = kps[i]
        fields = struct.unpack_from('<8i', raw, 0)
        print(f'{kpi:>4} ' + ' '.join(f'{v:>10}' for v in fields))
    print()

    # Are there any kp records longer than 32B?
    sizes = set(len(r) for _, r in kps)
    print(f'kp record sizes: {sizes}\n')

    # Range of subpix x/y (Q16 → pixels):
    xs = [struct.unpack_from('<i', r, 0x14)[0] / 65536 for _, r in kps]
    ys = [struct.unpack_from('<i', r, 0x18)[0] / 65536 for _, r in kps]
    print(f'x range: [{min(xs):.2f}, {max(xs):.2f}]')
    print(f'y range: [{min(ys):.2f}, {max(ys):.2f}]')
    print()

    # Tile-detection candidates:
    # Field 0 → scale/pass? Field 1 → frame? Field 2 → tile_id? Field 3 → ?
    for fi in range(8):
        if fi in (4, 5, 6):
            continue
        vals = [struct.unpack_from('<i', r, fi*4)[0] for _, r in kps]
        uniq = set(vals)
        if len(uniq) < 50:
            print(f'field {fi}: {len(uniq)} unique values: '
                  f'{sorted(uniq)[:20]}{"..." if len(uniq)>20 else ""}')

    # Look at x/y to see how they cluster. Tile-local coords are [0..57].
    # If kps are bucketed per-tile, we'd see x/y stay in [0..57] but with
    # internal jumps that correspond to tile transitions. If they're global
    # to the 112×112 frame, x/y span [0..112].
    print()
    print('Sample of (kp_idx, x_pixel, y_pixel) every 50:')
    for i in range(0, len(kps), 50):
        kpi, r = kps[i]
        x = struct.unpack_from('<i', r, 0x14)[0] / 65536
        y = struct.unpack_from('<i', r, 0x18)[0] / 65536
        # Also unpack all i32s as a hint
        f = struct.unpack_from('<8i', r, 0)
        print(f'  kp{kpi:>4}: x={x:6.2f} y={y:6.2f}  fields={f}')


if __name__ == '__main__':
    main()
