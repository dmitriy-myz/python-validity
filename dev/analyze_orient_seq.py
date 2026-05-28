"""Look at orient_before in detail: where do CF90 raster-scan resets actually
appear? Print (x_int, y_int) for the full 1024 sequence to spot boundaries."""
import os, glob, struct, re

DUMP = os.environ.get('FRIDA_DUMP_DIR', '/media/sf_vbox-rw/finger/frida_dumps')

kps = []
for p in glob.glob(os.path.join(DUMP, 'orient_before_*_kp*.bin')):
    m = re.search(r'_kp(\d{4})\.bin$', os.path.basename(p))
    if m:
        kps.append((int(m.group(1)), open(p, 'rb').read()))
kps.sort()

# Field 0 sequence to map out base values where allocations restart
print('Field-0 BASE VALUES (look for repetitive resets):')
seen_bases = set()
prev_delta = None
for i, (kpi, r) in enumerate(kps):
    f0 = struct.unpack_from('<i', r, 0)[0]
    if i > 0:
        prev_f0 = struct.unpack_from('<i', kps[i-1][1], 0)[0]
        d = f0 - prev_f0
        if d != 16:
            print(f'  kp{i:4d}: f0={f0:>10}  delta_from_prev={d:>+8}  '
                  f'prev_f0={prev_f0}')
            if i < 30 or i > len(kps) - 5:
                pass
            else:
                pass

# Print the actual field 0 base at start of each run, with their xy
print()
print('Run starts (after non-+16 deltas) — first 30:')
boundaries = [0]
for i in range(1, len(kps)):
    f0c = struct.unpack_from('<i', kps[i][1], 0)[0]
    f0p = struct.unpack_from('<i', kps[i-1][1], 0)[0]
    if f0c - f0p != 16:
        boundaries.append(i)
boundaries.append(len(kps))

print(f'  {len(boundaries)-1} runs total')
import collections
sizes = [boundaries[i+1]-boundaries[i] for i in range(len(boundaries)-1)]
ctr = collections.Counter(sizes)
print('  run-size histogram:')
for sz in sorted(ctr):
    print(f'    size={sz:>3}: {ctr[sz]:>4} runs   (total kps in these runs: {sz*ctr[sz]})')

# Maybe the right bucketing is by FIELD 2:
print()
print('Field 2 sequence (first 60 kps):')
for i in range(min(60, len(kps))):
    f0, f1, f2 = struct.unpack_from('<3i', kps[i][1], 0)
    x = struct.unpack_from('<i', kps[i][1], 0x14)[0] / 65536
    y = struct.unpack_from('<i', kps[i][1], 0x18)[0] / 65536
    print(f'  kp{i:>3}: f0={f0:>7} f2={f2:>10}  x={x:5.2f} y={y:5.2f}')
