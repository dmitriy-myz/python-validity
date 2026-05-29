"""Overlay two captured ws_body files and extract the per-zone CONSTANT
byte skeleton (bytes that don't change between captures) vs the VARIANT
positions (bytes derived from each enrollment session).

Output for each zone:
  - skeleton:  bytes where they match (kept as-is), 0xXX placeholder where they differ
  - variant positions: list of byte offsets within the zone that vary
  - hex dumps of both captures aligned for visual inspection

The skeleton becomes a template we COPY into our from-scratch builder.
The variant positions are what we still need to DERIVE from our extraction.
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from validitysensor.moh_opencv import find_v30_regions


def hex_pretty(buf, mark_at=None):
    """Hex with '..' substituted at mark_at positions (variant marker)."""
    mark_at = set(mark_at or ())
    out = []
    for i, b in enumerate(buf):
        if i in mark_at:
            out.append('..')
        else:
            out.append(f'{b:02x}')
        if (i + 1) % 16 == 0:
            out.append('\n')
        elif (i + 1) % 4 == 0:
            out.append(' ')
    return ''.join(out)


def analyze_zone(a, b, label, offset, length):
    za = a[offset:offset+length]
    zb = b[offset:offset+length]
    variant = [i for i in range(length) if za[i] != zb[i]]
    n_var = len(variant)
    n_const = length - n_var
    print(f'\n=== {label}  [{offset}..{offset+length})  len={length}  '
          f'const={n_const}  variant={n_var} ===')
    if n_var == 0:
        print(f'  ENTIRELY CONSTANT, value: {za.hex()}')
        return
    if n_const == 0:
        print(f'  ENTIRELY VARIANT (sample): A={za[:32].hex()} ... B={zb[:32].hex()} ...')
        return
    # Build the skeleton: same bytes as constant, '??' as variant.
    print(f'  variant positions: {variant if len(variant) < 32 else f"{variant[:32]}... ({n_var} total)"}')
    print(f'  capture A:\n', hex_pretty(za, variant))
    print(f'  capture B:\n', hex_pretty(zb, variant))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('a', help='first ws_body capture')
    ap.add_argument('b', help='second ws_body capture')
    args = ap.parse_args()

    a = open(args.a, 'rb').read()
    b = open(args.b, 'rb').read()
    assert len(a) == len(b) == 23056

    # WS header zones
    analyze_zone(a, b, 'WS header [0..64)', 0, 64)
    # Specific sub-fields
    analyze_zone(a, b, '  geometry_stats', 44, 20)

    # Section pre-v30 zones — use the production region finder
    regions = find_v30_regions(a)
    print(f'\nv30 regions found: {regions}')

    prev_end = 64
    for i, r in enumerate(regions):
        analyze_zone(a, b, f'section{i}_pre_v30', prev_end, r - prev_end)
        prev_end = r + 4500

    # Tail
    if prev_end < len(a):
        analyze_zone(a, b, 'tail', prev_end, len(a) - prev_end)


if __name__ == '__main__':
    main()
