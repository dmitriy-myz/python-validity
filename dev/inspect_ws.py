"""Annotate every byte zone of a captured Wine ws_body.

Walks the 23056-byte WS body and labels each zone with:
  - offset range
  - zone name + memory ref where defined
  - hex content (truncated for long zones)
  - decoded value when format is known
  - status: KNOWN / PARTIAL / UNKNOWN

This is the spec the from-scratch builder works against. Run it on
multiple captured ws_body files to diff and surface session-variant vs
constant bytes.

Usage:
  ./.venv-poc/bin/python dev/inspect_ws.py <ws_body.bin> [<another.bin>]

With one arg: full annotated dump.
With two args: only zones whose bytes DIFFER between the two captures.
"""
import argparse
import os
import struct
import sys


# Each zone: (offset, length, name, status, decoder)
#   decoder(bytes) -> str   (human-readable interpretation, or '' if raw hex)
def _zeros(b): return f'zeros' if b == b'\0' * len(b) else f'NON-ZERO ({b.hex()})'
def _u16le(b): return f'u16 = {struct.unpack("<H", b)[0]} (0x{struct.unpack("<H", b)[0]:x})'
def _u32le(b): return f'u32 = {struct.unpack("<I", b)[0]} (0x{struct.unpack("<I", b)[0]:x})'
def _u8s(b):   return f'bytes = {list(b)}'
def _raw(b):
    if len(b) <= 32:
        return b.hex()
    return f'{b[:16].hex()}...{b[-8:].hex()} ({len(b)}B)'


# WS body header [0..64)
HEADER_ZONES = [
    (0, 4, 'zeros', 'KNOWN', _zeros),
    (4, 4, 'size_u32', 'KNOWN', _u32le),
    (8, 8, 'fixed_config', 'KNOWN', lambda b: f'const 06 02 05 00 02 00 08 01 (matches: {b == bytes.fromhex("0602050002000801")})'),
    (16, 8, 'accepted_frame_ids', 'KNOWN',
     lambda b: f'frame_ids[0..8) bytes = {list(b)}; reverse = {list(reversed(b))}'),
    (24, 16, 'per_section_counts_4', 'KNOWN',
     lambda b: f'4 u32s = {struct.unpack("<IIII", b)} (per-section minutia counts for first 4 sections)'),
    (40, 4, 'section5_count_plus_flags', 'PARTIAL',
     lambda b: f'bytes = {list(b)}; likely byte[0]={b[0]} = 5th section count + 3 bytes of flags/extra'),
    (44, 20, 'geometry_stats', 'UNKNOWN', _raw),
]


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from validitysensor.moh_opencv import find_v30_regions  # noqa: E402


def analyze(ws):
    """Yield (offset, length, name, status, value_str)."""
    # Header
    for off, ln, name, status, dec in HEADER_ZONES:
        yield off, ln, name, status, dec(ws[off:off+ln])

    # Section discovery
    regions = find_v30_regions(ws)
    # Section starts: WS header ends at 64. Section i v30 record start = regions[i].
    # Section i body ends at regions[i] + 250*18 = regions[i] + 4500.
    for i, rstart in enumerate(regions):
        # Pre-v30 area for this section: from prev section end (or 64) to rstart
        prev_end = regions[i-1] + 4500 if i > 0 else 64
        pre_len = rstart - prev_end

        # The v30 TLV header (12B) lives at rstart - 29 (= 12 + 17 lead-in)
        # if section 0; for subsequent sections, the lead-in may differ.
        # Show the pre-v30 zone as a single UNKNOWN blob for now.
        yield prev_end, pre_len, f'section{i}_pre_v30', 'UNKNOWN', _raw(ws[prev_end:rstart])

        # v30 records
        yield rstart, 4500, f'section{i}_v30_records', 'KNOWN', (
            f'250 × [u8 x][u8 y][16B desc]; '
            f'first record: x={ws[rstart]} y={ws[rstart+1]} '
            f'desc={ws[rstart+2:rstart+18].hex()}; '
            f'first nonzero count: {sum(1 for k in range(250) if ws[rstart+k*18:rstart+(k+1)*18] != b"\\0"*18)}'
        )

    # Tail after last v30 records
    last = regions[-1] + 4500
    if last < len(ws):
        yield last, len(ws) - last, 'tail', 'UNKNOWN', _raw(ws[last:])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('ws_body', nargs='+',
                    help='one or two captured ws_body_<ts>_23056.bin files')
    args = ap.parse_args()

    if len(args.ws_body) > 2:
        print('at most 2 files supported')
        sys.exit(1)

    bodies = []
    for p in args.ws_body:
        b = open(p, 'rb').read()
        print(f'{os.path.basename(p)}: {len(b)} bytes')
        bodies.append(b)

    if len(bodies) == 1:
        ws = bodies[0]
        print('\nFull zone dump:')
        print(f'{"offset":>8s}  {"end":>8s}  {"len":>5s}  {"status":<8s}  {"name":<28s}  value')
        print('-' * 130)
        for off, ln, name, status, value in analyze(ws):
            print(f'{off:>8d}  {off+ln:>8d}  {ln:>5d}  {status:<8s}  {name:<28s}  {value}')
    else:
        # Two-file diff mode: show zones whose bytes differ
        a, b = bodies
        if len(a) != len(b):
            print(f'!!! size mismatch {len(a)} vs {len(b)}; comparing common prefix')
        n = min(len(a), len(b))
        zones_a = list(analyze(a))
        print('\nZone-by-zone diff (zones with at least 1 differing byte):')
        print(f'{"offset":>8s}  {"len":>5s}  {"status":<8s}  {"name":<28s}  diffs  a→b sample')
        print('-' * 130)
        for off, ln, name, status, _ in zones_a:
            if off + ln > n:
                continue
            za, zb = a[off:off+ln], b[off:off+ln]
            diff = [i for i in range(ln) if za[i] != zb[i]]
            if not diff:
                continue
            sample = ', '.join(f'[{i}] {za[i]:#04x}→{zb[i]:#04x}'
                                for i in diff[:6])
            print(f'{off:>8d}  {ln:>5d}  {status:<8s}  {name:<28s}  '
                  f'{len(diff):5d}  {sample}'
                  + (' ...' if len(diff) > 6 else ''))


if __name__ == '__main__':
    main()
