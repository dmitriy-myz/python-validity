"""Parse the WS body of a Wine-captured finger template using the layout
inferred from map_template_layout.py output:

  WS[0..4]    u32  end_of_features_ptr (in capture1 = 18496)
  WS[4..16]   12 bytes — stable header words (mostly)
  WS[16..20]  u32  reserved = 0
  WS[20..36]  4 × u32 counts, one per section, varying per session
  WS[36..end] feature data divided into sections separated by stable
              anchors at offsets 4829, 4845, 9433, 13973
  WS[~18496..23056]  zero padding to fill out the 23056-byte buffer

The script:
  1. Decodes the header
  2. Finds the anchor positions
  3. Reports each anchor's bytes (raw + decoded)
  4. Defines candidate sections and prints (offset, size, count) tuples
  5. For each section, tests whether the data inside looks like fixed-size
     records by checking byte-frequency periodicity (compares lane stats
     for record sizes 8, 12, 16, 20, 24, 28, 32, 40)

Usage:
    python -m dev.dissect_ws [path1] [path2]
       paths default to /tmp/wine_finger_fresh.bin and …fresh2.bin
"""
import collections
import math
import os
import struct
import sys
from typing import List, Optional, Tuple


# Anchor signatures validated across 5 distinct Wine captures (2 fingers,
# 2 modes — see dev/extract_finger_templates.py). Offsets are RELATIVE TO
# THE CHIP-VIEW WS BODY (envelope offset − 12; the WS body is the 23056-byte
# TLV1 payload at envelope[12..23068]).
#
# Each anchor is byte-stable across every captured template. Section
# trailer markers carry a u32 BE index in their leading 4 bytes; observed
# indices form the sequence 4, 5, 6, 7, (8 in mode B) — sections are
# numbered 4..N, not 0..N.
ANCHORS = [
    (  223, 70),    # env 235:  section-4 trailer, 57 zeros + `04 00 b8 11…fa`
    ( 4817, 15),    # env 4829: short marker `00000068 00040000 00000003 0004 00`
    ( 4833, 43),    # env 4845: section-5 trailer (43 bytes stable across both modes;
                    #            mode B has an additional 21 bytes through env 4909)
    ( 9421, 16),    # env 9433: section-6 trailer `00000006…fa` (last 2 bytes session tail)
    (13961, 16),    # env 13973: section-7 trailer `00000007…fa`
    (18508,  8),    # env 18520: section-7/8 boundary, 8 zeros (stable in BOTH modes;
                    #            in mode B section 8 follows, ending at the pre-TLV2 region)
    (23047,  9),    # env 23059: trailing 9 zeros of WS body, just before the TLV2 header
                    #            (the TLV2 header `02 00 20 00` at env 23068..23072 lives
                    #             OUTSIDE the WS body — written by the envelope serializer)
    # Anchors RULED OUT by multi-capture analysis (were coincidental
    # 2-capture matches, not real structure):
    #   - (5083, 4): bytes `60c4d090` at env 5095
    #   - (17401, 4): bytes `c34e8799` at env 17413
]


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = collections.Counter(b)
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def parse_header(ws: bytes) -> dict:
    """Decode the first 40 bytes of the chip-view WS body.

    Header layout (offsets relative to envelope offset 12):
      WS[ 0.. 4]  4 leading zero bytes (natural padding)
      WS[ 4.. 8]  u32 end_of_features_ptr
      WS[ 8..20]  3 × u32 header words (last one is the mode discriminator)
      WS[20..24]  u32 reserved = 0
      WS[24..40]  4 × u32 section counts
    """
    leading,     = struct.unpack_from('<I', ws, 0)
    end_ptr,     = struct.unpack_from('<I', ws, 4)
    hdr_words    = struct.unpack_from('<3I', ws, 8)
    reserved,    = struct.unpack_from('<I', ws, 20)
    counts       = struct.unpack_from('<4I', ws, 24)
    return {
        'leading':     leading,           # always 0 in observed captures
        'end_ptr':     end_ptr,
        'hdr_words':   hdr_words,
        'reserved':    reserved,
        'counts':      counts,
        'feature_data_start': 40,
        'feature_data_end':   end_ptr,
    }


def print_header(hdr: dict, label: str):
    print(f'{label}:')
    print(f'  WS[ 0.. 4] leading zeros     = 0x{hdr["leading"]:08x}')
    print(f'  WS[ 4.. 8] end_features_ptr  = {hdr["end_ptr"]:>6d}  (0x{hdr["end_ptr"]:04x})')
    print(f'  WS[ 8..20] header words      = {[f"0x{w:08x}" for w in hdr["hdr_words"]]}')
    print(f'  WS[20..24] reserved          = 0x{hdr["reserved"]:08x}')
    print(f'  WS[24..40] section counts    = {hdr["counts"]}  (sum={sum(hdr["counts"])})')


def carve_sections(ws: bytes, hdr: dict) -> List[Tuple[int, int, str]]:
    """Return list of (start, end, label) tuples for the body regions.

    Boundaries: feature_data_start, anchor positions, end_ptr, end-of-WS.
    """
    boundaries = [hdr['feature_data_start']]
    for off, length in ANCHORS:
        boundaries.append(off)
        boundaries.append(off + length)
    boundaries.append(hdr['end_ptr'])
    boundaries.append(len(ws))
    boundaries = sorted(set(boundaries))

    regions = []
    for a, b in zip(boundaries, boundaries[1:]):
        if b - a == 0:
            continue
        is_anchor = any(off == a and (a + length) == b for off, length in ANCHORS)
        if is_anchor:
            label = 'anchor'
        elif a >= hdr['end_ptr']:
            label = 'zero-pad'
        else:
            label = 'section'
        regions.append((a, b, label))
    return regions


def lane_byte_frequencies(buf: bytes, period: int) -> List[collections.Counter]:
    """For each lane 0..period-1, count byte values at positions lane, lane+period, …"""
    lanes = [collections.Counter() for _ in range(period)]
    for i, byte in enumerate(buf):
        lanes[i % period][byte] += 1
    return lanes


def lane_entropy(buf: bytes, period: int) -> List[float]:
    """Per-lane entropy. Used to detect record structure: if some lanes have
    much lower entropy than others (e.g. lane 3,7,11 mostly == 0xff for sign
    bits of small negatives, lane 4,8,12 mostly == 0x00) the period is right.
    """
    lanes = lane_byte_frequencies(buf, period)
    out = []
    for c in lanes:
        n = sum(c.values()) or 1
        out.append(-sum((v / n) * math.log2(v / n) for v in c.values() if v > 0))
    return out


def lane_top_value(buf: bytes, period: int) -> List[Tuple[int, float]]:
    """Per-lane: most common byte value + its frequency. Helps surface
    'every Nth byte is mostly 0xff' patterns from sign-extension."""
    lanes = lane_byte_frequencies(buf, period)
    out = []
    for c in lanes:
        n = sum(c.values()) or 1
        top_byte, top_count = c.most_common(1)[0]
        out.append((top_byte, top_count / n))
    return out


def try_periods(buf: bytes, periods: List[int]) -> None:
    """Score periodicity for several candidate record sizes."""
    overall_e = _entropy(buf)
    print(f'    overall entropy: {overall_e:.3f} bits/byte (raw)')
    print(f'    period  lane-entropy spread       best-evidence-byte:freq  size/period evidence')
    for p in periods:
        if len(buf) < p * 4:
            continue
        es = lane_entropy(buf, p)
        tops = lane_top_value(buf, p)
        spread = max(es) - min(es)
        # Identify the lane with the LOWEST entropy (most structured) and its top byte
        weakest = min(range(p), key=lambda i: es[i])
        b, f = tops[weakest]
        marker = '  ← interesting' if (spread > 0.5 and f > 0.4) else ''
        print(f'      {p:>3d}    {spread:>5.2f}                    '
              f'lane {weakest:>2d}: 0x{b:02x} ({f*100:.0f}%)'
              f'   {marker}')


def diff_section(a_buf: bytes, b_buf: bytes, period: int) -> None:
    """Diff two captures' bytes within one section. If records have a fixed
    period, the diff density per lane should cluster on particular lanes
    (the lanes carrying variable content) and zero on padding lanes."""
    n = min(len(a_buf), len(b_buf))
    diffs = bytearray(1 if a_buf[i] != b_buf[i] else 0 for i in range(n))
    per_lane = [0] * period
    counts   = [0] * period
    for i, d in enumerate(diffs):
        per_lane[i % period] += d
        counts[i % period]   += 1
    print(f'    diff vs other capture, by lane (period={period}):')
    for lane in range(period):
        if counts[lane] == 0:
            continue
        pct = 100 * per_lane[lane] / counts[lane]
        bar = '█' * int(pct / 5)
        print(f'      lane {lane:>2d}: {pct:>5.1f}%  {bar}')


# ─── Variable-length record discovery ──────────────────────────────────

def find_signature_byte(buf: bytes, expected_count: int,
                         tolerance: int = 3) -> List[Tuple[float, int, int, float, float]]:
    """Find byte values whose occurrences are roughly evenly spaced AND
    number close to expected_count.

    If records are length-prefixed (byte[0] = length or type), the first
    byte of each record likely takes a small set of values. Find which
    byte value v satisfies:
      - occurs (expected_count ± tolerance) times in the buffer
      - spacing between occurrences has low stdev (= regular)

    Returns sorted list of (stdev, value, count, mean_spacing, min_spacing).
    """
    candidates = []
    for v in range(256):
        positions = [i for i, b in enumerate(buf) if b == v]
        if abs(len(positions) - expected_count) > tolerance:
            continue
        if len(positions) < 2:
            continue
        spacings = [positions[i + 1] - positions[i] for i in range(len(positions) - 1)]
        mean = sum(spacings) / len(spacings)
        var = sum((s - mean) ** 2 for s in spacings) / len(spacings)
        stdev = var ** 0.5
        candidates.append((stdev, v, len(positions), mean, min(spacings)))
    candidates.sort()
    return candidates


# A small library of candidate "record-walker" rules. Each rule takes
# (buf, pos) and returns the start of the next record, or None to reject.
WALKER_RULES = {
    'byte[0] is total record length':
        lambda b, p: p + b[p] if 8 <= b[p] <= 200 else None,
    'byte[0]+1 is total length':
        lambda b, p: p + b[p] + 1 if 7 <= b[p] <= 200 else None,
    'byte[0] is payload length, +1 for length byte itself':
        lambda b, p: p + b[p] + 1 if 7 <= b[p] <= 200 else None,
    'low 7 bits of byte[0] is total length':
        lambda b, p: p + (b[p] & 0x7f) if 8 <= (b[p] & 0x7f) <= 100 else None,
    'byte[1] is total length':
        lambda b, p: p + b[p + 1] if p + 1 < len(b) and 8 <= b[p + 1] <= 200 else None,
    'u16 LE at offset 0 is total length':
        lambda b, p: (p + int.from_bytes(b[p:p + 2], 'little')
                      if p + 2 <= len(b) and 8 <= int.from_bytes(b[p:p + 2], 'little') <= 200
                      else None),
}


def try_length_walkers(buf: bytes, expected_count: int) -> None:
    n = len(buf)
    found_any = False
    for name, rule in WALKER_RULES.items():
        pos = 0
        records = []
        ok = True
        while pos < n:
            try:
                nxt = rule(buf, pos)
            except IndexError:
                ok = False
                break
            if nxt is None or nxt <= pos or nxt > n:
                ok = False
                break
            records.append((pos, nxt - pos))
            pos = nxt
        if ok and pos == n:
            star = ' ★ matches expected count!' if len(records) == expected_count else ''
            print(f'      ok: "{name}" → {len(records)} records, '
                  f'consumes all {n} bytes{star}')
            found_any = True
        else:
            # Don't spam failures unless they got far
            if len(records) > expected_count // 2:
                print(f'      partial: "{name}" → {len(records)} records, '
                      f'stopped at offset {pos}/{n}')
    if not found_any:
        print('      (no length-walker rule consumed the section exactly)')


def show_records(buf: bytes, expected_count: int, max_show: int = 6) -> None:
    """If we found a working walker that produces expected_count records,
    print the first few records' bytes for visual inspection."""
    for name, rule in WALKER_RULES.items():
        pos = 0
        recs = []
        while pos < len(buf):
            try:
                nxt = rule(buf, pos)
            except IndexError:
                break
            if nxt is None or nxt <= pos or nxt > len(buf):
                break
            recs.append((pos, nxt - pos))
            pos = nxt
        if len(recs) == expected_count and pos == len(buf):
            print(f'\n      first {max_show} records as parsed by "{name}":')
            for off, length in recs[:max_show]:
                print(f'        +{off:>4d} len={length:>3d}  {buf[off:off+min(length, 40)].hex()}'
                      f'{"…" if length > 40 else ""}')
            sizes = collections.Counter(length for _, length in recs)
            print(f'      record-size histogram: '
                  f'{sorted(sizes.items())[:10]}')
            return
    # No matching walker — just dump the first few suspected boundaries
    # using the avg spacing as a guide
    avg = len(buf) / expected_count
    print(f'\n      (no clean walker; dumping snapshots at every ~{avg:.0f} bytes)')
    for k in range(min(max_show, expected_count)):
        off = int(round(k * avg))
        snippet = buf[off:off + 24]
        print(f'        +{off:>4d}  {snippet.hex()}')


def main(path1='/tmp/wine_finger_fresh.bin',
         path2='/tmp/wine_finger_fresh2.bin'):
    data1 = open(path1, 'rb').read()
    data2 = open(path2, 'rb').read() if path2 else None
    # WS body is the chip-view TLV1 payload at envelope[12..12+23056]
    ws1 = data1[12:12 + 23056]
    ws2 = data2[12:12 + 23056] if data2 else None
    assert len(ws1) == 23056

    print(f'=== {path1} ===')
    hdr1 = parse_header(ws1)
    print_header(hdr1, 'header')
    print()

    if ws2 is not None:
        print(f'=== {path2} ===')
        hdr2 = parse_header(ws2)
        print_header(hdr2, 'header')
        print()

    # Anchors verbatim
    print('=== anchors (bytes shown for capture1) ===')
    for off, length in ANCHORS:
        chunk = ws1[off:off + length]
        print(f'  offset {off:>5d}  ({length:>2d} bytes)  {chunk.hex()}')
        if ws2 is not None and chunk != ws2[off:off + length]:
            print(f'    ↑ differs from capture2: {ws2[off:off+length].hex()}')
    print()

    # Section carving
    regions = carve_sections(ws1, hdr1)
    print('=== regions ===')
    print(f'  {"offset":>8s}  {"end":>8s}  {"size":>5s}  kind       entropy  c2 same?')
    for a, b, label in regions:
        size = b - a
        e = _entropy(ws1[a:b])
        same = ''
        if ws2 is not None:
            same = '✓' if ws1[a:b] == ws2[a:b] else f'{sum(1 for i in range(a,b) if ws1[i]!=ws2[i])} differ'
        print(f'  {a:>8d}  {b:>8d}  {size:>5d}  {label:<10s} {e:>5.2f}    {same}')
    print()

    # Section-by-section variable-length record discovery.
    # The 4 u32 counts in the WS header correspond to the 4 MAIN feature
    # sections (size > 1000), not to every region between anchors.
    print('=== variable-length record discovery ===')
    big_sections = [r for r in regions if r[2] == 'section' and (r[1] - r[0]) > 1000]
    small_sections = [r for r in regions if r[2] == 'section' and (r[1] - r[0]) <= 1000]
    print(f'(found {len(big_sections)} main feature sections, '
          f'{len(small_sections)} small/prelude regions)')
    if small_sections:
        print('  small/prelude regions (not paired with a count):')
        for a, b, _ in small_sections:
            sz = b - a
            ent = _entropy(ws1[a:b])
            print(f'    WS[{a}..{b}]  size={sz}  entropy={ent:.2f}')

    for i, (a, b, _) in enumerate(big_sections):
        size = b - a
        cnt = hdr1['counts'][i] if i < len(hdr1['counts']) else None
        avg = size / cnt if cnt else 0
        print(f'\n  main section {i}: WS[{a}..{b}]  size={size}  count={cnt}  avg={avg:.1f} bytes/rec')
        buf = ws1[a:b]

        # 1. Signature-byte search
        print('    signature-byte search (byte values whose '
              f'occurrence count ≈ {cnt}, ranked by spacing regularity):')
        sigs = find_signature_byte(buf, cnt, tolerance=3) if cnt else []
        if not sigs:
            print('      (no byte value occurs the expected number of times)')
        else:
            for stdev, v, occ, mean, min_sp in sigs[:5]:
                print(f'      byte 0x{v:02x} ({v:>3d})  '
                      f'occurs {occ:>3d}× mean_spacing={mean:>5.1f} '
                      f'stdev={stdev:>5.1f} min_spacing={min_sp}')

        # 2. Length-walker search
        print('    length-walker search (rules that consume the section exactly):')
        if cnt:
            try_length_walkers(buf, cnt)
            show_records(buf, cnt, max_show=8)

        # 3. Same-finger diff (still useful as sanity check)
        if ws2 is not None:
            buf2 = ws2[a:b]
            n_diff = sum(1 for j in range(size) if buf[j] != buf2[j])
            print(f'\n    inter-capture diff: {n_diff}/{size} bytes differ '
                  f'({100*n_diff/size:.1f}%) — confirms section carries '
                  f'session-variable feature content')


def multi_capture_report(template_dir: str = '/tmp/finger_templates') -> None:
    """Run a multi-capture stability analysis across every template file
    in `template_dir`. Useful for separating real structural anchors from
    coincidental 2-capture matches.

    For each captured template:
      - Decode the WS header (end_ptr, mode bytes, counts)
      - Group templates by mode (header_words[2])
    For each section in each mode:
      - Report which bytes are stable across all templates in that mode
      - Surface section trailers found at unexpected positions
    """
    import glob
    paths = sorted(glob.glob(os.path.join(template_dir, '*.bin')))
    if not paths:
        print(f'no templates in {template_dir}', file=sys.stderr)
        return

    # Load and dedup
    by_hash = {}
    for p in paths:
        d = open(p, 'rb').read()
        key = hash(d)
        if key not in by_hash:
            by_hash[key] = (os.path.basename(p), d)
    templates = list(by_hash.values())
    print(f'=== {len(templates)} unique templates ===')
    for name, _ in templates:
        print(f'  {name}')
    print()

    # Group by mode (header word 3 = WS[16..20] = envelope[28..32] is the
    # mode discriminator).
    def mode_of(t):
        return struct.unpack_from('<I', t, 28)[0]

    modes = {}
    for name, data in templates:
        m = mode_of(data)
        modes.setdefault(m, []).append((name, data))

    print(f'=== {len(modes)} distinct modes detected ===')
    for m, ts in sorted(modes.items()):
        # end_ptr lives at WS[4..8] = envelope[16..20]
        end_ptr = struct.unpack_from('<I', ts[0][1], 16)[0]
        print(f'  mode 0x{m:08x}  end_ptr={end_ptr:>6d}  {len(ts)} captures: '
              f'{", ".join(t[0] for t in ts)}')
    print()

    # Section ranges expressed as envelope offsets. Anchors live at the
    # boundaries (see ANCHORS above, +12 for envelope).
    section_ranges = [
        ('section 4 features', 40, 235),       # WS[28..223]
        ('section 5 features', 305, 4829),     # WS[293..4817]
        ('section 6 features', 4888, 9433),    # WS[4876..9421]
        ('section 7 features', 9449, 13973),   # WS[9437..13961]
        ('section 8 features (mode A: zero-pad)', 13989, 18520),  # WS[13977..18508]
        ('section 9 features (mode B only)', 18528, 23059),       # WS[18516..23047]
    ]

    print('=== intra-section stability per mode ===')
    for m, ts in sorted(modes.items()):
        if len(ts) < 2:
            print(f'\nmode 0x{m:08x}: only {len(ts)} capture, skipping')
            continue
        print(f'\nmode 0x{m:08x}: stability across {len(ts)} captures')
        bufs = [t[1] for t in ts]
        for name, a, b in section_ranges:
            n = b - a
            stable_count = sum(1 for i in range(n)
                               if all(bufs[k][a + i] == bufs[0][a + i]
                                      for k in range(1, len(bufs))))
            print(f'  {name:<48s} env[{a:>5d}..{b:>5d}]  size={n:>5d}  '
                  f'stable={stable_count} ({100*stable_count/n:.1f}%)')
            # Print short stable runs >= 4 inside this section
            runs = []
            i = 0
            while i < n:
                if all(bufs[k][a + i] == bufs[0][a + i] for k in range(1, len(bufs))):
                    j = i
                    while j < n and all(bufs[k][a + j] == bufs[0][a + j]
                                        for k in range(1, len(bufs))):
                        j += 1
                    if j - i >= 4:
                        runs.append((i, j - i))
                    i = j
                else:
                    i += 1
            for off, length in runs[:3]:
                preview = bufs[0][a + off:a + off + min(24, length)].hex()
                tail = '…' if length > 24 else ''
                print(f'      sect-rel +{off:>4d}  env {a+off:>5d}  '
                      f'len {length:>3d}: {preview}{tail}')
            if len(runs) > 3:
                print(f'      … +{len(runs)-3} more stable runs')


if __name__ == '__main__':
    args = sys.argv[1:]
    if args and args[0] == 'multi':
        multi_capture_report(args[1] if len(args) > 1 else '/tmp/finger_templates')
    elif len(args) >= 2:
        main(args[0], args[1])
    elif len(args) == 1:
        main(args[0], None)
    else:
        main()
