"""Byte-diff a Wine-produced WS body vs our native_template's WS body,
given the SAME 8 input frames.

Both Wine and our pipeline consume the same 8 enrollment frames. Wine's
WS body is captured at sub_180004900 entry (ws_body_<ts>_23056.bin). Our
WS body is whatever native_template produces. Diffing them byte-by-byte
exposes every structural divergence (header, section metadata, per-section
POSE records, v30 records) so we can see exactly what our template gets
wrong.

Usage:
  ./.venv-poc/bin/python dev/diff_template_structure.py \\
      --frames-dir /tmp/log_images \\
      --wine-ws /media/sf_vbox-rw/finger/frida_dumps/ws_body_<ts>_23056.bin \\
      --ref /tmp/wine_finger_fresh.bin
"""
import argparse
import glob
import os
import struct
import sys
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ─── byte-diff utilities ────────────────────────────────────────────────

# Annotated zones in the WS body (offsets and meanings per memory):
#   [0..4)   zeros
#   [4..8)   u32 size
#   [8..16)  fixed config 06 02 05 00 02 00 08 01
#   [16..24) accepted-frame id list (reverse)
#   [24..44) per-section count table (u32 × N)
#   [44..~64) geometry/stats
#   then N sections × ~4540 B (each = [POSE table ~276B] + [v30 records 4533B])

ZONES = [
    (0, 4, 'zeros'),
    (4, 8, 'size_u32'),
    (8, 16, 'fixed_config'),
    (16, 24, 'accepted_frame_ids'),
    (24, 44, 'per_section_counts'),
    (44, 64, 'geometry_stats'),
]


def classify_offset(off, region_starts):
    """Return a human-readable label for byte offset `off`."""
    for s, e, name in ZONES:
        if s <= off < e:
            return name
    for i, rs in enumerate(region_starts):
        # Each region: [header before v30 record][v30 record body]
        # The find_v30_regions returns the OFFSET OF THE V30 RECORD BODY,
        # so the section "header" ends just before this offset.
        # Section size ~ next_region_start - this_region_start (or to end)
        re_end = region_starts[i + 1] if i + 1 < len(region_starts) else None
        if rs <= off and (re_end is None or off < re_end):
            # Is `off` within the v30 records portion or before?
            return f'section{i}'
    return 'tail'


def summarise(diff_indices, region_starts):
    by_zone = {}
    for off in diff_indices:
        z = classify_offset(off, region_starts)
        by_zone.setdefault(z, []).append(off)
    for z, offs in sorted(by_zone.items(), key=lambda kv: kv[1][0]):
        rng = f'[0x{offs[0]:04x}..0x{offs[-1]:04x}]'
        print(f'  {z:25s} {len(offs):6d} diffs in {rng}')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--frames-dir', default='/tmp/log_images',
                    help='dir of log-extracted images (frame00.bin ... frame07.bin)')
    ap.add_argument('--wine-ws', required=True,
                    help='captured Wine ws_body_<ts>_23056.bin from this enrollment')
    ap.add_argument('--ref', default='/tmp/wine_finger_fresh.bin',
                    help='23136-byte reference envelope used as scaffold')
    ap.add_argument('--max-frames', type=int, default=4,
                    help='frames to feed into native_template (default 4 — one per v30 region)')
    args = ap.parse_args()

    from validitysensor.moh_native import extract_frame_native
    from validitysensor.moh_opencv import WS_SIZE, V30_RECORD_LEN, find_v30_regions

    # Load the Wine-produced WS body (ground truth for this enrollment)
    with open(args.wine_ws, 'rb') as f:
        wine_ws = f.read()
    print(f'wine_ws size: {len(wine_ws)} ({args.wine_ws})')

    # Load reference (scaffold) — strip envelope header, keep just the WS body
    with open(args.ref, 'rb') as f:
        ref = f.read()
    ref_ws = ref[12:12 + WS_SIZE]
    print(f'ref_ws size: {len(ref_ws)}')

    # Load the 8 log-extracted images (the same input Wine consumed)
    image_paths = sorted(glob.glob(os.path.join(args.frames_dir, 'frame*.bin')))
    print(f'log-extracted images: {len(image_paths)} (using first {args.max_frames})')
    images = []
    for p in image_paths[:args.max_frames]:
        img = np.frombuffer(open(p, 'rb').read(), dtype=np.uint8).reshape(112, 112)
        images.append(img.astype(np.int32) << 16)

    # Build OUR ws_body using the same per-frame distribution Sensor.enroll_native uses
    print(f'\nbuilding our ws_body from {len(images)} frame(s)...')
    per_frame_kps = [extract_frame_native(img, h=112, w=112) for img in images]
    for i, kps in enumerate(per_frame_kps):
        print(f'  frame{i}: {len(kps)} kp(s)')

    our_ws = bytearray(ref_ws)
    regions = find_v30_regions(bytes(our_ws))
    print(f'v30 regions in scaffold: {regions}')

    for idx, base in enumerate(regions):
        src = per_frame_kps[idx % len(per_frame_kps)]
        records_bytes = b''.join(
            bytes((gx & 0xFF, gy & 0xFF)) + (desc[:16] if len(desc) >= 16
                                              else desc + bytes(16 - len(desc)))
            for (gx, gy, _o, desc) in src[:250])
        records_bytes = (records_bytes
                         + bytes(V30_RECORD_LEN) * max(0, 250 - len(src))
                         )[:250 * V30_RECORD_LEN]
        our_ws[base:base + len(records_bytes)] = records_bytes
    our_ws = bytes(our_ws)

    # Byte-diff
    if len(our_ws) != len(wine_ws):
        print(f'\n!!! SIZE MISMATCH: ours={len(our_ws)} wine={len(wine_ws)}')

    n = min(len(our_ws), len(wine_ws))
    diff = [i for i in range(n) if our_ws[i] != wine_ws[i]]
    print(f'\ntotal byte diffs: {len(diff)} / {n} ({100*len(diff)/n:.1f}%)')
    print(f'\nbreakdown by zone:')
    summarise(diff, regions)

    # If we used different input frames than Wine, v30 records WILL differ
    # massively (different kps). Hex-dump the WS header [0..64) so the user
    # can eyeball the actually-actionable differences.
    print(f'\nWS header [0..64) byte-by-byte:')
    print(f'  offset  ours      wine      label')
    for off in range(64):
        z = classify_offset(off, regions)
        ours_b = our_ws[off]
        wine_b = wine_ws[off]
        marker = '   '
        if ours_b != wine_b:
            marker = ' ! '
        print(f'  0x{off:02x}   {ours_b:#04x}     {wine_b:#04x}    {marker}{z}')

    # For each section, separately count diffs INSIDE the v30 records vs the
    # pre-v30 area (the POSE table + section header).
    print(f'\nper-section detail:')
    for i, rs in enumerate(regions):
        re_end = regions[i + 1] if i + 1 < len(regions) else n
        # section header = bytes from preceding region end (or 64) to rs
        prev_end = regions[i - 1] + 250 * V30_RECORD_LEN if i > 0 else 64
        v30_end = rs + 250 * V30_RECORD_LEN
        section_hdr_range = (prev_end, rs)
        v30_range = (rs, v30_end)
        v30_tail_range = (v30_end, re_end)
        for label, (s, e) in [('hdr+POSE', section_hdr_range),
                                ('v30_records', v30_range),
                                ('v30_tail', v30_tail_range)]:
            d = sum(1 for k in range(s, e) if k < n and our_ws[k] != wine_ws[k])
            if d:
                print(f'  section{i}  {label:13s} [0x{s:04x}..0x{e:04x}]: {d} diffs')


if __name__ == '__main__':
    main()
