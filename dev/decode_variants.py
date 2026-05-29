"""Hypothesis-testing harness for WS body variant byte zones.

For each VARIANT byte zone in a captured Wine ws_body (= bytes that differ
across enrollments — see dev/extract_skeleton.py), we register candidate
DERIVATIONS that compute the bytes from per-frame minutia data. Each
hypothesis is tested against BOTH captures (different fingers); a
hypothesis that matches both is likely the real derivation.

Inputs per session (Session A: ts 1780044*, Session B: ts 1780047*):
  - minutia_table_<ts>_250.bin × 8 (= the 250 kp_array at each AAB0 exit,
    32B records: +0x08 flag, +0x09 tile_id, +0x0a qual, +0x0c orient_q16,
    +0x10 resp, +0x14 gx, +0x18 gy)
  - ws_body_<ts>_23056.bin (= the consolidated 23056-byte WS body)

A hypothesis is a function:
   hyp(per_frame_minutiae, section_idx) -> bytes
that produces the expected variant bytes for one section. The tester
runs it on both sessions and reports byte-equality.

Add new hypotheses to HYPOTHESES below; run the script to see what fits.
"""
import argparse
import glob
import os
import struct
import sys
from typing import Callable, List, Optional

import numpy as np

DUMP_DIR = '/media/sf_vbox-rw/finger/frida_dumps'

# Sessions: minutia_tables fire on AAB0 returns (ts ~1780044677-1780044690
# for session A); ws_body fires at sub_180004900 entry (= the final-store
# action, much later: ts ~1780044703 for A, ~1780047152 for B). So we use
# a SHARED prefix for both kinds, but with different precision.
# - Session A: minutia ts 17800446..1780046, ws_body ts 178004470
# - Session B: minutia ts 17800471..17800471, ws_body ts 178004715
SESSION_A_MT_PREFIX = '17800446'    # minutia covers 1780044677-1780044700
SESSION_A_WS_PREFIX = '178004470'   # ws_body 1780044703862
SESSION_B_MT_PREFIX = '17800471'    # minutia covers 1780047132-1780047151
SESSION_B_WS_PREFIX = '178004715'   # ws_body 1780047152722


# ─── data loaders ───────────────────────────────────────────────────────

def load_minutia(path):
    """Return a list of 250 dicts per record."""
    with open(path, 'rb') as f:
        data = f.read()
    n = len(data) // 32
    out = []
    for i in range(n):
        r = data[i * 32:(i + 1) * 32]
        out.append({
            'flag': r[8],
            'tile_id': r[9],
            'qual': r[10],
            'b0b': r[11],
            'orient': struct.unpack('<I', r[0x0c:0x10])[0],
            'resp': struct.unpack('<i', r[0x10:0x14])[0],
            'gx': struct.unpack('<i', r[0x14:0x18])[0],
            'gy': struct.unpack('<i', r[0x18:0x1c])[0],
        })
    return out


def load_session(mt_prefix, ws_prefix):
    """Load per-frame minutia_tables and the ws_body for a session."""
    mt_paths = sorted(glob.glob(os.path.join(DUMP_DIR,
                                              f'minutia_table_{mt_prefix}*_250.bin')))
    ws_paths = sorted(glob.glob(os.path.join(DUMP_DIR,
                                              f'ws_body_{ws_prefix}*_23056.bin')))
    if not ws_paths:
        raise RuntimeError(f'no ws_body matching prefix {ws_prefix}*')
    minutia = [load_minutia(p) for p in mt_paths]
    ws = open(ws_paths[0], 'rb').read()
    return {
        'minutia': minutia,                 # list of frames; each = list of 250 dicts
        'ws': ws,
        'mt_paths': mt_paths,
        'ws_path': ws_paths[0],
    }


# ─── zone offsets ──────────────────────────────────────────────────────

# WS body layout (per dev/inspect_ws.py)
SECTION_PRE_V30 = [
    ('section0', 64, 309),       # 245B
    ('section1', 4809, 4905),    # 96B
    ('section2', 9405, 9453),    # 48B
    ('section3', 13953, 13993),  # 40B
    ('section4', 18493, 18533),  # 40B
]
TAIL = (23033, 23056)            # 23B


# ─── hypothesis utilities ──────────────────────────────────────────────

def quantiles(values, n=8):
    """Return n equally-spaced quantiles of `values` as integers (0..255)."""
    if len(values) == 0:
        return [0] * n
    arr = np.asarray(values)
    qs = np.linspace(0, 1, n)
    return [int(np.quantile(arr, q)) for q in qs]


def percentile_bytes(values, n=8):
    """Same as quantiles but ensure ascending and clamped to [0, 255]."""
    return [max(0, min(255, v)) for v in quantiles(values, n)]


# ─── hypotheses for the 8-byte ascending lead of each section pre-v30 ──

def hyp_section_lead_gy_quantiles(per_frame_minutiae, section_idx):
    """8 sorted quantiles of frame section_idx's gy values."""
    if section_idx >= len(per_frame_minutiae):
        return None
    frame = per_frame_minutiae[section_idx]
    gys = [m['gy'] for m in frame]
    return bytes(percentile_bytes(gys, 8))


def hyp_section_lead_gx_quantiles(per_frame_minutiae, section_idx):
    """8 sorted quantiles of frame section_idx's gx values."""
    if section_idx >= len(per_frame_minutiae):
        return None
    frame = per_frame_minutiae[section_idx]
    gxs = [m['gx'] for m in frame]
    return bytes(percentile_bytes(gxs, 8))


def hyp_section_lead_qual_quantiles(per_frame_minutiae, section_idx):
    """8 sorted quantiles of qual (byte +0xa) — uses only the 'good' kps with
    qual > 0 since many records have qual=0."""
    if section_idx >= len(per_frame_minutiae):
        return None
    frame = per_frame_minutiae[section_idx]
    quals = [m['qual'] for m in frame if m['qual'] > 0]
    return bytes(percentile_bytes(quals, 8)) if quals else None


def hyp_section_lead_resp_quantiles_scaled(per_frame_minutiae, section_idx, shift=8):
    """8 sorted quantiles of resp >> shift to fit in 0..255."""
    if section_idx >= len(per_frame_minutiae):
        return None
    frame = per_frame_minutiae[section_idx]
    resps = [m['resp'] >> shift for m in frame]
    return bytes(percentile_bytes(resps, 8))


def hyp_section_lead_orient_quantiles(per_frame_minutiae, section_idx):
    """8 sorted quantiles of orient_q16 reduced to byte range (top 8 bits)."""
    if section_idx >= len(per_frame_minutiae):
        return None
    frame = per_frame_minutiae[section_idx]
    # orient_q16 is in [0, 2π·65536); scale to [0, 256)
    ors = [(m['orient'] >> 18) & 0xff for m in frame]   # 2π·65536/256 ≈ 1608
    return bytes(percentile_bytes(ors, 8))


# Hypothesis: 8 bytes = sorted gy values of the kps that ENDED UP in this
# section (= the captured ws_body's section_idx v30 record gy values).
# This is the trivial "cheat" hypothesis — those bytes ARE the section's
# minutia values. If TRUE, we've found the source. If matches one byte by
# coincidence, ignore.
def hyp_section_lead_stored_y_quantiles(ws_body, section_idx, _):
    """8 quantiles of the stored v30 records' y values (not from minutia tables)."""
    region_starts = [309, 4905, 9453, 13993, 18533]
    if section_idx >= len(region_starts):
        return None
    base = region_starts[section_idx]
    n_records = 250
    ys = []
    for i in range(n_records):
        rec = ws_body[base + i * 18 : base + (i + 1) * 18]
        if rec == b'\0' * 18:
            continue
        ys.append(rec[1])
    return bytes(percentile_bytes(ys, 8)) if ys else None


def hyp_section_lead_stored_x_quantiles(ws_body, section_idx, _):
    region_starts = [309, 4905, 9453, 13993, 18533]
    if section_idx >= len(region_starts):
        return None
    base = region_starts[section_idx]
    xs = []
    for i in range(250):
        rec = ws_body[base + i * 18 : base + (i + 1) * 18]
        if rec == b'\0' * 18:
            continue
        xs.append(rec[0])
    return bytes(percentile_bytes(xs, 8)) if xs else None


# ─── runner ─────────────────────────────────────────────────────────────

def hyp_section_lead_stored_y_plus_128(ws_body, section_idx, _):
    """8 stored-record y values + 128 (in case y is offset/scaled)."""
    region_starts = [309, 4905, 9453, 13993, 18533]
    if section_idx >= len(region_starts):
        return None
    base = region_starts[section_idx]
    ys = []
    for i in range(250):
        rec = ws_body[base + i * 18:base + (i + 1) * 18]
        if rec == b'\0' * 18:
            continue
        ys.append((rec[1] + 128) & 0xff)
    return bytes(percentile_bytes(ys, 8)) if ys else None


def hyp_section_lead_desc_byte_quantiles(ws_body, section_idx, _, desc_byte=0):
    """8 quantiles of one specific byte of all section's BRIEF descriptors."""
    region_starts = [309, 4905, 9453, 13993, 18533]
    if section_idx >= len(region_starts):
        return None
    base = region_starts[section_idx]
    vals = []
    for i in range(250):
        rec = ws_body[base + i * 18:base + (i + 1) * 18]
        if rec == b'\0' * 18:
            continue
        vals.append(rec[2 + desc_byte])
    return bytes(percentile_bytes(vals, 8)) if vals else None


def hyp_section_lead_radial_distance(ws_body, section_idx, _):
    """8 quantiles of radial distance from image center (56, 56)."""
    region_starts = [309, 4905, 9453, 13993, 18533]
    if section_idx >= len(region_starts):
        return None
    base = region_starts[section_idx]
    dists = []
    for i in range(250):
        rec = ws_body[base + i * 18:base + (i + 1) * 18]
        if rec == b'\0' * 18:
            continue
        x, y = rec[0], rec[1]
        d = int(((x - 56) ** 2 + (y - 56) ** 2) ** 0.5)
        dists.append(d)
    return bytes(percentile_bytes(dists, 8)) if dists else None


HYPOTHESES = [
    ('per-frame gy quantiles', hyp_section_lead_gy_quantiles, 'per-frame minutiae'),
    ('per-frame gx quantiles', hyp_section_lead_gx_quantiles, 'per-frame minutiae'),
    ('per-frame qual quantiles', hyp_section_lead_qual_quantiles, 'per-frame minutiae'),
    ('per-frame resp>>8 quantiles', hyp_section_lead_resp_quantiles_scaled, 'per-frame minutiae'),
    ('per-frame orient>>18 quantiles', hyp_section_lead_orient_quantiles, 'per-frame minutiae'),
    ('stored v30 y quantiles', hyp_section_lead_stored_y_quantiles, 'stored v30 records'),
    ('stored v30 x quantiles', hyp_section_lead_stored_x_quantiles, 'stored v30 records'),
    ('stored v30 y + 128 quantiles', hyp_section_lead_stored_y_plus_128, 'stored v30 records'),
    ('stored v30 radial distance', hyp_section_lead_radial_distance, 'stored v30 records'),
] + [
    (f'desc_byte[{db}] quantiles', lambda ws, si, _, db=db: hyp_section_lead_desc_byte_quantiles(ws, si, _, db),
     'stored v30 records') for db in (0, 1, 2, 4, 8, 15)
]


def test_section_lead_hypothesis(name, fn, fn_input_kind, sessions):
    """Test a hypothesis against the 8-byte section lead of each pre-v30
    block in every captured session. Returns total bytes matched / 80 (= 8
    bytes × 5 sections × 2 sessions)."""
    total = 0
    matched = 0
    details = []
    for s_name, sess in sessions.items():
        ws = sess['ws']
        for sec_idx, (label, start, _) in enumerate(SECTION_PRE_V30):
            cap = ws[start:start + 8]
            if fn_input_kind == 'per-frame minutiae':
                exp = fn(sess['minutia'], sec_idx)
            elif fn_input_kind == 'stored v30 records':
                exp = fn(ws, sec_idx, None)
            else:
                exp = None
            if exp is None:
                continue
            byte_match = sum(1 for i in range(8) if cap[i] == exp[i])
            total += 8
            matched += byte_match
            details.append(f'{s_name}/{label}: cap={cap.hex()} exp={exp.hex()} '
                          f'matched={byte_match}/8')
    return matched, total, details


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--show-details', action='store_true',
                    help='print per-section per-session match details')
    args = ap.parse_args()

    print('loading sessions...')
    try:
        sess_a = load_session(SESSION_A_MT_PREFIX, SESSION_A_WS_PREFIX)
        sess_b = load_session(SESSION_B_MT_PREFIX, SESSION_B_WS_PREFIX)
    except RuntimeError as e:
        print(f'!!! load failure: {e}')
        sys.exit(1)
    print(f'session A: {len(sess_a["minutia"])} frames, ws={sess_a["ws_path"]}')
    print(f'session B: {len(sess_b["minutia"])} frames, ws={sess_b["ws_path"]}')
    sessions = {'A': sess_a, 'B': sess_b}

    print('\n=== Testing section-lead hypotheses (8 ascending bytes per pre-v30 start) ===')
    print(f'  total bytes per session: 5 sections × 8 bytes = 40')
    print(f'  total across 2 sessions: 80\n')
    print(f'  {"hypothesis":<40s}  {"matched":>10s}  {"%":>6s}')
    print(f'  {"-"*40}  {"-"*10}  {"-"*6}')
    for name, fn, kind in HYPOTHESES:
        matched, total, details = test_section_lead_hypothesis(name, fn, kind, sessions)
        pct = 100.0 * matched / total if total else 0.0
        marker = ' ✓✓' if pct == 100 else ('  *' if pct >= 50 else '   ')
        print(f'  {name:<40s}  {matched:>4d}/{total:<5d}  {pct:>5.1f}%{marker}')
        if args.show_details:
            for d in details:
                print(f'      {d}')

    # Also print the captured leads side by side for human eyeballing
    print('\n=== Captured section leads (for manual inspection) ===')
    for sec_idx, (label, start, _) in enumerate(SECTION_PRE_V30):
        a = sess_a['ws'][start:start + 8]
        b = sess_b['ws'][start:start + 8]
        print(f'  {label}: A={a.hex()}  B={b.hex()}')


if __name__ == '__main__':
    main()
