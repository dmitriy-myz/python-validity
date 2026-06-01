#!/usr/bin/env python3
"""Build SELF-CONSISTENT single-frame test templates from a Wine enroll log.

Motivation (2026-05-31 hardware result): the chip's v30 sections are CONSOLIDATED
multi-frame tracks — a track's descriptor and stored position come from different
frames' observations, and the DLL's sec0_pre describes that consolidated geometry.
Our single-frame-detection records (correct pos↔desc pairing, but in the detection
frame) are geometrically inconsistent with the DLL's sec0_pre → the diagnostic T1
(our v30 + DLL sec0_pre) does not match, while T0 (exact DLL template) does.

This builder removes the consolidation+registration coupling: it emits templates
whose v30 records are OUR single-frame extraction (pos↔desc paired correctly, the
way the matcher's descriptor-correspondence step expects within one frame) AND whose
sec0_pre transforms are forced to IDENTITY (sections declared identically aligned).
A query of the same finger should then match via a ~identity transform.

  T2  <tag>_frame00x5_identity.bin  — frame00 replicated into all 5 sections
  T3  <tag>_5frames_identity.bin    — 5 distinct mapped frames (fallback)

Hardware (user-run; delete competing FINGER dbids first; T0 is the placement control):
    sudo ./.venv-poc/bin/python dev/enroll_native_chip.py --ref <bin> --store-ref --match

Usage:
    ./.venv-poc/bin/python dev/build_singleframe_template.py LOG FRAMEDIR [OUTDIR]
"""
import os, sys, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import glob
import numpy as np
from validitysensor.moh_opencv import find_v30_regions, WS_SIZE
from validitysensor.moh_native import extract_frame_native, serialize_v30_section
from validitysensor.moh_extract import compute_tid, _build_envelope
from sec0pre_serialize import parse_sec0pre

ONE = 0x10000


def extract_template(log):
    for line in open(log, 'rb'):
        if not line.startswith(b'To be encrypted: 47'):
            continue
        w = bytes.fromhex(line.removeprefix(b'To be encrypted: ').strip().decode())
        o, par, typ, st, ln = struct.unpack('<BHHHH', w[:9])
        if o == 0x47 and typ == 6 and ln == 23136:
            return w[9:9 + ln]
    raise SystemExit(f'no template in {log}')


def frame_recs(path):
    img = np.frombuffer(open(path, 'rb').read(), np.uint8).reshape(112, 112)
    return [(gx, gy, d) for (gx, gy, o, d) in extract_frame_native(img.astype(np.int64) << 16)]


def force_identity_sec0pre(ws):
    """Force all sec0_pre matrix transforms to identity {a=ONE,b=0,tx=0,ty=0},
    keeping anchors. sec0_pre framed at template[24:] → ws offset 12; matrix @ ws+43."""
    p = parse_sec0pre(b'\x00' * 12 + bytes(ws), 24)   # parse to learn N
    n = p['n']
    moff = (55 - 12)
    for k in range(n * (n - 1) // 2):
        struct.pack_into('<4i', ws, moff + k * 18 + 2, ONE, 0, 0, 0)


def build(ws0, regs, subtype, section_records, out):
    ws = bytearray(ws0)
    for j, base in enumerate(regs):
        sec = serialize_v30_section([(x, y, d) for (x, y, d) in section_records[j]])
        ws[base - 16:base - 16 + len(sec)] = sec   # records start at anchor-16 ([desc][x][y])
    force_identity_sec0pre(ws)
    nws = bytes(ws)
    env = _build_envelope(subtype, nws, compute_tid(nws))
    assert len(env) == 23136 and find_v30_regions(env[12:12 + WS_SIZE]) == regs
    assert compute_tid(env[12:12 + WS_SIZE]) == env[23072:23104]
    p = parse_sec0pre(env, 24)
    ident = all((r[2], r[3], r[4], r[5]) == (ONE, 0, 0, 0) for r in p['transforms'].values())
    open(out, 'wb').write(env)
    print(f'  wrote {out}  sec0_pre all-identity={ident}  sections={p["n"]}')


def main():
    if len(sys.argv) < 3:
        print(__doc__); return 2
    log, framedir = sys.argv[1], sys.argv[2]
    outdir = sys.argv[3] if len(sys.argv) > 3 else '/tmp/ft'
    os.makedirs(outdir, exist_ok=True)
    tag = os.path.basename(log).removesuffix('.log')

    stored = extract_template(log)
    subtype = struct.unpack_from('<H', stored, 0)[0]
    ws0 = stored[12:12 + WS_SIZE]
    regs = find_v30_regions(ws0)

    frames = sorted(glob.glob(os.path.join(framedir, 'frame*.bin')))
    # map sections to frames by position overlap (for T3)
    def secxy(base):
        r = []
        for k in range(250):
            o = base + k * 18; x, y = ws0[o], ws0[o + 1]
            if not (0 < x <= 112 and 0 < y <= 112): break
            r.append((x, y))
        return np.array(r, float)
    secs = [secxy(b) for b in regs]
    fkp = {os.path.basename(f): frame_recs(f) for f in frames}

    def ov(F, S):
        A = np.array([(x, y) for x, y, _ in F], float)
        if not len(A) or not len(S): return 0
        d2 = ((A[:, None, 0]-S[None, :, 0])**2 + (A[:, None, 1]-S[None, :, 1])**2)
        return int((np.sqrt(d2.min(1)) <= 2).sum())
    mapping = [max(fkp.items(), key=lambda kv: ov(kv[1], secs[j]))[0] for j in range(len(regs))]
    print(f'{tag}: {len(regs)} sections; mapping {mapping}')

    f0 = fkp[mapping[0]]
    print('T2: frame00 x5 + identity sec0_pre')
    build(ws0, regs, subtype, [f0] * len(regs), os.path.join(outdir, f'{tag}_frame00x5_identity.bin'))
    print('T3: 5 distinct frames + identity sec0_pre')
    build(ws0, regs, subtype, [fkp[mapping[j]] for j in range(len(regs))],
          os.path.join(outdir, f'{tag}_5frames_identity.bin'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
