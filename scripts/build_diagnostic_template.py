#!/usr/bin/env python3
"""Build diagnostic templates from a Wine enroll log, to isolate WHICH part of a
from-scratch template the chip's geometric matcher needs.

Given a Wine enroll log that contains both the source frames (0x0278 image
blocks) AND the stored finger template (0x47 typ=6 len=23136 record), this:

  1. extracts the stored template (a known-good mode-B N-section DLL template);
  2. extracts the source frames and maps each stored v30 section to its source
     frame by keypoint-position overlap (our doh→nms→subpix pipeline);
  3. compares OUR v30 (positions + descriptors) to the DLL's stored v30;
  4. emits two test templates:
       T0  stored_<id>.bin            — the exact DLL template (positive control)
       T1  diagnostic_<id>_ourv30.bin — OUR v30 for the mapped frames, with the
                                        DLL's sec0_pre / leads / blob / framing
                                        kept BYTE-IDENTICAL (recomputed TID only).

T1 isolates the v30-content variable: it pairs OUR keypoints (positions byte-exact
~95%+, descriptors differ — but the matcher is positional Hough, sub_18000c6a0,
so descriptors should not matter) with the DLL's EXACT inter-frame geometry. If
the chip matches T1, then sec0_pre transform GENERATION is the sole remaining
from-scratch blocker (serialization is already byte-exact, dev/sec0pre_serialize.py).

Hardware test (user-run; delete competing FINGER dbids first, not the user dbid):
    sudo ./.venv-poc/bin/python dev/enroll_native_chip.py --ref <T0.bin> --store-ref --match
    sudo ./.venv-poc/bin/python dev/enroll_native_chip.py --ref <T1.bin> --store-ref --match

Usage:
    ./.venv-poc/bin/python dev/build_diagnostic_template.py LOG FRAMEDIR [OUTDIR]
"""
import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import glob
import numpy as np
from validitysensor.moh_opencv import find_v30_regions, WS_SIZE
from validitysensor.moh_native import extract_frame_native, serialize_v30_section
from validitysensor.moh_extract import compute_tid, _build_envelope


def extract_template(log):
    for line in open(log, 'rb'):
        if not line.startswith(b'To be encrypted: 47'):
            continue
        wire = bytes.fromhex(line.removeprefix(b'To be encrypted: ').strip().decode())
        opc, par, typ, sto, ln = struct.unpack('<BHHHH', wire[:9])
        if opc == 0x47 and typ == 6 and ln == 23136:
            return wire[9:9 + ln]
    raise SystemExit(f'no 0x47 typ=6 template in {log}')


def sec_records(wsb, base):
    """Parse a v30 section. TRUE layout = [16B desc][x:u8][y:u8]; the (x,y)
    anchor returned by find_v30_regions is +16 into the record, so the record
    area starts at base-16."""
    recs = []
    s = base - 16
    for k in range(250):
        o = s + k * 18
        x, y = wsb[o + 16], wsb[o + 17]
        if not (0 < x <= 112 and 0 < y <= 112):
            break
        recs.append((x, y, bytes(wsb[o:o + 16])))
    return recs


def our_frame_kps(path):
    img = np.frombuffer(open(path, 'rb').read(), np.uint8).reshape(112, 112)
    kps = extract_frame_native(img.astype(np.int64) << 16)
    return [(gx, gy, d) for (gx, gy, o, d) in kps]


def overlap_xy(A, B, thr=2.0):
    if not len(A) or not len(B):
        return 0
    A = np.array([(x, y) for x, y, *_ in A], float)
    B = np.array([(x, y) for x, y, *_ in B], float)
    d2 = ((A[:, None, 0]-B[None, :, 0])**2 + (A[:, None, 1]-B[None, :, 1])**2)
    return int((np.sqrt(d2.min(1)) <= thr).sum())


def main():
    if len(sys.argv) < 3:
        print(__doc__); return 2
    log, framedir = sys.argv[1], sys.argv[2]
    outdir = sys.argv[3] if len(sys.argv) > 3 else '/tmp/ft'
    os.makedirs(outdir, exist_ok=True)
    tag = os.path.basename(log).removesuffix('.log')

    stored = extract_template(log)
    subtype = struct.unpack_from('<H', stored, 0)[0]
    ws = stored[12:12 + WS_SIZE]
    regs = find_v30_regions(ws)
    stored_secs = [sec_records(ws, b) for b in regs]
    print(f'template {tag}: subtype=0x{subtype:04x}  {len(regs)} sections @ {regs}')

    frames = sorted(glob.glob(os.path.join(framedir, 'frame*.bin')))
    frame_kps = {os.path.basename(f): our_frame_kps(f) for f in frames}

    # map each section to its best source frame by position overlap
    mapping = []
    for j in range(len(regs)):
        best = max(frame_kps.items(), key=lambda kv: overlap_xy(kv[1], stored_secs[j]))
        mapping.append(best[0])
        print(f'  section {j} <- {best[0]} ({overlap_xy(best[1], stored_secs[j])}/250)')

    # compare our v30 vs stored v30
    print('\n=== our v30 vs stored v30 ===')
    our_secs = [frame_kps[mapping[j]] for j in range(len(regs))]
    for j in range(len(regs)):
        S, O = stored_secs[j], our_secs[j]
        Sxy = np.array([(x, y) for x, y, _ in S], float)
        Oxy = np.array([(x, y) for x, y, _ in O], float)
        d2 = ((Oxy[:, None, 0]-Sxy[None, :, 0])**2 + (Oxy[:, None, 1]-Sxy[None, :, 1])**2)
        idx = d2.argmin(1); dist = np.sqrt(d2[np.arange(len(O)), idx])
        m = dist <= 1.5
        hd = [bin(int.from_bytes(O[oi][2], 'big') ^ int.from_bytes(S[idx[oi]][2], 'big')).count('1')
              for oi in np.where(m)[0]]
        hd = np.array(hd) if hd else np.array([128])
        print(f'  sec{j}: pos {m.sum()}/250  desc Hamming med={np.median(hd):.0f} '
              f'min={hd.min()} (==0:{(hd == 0).sum()})')

    # T0: exact stored template
    t0 = os.path.join(outdir, f'stored_{tag}.bin')
    open(t0, 'wb').write(stored)

    # T1: our v30 + DLL sec0_pre/framing untouched
    nws = bytearray(ws)
    for j, base in enumerate(regs):
        sec = serialize_v30_section([(x, y, d) for x, y, d in our_secs[j]])
        nws[base - 16:base - 16 + len(sec)] = sec   # records start at anchor-16
    nws = bytes(nws)
    env = _build_envelope(subtype, nws, compute_tid(nws))
    assert len(env) == 23136 and find_v30_regions(env[12:12 + WS_SIZE]) == regs
    assert compute_tid(env[12:12 + WS_SIZE]) == env[23072:23104]
    # sec0_pre untouched (template offset 24..292 == ws offset 12..280)
    assert env[24:292] == stored[24:292], 'sec0_pre changed!'
    t1 = os.path.join(outdir, f'diagnostic_{tag}_ourv30.bin')
    open(t1, 'wb').write(env)

    print(f'\nwrote:\n  T0 (exact DLL template) {t0}\n  T1 (our v30 + exact sec0_pre) {t1}')
    print('\nHardware (user-run): enroll_native_chip.py --ref <bin> --store-ref --match')
    return 0


if __name__ == '__main__':
    sys.exit(main())
