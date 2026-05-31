#!/usr/bin/env python3
"""Can we SYNTHESIZE a matchable sec0_pre offline? (investigation harness)

Context: the chip matcher (sub_18000c6a0) uses the stored sec0_pre rigid
transforms as candidate alignment hypotheses (SCORER §1), so a from-scratch
template needs CORRECT sec0_pre. The matcher (c6a0) only SCORES given
transforms and bdf0/51f0 only SERIALIZE them — the GENERATION lives in the
undecoded per-frame model-fitter (sub_1800046e0 / sub_1800082a0).

This harness tests whether we can bypass that RE by recomputing the transforms
offline from a captured MATCHABLE template's own sections, and checking they
reproduce its stored sec0_pre. Run against /tmp/ft/wine_1780232416_0.bin
(extracted from Wine log 1780232416.log).

RESULT (2026-05-31): BOTH standard approaches FAIL to reproduce the stored
transforms —
  * descriptor-match + RANSAC rigid fit → 5-7 garbage inliers (BRIEF is too
    ambiguous to correspond keypoints across frames);
  * geometric Hough overlap → degenerates to identity (the 5 sections densely
    fill the same 112x112 frame, so the trivial t=0 overlap dominates).
The stored transforms have large translations (±55px) and anchors >112px, i.e.
they are NOT simple pairwise image-space keypoint alignments (the 5 frames are
different overlapping finger regions; the transforms likely map each section to
a consolidated multi-view model).

CONCLUSION: a matchable from-scratch sec0_pre needs the DLL's registration
algorithm. Either RE sub_1800046e0/sub_1800082a0, or gdb-capture the generation
during a Wine enroll, or sidestep with a single-section/identity-sec0_pre
template. Also: re-verify the sec0_pre parse (51f0 serialization; anchors>112
suggest the naive 18-byte read is partly wrong).

Usage: ./.venv-poc/bin/python dev/verify_sec0pre_synthesis.py [template.bin]
"""
import sys, os, struct, math, itertools
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np
from validitysensor.moh_opencv import find_v30_regions, WS_SIZE

PATH = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ft/wine_1780232416_0.bin"
ONE = 0x10000


def sections(ws, regs):
    out = []
    for base in regs:
        recs = []
        for k in range(250):
            o = base + k * 18
            x, y = ws[o], ws[o + 1]
            if not (0 < x <= 112 and 0 < y <= 112):
                break
            recs.append((x, y, ws[o + 2:o + 18]))
        out.append(recs)
    return out


def stored_transforms(ws):
    s0 = ws[64:309]

    def rigid(a, b):
        return abs(a * a + b * b - ONE * ONE) < ONE * ONE * 0.05
    best = []
    for start in range(60):
        tmp, o = [], start
        while o + 18 <= len(s0):
            a, b, tx, ty = struct.unpack_from('<4i', s0, o + 2)
            if not rigid(a, b):
                break
            tmp.append((math.degrees(math.atan2(b, a)), tx / ONE, ty / ONE))
            o += 18
        if len(tmp) > len(best):
            best = tmp
    return best


def hough(A, B, rots=np.arange(-6, 6.01, 0.5), bin=8):
    A = np.array([(x, y) for x, y, _ in A], float)
    B = np.array([(x, y) for x, y, _ in B], float)
    best = None
    for th in rots:
        c, s = math.cos(math.radians(th)), math.sin(math.radians(th))
        RA = np.column_stack([c * A[:, 0] - s * A[:, 1], s * A[:, 0] + c * A[:, 1]])
        tx = (B[:, 0][None, :] - RA[:, 0][:, None]).ravel()
        ty = (B[:, 1][None, :] - RA[:, 1][:, None]).ravel()
        keys = np.round(np.column_stack([tx, ty]) / bin).astype(int)
        uniq, cnt = np.unique(keys, axis=0, return_counts=True)
        k = cnt.argmax()
        if best is None or cnt[k] > best[0]:
            best = (int(cnt[k]), float(th), float(uniq[k][0] * bin), float(uniq[k][1] * bin))
    return best


def main():
    T = open(PATH, "rb").read()
    ws = T[12:12 + WS_SIZE]
    regs = find_v30_regions(ws)
    secs = sections(ws, regs)
    print(f"template: {PATH}")
    print(f"v30 regions: {regs}  ({len(secs)} sections, "
          f"sizes {[len(s) for s in secs]})")
    st = stored_transforms(ws)
    print(f"\nstored sec0_pre transforms ({len(st)}):")
    for i, (a, tx, ty) in enumerate(st):
        print(f"  T{i}: rot={a:+6.2f}  t=({tx:+7.2f},{ty:+7.2f})")

    print("\ngeometric Hough alignment per section pair (votes, rot, t):")
    matched = 0
    for i, j in itertools.combinations(range(len(secs)), 2):
        v, th, tx, ty = hough(secs[i], secs[j])
        near = min(abs(th - a) + abs(tx - sx) / 8 + abs(ty - sy) / 8
                   for a, sx, sy in st)
        ok = any(abs(th - a) < 2 and abs(tx - sx) < 8 and abs(ty - sy) < 8
                 for a, sx, sy in st)
        matched += ok
        print(f"  sec{i}->{j}: {v:3} votes  rot={th:+5.1f} t=({tx:+6.1f},{ty:+6.1f})"
              f"  {'~stored' if ok else 'NO stored match'}")

    print(f"\n=== {matched}/{len(list(itertools.combinations(range(len(secs)),2)))} "
          "pairs reproduce a stored transform ===")
    print("If ~0 (expected): sec0_pre is NOT reproducible by naive geometric "
          "alignment → generation needs the DLL model-fitter (RE or capture).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
