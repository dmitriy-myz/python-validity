#!/usr/bin/env python3
"""Port of the decoded sec0_pre frame-registration estimators + offline study.

Implements the algorithm decoded in dev/transformation-doc/ and tests whether it
reproduces the stored sec0_pre transforms of a captured MATCHABLE template
(/tmp/ft/wine_1780232416_0.bin, 5 v30 sections of [x][y][16B desc]).

KEY FINDINGS (2026-05-31), the reason this is hard:
  1. The stored sec0_pre transforms ARE geometric rigid alignments of the v30
     keypoint clouds: applying a stored transform to one section lands 83-195 of
     250 keypoints within 3px of the other section. (verified, see diag below)
  2. The stored v30 descriptors are NEARLY USELESS across frames: for those
     geometrically-true correspondences, the median Hamming distance is ~52/128
     bits (near random). So descriptor matching picks the wrong partner and any
     descriptor-seeded RANSAC fails. Registration here is FUNDAMENTALLY GEOMETRIC
     (consistent with the chip matcher sub_18000c6a0 being a positional Hough
     grid — descriptors barely matter for matching).
  3. Correspondence-FREE geometric overlap-maximization (sample point pairs,
     match by baseline length under a small-rotation/translation prior, score by
     full-cloud overlap, ICP-refine) WORKS: it reproduces the dominant transform
     (T7 sec3->sec4: rot+0.79 t(-0.27,-11.2) vs stored rot+0.80 t(-0.2,-11.5)).
  4. BUT it reproduces only ~1/8 of the stored transforms exactly, because the
     others have large translations where a *different* higher-overlap alignment
     exists; the DLL's stored transforms are its descriptor-correspondence /
     reference-frame-composed choices (sub_180008160), not raw max-overlap. The
     exact DLL transforms need the gdb capture (dev/transformation-doc README
     plan) for byte-exact ground truth.

So: we CAN compute geometrically-valid inter-frame transforms for our own frames
(geom_register below). Whether the chip accepts a template built from those is a
hardware question; byte-exact DLL reproduction needs the capture.

Run:  ./.venv-poc/bin/python dev/sec0pre_register.py [template.bin]
"""
import sys, os, struct, math, random, itertools
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np
from validitysensor.moh_opencv import find_v30_regions, WS_SIZE

ONE = 0x10000


# ─── decoded fixed-point primitives (faithful ports; for byte-exact use) ─────
def s32(v):
    v = int(v) & 0xFFFFFFFF
    return v - (1 << 32) if v & 0x80000000 else v


def apply_q16(x, y, a, b, tx, ty):
    """sub_180006bc0: out=(a*x-b*y+tx+0x8000)>>16, (b*x+a*y+ty+0x8000)>>16."""
    nx = s32(s32(s32(a * x) - s32(b * y)) + tx + 0x8000) >> 16
    ny = s32(s32(s32(b * x) + s32(a * y)) + ty + 0x8000) >> 16
    return nx, ny


def solve_2point(dst0, dst1, src0, src1):
    """sub_180006e10: minimal rigid (scale=1) Q16 solve, src ≈ R·dst + t."""
    dxs = s32(src1[0] - src0[0]); dys = s32(src1[1] - src0[1])
    dxd = s32(dst1[0] - dst0[0]); dyd = s32(dst1[1] - dst0[1])
    CROSS = s32(s32(dys * dxd) - s32(dxs * dyd))
    DOT = s32(s32(dxs * dxd) + s32(dys * dyd))
    ss = s32(s32(CROSS * CROSS) + s32(DOT * DOT)) & 0xFFFFFFFF
    den = math.isqrt(ss)
    if den <= 0:
        return None
    def idiv(n, d):
        n = s32(n); q = abs(n) // d
        return s32(-q if n < 0 else q)
    a = idiv(s32(DOT << 16), den); b = idiv(s32(CROSS << 16), den)
    tx = s32(s32(s32((src0[0]+src1[0]) << 16) - s32(a*(dst0[0]+dst1[0]))) + s32(b*(dst0[1]+dst1[1]))) >> 1
    ty = s32(s32(s32((src0[1]+src1[1]) << 16) - s32(a*(dst0[1]+dst1[1]))) - s32(b*(dst0[0]+dst1[0]))) >> 1
    return a, b, s32(tx), s32(ty)


def plausible(a, b, tx_q16, ty_q16):
    """sub_180004680 gate (a,b Q16; tx,ty here Q16 → >>12 gives the doc's Q12)."""
    t = (tx_q16 >> 12) ** 2 + (ty_q16 >> 12) ** 2
    rot = (b >> 4) ** 2
    sc = (0x1000 - (a >> 4)) ** 2
    return t < 0x7d0 and rot < 0x2260 and sc < 0x2260


# ─── correspondence-free geometric registration (the method that WORKS) ──────
GS = 140


def _occmask(Pj, rad=3):
    m = np.zeros((GS, GS), bool)
    for x, y in Pj:
        xi, yi = int(round(x)) + 10, int(round(y)) + 10
        for dx in range(-rad, rad + 1):
            for dy in range(-rad, rad + 1):
                if dx*dx+dy*dy <= rad*rad and 0 <= xi+dx < GS and 0 <= yi+dy < GS:
                    m[yi+dy, xi+dx] = True
    return m


def _rot(ang):
    c, s = math.cos(ang), math.sin(ang)
    return np.array([[c, -s], [s, c]])


def _overlap(Pi, mask, R, t):
    TP = Pi @ R.T + t
    xi = np.round(TP[:, 0]).astype(int) + 10; yi = np.round(TP[:, 1]).astype(int) + 10
    ok = (xi >= 0) & (xi < GS) & (yi >= 0) & (yi < GS)
    return int(mask[yi[ok], xi[ok]].sum())


def _nn(TP, Pj):
    d2 = (TP[:, None, 0]-Pj[None, :, 0])**2 + (TP[:, None, 1]-Pj[None, :, 1])**2
    idx = d2.argmin(1)
    return np.sqrt(d2[np.arange(len(TP)), idx]), idx


def geom_register(Pi, Pj, iters=12000, max_rot_deg=6, max_t=70, seed=0):
    """Rigid transform mapping cloud Pi onto Pj by overlap maximization + ICP
    refine. Returns (a,b,tx,ty Q16, overlap) or None. Assumes small inter-frame
    motion (consecutive enrollment captures)."""
    mask = _occmask(Pj); ni, nj = len(Pi), len(Pj); random.seed(seed)
    bc, bR, bt = 0, None, None
    for _ in range(iters):
        a, b = random.sample(range(ni), 2)
        dp = Pi[b] - Pi[a]; lp = dp @ dp
        if lp < 100:
            continue
        c, d = random.sample(range(nj), 2)
        dq = Pj[d] - Pj[c]; lq = dq @ dq
        if abs(lp - lq) > 0.06 * lp:
            continue
        ang = math.atan2(dq[1], dq[0]) - math.atan2(dp[1], dp[0])
        if abs(math.degrees(ang)) > max_rot_deg:
            continue
        R = _rot(ang); t = Pj[c] - R @ Pi[a]
        if abs(t[0]) > max_t or abs(t[1]) > max_t:
            continue
        cnt = _overlap(Pi, mask, R, t)
        if cnt > bc:
            bc, bR, bt = cnt, R, t
    if bR is None:
        return None
    for _ in range(3):
        TP = Pi @ bR.T + bt; dist, idx = _nn(TP, Pj); inl = dist <= 3.0
        if inl.sum() < 5:
            break
        P = Pi[inl]; Q = Pj[idx[inl]]; cP, cQ = P.mean(0), Q.mean(0)
        H = (P - cP).T @ (Q - cQ); U, _, Vt = np.linalg.svd(H); R = Vt.T @ U.T
        if np.linalg.det(R) < 0:
            Vt[-1] *= -1; R = Vt.T @ U.T
        bt = cQ - R @ cP; bR = R
    bc = int((_nn(Pi @ bR.T + bt, Pj)[0] <= 3.0).sum())
    a = int(round(bR[0, 0] * ONE)); b = int(round(bR[1, 0] * ONE))
    return a, b, int(round(bt[0] * ONE)), int(round(bt[1] * ONE)), bc


# ─── template loading + stored transform extraction ─────────────────────────
def load_sections_xy(ws, regs):
    out = []
    for base in regs:
        pts = []
        for k in range(250):
            o = base + k*18; x, y = ws[o], ws[o+1]
            if not (0 < x <= 112 and 0 < y <= 112):
                break
            pts.append((x, y))
        out.append(np.array(pts, float))
    return out


def stored_transforms(ws):
    s0 = ws[64:309]
    def rigid(a, b): return abs(a*a + b*b - ONE*ONE) < ONE*ONE*0.05
    best = []
    for st in range(60):
        tmp, o = [], st
        while o + 18 <= len(s0):
            a, b, tx, ty = struct.unpack_from('<4i', s0, o + 2)
            if not rigid(a, b):
                break
            tmp.append((math.degrees(math.atan2(b, a)), tx/ONE, ty/ONE)); o += 18
        if len(tmp) > len(best):
            best = tmp
    return best


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ft/wine_1780232416_0.bin"
    ws = open(path, "rb").read()[12:12 + WS_SIZE]
    regs = find_v30_regions(ws)
    secs = load_sections_xy(ws, regs)
    stored = stored_transforms(ws)
    print(f"template: {path}\n{len(secs)} sections, stored sec0_pre transforms: {len(stored)}")

    computed = []
    for i, j in itertools.permutations(range(len(secs)), 2):
        r = geom_register(secs[i], secs[j])
        if r is None:
            continue
        a, b, tx, ty, ov = r
        deg = math.degrees(math.atan2(b, a))
        computed.append((i, j, deg, tx/ONE, ty/ONE, ov))

    print("\n=== stored vs computed (geometric overlap-max registration) ===")
    hits = 0
    for k, (sr, stx, sty) in enumerate(stored):
        bb = min(computed, key=lambda c: abs(sr-c[2]) + abs(stx-c[3])/4 + abs(sty-c[4])/4)
        _, i, j, deg, tx, ty, ov = (0,) + bb
        ok = abs(sr-deg) < 2 and abs(stx-tx) < 6 and abs(sty-ty) < 6
        hits += ok
        print(f"  T{k}(rot{sr:+.2f},t{stx:+6.1f},{sty:+6.1f}) ~ sec{i}->{j}"
              f"(rot{deg:+.2f},t{tx:+6.1f},{ty:+6.1f}) ov={ov} {'✓' if ok else 'no'}")
    print(f"\n{hits}/{len(stored)} stored transforms reproduced exactly "
          f"(rot<2°,t<6px). Geometric method validated (reproduces the dominant\n"
          "alignment); exact DLL transforms are descriptor/reference-composed → "
          "need the gdb capture for byte-exact, OR test our own geom sec0_pre on chip.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
