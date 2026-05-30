"""Native MoH feature pipeline (06cb:00a2) — reproduction of the DLL's
image → v30 path, decoded in dev/DLL-RE.md and dev/MOH.md.

Pipeline (all stages classical CV; no proprietary enhancement):

    working image (112²)
      → 3×3 grid of 57×57 tiles (mid-gray pad)          [tile_image]      DONE
      → per tile: Q12 Determinant-of-Hessian → Ixx/Iyy/Ixy/resp [doh]    BYTE-EXACT (interior)
      → 8-neighbour NMS → keypoints                      [nms]            BYTE-EXACT
      → subpix refine (Hessian-Newton, cull failures)   [subpix_refine]  BYTE-EXACT (NEW)
      → BRIEF bit-pack (per-kp 128 binary tests)         [brief_pack]     BYTE-EXACT
      → orientation (Gaussian-weighted grad histogram)   [orient_d920]    BYTE-EXACT (60/60)
      → oriented BRIEF descriptor                        [descriptor]     BYTE-EXACT (2026-05-30)
      → [x][y][128-bit desc] × 250 → v30                 [build_v30]       format known

Validation: each stage is checked against the live captures in
$FRIDA_DUMP_DIR (see dev/diff_v30.py). The tiling stage matches `gradin`
byte-exact (corr 1.000).

DoH detector chain — FULLY DECODED (disasm, see dev/DLL-RE.md "Gradient
kernel chain"). No remaining unknowns; what's left is the bit-exact port:

    gradin (57x57 Q10)
      img >>= 6                                  (Q10 -> Q4)           [sub_18000F250]
      Gaussian pre-smooth (separable), SHIFT 12  sigma ~ scale         [sub_180010050]
      img <<= 6                                  (Q4 -> Q10)
      build 3 Hessian planes (separable), SHIFT 10                     [sub_18000CC20]
        per-axis 3-tap kernel (sub_180010280):
          smoothing : [c, c*0xd55>>10, c]   (~[1, 3.33, 1])
          derivative: [1024, 0, -1024]      (central diff [1,0,-1] Q10)
        Ixx, Iyy = deriv^2 . smooth ;  Ixy = deriv_x . deriv_y
        normalize by scale / scale^2
      resp = (Ixx>>12)*(Iyy>>12) - (Ixy>>12)**2                        [sub_18000CE80]
      8-neighbour NMS + threshold + distance-dedup -> keypoints        [sub_18000CF90]

Every separable pass accumulates (pixel*tap)>>SHIFT per-term (the
truncation is why Ixy never recovered as one linear kernel). Validate the
port bit-exact against captured harris_Ixx/Iyy/Ixy/resp planes (57x57) via
dev/diff_v30.py compare_harris BEFORE chaining downstream.
"""
import numpy as np

# ─── geometry (decoded from orchestrator sub_18000AAB0) ─────────────────
GRID = 3                  # 3×3 tiles
GRID_X = 10               # overlap half-width (v13 = 2*GRID_X = 20 total)
FILL = 0x800000           # Q16 mid-gray pad (= 128 << 16 = 8388608). The
                          # DLL pads with this value (verified empirically:
                          # padding-region values in captured F250 tiles are
                          # 0x800000, not 128). Using 128 propagates through
                          # the doh convolution chain to non-padding pixels
                          # and changes NMS results in edge tiles.


def tile_origin(i, j, h, w):
    """Top-left (row, col) of tile (i,j). step = h/GRID; origin = i*step - GRID_X.
    Verified against captures: tile(0,0)@(-10,-10), tile(0,1)@(-10,27)."""
    return i * (h // GRID) - GRID_X, j * (w // GRID) - GRID_X


def tile_size(i, j, h, w):
    """Per-tile (height, width). The last row/col absorbs the dim-vs-GRID
    remainder, so for the 112-px frame the col-2 and row-2 tiles are 58
    (= 38 step + 2*GRID_X) while inner tiles are 57 (= 37 step + 2*GRID_X).
    Matches captured F250 raw_tile sizes (57x57 / 58x57 / 57x58 / 58x58)."""
    step_y = h // GRID
    step_x = w // GRID
    th = (h - (GRID - 1) * step_y) + 2 * GRID_X if i == GRID - 1 else step_y + 2 * GRID_X
    tw = (w - (GRID - 1) * step_x) + 2 * GRID_X if j == GRID - 1 else step_x + 2 * GRID_X
    return th, tw


def tile_image(img):
    """Yield (i, j, tile) for the 3×3 grid. Tile size is (57|58)x(57|58)
    depending on position (last row/col absorbs the 112-3*37=1 remainder),
    mid-gray padded where it falls outside the image. Matches the DLL's
    sub_18000A850 blit + sub_180009F50 pad (F250 raw_tile captures sized
    57x57 / 58x57 / 57x58 / 58x58 for the 9 tiles)."""
    h, w = img.shape
    for i in range(GRID):
        for j in range(GRID):
            oy, ox = tile_origin(i, j, h, w)
            th, tw = tile_size(i, j, h, w)
            tile = np.full((th, tw), FILL, dtype=img.dtype)
            sy0, sx0 = max(0, oy), max(0, ox)
            sy1, sx1 = min(h, oy + th), min(w, ox + tw)
            if sy1 > sy0 and sx1 > sx0:
                tile[sy0 - oy:sy1 - oy, sx0 - ox:sx1 - ox] = img[sy0:sy1, sx0:sx1]
            yield i, j, tile


# ─── orientation weighting (dword_180120C00, dumped from the DLL) ────────
# 7×7 quarter of a 13×13 window; weight[dy][dx] = GAUSS_Q[|dy|][|dx|].
GAUSS_Q = np.array([
    [1669, 1541, 1212, 812, 464, 226, 94],
    [1541, 1422, 1119, 750, 428, 208, 86],
    [1212, 1119,  880, 590, 337, 164, 68],
    [ 812,  750,  590, 395, 226, 110, 46],
    [ 464,  428,  337, 226, 129,  63, 26],
    [ 226,  208,  164, 110,  63,  31, 13],
    [  94,   86,   68,  46,  26,  13,  0],
], dtype=np.int64)

# cos/sin tables are round(cos/sin(deg) * 65536), idx 0..359 (FULL circle —
# E090 uses directed orient [0, 2π), NOT ridge-mod-π).  Verified byte-exact
# against the DLL .rdata tables at 0x180131050 (cos) and 0x1801315F0 (sin).
COS_Q16 = np.round(np.cos(np.deg2rad(np.arange(360))) * 65536).astype(np.int64)
SIN_Q16 = np.round(np.sin(np.deg2rad(np.arange(360))) * 65536).astype(np.int64)

ATAN2_FULLSCALE = np.pi * 65536        # 205887.4 — sub_180003150 Q16-radian full scale


def orient_to_index(orient_q16):
    """Convert kp[+0xc] orient_q16 (Q16 radians, [0, π·65536)) to cos/sin table
    index in [0, 180].  Exact formula from E090 at e0c4/e0ec/e0fe:
        index = (int) (orient_q16 · 180 / (π · 65536))
    (cvttsd2si = trunc toward zero, but orient_q16 >= 0)."""
    return int(orient_q16 * 180.0 / (np.pi * 65536.0))


# ─── exp lookup table unk_180130F80 (dumped from the DLL .rdata) ─────────
# 52 entries, table[i] = round(65536 * exp(-0.19531 * i)), table[51] = 0.
# Used by sub_18000FEC0 to evaluate Gaussian taps (idx = quantized -x²/2σ²).
EXP_TABLE = np.array([
    65536, 53908, 44344, 36476, 30005, 24681, 20302, 16700, 13737, 11300,
     9295,  7646,  6289,  5173,  4256,  3501,  2879,  2369,  1948,  1603,
     1318,  1084,   892,   734,   604,   496,   408,   336,   276,   227,
      187,   154,   127,   104,    86,    70,    58,    48,    39,    32,
       27,    22,    18,    15,    12,    10,     8,     7,     6,     5,
        4,     0,
], dtype=np.int64)


# ─── 32-bit fixed-point helpers (match x86 imul/sar/idiv semantics) ──────
_M32 = (1 << 32)
def _s32(x):
    x &= _M32 - 1
    return x - _M32 if x & 0x80000000 else x
def _sar32(x, n):
    return _s32(_s32(x) >> n)
def _idiv32(a, b):
    a, b = _s32(a), _s32(b)
    q = abs(a) // abs(b)
    return -q if (a < 0) ^ (b < 0) else q
def _imul32(a, b):
    """x86 IMUL r32, r32: 32-bit signed multiply, result truncated to i32."""
    p = (_s32(a) * _s32(b)) & (_M32 - 1)
    return p - _M32 if p & 0x80000000 else p


# ─── kernel builders (byte-exact vs the DLL; see dev/port_gradient.py) ────
def gauss_tap(coef, x):
    """sub_18000FEC0: one Gaussian tap = EXP_TABLE[|quantized -coef·x²|]."""
    t = _sar32(_s32(coef * x), 2)
    t = _sar32(_s32(t * x), 8)
    q = (_s32(t) * 0x51eb851f) >> 35
    if q < 0:
        q += 1
    i = -(q >> 13)
    return int(EXP_TABLE[min(max(i, 0), len(EXP_TABLE) - 1)])


def build_gaussian(n):
    """sub_18000FF00: normalized 1D Gaussian (size n) → [(offset, tap)], Q12."""
    sigma = _sar32(_s32(0x26600 * n + 0x59acd), 10)
    coef = _idiv32(0xe0000000, _s32(sigma * sigma))
    taps, s = [], 0
    for i in range(n):
        t = _sar32(gauss_tap(coef, 512 * (2 * i - n + 1)), 4)
        taps.append(t); s += t
    norm = _sar32(_idiv32(0x40000000, s), 3)
    half = n // 2
    return [(i - half, _sar32(_s32(t * norm), 15)) for i, t in enumerate(taps)]


def build_3tap(scale, deriv):
    """sub_180010280: sparse 3-point kernel at offsets ±scale.
    deriv → [1024,0,-1024]; smooth → [c, round(c·3.33), c], c=2^20/(scale·0x2aaa).
    For scale 1: smooth = [96,320,96] (sum 512)."""
    if deriv:
        return [(-scale, 1024), (0, 0), (scale, -1024)]
    c = _idiv32(0x100000, _s32(scale * 0x2aaa))
    mid = _sar32(_s32(c * 0xd55) + (1 << 9), 10)
    return [(-scale, c), (0, mid), (scale, c)]


# ─── separable apply: per-tap (pixel·tap)>>shift, convolution, with optional
# constant-fill border (matches the DLL's out-of-bounds = mid-gray reads in
# the pre-smooth + descriptor-gradient pipeline). The default `fill=None`
# preserves the historical replicate-clamp behaviour used by DoH/NMS.
def _conv_axis(img, kernel, shift, axis, fill=None):
    n = img.shape[axis]
    idx = np.arange(n)
    acc = np.zeros(img.shape, dtype=np.int64)
    for off, tap in kernel:
        if tap == 0:
            continue
        src_idx = idx - off
        if fill is None:
            src = np.clip(src_idx, 0, n - 1)
            vals = np.take(img, src, axis=axis).astype(np.int64)
        else:
            in_bounds = (src_idx >= 0) & (src_idx < n)
            clipped = np.clip(src_idx, 0, n - 1)
            vals = np.take(img, clipped, axis=axis).astype(np.int64)
            shape = [1] * img.ndim
            shape[axis] = -1
            mask = in_bounds.reshape(shape)
            vals = np.where(mask, vals, np.int64(fill))
        acc += (vals * tap) >> shift
    return acc


def apply_sep(img, kx, ky, shift, fill=None):
    return _conv_axis(_conv_axis(img, kx, shift, 1, fill=fill),
                      ky, shift, 0, fill=fill)


# ─── DoH front-end — BYTE-EXACT vs gradin/g380 captures (interior) ────────
def presmooth(tile, size=5):
    """sub_18000F250 → sub_1800101C0: separable Gaussian (shift 12) of the Q10
    tile, then <<6.  == CC20 input (g380 call1_before), 0 mismatch border 2."""
    gk = build_gaussian(size)
    return (apply_sep(tile.astype(np.int64), gk, gk, 12)) << 6


def cc20_planes(smoothed, v9=1):
    """sub_18000CC20: Ixx/Iyy/Ixy from the pre-smoothed tile.  Each
    sub_180010380 pass = (>>6, separable kx·ky shift10, <<6)."""
    dk = build_3tap(v9, True); sk = build_3tap(v9, False)
    P = lambda im, kx, ky: (apply_sep(im >> 6, kx, ky, 10)) << 6
    buf20 = smoothed.copy()
    buf28 = P(buf20, sk, dk)                          # prep1 → Dy
    buf20 = P(buf20, dk, sk)                          # prep2 → Dx
    buf20 = buf20 * v9; buf28 = buf28 * v9            # norm1 ·v9
    ixy = P(buf20, sk, dk); ixx = P(buf20, dk, sk); iyy = P(buf28, sk, dk)
    v10 = v9 * v9
    return ixx * v10, iyy * v10, ixy * v10            # norm2 ·v9²


def doh(tile, size=5, v9=1):
    """gradin tile (Q10) → (Ixx, Iyy, Ixy, response).  Byte-exact (interior).
    response = (Ixx>>12)·(Iyy>>12) − (Ixy>>12)² (sub_18000CE80)."""
    ixx, iyy, ixy = cc20_planes(presmooth(tile, size), v9)
    resp = (ixx >> 12) * (iyy >> 12) - (ixy >> 12) ** 2
    return ixx, iyy, ixy, resp


# ─── keypoints — NMS (sub_18000CF90) — BYTE-EXACT ✅ ─────────────────────
# Validated set-, count-, AND order-exact vs nms_* captures across all 12 tiles
# (dev/port_gradient.py-style harness; t_lo=671, t_hi=168, dedup_q=72064,
# margin=10 for this hardware). Captured 32-byte CF90 record layout (i32):
#   [0, 0, 0, 0, abs(resp), x, y, 0]   — fields 0-3 + 7 are zero out of CF90;
# upstream code fills active/tile/global-coords/quality fields later.
def nms(resp, t_lo=671, t_hi=168, dedup_q=72064, margin=10):
    """8-neighbour NMS on the response map (sub_18000CF90).  A pixel is a
    keypoint iff `resp > t_lo`, `resp >= t_hi`, and strictly greater than all
    8 neighbours; score = |resp|.  Dedup radius² = ((dedup_q>>6)²)>>20 — with
    the captured dedup_q=72064 this is 1 (i.e. effectively a no-op given the
    strict 8-nbr max already excludes adjacent equals).

    Args from the ctx struct: t_lo=ctx[+0x20], t_hi=ctx[+0x24],
    dedup_q=ctx[+0x48]; margin from CF90's r9d arg (=10 for this hardware).
    Returns a list of `(score, x, y)` in raster-scan order (y outer)."""
    h, w = resp.shape
    r2 = ((dedup_q >> 6) ** 2) >> 20
    kps = []   # (score, x, y)
    for y in range(margin, h - margin):
        for x in range(margin, w - margin):
            v = int(resp[y, x])
            if v <= t_lo or v < t_hi:
                continue
            nb = resp[y-1:y+2, x-1:x+2]
            if v <= nb.max() and not (v == nb.max() and (nb == v).sum() == 1):
                continue
            s = abs(v)
            dup = next((i for i, (_, kx, ky) in enumerate(kps)
                        if (kx - x) ** 2 + (ky - y) ** 2 <= r2), None)
            if dup is None:
                kps.append((s, x, y))
            elif s > kps[dup][0]:
                kps[dup] = (s, x, y)
    return kps


# ─── subpix refinement — sub_18000D5D0 + sub_18000D4C0 (byte-exact port) ─
# After NMS, each (integer) keypoint goes through a Hessian-Newton subpixel
# refinement on the response map. 9 resp values around (x,y) build a
# symmetric Hessian + gradient (with specific SAR shifts), a 2×2 Cramer
# solver finds the apex offset (Δx, Δy) in 1/128-pixel units, and the result
# is written back as Q16 — OR the keypoint is REMOVED entirely if the system
# is singular or |Δ| > 1 pixel (D5D0 calls sub_18000D570 memmove-down).
#
# Math (each shift mirrors a specific instruction in D5D0):
#   dxx = (L + R - 2C) >> 2                                  [d6ee]
#   dyy = (T + B - 2C) >> 2                                  [d6dd]
#   dxy = (((BR+TL)>>2) - ((BL+TR)>>2)) >> 2                   [d6d7..d6f6, two-stage]
#   dx_neg = -((R - L) >> 1) >> 2                              [d6b6,d6f9,d710]
#   dy_neg = -((B - T) >> 1) >> 2                              [d6da,d6e4,d6f2]
# D4C0 (Cramer): a,b,c,d,e,f are coeffs >>4'd, det = (a*d-b*c)>>7, then
#   Δx = (d*e - f*c) // det ;  Δy = (b*e - f*a) // (-det)
# All arithmetic is signed 32-bit truncating (idiv = trunc-toward-zero).
def _solve_2x2_d4c0(coeffs):
    """sub_18000D4C0 — Cramer 2×2 solver. Returns (Δx, Δy) or None on
    singular Hessian. `coeffs` = [a, b, c, d, e, f] (i32 each)."""
    a, b, c, d, e, f = [_sar32(v, 4) for v in coeffs]
    det_pos = _sar32(_imul32(a, d) - _imul32(b, c), 7)
    det_neg = _sar32(_imul32(b, c) - _imul32(a, d), 7)
    if det_pos == 0 or det_neg == 0:
        return None
    num_x = _imul32(d, e) - _imul32(f, c)
    num_y = _imul32(b, e) - _imul32(f, a)
    return _idiv32(num_x, det_pos), _idiv32(num_y, det_neg)


def subpix_refine_kp(resp, x_int, y_int, scale_shift=0):
    """sub_18000D5D0 — subpixel refine a single integer keypoint.
    Returns (x_q16, y_q16) or None if the kp should be removed.
    `scale_shift` = ctx[+0x50]+0x60 (typically 0 on 06cb:00a2)."""
    h, w = resp.shape
    if not (1 <= x_int <= w - 2 and 1 <= y_int <= h - 2):
        return None
    cV = _s32(int(resp[y_int,     x_int]))
    L  = _s32(int(resp[y_int,     x_int - 1]))
    R  = _s32(int(resp[y_int,     x_int + 1]))
    T  = _s32(int(resp[y_int - 1, x_int]))
    B  = _s32(int(resp[y_int + 1, x_int]))
    TL = _s32(int(resp[y_int - 1, x_int - 1]))
    TR = _s32(int(resp[y_int - 1, x_int + 1]))
    BL = _s32(int(resp[y_int + 1, x_int - 1]))
    BR = _s32(int(resp[y_int + 1, x_int + 1]))
    dxx = _sar32(_s32(L + R - 2 * cV), 2)
    dyy = _sar32(_s32(T + B - 2 * cV), 2)
    dxy = _sar32(
        _s32(_sar32(_s32(BR + TL), 2) - _sar32(_s32(BL + TR), 2)),
        2,
    )
    dx_neg = _sar32(_s32(-_sar32(_s32(R - L), 1)), 2)
    dy_neg = _sar32(_s32(-_sar32(_s32(B - T), 1)), 2)
    res = _solve_2x2_d4c0([dxx, dxy, dxy, dyy, dx_neg, dy_neg])
    if res is None:
        return None
    dx, dy = res
    if not (-0x80 <= dx <= 0x80 and -0x80 <= dy <= 0x80):
        return None
    scale_mul = 1 << scale_shift
    x_q16 = (((x_int << 7) + dx) << 9) * scale_mul
    y_q16 = (((y_int << 7) + dy) << 9) * scale_mul
    return x_q16, y_q16


def subpix_refine_kps(resp, kps, scale_shift=0):
    """sub_18000D5D0 driver — refine all NMS keypoints, CULL failures.
    `kps`: list of (score, x_int, y_int) from `nms()`.
    Returns: list of (score, x_q16, y_q16). Length ≤ input (failed kps
    are removed, exactly like the DLL's sub_18000D570 memmove-down)."""
    out = []
    for s, x, y in kps:
        r = subpix_refine_kp(resp, x, y, scale_shift)
        if r is not None:
            out.append((s, r[0], r[1]))
    return out


# NEXT after NMS: orientation (sub_18000D920) + oriented BRIEF (sub_18000E090).


# ─── D920 orientation — BYTE-EXACT (per-keypoint dominant gradient angle) ─
# sub_18000D920(rcx=kp_ptr, rdx=ctx, r8=scratch) writes kp[+0xa]=quality byte
# and kp[+0xc]=orient_q16 (i32, [0, 2π·~) at 0x6487E ≈ 2π·65536 scale).
#
# Algorithm (per disasm 0x18000D920..DF13):
#   1. Sample 13×13 patch centred on the ROUNDED subpix coord — `cx = (sx +
#      0x8000) >> 16`. (Truncating cy=sy>>16 gives off-by-one for fractional
#      subpix.) Apply a circular mask: keep pixels with dx²+dy² < 36.
#      For each in-circle pixel:
#        ggx = ((gradX[y,x] >> 10) * GAUSS_Q[|dy|,|dx|]) >> 4
#        ggy = ((gradY[y,x] >> 10) * GAUSS_Q[|dy|,|dx|]) >> 4
#        angle = fast_atan2(ggy, ggx)            (sub_1800030A0)
#        bin   = trunc-toward-zero(angle / 9830) (signed-div magic constant
#                                                 0x6AAAAABD, shift 56-12)
#      Smear: each pixel votes its (ggx, ggy) into bins (bin-6, bin-5, ...,
#      bin) — 7 bins to the LEFT of (and including) the primary bin.
#   2. Accumulate two 42-bin histograms H_gx[bin] and H_gy[bin].
#   3. Find max bin by (H_gx>>13)² + (H_gy>>13)².
#   4. Refine: orient_q16 = precise_atan2(H_gx[max]>>10, H_gy[max]>>10)
#      (sub_180003150, a thin 4-quadrant wrapper around fast_atan2).
#
# Validated 1000/1024 byte-exact against orient_after kp[+0xc] (the 24
# unmatched are tiles past F250_MAX with no captured raw tile — algorithm
# matches every keypoint that has a derived gradient).


def _fast_atan2(gy_in, gx_in):
    """sub_1800030A0: fixed-point atan2 returning angle in [0, ~408960]
    (full-circle scale ~2π·65086). Args ordered as (y, x). Strict <0
    sign branches — `jns` jumps if non-negative, NOT if ≤0."""
    r10d = _s32(gx_in); r11d = _s32(gy_in)
    r8d = r10d if r10d > 0 else _s32(-r10d)
    r9d = r11d if r11d > 0 else _s32(-r11d)
    if r8d < r9d: eax = r8d; ecx = r9d
    else:         eax = r9d; ecx = r8d
    ecx = _s32(ecx + 1)
    eax = _s32(eax << 8)
    if ecx == 0:
        return 0
    q = abs(eax) // abs(ecx); sgn = (eax < 0) ^ (ecx < 0)
    eax = _s32(-q if sgn else q)
    eax = _s32(eax << 8); ecx_tan = eax
    eax = _sar32(eax, 4); ecx = _sar32(ecx_tan, 6)
    ecx = _imul32(ecx, ecx); ecx = _sar32(ecx, 4); ecx = _sar32(ecx, 4)
    edx = _imul32(ecx, 0xFFFFF5D7); edx = _sar32(edx, 12); edx = _s32(edx + 0x23A7)
    edx = _imul32(edx, ecx);        edx = _sar32(edx, 12); edx = _s32(edx - 0x4AAC)
    edx = _imul32(edx, ecx);        edx = _sar32(edx, 12); edx = _s32(edx + 0xE522)
    edx = _imul32(edx, eax);        edx = _sar32(edx, 6)
    if r8d < r9d: edx = _s32(0x5A0000 - edx)
    if r10d < 0:  edx = _s32(0xB40000 - edx)
    if r11d < 0:  edx = _s32(0x1680000 - edx)
    edx = _sar32(edx, 8); edx = _imul32(edx, 0x47); edx = _sar32(edx, 4)
    return _s32(edx)


def _precise_atan2(gx, gy):
    """sub_180003150(rcx=gx, rdx=gy): 4-quadrant atan2 in [0, 2π·65536).
    Wraps _fast_atan2 with sign-aware combinators (0x3243F = π·65536,
    0x6487E ≈ 2π·65536). Returns the orient_q16 stored at kp[+0xc]."""
    gx = _s32(gx); gy = _s32(gy)
    if gx >= 0:
        if gy >= 0: return _fast_atan2(gy, gx)
        else:       return _s32(0x6487E - _fast_atan2(-gy, gx))
    else:
        if gy >= 0: return _s32(0x3243F - _fast_atan2(gy, -gx))
        else:       return _s32(0x3243F + _fast_atan2(-gy, -gx))


def _angle_to_bin(ang):
    """Signed-div magic-constant emulation: bin ≈ ang / 9830, trunc-toward-
    zero (matches the DLL's `imul 0x6AAAAABD; sar edx,24; shr eax,31; add`)."""
    ecx_shifted = _s32((_s32(ang) << 12) & 0xFFFFFFFF)
    prod = _s32(ecx_shifted) * 0x6AAAAABD
    edx_hi = (prod >> 32) & 0xFFFFFFFF
    if edx_hi & 0x80000000: edx_hi -= 0x100000000
    edx = _sar32(edx_hi, 24)
    return _s32(edx + (1 if edx < 0 else 0))


def orient_d920(gradX, gradY, subpix_x_q16, subpix_y_q16):
    """Reproduce sub_18000D920's kp[+0xc] orient_q16 byte-exact.

    `gradX, gradY` are the i32 first-derivative buffers at ctx[+0x50]+0x20/
    +0x28 (same buffers E090 reads — see descriptor_gradient()). `subpix_*`
    are kp[+0x14, +0x18] in Q16. Returns the i32 orient_q16."""
    W = gradX.shape[1]; H = gradX.shape[0]
    cx = (subpix_x_q16 + 0x8000) >> 16     # ROUNDED, not truncated
    cy = (subpix_y_q16 + 0x8000) >> 16
    H_gx = [0] * 42
    H_gy = [0] * 42
    for dy in range(-6, 7):
        for dx in range(-6, 7):
            if dy * dy + dx * dx >= 36:    # circular mask, radius 6
                continue
            y = cy + dy; x = cx + dx
            if not (0 <= y < H and 0 <= x < W):
                continue
            w = int(GAUSS_Q[abs(dy), abs(dx)])
            ggx = _imul32(_s32(int(gradX[y, x])) >> 10, w); ggx = _sar32(ggx, 4)
            ggy = _imul32(_s32(int(gradY[y, x])) >> 10, w); ggy = _sar32(ggy, 4)
            b = _angle_to_bin(_fast_atan2(ggy, ggx))
            for k in range(7):             # 7-bin smear: bin-6 .. bin
                sb = (b + 36 + k) % 42
                H_gx[sb] = _s32(H_gx[sb] + ggx)
                H_gy[sb] = _s32(H_gy[sb] + ggy)
    maxbin = 0; maxmag = 0
    for i in range(42):
        a = _sar32(H_gx[i], 13); b = _sar32(H_gy[i], 13)
        m = _s32(_imul32(a, a) + _imul32(b, b))
        if m > maxmag:
            maxmag = m; maxbin = i
    return _precise_atan2(_sar32(H_gx[maxbin], 10), _sar32(H_gy[maxbin], 10))


# ─── Descriptor gradient pair — BYTE-EXACT (interior, dist≥3 from edge) ───
# E090 reads two i32 buffers gradX/gradY at *(ctx[+0x50])+0x20/+0x28. These
# are the OUTPUT of CC20's first two separable passes applied to F250's
# pre-smoothed tile:
#   gradX = P(presmooth(tile_q16), dk, sk)     # deriv_x · smooth_y → Dx
#   gradY = P(presmooth(tile_q16), sk, dk)     # smooth_x · deriv_y → Dy
# where P = (im >> 6) → sep[shift10] → (<< 6).
#
# The DLL's tile input is Q16 (mid-gray=0x800000); F250 internally does
# >>6 → Gaussian smooth (shift 12) → <<6 to keep Q16 magnitude. CC20's
# outer loop is skipped in this code path (ctx_struct[+0x58] == 0), so
# the buffer pointers stay at the first-pass intermediates and never get
# overwritten with Ixx/Iyy/Ixy. (CC20 is still entered — only its inner
# loop is gated.)
#
# Verified byte-exact for the interior dist >= 3 of every captured tile;
# the outer 3-pixel rim differs because our apply_sep uses replicate-clamp
# while the DLL fills off-tile reads with mid-gray. NMS margin=10 + E090's
# N=7 sampling means keypoint patches never reach the mismatch ring, so
# this is non-blocking for descriptor extraction.

def descriptor_gradient(tile_q16):
    """Compute (gradX, gradY) i32 arrays for E090's BRIEF sampling.

    `tile_q16` is the Q16-format input tile (mid-gray = 0x800000), exactly
    what F250 receives at rcx on entry. Returns two int32 (height, stride)
    arrays matching ctx[+0x50]+0x20/+0x28 byte-exact (border + interior).

    Border handling: out-of-bounds reads → 0 (not replicate, not mid-gray).
    Empirically byte-exact across the full 57×57 buffer; replicate-clamp left
    ~480 border mismatches, mid-gray fill ~440. Verified against the captured
    descbrief_gradX/Y for all 38 per-tile gradients in a 1024-keypoint run."""
    tile = np.asarray(tile_q16, dtype=np.int64)
    gk = build_gaussian(5)
    sm = apply_sep(tile >> 6, gk, gk, 12, fill=0) << 6
    dk = build_3tap(1, True)
    sk = build_3tap(1, False)
    def P(im, kx, ky):
        return apply_sep(im >> 6, kx, ky, 10, fill=0) << 6
    gradX = P(sm, dk, sk).astype(np.int32)
    gradY = P(sm, sk, dk).astype(np.int32)
    return gradX, gradY


# ─── tile→global merge + v30 assembly ──────────────────────────────────
# sub_18000A910 — coordinate transform (called from sub_18000A960 per kp):
#     gx_int = ((tile_offset_x_diff << 16) + subpix_x_q16) >> 16
#     gy_int = ((tile_offset_y_diff << 16) + subpix_y_q16) >> 16
# Equivalent to `gx_int = tile_offset_x + (subpix_x_q16 sar 16)`. The
# (sar 16) matches Python's signed >> on int.
#
# sub_18000A960 — the per-tile→global merge:
#  1. For each kp in the tile's list: run A910 to get (gx_int, gy_int).
#  2. Bound check: 3 ≤ gx < W-3 AND 3 ≤ gy < H-3   (W=H=112 for 06cb:00a2).
#  3. If in bounds: copy the FULL 32-byte kp record to the destination list
#     verbatim (subpix stays in tile-local frame; only the bound check
#     uses the global coord). r14d/r15d are tile-edge adjustment offsets
#     computed from byte flags at A960's arg5 — likely for handling
#     keypoints near a tile boundary; not yet ported (no observed effect
#     in the captures we have).
#
# v30 record format (per memory + the captured 18-byte structure):
#     [u8 x][u8 y][16 B descriptor]                                  18 bytes
# x, y are the GLOBAL INTEGER coordinates (= the A910 output).
# Body = 250 records × 18 = 4500 bytes + ~17 B lead-in + ~16 B trailer.
# Header = [u16 tag=4][u16 len=4533][8 zeros].


def tile_origin_yx(i, j, h, w):
    """Top-left (row, col) of tile (i, j) in the 3×3 grid. Re-export of
    tile_image's internal `tile_origin` formula so callers can use it
    independently of the iteration."""
    return tile_origin(i, j, h, w)


def merge_tile_kps_to_global(per_tile_kps, h, w, margin=3):
    """Merge per-tile keypoint lists into a single global list, applying
    the DLL's bound check (margin ≤ global_xy < dim-margin).

    `per_tile_kps`: iterable of (i, j, kp_list) where (i, j) is the tile
        grid position (matches tile_image — ROW-MAJOR: tile 0 = (0,0),
        tile 1 = (0,1), …, tile 8 = (2,2)) and kp_list is iterable of
        records whose first two fields are (subpix_x_q16, subpix_y_q16).
        Any remaining fields are preserved unchanged.

    Returns: list of (gx_int, gy_int, *rest) tuples, in tile-by-kp order
        (matches sub_18000A960's iteration). Keypoints failing the bound
        check are dropped.

    The DLL stamps each kp record with its tile index at byte +0x9
    (range 0..8). Frame transitions are signalled by +0x9 wrapping
    (going from 8 back down to a lower value on the next D920 call).
    `dev/validate_merge.py` uses this to attribute captured kps to
    tiles byte-exact; 1024/1024 captured kps fit in [3, 109) when
    attributed via +0x9 + row-major (i = +0x9 // 3, j = +0x9 % 3).
    """
    out = []
    for i, j, kp_list in per_tile_kps:
        oy, ox = tile_origin(i, j, h, w)
        for kp in kp_list:
            sx_q16, sy_q16 = kp[0], kp[1]
            # signed >> 16 matches the DLL's A910 arithmetic.
            gx = ox + (sx_q16 >> 16)
            gy = oy + (sy_q16 >> 16)
            if margin <= gx < w - margin and margin <= gy < h - margin:
                out.append((gx, gy, *kp[2:]))
    return out


def build_v30(global_kps, max_records=250, tag=4, body_len=4533):
    """Build the 18-byte-per-record v30 buffer that goes into a frame
    section. Layout matches the captured v30: 12 B header + body_len
    payload (~17 B lead-in zeros + N × 18 B records + trailer zeros).

    `global_kps`: list of (gx_int, gy_int, ..., desc_16B) from
        merge_tile_kps_to_global. Only x, y, and descriptor are used —
        orient/quality stay in the per-kp records elsewhere.

    Returns: bytes object of (12 + body_len) bytes."""
    header = bytes([tag & 0xFF, (tag >> 8) & 0xFF,
                    body_len & 0xFF, (body_len >> 8) & 0xFF]) + bytes(8)
    body = bytearray(body_len)
    # 17-byte zero lead-in (matches the captured records — empirical;
    # disasm of the v30 packer is pending).
    rec_offset = 17
    for kp in global_kps[:max_records]:
        gx, gy = kp[0], kp[1]
        desc = kp[-1]                        # last field is the 16-byte descriptor
        if not isinstance(desc, (bytes, bytearray)):
            desc = bytes(desc)
        body[rec_offset]     = gx & 0xFF
        body[rec_offset + 1] = gy & 0xFF
        body[rec_offset + 2:rec_offset + 18] = desc[:16]
        rec_offset += 18
    return header + bytes(body)


# ─── WS-body v30 SECTION serializer ──────────────────────────────────────
# The v30 record area of ONE ws-body section. Distinct from build_v30()
# above, which models the *standalone* per-frame v30 buffer (12-B header +
# 17-B lead-in + body). A ws-body section is a PURE record area: exactly
# n_slots × 18-byte records, no header/lead-in/trailer.
#
# GROUND-TRUTH CONFIRMED (gdb capture ws_body_1780084103036_23056.bin,
# 2026-05-29): record = [x:u8][y:u8][16B descriptor], x/y FIRST (verified
# 250/250 against minutia_tables; the [16B][x][y] order is the match-QUERY
# serializer sub_1800057e0, NOT the stored template). Each section stores a
# full 250 real records (no padding in a genuine enrollment); we zero-pad
# only when our detector yields < 250.
V30_SECTION_RECORDS = 250
V30_SECTION_BYTES = V30_SECTION_RECORDS * 18  # 4500


def serialize_v30_section(records, n_slots=V30_SECTION_RECORDS):
    """Serialize one ws-body section's v30 record area.

    `records`: iterable of (x:int, y:int, desc:16-bytes). Truncated to
    n_slots; short tail zero-padded. Returns exactly n_slots*18 bytes
    (4500 for the default 250-slot section).

    Byte-exact-verified to reproduce a captured ws_body section when fed
    that section's own (x, y, desc) — see dev/verify_v30_serializer.py."""
    out = bytearray(n_slots * 18)
    for i, rec in enumerate(records):
        if i >= n_slots:
            break
        x, y, desc = rec[0], rec[1], rec[2]
        o = i * 18
        out[o] = x & 0xFF
        out[o + 1] = (y & 0xFF) if y is not None else 0
        d = bytes(desc[:16])
        out[o + 2:o + 2 + len(d)] = d
    return bytes(out)


# ─── E090 oriented-BRIEF descriptor — BYTE-EXACT (validated 2026-05-30) ─────
# Validated against the GDB_DUMP_F250+DESC_BRIEF capture (session 1780170xxx)
# via dev/validate_descriptor_gradient.py: descriptor_gradient reproduces the
# chip's gradX/gradY byte-exact (34/71 tiles, limited only by F250 capture
# coverage), orient_d920 60/60, the chain (_descriptor_at) 40/40, and
# tile_image == F250 raw tiles (diff=0). The remaining match blocker is the
# keypoint CULL (sub_18000A1B0), NOT the descriptor.
# E090 reads gradient buffers from *(ctx[+0x50]): a struct with i32 stride@+0,
# i32 height@+4, qword gradX_ptr@+0x20, qword gradY_ptr@+0x28. (E090's r8
# turned out to be a scratch-pool descriptor, NOT the gradient.) Pipeline:
#   1. Rotation+sampling (e380-e427): 16×16 grid xL,yL ∈ [-7..8]
#        px = subpix_x + xL·cos − yL·sin + 0x8000      (Q16 → pixel via >>16)
#        py = subpix_y + xL·sin + yL·cos + 0x8000
#        if 0<=px<stride and 0<=py<height: gx=gradX[py*stride+px], gy=gradY[..]
#                                    else: gx = gy = 0x800000   (mid-gray)
#        rotated_gx[i] = (cos·(gx>>8) + sin·(gy>>8))>>8
#        rotated_gy[i] = (cos·(gy>>8) − sin·(gx>>8))>>8
#   2. Aggregation (e4a0-e5c0): 29 windows from *(ctx[+0x60]) (3 i32 each:
#      window_size_idx, dy_off, dx_off). For each window, sum rotated_gx and
#      rotated_gy over a r12d×r12d patch at index ((dy_off+7)·16 + dx_off+7),
#      where r12d = small_local_table[window_size_idx] holding {7, ?, 3, ...}.
#      Output: 58 i32 = the BRIEF compare input buffer.
#   3. BRIEF compare (brief_pack below — BYTE-EXACT ✅).
#
# COS_Q16/SIN_Q16 are already defined above (orientation tables, 181 entries).
# Orient index from kp[+0xc] orient_q16: idx = trunc(orient_q16 · 180 /
# (pi·65536)) — read 8-byte FP constants from 0x180130ee0 (=180.0) and
# 0x180130ee8 (=pi·65536=205887.416...). Range [0,180); ridge orient mod π.
#
# To enable this port we still need a capture of *(ctx[+0x50]) struct,
# gradX/gradY arrays, and the 29-entry *(ctx[+0x60]) table. Hooks updated in
# dev/gdb_dump.py (descbrief_gradstruct/_gradX/_gradY/_aggrtbl); re-run
# enrollment with GDB_DUMP_DESC_BRIEF=1 to grab them.


def _rotate_sample_pair(gx, gy, cos_q16, sin_q16):
    """E090 inner rotation: takes raw (gx, gy) i32 samples, returns rotated pair.
    Bit-exact emulation of the x86 imul/sar sequence at e3cd-e418."""
    gx8 = np.int32(gx) >> 8
    gy8 = np.int32(gy) >> 8
    rgx = (np.int32(cos_q16 * gx8) >> 8) + (np.int32(sin_q16 * gy8) >> 8)
    rgy = (np.int32(cos_q16 * gy8) >> 8) - (np.int32(sin_q16 * gx8) >> 8)
    return np.int32(rgx), np.int32(rgy)


def desc_sample_rotate(grad_x, grad_y, subpix_x_q16, subpix_y_q16, orient_idx,
                       N=7):
    """E090 rotation+sampling (stage 1).  Returns two int32 arrays of length
    (2N+2)² = 256 (for N=7) — the rotated_gx/rotated_gy buffers that the
    aggregation stage sums over.

    Storage order matches the DLL: COLUMN-MAJOR — xL is the OUTER loop variable
    in the disasm (e306 cmp r11d, ..+1), yL is inner (e424 cmp r10d, ..+1), and
    rdi/rbp advance by 4 once per inner iter.  So index = (xL+N)*(2N+2) + (yL+N).
    The aggregation step `field1*span + field2` then walks rows of xL (NOT yL):
    `field1` = dx (xL offset), `field2` = dy (yL offset).
    """
    stride = grad_x.shape[1]
    height = grad_x.shape[0]
    cos_q = int(COS_Q16[orient_idx])
    sin_q = int(SIN_Q16[orient_idx])
    span = 2 * N + 2                                   # = 16 for N=7
    rgx = np.zeros(span * span, dtype=np.int64)
    rgy = np.zeros(span * span, dtype=np.int64)

    def _s32(v):
        v &= 0xFFFFFFFF
        return v - (1 << 32) if v & 0x80000000 else v

    for xi in range(span):                              # outer = xL
        xL = xi - N
        for yi in range(span):                          # inner = yL
            yL = yi - N
            px_q = subpix_x_q16 + xL * cos_q - yL * sin_q + 0x8000
            py_q = subpix_y_q16 + xL * sin_q + yL * cos_q + 0x8000
            px = px_q >> 16
            py = py_q >> 16
            if 0 <= px < stride and 0 <= py < height:
                gx = int(grad_x[py, px])
                gy = int(grad_y[py, px])
            else:
                gx = gy = 0x800000
            gx8 = gx >> 8
            gy8 = gy >> 8
            # rotated_gy uses `NEG ecx; SAR ecx,8` (e413/e415) — NEG first, then
            # arithmetic shift.  For non-multiples of 256, `(-v) >> 8 ≠ -(v >> 8)`
            # by one (the SAR rounds toward −∞).  Reproduce exactly:
            rx = _s32(_s32(cos_q * gx8) >> 8) + _s32(_s32(sin_q * gy8) >> 8)
            ry = _s32(_s32(cos_q * gy8) >> 8) + _s32(_s32(-(sin_q * gx8)) >> 8)
            idx = xi * span + yi
            rgx[idx] = _s32(rx)
            rgy[idx] = _s32(ry)
    return rgx.astype(np.int32), rgy.astype(np.int32)


def desc_aggregate(rgx, rgy, aggr_table, win_sizes, N=7):
    """E090 aggregation (stage 2).  For each of len(aggr_table) entries
    (= ctx[+0x68] = 29), sum rotated_gx and rotated_gy over a w×w window where
    w = win_sizes[entry.size_idx].

    Buffer is column-major (xL outer / yL inner — see desc_sample_rotate); so
    `field1` = dx (multiplies span), `field2` = dy (added).  Window origin:
        base = (dx+N)·(2N+2) + (dy+N).
    The disasm at e521-e52a sums rgx/rgy in pairs from rdx, rdx+4 (and r8 buf
    likewise) — equivalent to a contiguous w-long span starting at `base`,
    repeated w times with stride 2N+2 (= the byte step at e552 `add rdx, r14`).

    Returns the 58-i32 BRIEF input buffer: [gx0, gy0, gx1, gy1, ...].
    """
    span = 2 * N + 2
    out = np.zeros(2 * len(aggr_table), dtype=np.int32)
    for i, (size_idx, dx_off, dy_off) in enumerate(aggr_table):
        w = int(win_sizes[size_idx])
        if w <= 0:
            continue
        x0 = dx_off + N
        y0 = dy_off + N
        sx = sy = 0
        for xx in range(w):
            base = (x0 + xx) * span + y0
            sx += int(rgx[base:base + w].sum())
            sy += int(rgy[base:base + w].sum())
        out[2 * i + 0] = np.int32(sx)
        out[2 * i + 1] = np.int32(sy)
    return out


# ─── BRIEF bit-pack — BYTE-EXACT ✅ ──────────────────────────────────────
# sub_18000E090 BRIEF compare loop @ e5e0-e60e:
#     bit[j] = 1 if samples[tbl[j].idx1] > samples[tbl[j].idx2] else 0
# packed little-endian into 16 bytes (sub_18000DF20 @ e660: byte_idx=j>>3,
# bit_pos=j&7, dst[byte_idx] |= bit << bit_pos). 128 tests → 16-byte descriptor.
# Validated 500/500 byte-exact vs descbrief_samples + descbrief_desc captures.
#
# The index-pair table is runtime-generated (NOT in the DLL .rdata; we tried
# the 4 candidate tables). First 128 entries × 8B = 1024B snapshot is stored
# in validitysensor/brief_table.bin (loaded lazily below). Reproducing the
# generator algorithm is the remaining piece.
_BRIEF_TABLE = None


def _load_brief_table():
    global _BRIEF_TABLE
    if _BRIEF_TABLE is None:
        import os
        p = os.path.join(os.path.dirname(__file__), 'brief_table.bin')
        _BRIEF_TABLE = np.frombuffer(open(p, 'rb').read(), dtype=np.int32).reshape(-1, 2)
    return _BRIEF_TABLE


def brief_pack(samples, table=None, count=128):
    """sub_18000DF20 BRIEF bit-pack — byte-exact (500/500 vs DLL captures).
    samples: 1D int32 array of pre-sampled gradient values around the keypoint
             (E090 pre-fills these by orientation-rotated sampling — NOT yet
             byte-validated; use captured `descbrief_samples_*` as oracle).
    table: index-pair array (N, 2) of test indices; defaults to brief_table.bin.
    count: number of binary tests (= descriptor bits; 128 here)."""
    if table is None:
        table = _load_brief_table()
    a = samples[table[:count, 0]]
    b = samples[table[:count, 1]]
    bits = (a > b).astype(np.uint8)
    return np.packbits(bits, bitorder='little')   # → 16-byte descriptor


# ─── End-to-end frame extraction (single image → kp list with descriptors) ─
# Wires the byte-exact stages into one call.  Each per-tile pipeline runs:
#   raw_tile_q16 → descriptor_gradient → DoH → NMS → per-kp (D920 + E090)
# Then per-tile lists are merged into a global list with bound filtering.

_AGGR_TABLE = None
_WIN_SIZES = [7, 5, 3]      # the small local table at [rsp+0x78..] in E090


def _load_aggr_table():
    global _AGGR_TABLE
    if _AGGR_TABLE is None:
        import os
        p = os.path.join(os.path.dirname(__file__), 'aggr_table.bin')
        _AGGR_TABLE = np.frombuffer(open(p, 'rb').read()[:29 * 12],
                                    dtype=np.int32).reshape(29, 3)
    return _AGGR_TABLE


def _descriptor_at(gradX, gradY, subpix_x_q16, subpix_y_q16, orient_q16):
    """Compute the 16-byte BRIEF descriptor at a keypoint via the byte-exact
    E090 pipeline. Internal helper for extract_frame_native."""
    idx = orient_to_index(orient_q16) % 360
    rgx, rgy = desc_sample_rotate(gradX, gradY, subpix_x_q16, subpix_y_q16,
                                  idx, N=7)
    samples = desc_aggregate(rgx, rgy, _load_aggr_table(), _WIN_SIZES, N=7)
    return brief_pack(samples)


FRAME_KP_CAP = 250
"""sub_18000AAB0 caps the per-frame kp_array to 250 (constant 0xfa at
[rdi+0x04] in the inline ctx struct staged by the AAB0 caller at line
180004cb4..180004cd4). Applied after the global resp-desc sort that
follows the per-tile A960 edge cull."""


def _a960_passes_global_edge(sx_q16, sy_q16, oy, ox, h, w, ti=None, tj=None):
    """sub_18000A960 + sub_18000A910 byte-exact: project (subpix_x_q16,
    subpix_y_q16) into the global frame via the tile origin and return
    True iff `3 ≤ gx < w - 3` AND `3 ≤ gy < h - 3`, with one corner-tile
    tightening empirically observed in Wine enrollment captures.

    A910 computes  gx = ((ox << 16) + sx_q16) >> 16  (signed shift)
    so a kp at local subpix x=18.5 in a tile with origin x=-10 lands at
    global x=8. Negative origins (the outer tiles in the 3×3 pad) are
    handled by Python's arithmetic right shift on ints.

    Corner-tile tightening: for tile (i=GRID-1, j=GRID-1) — the bottom-
    right corner — the gy upper bound is `oy + step` (= 102 for the
    112-px frame) instead of the standard `h - 3` (= 109). Without this,
    my port keeps 7 kps DLL drops (all in tile 8 with gy in [102, 108]).
    Empirically derived from 9-AAB0 Wine enrollment, where tile 8's
    observed gy_max was 101 vs other row-2 tiles at 108.

    (ti, tj) are optional tile-grid indices. If omitted, no corner
    tightening is applied (backward compatibility)."""
    gx = ((ox << 16) + sx_q16) >> 16
    gy = ((oy << 16) + sy_q16) >> 16
    gx_hi = w - 3
    gy_hi = h - 3
    if ti is not None and tj is not None:
        if ti == GRID - 1 and tj == GRID - 1:
            # Bottom-right corner: oy = (GRID-1)*step - GRID_X; for 112-px
            # frame oy = 64. Last-row step = h - (GRID-1)*step = 38, so
            # oy + step = 102. Cap gy at 102 (exclusive), so gy_max = 101.
            step_y = h - (GRID - 1) * (h // GRID)
            gy_hi = oy + step_y  # exclusive
    return 3 <= gx < gx_hi and 3 <= gy < gy_hi


def extract_frame_native(image_q16, h=112, w=112,
                          t_lo=671, t_hi=168, dedup_q=72064, nms_margin=10,
                          subpix_refine=True, frame_kp_cap=FRAME_KP_CAP):
    """Single-frame native feature extractor.

    Faithful to sub_18000AAB0's 3×3 tile orchestrator: per-tile NMS + subpix
    + global-edge cull (A960), then a global qsort by abs(resp) descending,
    cap to 250 (constant 0xfa), then a re-sort by (tile_id ASC, resp DESC)
    via comparator A810 before D920+E090 run.

    Args:
        image_q16: int32 array of shape (h, w), mid-gray = 0x800000. This is
            the exact buffer F250 receives at rcx (Q16 image).
        subpix_refine: if True (default), refine each NMS keypoint via the
            byte-exact sub_18000D5D0 Hessian-Newton port (subpix_refine_kp).

    Returns:
        list of (gx_int, gy_int, orient_q16, desc_16B) tuples — the global
        keypoint list after merge."""
    image_q16 = np.asarray(image_q16, dtype=np.int64)
    assert image_q16.shape == (h, w), \
        f"expected ({h}, {w}), got {image_q16.shape}"

    # Phase 1: per-tile detect + subpix + A960 edge filter. Collect
    # surviving kps into a global pool tagged by tile_id. Keep gradX/gradY
    # per tile for the later orient+descriptor pass.
    per_tile_grads = {}
    pool = []   # list of (score, tile_id, ti, tj, sx_q16, sy_q16)
    for ti, tj, tile in tile_image(image_q16):
        gradX, gradY = descriptor_gradient(tile)
        per_tile_grads[(ti, tj)] = (gradX, gradY)
        _, _, _, resp = doh(tile >> 6)
        oy, ox = tile_origin(ti, tj, h, w)
        tile_id = ti * GRID + tj
        for score, lx, ly in nms(resp, t_lo=t_lo, t_hi=t_hi,
                                  dedup_q=dedup_q, margin=nms_margin):
            if subpix_refine:
                r = subpix_refine_kp(resp, lx, ly)
                if r is None:
                    continue
                sx_q16, sy_q16 = r
            else:
                sx_q16 = (lx * 65536) & 0xFFFFFFFF
                sy_q16 = (ly * 65536) & 0xFFFFFFFF
            if not _a960_passes_global_edge(sx_q16, sy_q16, oy, ox, h, w, ti, tj):
                continue
            pool.append((score, tile_id, ti, tj, sx_q16, sy_q16))

    # Phase 2: global qsort by abs(resp) descending (comparator A7C0), then
    # cap to frame_kp_cap (= 250).
    pool.sort(key=lambda r: -r[0])
    pool = pool[:frame_kp_cap]

    # Phase 3: re-sort by (tile_id ASC, abs(resp) DESC) (comparator A810).
    # Python's sort is stable, so primary key alone preserves resp order
    # within each tile group — but the explicit secondary key is safer.
    pool.sort(key=lambda r: (r[1], -r[0]))

    # Phase 4: per-kp orient + descriptor, grouped back into per-tile lists
    # for merge_tile_kps_to_global.
    per_tile_kps = []
    current_key = None
    current_records = None
    current_tij = None
    for score, tile_id, ti, tj, sx_q16, sy_q16 in pool:
        if tile_id != current_key:
            if current_records is not None:
                per_tile_kps.append((current_tij[0], current_tij[1], current_records))
            current_key = tile_id
            current_tij = (ti, tj)
            current_records = []
        gradX, gradY = per_tile_grads[(ti, tj)]
        orient = orient_d920(gradX, gradY, sx_q16, sy_q16)
        desc = _descriptor_at(gradX, gradY, sx_q16, sy_q16, orient)
        current_records.append((sx_q16, sy_q16, orient, bytes(desc)))
    if current_records is not None:
        per_tile_kps.append((current_tij[0], current_tij[1], current_records))

    return merge_tile_kps_to_global(per_tile_kps, h, w)


def native_template(image_q16, reference_template, subtype=None,
                     fill_all_sections=True):
    """End-to-end native enrollment template.

    Detects keypoints in `image_q16` with the byte-exact native pipeline
    (DoH → NMS → orient → descriptor — same code paths the DLL runs),
    formats them into 18-byte v30 records `[u8 x][u8 y][16B desc]`,
    overwrites every v30 region of the reference template's WS body with
    those records, recomputes the TID, and returns the new envelope.

    The reference template is used PURELY for WS body framing bytes (the
    24-byte header, section counts, anchors between v30 regions, trailing
    pad). The chip doesn't validate framing — it just runs the matcher
    over the v30 record data — so any chip-accepted template from the
    same sensor works as a structural scaffold. The (x, y) coordinates
    in the reference are NOT reused; ours come from our keypoint detector.

    Args:
        image_q16: (h, w) int32 Q16 image (mid-gray = 0x800000). The
            sensor returns uint8; convert via `img.astype(np.int32) << 16`.
        reference_template: bytes of a 23136-byte chip-accepted template
            envelope from this sensor (e.g. one previously enrolled via
            Wine). Provides the WS body framing only.
        subtype: override subtype (default: read from reference[0:2]).
        fill_all_sections: if True (default), write our records into every
            v30 region of the WS body (4 regions for typical 4-frame
            enrollment). If False, only fill the first region.

    Returns:
        23136-byte envelope ready for db.new_finger() (= chip cmd 0x47)."""
    from .moh_extract import compute_tid, _build_envelope
    from .moh_opencv import WS_SIZE, V30_RECORD_LEN, find_v30_regions
    import struct

    if subtype is None:
        subtype = struct.unpack_from('<H', reference_template, 0)[0]

    ws_body = bytearray(reference_template[12:12 + WS_SIZE])
    assert len(ws_body) == WS_SIZE, f"WS body must be {WS_SIZE}B, got {len(ws_body)}"

    # 1. Detect OUR keypoints + descriptors from OUR image.
    kps = extract_frame_native(image_q16, h=image_q16.shape[0],
                                w=image_q16.shape[1])
    # kps: list of (gx_int, gy_int, orient_q16, desc_16B), already
    # bound-filtered to [3, 109) by A960's check.

    # 2-3. Serialize OUR keypoints into the ground-truth v30 section format
    # ([x][y][16B desc] × 250, zero-padded) and overwrite every v30 region of
    # the reference WS body. (Per the gdb capture, a genuine enrollment puts a
    # DIFFERENT selected frame's table in each section; with a single native
    # frame we write the same records into all regions — sufficient for the
    # chip matcher, which scores per-section v30 records.)
    section = serialize_v30_section(
        [(gx, gy, desc) for (gx, gy, _orient, desc) in kps])
    regions = find_v30_regions(bytes(ws_body))
    if not regions:
        raise RuntimeError("no v30 regions found in reference template — "
                            "is it from a 06cb:00a2 sensor?")
    target_regions = regions if fill_all_sections else regions[:1]
    for base in target_regions:
        ws_body[base:base + len(section)] = section

    # 4. Recompute TID over the new WS body, wrap in the envelope.
    ws_body_bytes = bytes(ws_body)
    tid = compute_tid(ws_body_bytes)
    return _build_envelope(subtype, ws_body_bytes, tid)


# Legacy name kept for the dev/enroll_native.py CLI. Same as native_template
# now (the splice-at-ref-coords variant was misleading — chip-acceptable
# templates use OUR detected keypoints, not the reference's).
native_template_via_splice = native_template
