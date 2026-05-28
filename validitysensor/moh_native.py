"""Native MoH feature pipeline (06cb:00a2) — reproduction of the DLL's
image → v30 path, decoded in dev/DLL-RE.md and dev/MOH.md.

Pipeline (all stages classical CV; no proprietary enhancement):

    working image (112²)
      → 3×3 grid of 57×57 tiles (mid-gray pad)          [tile_image]      DONE
      → per tile: Q12 Determinant-of-Hessian → Ixx/Iyy/Ixy/resp [doh]    BYTE-EXACT (interior)
      → 8-neighbour NMS → keypoints                      [nms]            BYTE-EXACT
      → BRIEF bit-pack (per-kp 128 binary tests)         [brief_pack]     BYTE-EXACT
      → orientation (Gaussian-weighted grad histogram)   [orientation]    decoded; impl WIP
      → oriented BRIEF descriptor                        [descriptor]     decoded; impl WIP
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
TILE = 57                 # 2*GRID_X + step  (= 20 + 37 for a 112 image)
FILL = 128                # mid-gray pad (0x800000 in Q16 = 128.0)


def tile_origin(i, j, h, w):
    """Top-left (row, col) of tile (i,j). step = h/3; origin = i*step - GRID_X.
    Verified against captures: tile(0,0)@(-10,-10), tile(0,1)@(-10,27)."""
    return i * (h // GRID) - GRID_X, j * (w // GRID) - GRID_X


def tile_image(img):
    """Yield (i, j, tile) for the 3×3 grid. Each tile is TILE×TILE, mid-gray
    padded where it falls outside the image. Matches the DLL's sub_18000A850
    blit + sub_180009F50 pad (gradin == this, corr 1.000)."""
    h, w = img.shape
    for i in range(GRID):
        for j in range(GRID):
            oy, ox = tile_origin(i, j, h, w)
            tile = np.full((TILE, TILE), FILL, dtype=img.dtype)
            sy0, sx0 = max(0, oy), max(0, ox)
            sy1, sx1 = min(h, oy + TILE), min(w, ox + TILE)
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


# ─── separable apply: per-tap (pixel·tap)>>shift, convolution, replicate ──
def _conv_axis(img, kernel, shift, axis):
    n = img.shape[axis]
    idx = np.arange(n)
    acc = np.zeros(img.shape, dtype=np.int64)
    for off, tap in kernel:
        if tap == 0:
            continue
        src = np.clip(idx - off, 0, n - 1)           # convolution (kernel reversed)
        acc += (np.take(img, src, axis=axis).astype(np.int64) * tap) >> shift
    return acc


def apply_sep(img, kx, ky, shift):
    return _conv_axis(_conv_axis(img, kx, shift, 1), ky, shift, 0)


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


# NEXT after NMS: orientation (sub_18000D920) + oriented BRIEF (sub_18000E090).


# ─── E090 oriented-BRIEF descriptor — disasm-decoded; impl pending capture ─
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
