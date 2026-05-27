"""Native MoH feature pipeline (06cb:00a2) — reproduction of the DLL's
image → v30 path, decoded in dev/DLL-RE.md and dev/MOH.md.

Pipeline (all stages classical CV; no proprietary enhancement):

    working image (112²)
      → 3×3 grid of 57×57 tiles (mid-gray pad)          [tile_image]      DONE
      → per tile: Q12 Determinant-of-Hessian → keypoints [doh_response]   approx (gradient kernel TBD)
      → orientation (Gaussian-weighted grad histogram)   [orientation]    decoded; impl WIP
      → oriented BRIEF descriptor                        [descriptor]     decoded; impl WIP
      → [x][y][128-bit desc] × 250 → v30                 [build_v30]       format known

Validation: each stage is checked against the live captures in
$FRIDA_DUMP_DIR (see dev/diff_v30.py). The tiling stage matches `gradin`
byte-exact (corr 1.000). The gradient kernels (esp. Ixy, which does not
recover by regression) are the remaining bit-exactness blocker — needs the
decompilation of sub_18000FDF0 / sub_1800101C0.
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

# cos/sin tables are round(cos/sin(deg) * 65536), idx 0..180 (ridge orient mod 180)
COS_Q16 = np.round(np.cos(np.deg2rad(np.arange(181))) * 65536).astype(np.int64)
SIN_Q16 = np.round(np.sin(np.deg2rad(np.arange(181))) * 65536).astype(np.int64)

ATAN2_FULLSCALE = np.pi * 65536        # 205887.4 — sub_180003150 Q16-radian full scale


# ─── DoH detector (Q12) — gradient kernels are the remaining unknown ─────
def doh_response(tile_q10, kxx, kyy, kxy):
    """Determinant-of-Hessian response on a tile (gradin = tile<<10).
    out = (Ixx>>12)*(Iyy>>12) - (Ixy>>12)**2, int32 (sub_18000CE80).
    kxx/kyy/kxy are the 2nd-derivative conv kernels — kxx/kyy recover by
    regression (corr 0.93-0.97); kxy does NOT (see module docstring), so
    this is approximate until sub_18000FDF0 is decompiled."""
    import cv2
    img = (tile_q10.astype(np.int64) >> 6).astype(np.float64)
    ixx = cv2.filter2D(img, cv2.CV_64F, kxx).astype(np.int64)
    iyy = cv2.filter2D(img, cv2.CV_64F, kyy).astype(np.int64)
    ixy = cv2.filter2D(img, cv2.CV_64F, kxy).astype(np.int64)
    return (ixx >> 12) * (iyy >> 12) - (ixy >> 12) ** 2


# orientation() and descriptor() are decoded (dev/DLL-RE.md "Descriptor
# algorithm") and will be filled in once the gradient kernels are exact —
# they consume the same Ix/Iy buffers the DoH stage produces.
