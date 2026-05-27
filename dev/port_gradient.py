"""Port + validate the DoH gradient (06cb:00a2) against the captured planes.

Decoded chain (dev/DLL-RE.md "Gradient kernel chain"):
  gradin(57² Q10) → >>6 → Gaussian pre-smooth (separable, shift 12)
                  → <<6 → derivative passes (separable [1,0,-1]/[1,3.33,1], shift 10)
                  → Ixx, Iyy ; resp = (Ixx>>12)(Iyy>>12) - (Ixy>>12)²

Oracle (clean): harris_Ixx, harris_Iyy.  Oracle (resp/in-place Ixy): harris_resp.
The two free integer params (smoothing size, derivative scale) come from the
ctx struct we didn't capture, so we sweep them and match the captures.

Run:  ./.venv-poc/bin/python dev/port_gradient.py
"""
import os, glob
import numpy as np

DUMP = os.environ.get('FRIDA_DUMP_DIR', '/media/sf_vbox-rw/finger/frida_dumps')

# ─── 32-bit fixed-point helpers (match x86 imul/sar/idiv semantics) ──────
M32 = (1 << 32)
def s32(x):
    x &= M32 - 1
    return x - M32 if x & 0x80000000 else x
def sar32(x, n):          # arithmetic shift on a 32-bit signed value
    return s32(s32(x) >> n)
def idiv32(a, b):         # truncating (toward zero) signed division
    a, b = s32(a), s32(b)
    q = abs(a) // abs(b)
    return -q if (a < 0) ^ (b < 0) else q

EXP_TABLE = [
    65536,53908,44344,36476,30005,24681,20302,16700,13737,11300,9295,7646,
     6289, 5173, 4256, 3501, 2879, 2369, 1948, 1603,1318,1084, 892, 734,
      604,  496,  408,  336,  276,  227,  187,  154, 127, 104,  86,  70,
       58,   48,   39,   32,   27,   22,   18,   15,  12,  10,   8,   7,
        6,    5,    4,    0]

# ─── sub_18000FEC0: Gaussian tap evaluator ───────────────────────────────
def gauss_tap(coef, x):
    t = sar32(s32(coef * x), 2)
    t = sar32(s32(t * x), 8)            # t = coef·x²>>10
    q = (s32(t) * 0x51eb851f) >> 35     # signed 64-bit magic /25
    if q < 0: q += 1                    # round toward zero
    idx = q >> 13                       # arithmetic; idx <= 0
    i = -idx
    if i < 0: i = 0
    if i >= len(EXP_TABLE): i = len(EXP_TABLE) - 1
    return EXP_TABLE[i]

# ─── sub_18000FF00: normalized 1D Gaussian kernel (returns (offset,tap)) ──
def build_gaussian(n, sigma=0):
    if sigma <= 0:
        sigma = sar32(s32(0x26600 * n + 0x59acd), 10)   # (157184n+367309)>>10
    sig2 = s32(sigma * sigma)
    coef = idiv32(0xe0000000, sig2)                      # -2^29 / σ²
    taps, s = [], 0
    for i in range(n):
        pos = 512 * (2 * i - n + 1)                      # Q10 position, step 1024
        t = sar32(gauss_tap(coef, pos), 4)
        taps.append(t); s += t
    norm = sar32(idiv32(0x40000000, s), 3)               # (2^30/sum)>>3
    half = n // 2
    return [(i - half, sar32(s32(t * norm), 15)) for i, t in enumerate(taps)]

# ─── sub_180010280: sparse 3-point kernel (smoothing / derivative) ────────
# taps live at offsets -scale, 0, +scale.  c = 2^20/(scale·0x2aaa) (NOT n·…),
# so scale=1 → c=96, mid=320, smoothing = [96,320,96] (sum 512, gain 0.5).
# Verified byte-exact against g380_* per-pass captures.
def build_3tap(scale, deriv):
    if deriv:
        return [(-scale, 1024), (0, 0), (scale, -1024)]
    c = idiv32(0x100000, s32(scale * 0x2aaa))            # 2^20/(scale·10922)
    mid = sar32(s32(c * 0xd55) + (1 << 9), 10)           # round(c·3413/1024) ≈ 3.33c
    return [(-scale, c), (0, mid), (scale, c)]            # scale=1 → [96,320,96] sum 512

# ─── separable apply: per-tap (pixel·tap)>>shift, replicate edges ─────────
def conv_axis(img, kernel, shift, axis):
    h, w = img.shape
    acc = np.zeros((h, w), dtype=np.int64)
    n = img.shape[axis]
    idx = np.arange(n)
    for off, tap in kernel:
        if tap == 0:
            continue
        src = np.clip(idx - off, 0, n - 1)               # convolution (kernel reversed); replicate edge
        shifted = np.take(img, src, axis=axis)
        acc += (shifted.astype(np.int64) * tap) >> shift  # arithmetic, per-tap
    return acc

def apply_sep(img, kx, ky, shift):
    return conv_axis(conv_axis(img, kx, shift, axis=1), ky, shift, axis=0)


# ─── full DoH front-end (byte-exact vs g380/gradin captures) ──────────────
def presmooth(tile, size=5):
    """sub_18000F250 → sub_1800101C0: separable Gaussian smooth (shift 12) of
    the Q10 tile, then <<6.  Byte-exact vs CC20's input (g380 call1_before)."""
    gk = build_gaussian(size)
    return (apply_sep(tile.astype(np.int64), gk, gk, 12)) << 6


def cc20_planes(smoothed, v9=1):
    """sub_18000CC20: build Ixx/Iyy/Ixy from the pre-smoothed tile.  Each
    sub_180010380 pass = (>>6, separable kx·ky shift10, <<6); kernels at ±v9
    (deriv [1024,0,-1024] / smooth [96,320,96]).  Byte-exact vs g380 planes."""
    dk = build_3tap(v9, deriv=True); sk = build_3tap(v9, deriv=False)
    P = lambda img, kx, ky: (apply_sep(img >> 6, kx, ky, 10)) << 6
    buf20 = smoothed.copy()
    buf28 = P(buf20, sk, dk)              # prep1 (0,1)  -> Dy
    buf20 = P(buf20, dk, sk)              # prep2 (1,0)  -> Dx
    buf20 = buf20 * v9; buf28 = buf28 * v9            # norm1 ·v9
    ixy = P(buf20, sk, dk)                # plane1 (0,1) Ixy = Dy(Dx)
    ixx = P(buf20, dk, sk)                # plane2 (1,0) Ixx = Dx(Dx)
    iyy = P(buf28, sk, dk)                # plane3 (0,1) Iyy = Dy(Dy)
    v10 = v9 * v9
    return ixx * v10, iyy * v10, ixy * v10            # norm2 ·v9²


def doh(tile, size=5, v9=1):
    """gradin tile (Q10) → Ixx, Iyy, Ixy, response (Q12 det-of-Hessian)."""
    ixx, iyy, ixy = cc20_planes(presmooth(tile, size), v9)
    resp = (ixx >> 12) * (iyy >> 12) - (ixy >> 12) ** 2
    return ixx, iyy, ixy, resp

# ─── load captures ────────────────────────────────────────────────────────
def load(name, call='call0'):
    f = sorted(glob.glob(os.path.join(DUMP, '%s_*_%s_*.bin' % (name, call))))[0]
    b = os.path.basename(f); w, h = map(int, b.split('_')[-1].replace('.bin', '').split('x'))
    return np.fromfile(f, dtype=np.int32).reshape(h, w)

def score(pred, ref, bd=5, tag=''):
    I = np.s_[bd:-bd, bd:-bd]
    p, r = pred[I].astype(np.int64), ref[I].astype(np.int64)
    exact = int((p == r).all()); mm = int((p != r).sum())
    cc = np.corrcoef(p.ravel().astype(float), r.ravel().astype(float))[0, 1]
    print('  %-26s interior(b=%d): exact=%s  mism=%d/%d  corr=%.5f'
          % (tag, bd, bool(exact), mm, p.size, cc))
    return cc, mm

# ─── experiment ───────────────────────────────────────────────────────────
if __name__ == '__main__':
    call = os.environ.get('CALL', 'call0')
    gradin = load('gradin_image', call).astype(np.int64)   # 57² Q10
    Ixx = load('harris_Ixx', call); Iyy = load('harris_Iyy', call)
    print('gradin', gradin.shape, 'range', int(gradin.min()), int(gradin.max()))
    print('Ixx range', int(Ixx.min()), int(Ixx.max()), ' Iyy', int(Iyy.min()), int(Iyy.max()))

    base = gradin >> 6                                      # Q10 -> Q4

    def deriv_pass(img, kx, ky):
        """one sub_180010380 call: >>6, separable (shift 10), <<6."""
        return apply_sep(img >> 6, kx, ky, 10) << 6

    def mag(pred, ref, bd=5):
        I = np.s_[bd:-bd, bd:-bd]
        p, r = pred[I].astype(np.float64).ravel(), ref[I].astype(np.float64).ravel()
        k = (p @ r) / (p @ p) if (p @ p) else 0
        return k

    sm = 5; ds = 1
    gk = build_gaussian(sm)
    sm_img = (apply_sep(base, gk, gk, 12)) << 6             # Gaussian pre-smooth, back to Q10
    dk = build_3tap(ds, deriv=True); sk = build_3tap(ds, deriv=False)

    print('\nDiagnostics at sm=%d ds=%d (best corr candidate):' % (sm, ds))
    # Variant A: Dx∘Dx along x (per-pass >>6/<<6), then smooth y
    gx  = deriv_pass(sm_img, dk, sk)                        # 1st x-deriv, smooth y
    ixxA = deriv_pass(gx, dk, sk)                           # 2nd x-deriv
    print('  ref/pred magnitude factor (Ixx/predA) =', round(1/mag(ixxA, Ixx), 4) if mag(ixxA,Ixx) else 0)
    score(ixxA, Ixx, tag='A DxDx·Sy per-pass>>6')
    # Variant B: single separable pass kx=deriv,ky=deriv on smoothed (true Hessian-xy style for Ixx? no)
    ixxB = deriv_pass(sm_img, dk, sk)
    score(ixxB, Ixx, tag='B Dx·Sy (1st only)')
    # Variant C: scale-normalized A  (CC20 multiplies planes by scale²)
    for nf in (ds, ds*ds, 2*ds+1):
        score(ixxA * nf, Ixx, tag='C A·%d' % nf)

    # ── exact CC20 flow ──────────────────────────────────────────────────
    def cc20(presmoothed, v9):
        """Reproduce sub_18000CC20's per-block plane build for scale v9.
        Each sub_180010380 pass = (>>6, separable kx·ky shift10, <<6); kernels
        are 3-tap at offset ±v9 (deriv [1024,0,-1024] / smooth [c,3.33c,c])."""
        dk = build_3tap(v9, deriv=True); sk = build_3tap(v9, deriv=False)
        P = lambda img, kx, ky: (apply_sep(img >> 6, kx, ky, 10)) << 6
        buf20 = presmoothed.copy()
        buf28 = P(buf20, sk, dk)              # prep1 (0,1): smooth_x, deriv_y  -> Dy
        buf20 = P(buf20, dk, sk)              # prep2 (1,0): deriv_x, smooth_y  -> Dx
        buf20 = buf20 * v9                    # norm1 ·v9
        buf28 = buf28 * v9
        ixy   = P(buf20, sk, dk)              # (0,1): Dy(buf20)
        ixx   = P(buf20, dk, sk)              # (1,0): Dx(buf20)
        iyy   = P(buf28, sk, dk)              # (0,1): Dy(buf28)
        v10 = v9 * v9
        return ixx * v10, iyy * v10, ixy * v10

    # ── BYTE-EXACT validation against the per-pass g380 captures ─────────
    # The g380 run dumped the real CC20 input (call1 'before' = buf20) and the
    # plane outputs (block0: call2=Ixy, call3=Ixx, call4=Iyy), so we validate
    # cc20() directly — independent of the Gaussian pre-smooth and of the
    # (different-run) harris_* captures.
    def g380(kind, call, t):
        f = sorted(glob.glob(os.path.join(DUMP, 'g380_%s_*_call%d_t%s*.bin' % (kind, call, t))))
        if not f:
            return None
        a = np.fromfile(f[-1], dtype=np.int32)   # newest run
        sh = (57, 57) if a.size == 3249 else (57, 58)
        return a.reshape(sh)

    inp = g380('before', 1, '10')
    if inp is not None:
        ixx, iyy, ixy = cc20(inp.astype(np.int64), 1)
        print('\nBYTE-EXACT check vs same-run g380 plane captures (interior):')
        for nm, pred, ref in [('Ixx', ixx, g380('after', 3, '10')),
                              ('Iyy', iyy, g380('after', 4, '01')),
                              ('Ixy', ixy, g380('after', 2, '01'))]:
            I = np.s_[3:-3, 3:-3]
            mm = int((pred[I] != ref[I]).sum())
            print('  %s interior(b=3): EXACT=%s  mism=%d/%d'
                  % (nm, bool(mm == 0), mm, pred[I].size))
    else:
        print('\n(no g380_* per-pass captures found — run GDB_DUMP_G380=1)')

    # ── full chain (needs a run with BOTH gradin + g380): tile → doh() ────
    gt = sorted(glob.glob(os.path.join(DUMP, 'gradin_image_*_call0_*.bin')))
    g380b = sorted(glob.glob(os.path.join(DUMP, 'g380_before_*_call1_t10*.bin')))
    if gt and g380b:
        # match the run whose timestamps interleave (same prefix //100000)
        ts = lambda f: int(os.path.basename(f).split('_')[2])
        gts = {ts(f) // 100000 for f in g380b}
        tilef = [f for f in gt if ts(f) // 100000 in gts]
        if tilef:
            tile = np.fromfile(tilef[-1], dtype=np.int32).reshape(57, 57)
            inp2 = g380('before', 1, '10')   # picks newest = combined run
            sm = presmooth(tile)
            print('\nFULL CHAIN (combined gradin+g380 run):')
            print('  presmooth vs CC20 input (b=2): EXACT=%s'
                  % bool((sm[2:-2, 2:-2] == inp2[2:-2, 2:-2]).all()))
            ixx, iyy, ixy, resp = doh(tile)
            for nm, pred, ref in [('Ixx', ixx, g380('after', 3, '10')),
                                  ('Iyy', iyy, g380('after', 4, '01')),
                                  ('Ixy', ixy, g380('after', 2, '01'))]:
                I = np.s_[5:-5, 5:-5]
                print('  %s gradin→plane (b=5): EXACT=%s  mism=%d'
                      % (nm, bool((pred[I] == ref[I]).all()), int((pred[I] != ref[I]).sum())))
