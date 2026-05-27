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
# size n = 2*scale+1; taps live at offsets -scale, 0, +scale.
def build_3tap(scale, deriv):
    n = 2 * scale + 1
    if deriv:
        return [(-scale, 1024), (0, 0), (scale, -1024)]
    c = idiv32(0x100000, s32(n * 0x2aaa))                # 2^20/(n·10922)
    mid = sar32(s32(c * 0xd55), 10)                      # c·3413>>10 ≈ 3.33c
    return [(-scale, c), (0, mid), (scale, c)]

# ─── separable apply: per-tap (pixel·tap)>>shift, replicate edges ─────────
def conv_axis(img, kernel, shift, axis):
    h, w = img.shape
    acc = np.zeros((h, w), dtype=np.int64)
    n = img.shape[axis]
    idx = np.arange(n)
    for off, tap in kernel:
        if tap == 0:
            continue
        src = np.clip(idx + off, 0, n - 1)               # replicate (clamp)
        shifted = np.take(img, src, axis=axis)
        acc += (shifted.astype(np.int64) * tap) >> shift  # arithmetic, per-tap
    return acc

def apply_sep(img, kx, ky, shift):
    return conv_axis(conv_axis(img, kx, shift, axis=1), ky, shift, axis=0)

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

    print('\nExact CC20 flow — sweep presmooth size sm, scale v9:\n')
    for sm in (0, 3, 5, 7):
        gk = build_gaussian(sm) if sm else None
        smi = (apply_sep(base, gk, gk, 12) << 6) if sm else (base << 6)
        for v9 in (1, 2, 3):
            ixx, iyy, ixy = cc20(smi, v9)
            print('  sm=%d v9=%d:' % (sm, v9))
            score(ixx, Ixx, tag='    Ixx'); score(iyy, Iyy, tag='    Iyy')
