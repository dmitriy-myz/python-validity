#!/usr/bin/env python3
"""Validate moh_native.descriptor_gradient() byte-exact against the chip.

The ONLY remaining bug blocking byte-exact native descriptors is
descriptor_gradient (moh_native.py:502): everything downstream (orient_d920,
desc_sample_rotate/aggregate, brief_pack, the aggr table) is already verified
byte-exact GIVEN correct gradients (see the 2026-05-30 diagnosis in memory
native-pipeline-readiness).

This harness pairs the gradient stage's INPUT (F250 raw tile, captured by
GDB_DUMP_F250) with its OUTPUT (gradX/gradY, captured by GDB_DUMP_DESC_BRIEF)
and checks descriptor_gradient(input) == captured output, byte for byte.

CAPTURE (one Wine enrollment, after `git pull` on the box):
    GDB_DUMP_F250=1 GDB_DUMP_DESC_BRIEF=1 gdb -p <PID> -x dev/gdb_dump.py

Then:
    ./.venv-poc/bin/python dev/validate_descriptor_gradient.py [dumpdir]

PASS  → descriptor_gradient is byte-exact; the native descriptor pipeline is
        end-to-end byte-exact → the --match gate is unblocked.
FAIL  → prints the first differing tile + region + values to guide the fix
        (kernel taps / shift / border-fill in descriptor_gradient).
"""
import sys, os, glob, re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np
from validitysensor.moh_native import descriptor_gradient

D = sys.argv[1] if len(sys.argv) > 1 else "/media/sf_vbox-rw/finger/frida_dumps"


def _i32(path, h, w):
    return np.frombuffer(open(path, "rb").read()[:h * w * 4],
                         dtype=np.int32).reshape(h, w)


def load_f250_tiles():
    """f250_raw_tile_callNNN_<w>x<h>.bin → list of (label, h, w, arr[h,w])."""
    out = []
    for f in sorted(glob.glob(f"{D}/f250_raw_tile_*")):
        m = re.search(r'_(\d+)x(\d+)\.bin$', f)
        if not m:
            continue
        w, h = int(m.group(1)), int(m.group(2))
        try:
            out.append((os.path.basename(f), h, w, _i32(f, h, w)))
        except Exception:
            pass
    return out


def load_grad_tiles():
    """descbrief_gradX/Y_*_tNN_*_<stride>x<height>.bin → list of
    (tile_seq, height, stride, gradX[h,s], gradY[h,s])."""
    out = []
    for fx in sorted(glob.glob(f"{D}/descbrief_gradX_*")):
        m = re.search(r'_t(\d+)_.*_(\d+)x(\d+)\.bin$', fx)
        if not m:
            continue
        tseq, stride, height = int(m.group(1)), int(m.group(2)), int(m.group(3))
        fy = fx.replace('_gradX_', '_gradY_')
        if not os.path.exists(fy):
            continue
        out.append((tseq, height, stride, _i32(fx, height, stride),
                    _i32(fy, height, stride)))
    return out


def try_match(f250_arr, GX, GY):
    """Run descriptor_gradient on the F250 tile (trying Q-format variants) and
    compare to (GX, GY). Returns (variant, full_exact, interior_exact, dxn, dyn,
    gxn, gyn) for the best variant, or None if shapes never line up."""
    best = None
    for name, tile in (("asis", f250_arr.astype(np.int64)),
                       ("<<6", f250_arr.astype(np.int64) << 6),
                       (">>6", f250_arr.astype(np.int64) >> 6)):
        gxn, gyn = descriptor_gradient(tile)
        if gxn.shape != GX.shape:
            continue
        dxn = int((gxn != GX).sum()); dyn = int((gyn != GY).sum())
        full = (dxn == 0 and dyn == 0)
        intr = bool((gxn[3:-3, 3:-3] == GX[3:-3, 3:-3]).all()
                    and (gyn[3:-3, 3:-3] == GY[3:-3, 3:-3]).all())
        cand = (name, full, intr, dxn, dyn, gxn, gyn)
        if best is None or (full, intr, -(dxn + dyn)) > (best[1], best[2], -(best[3] + best[4])):
            best = cand
    return best


def main():
    f250 = load_f250_tiles()
    grads = load_grad_tiles()
    print(f"dumpdir: {D}")
    print(f"F250 raw tiles: {len(f250)} | descbrief gradient tiles: {len(grads)}")
    if not grads:
        print("\n[!] no descbrief_gradX/Y — run GDB_DUMP_DESC_BRIEF=1.")
        return 2
    if not f250:
        print("\n[!] no f250_raw_tile_* — re-capture with "
              "GDB_DUMP_F250=1 GDB_DUMP_DESC_BRIEF=1 (one enrollment).")
        print("    (harness is wired; it just needs the F250 input tiles.)")
        return 2

    full_ok = intr_ok = matched = 0
    first_fail = None
    for tseq, h, s, GX, GY in grads:
        # candidate F250 inputs of matching shape (auto-correlate by geometry)
        cands = [t for t in f250 if (t[1], t[2]) == (h, s)]
        best = None
        for (_lbl, _h, _w, arr) in cands:
            r = try_match(arr, GX, GY)
            if r and (best is None or (r[1], r[2]) > (best[1], best[2])):
                best = r
        if best is None:
            continue
        matched += 1
        variant, full, intr, dxn, dyn, gxn, gyn = best
        full_ok += full; intr_ok += intr
        status = "FULL byte-exact" if full else ("interior-exact" if intr else
                                                  f"DIFF gx={dxn} gy={dyn}")
        print(f"  t{tseq:02d} {h}x{s} [{variant}]: {status}")
        if not full and first_fail is None:
            first_fail = (tseq, GX, GY, gxn, gyn)

    print(f"\n=== descriptor_gradient: {full_ok}/{matched} FULL byte-exact, "
          f"{intr_ok}/{matched} interior-exact (of {matched} matched tiles) ===")
    if first_fail and full_ok < matched:
        tseq, GX, GY, gxn, gyn = first_fail
        dx = np.argwhere(gxn != GX)
        print(f"\nfirst gradX mismatch (t{tseq:02d}): {len(dx)} cells; sample:")
        for (y, x) in dx[:6]:
            print(f"  [{y},{x}] ours={int(gxn[y,x])} chip={int(GX[y,x])} "
                  f"(dist-from-edge={min(y, x, GX.shape[0]-1-y, GX.shape[1]-1-x)})")
        # are mismatches only on the border rim? (clue: border-fill bug)
        rim = all(min(y, x, GX.shape[0]-1-y, GX.shape[1]-1-x) < 3 for y, x in dx)
        print(f"  all gradX mismatches within 3px rim? {rim} "
              f"(if True → border-fill; if False → kernel/shift bug)")
    if full_ok == matched and matched:
        print("PASS — descriptor_gradient byte-exact → native descriptor "
              "pipeline is end-to-end byte-exact. Re-run the full-pipeline "
              "Hamming check; it should drop to 0.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
