#!/usr/bin/env python3
"""STEP 1 — the clean same-image test (resolves A vs B).

The full-pipeline native template matches the chip's ws_body on 233/250 (x,y)
but 0/250 full 18-byte records (every descriptor differs). Every descriptor
STAGE is byte-exact GIVEN the chip's subpix (orient_d920 60/60, _descriptor_at
40/40, descriptor_gradient interior-exact). So either:

  (A) our doh→nms→subpix differs from the chip's even on the SAME image
      (a sub-pixel shift corrupts every BRIEF descriptor), or
  (B) the 0/250 is pure frame-pairing — the chip's ws_body sections store its
      OWN selected best frames, so "our frameN vs chip sectionN" compares
      DIFFERENT images.

This harness runs our FULL per-tile detection pipeline on the chip's EXACT F250
input tile and compares OUR subpix to the chip's, byte-for-byte:

  F250 raw tile R  ──descriptor_gradient──▶ gx_R
       │                                      │  interior byte-exact?
       │                              chip descbrief_gradX (tile G)
       ▼
  doh(R>>6) ─▶ nms ─▶ subpix_refine_kps ─▶ our (x_q16, y_q16) per kp
                                              │  match by ROUND(subpix) ⇆
  chip descbrief_kp_before kp[+0x14/+0x18] ◀──┘  compare Q16 byte-for-byte

Tile↔kp grouping uses the captured gradient tags `_t##_kp####` (kp_start);
validate_d920 already proved this floor-mapping reliable (1000/1024 orient
byte-exact). Pinned to session 1780170 — the only one with F250 raw tiles.

VERDICT:
  subpix byte-exact (high) ⇒ (B): pipeline is byte-exact on the same image;
      0/250 was frame pairing. Go run the match gate (enroll_native_chip.py).
  subpix differs (low)     ⇒ (A): fix subpix_refine_kp / the doh() response.

Run:  ./.venv-poc/bin/python dev/validate_same_image.py [dumpdir] [--session 1780170]
"""
import sys, os, glob, re, struct, argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np
from validitysensor.moh_native import (
    doh, nms, subpix_refine_kps, orient_d920, _descriptor_at,
    descriptor_gradient,
)

DEFAULT_DUMP = "/media/sf_vbox-rw/finger/frida_dumps"
SESSION = "1780170"   # the only session with f250_raw_tile captures
N_KPS = 1024          # captured kp records per session
BORDER = 3            # interior margin for gradient byte-exact comparison


def _i32(path, rows, cols):
    return np.frombuffer(open(path, "rb").read()[:rows * cols * 4],
                         dtype=np.int32).reshape(rows, cols)


def _round_q16(q):
    """Same rounding D920/E090 apply to subpix: (q + 0x8000) >> 16."""
    return (q + 0x8000) >> 16


def load_grad_tiles(D, session):
    """Chip gradient tiles for `session`, keyed by kp_start.
    Returns sorted list of dicts: tseq, kp_start, (rows, cols) shape, gx, gy."""
    out = []
    for fx in sorted(glob.glob(f"{D}/descbrief_gradX_*{session}*.bin")):
        m = re.search(r'_t(\d+)_kp(\d+)_(\d+)x(\d+)\.bin$', os.path.basename(fx))
        if not m:
            continue
        tseq, kp_start, a, b = (int(m.group(1)), int(m.group(2)),
                                int(m.group(3)), int(m.group(4)))
        rows, cols = b, a           # filename `_AxB` → reshape(B, A) → (rows, cols)
        # gradY is a separate _save call, so its timestamp can drift 1-2 ms from
        # gradX (validate_e090 documents this). Match by TAG, not by filename.
        tag = f"_t{m.group(1)}_kp{m.group(2)}_{a}x{b}.bin"
        ys = [p for p in glob.glob(f"{D}/descbrief_gradY_*{session}*")
              if p.endswith(tag)]
        if not ys:
            continue
        fy = ys[0]
        out.append(dict(tseq=tseq, kp_start=kp_start, rows=rows, cols=cols,
                        gx=_i32(fx, rows, cols), gy=_i32(fy, rows, cols)))
    out.sort(key=lambda d: d['kp_start'])
    return out


def load_f250_tiles(D, session):
    """F250 raw Q16 tiles for `session`. Returns list of (shape, arr)."""
    out = []
    for f in sorted(glob.glob(f"{D}/f250_raw_tile_*{session}*.bin")):
        m = re.search(r'_(\d+)x(\d+)\.bin$', os.path.basename(f))
        if not m:
            continue
        a, b = int(m.group(1)), int(m.group(2))
        rows, cols = b, a
        try:
            out.append(((rows, cols), _i32(f, rows, cols)))
        except Exception:
            pass
    return out


def match_f250(tile, f250_tiles, used):
    """Find the F250 raw tile whose descriptor_gradient() interior matches the
    chip gradient `tile` byte-exact. Returns (index, F250 arr) or (None, None)."""
    gx_c, gy_c = tile['gx'], tile['gy']
    rows, cols = tile['rows'], tile['cols']
    for i, (shape, arr) in enumerate(f250_tiles):
        if i in used or shape != (rows, cols):
            continue
        gx_r, gy_r = descriptor_gradient(arr)
        if gx_r.shape != gx_c.shape:
            continue
        if (np.array_equal(gx_r[BORDER:-BORDER, BORDER:-BORDER],
                           gx_c[BORDER:-BORDER, BORDER:-BORDER]) and
            np.array_equal(gy_r[BORDER:-BORDER, BORDER:-BORDER],
                           gy_c[BORDER:-BORDER, BORDER:-BORDER])):
            return i, arr
    return None, None


def load_chip_kp(D, session, i):
    """(sx_q16, sy_q16, orient_q16, desc_16B) for chip kp #i, or None."""
    kpf = glob.glob(f"{D}/descbrief_kp_before_*{session}*_kp{i:04d}.bin")
    if not kpf:
        return None
    kp = open(kpf[0], "rb").read()
    sx = struct.unpack_from('<i', kp, 0x14)[0]
    sy = struct.unpack_from('<i', kp, 0x18)[0]
    orient = struct.unpack_from('<i', kp, 0x0c)[0]
    df = glob.glob(f"{D}/descbrief_desc_*{session}*_kp{i:04d}.bin")
    desc = open(df[0], "rb").read()[:16] if df else None
    return sx, sy, orient, desc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dumpdir", nargs="?", default=DEFAULT_DUMP)
    ap.add_argument("--session", default=SESSION)
    ap.add_argument("--show-mismatch", type=int, default=8,
                    help="how many subpix mismatches to detail")
    args = ap.parse_args()
    D, session = args.dumpdir, args.session

    grads = load_grad_tiles(D, session)
    f250 = load_f250_tiles(D, session)
    print(f"dumpdir: {D}  session: {session}")
    print(f"chip gradient tiles: {len(grads)} | F250 raw tiles: {len(f250)}")
    if not grads or not f250:
        print("[!] missing captures — need descbrief_gradX + f250_raw_tile for "
              f"session {session}.")
        return 2

    # kp range per gradient tile = [kp_start_i, kp_start_{i+1}) (last → N_KPS).
    starts = [g['kp_start'] for g in grads]
    ranges = [(starts[i], starts[i + 1] if i + 1 < len(starts) else N_KPS)
              for i in range(len(grads))]

    tot_kp = tot_subpix = tot_orient = tot_desc = 0
    tot_nopred = tot_no_f250_kp = 0
    matched_tiles = 0
    mism_samples = []
    used = set()

    for tile, (lo, hi) in zip(grads, ranges):
        idx, R = match_f250(tile, f250, used)
        if idx is None:
            tot_no_f250_kp += (hi - lo)
            print(f"  t{tile['tseq']:02d} kp[{lo:4d},{hi:4d})  "
                  f"{tile['rows']}x{tile['cols']}: NO gradient-matched F250 tile "
                  f"(not reproducible) — {hi-lo} kps skipped")
            continue
        used.add(idx)
        matched_tiles += 1

        # OUR detection on the chip's exact F250 tile.
        gx_R, gy_R = descriptor_gradient(R)
        resp = doh((R >> 6).astype(np.int64))[3]
        our = subpix_refine_kps(resp, nms(resp))
        pred = {}
        for _s, xq, yq in our:
            pred[(_round_q16(xq), _round_q16(yq))] = (xq, yq)

        t_kp = t_sub = t_ori = t_desc = t_nopred = 0
        for i in range(lo, hi):
            ck = load_chip_kp(D, session, i)
            if ck is None:
                continue
            sx_c, sy_c, ori_c, desc_c = ck
            t_kp += 1
            tot_kp += 1
            key = (_round_q16(sx_c), _round_q16(sy_c))
            if key not in pred:
                t_nopred += 1
                tot_nopred += 1
                continue
            xq, yq = pred[key]
            if xq == sx_c and yq == sy_c:
                t_sub += 1
                tot_subpix += 1
                # subpix matches → run OUR full per-kp chain on OUR gradient
                # (== chip gradient in interior) and check orient + descriptor.
                ori_o = orient_d920(gx_R, gy_R, xq, yq)
                if ori_o == ori_c:
                    t_ori += 1
                    tot_orient += 1
                if desc_c is not None:
                    desc_o = bytes(_descriptor_at(gx_R, gy_R, xq, yq, ori_o))
                    if desc_o == desc_c:
                        t_desc += 1
                        tot_desc += 1
            elif len(mism_samples) < args.show_mismatch:
                mism_samples.append((tile['tseq'], i, sx_c, sy_c, xq, yq))

        flag = "" if t_sub == t_kp else "  <<< subpix DIFF"
        print(f"  t{tile['tseq']:02d} kp[{lo:4d},{hi:4d}) F250#{idx:3d} "
              f"{tile['rows']}x{tile['cols']}: subpix {t_sub}/{t_kp} | "
              f"orient {t_ori}/{t_sub} | desc {t_desc}/{t_sub} | "
              f"no-NMS-peak {t_nopred}{flag}")

    print("\n" + "=" * 72)
    print(f"gradient-matched tiles: {matched_tiles}/{len(grads)}  "
          f"(skipped {tot_no_f250_kp} kps in non-reproducible tiles)")
    print(f"SUBPIX byte-exact:     {tot_subpix}/{tot_kp}")
    print(f"  orient byte-exact (of subpix-matched):     {tot_orient}/{tot_subpix}")
    print(f"  descriptor byte-exact (of subpix-matched): {tot_desc}/{tot_subpix}")
    print(f"  chip kps with NO matching NMS peak in our detection: {tot_nopred}")
    if mism_samples:
        print("\nsubpix mismatches (chip vs ours, Q16 and px):")
        for tseq, i, sx, sy, xq, yq in mism_samples:
            print(f"  t{tseq:02d} kp{i}: chip=({sx},{sy})=({sx/65536:.4f},"
                  f"{sy/65536:.4f}) ours=({xq},{yq})=({xq/65536:.4f},"
                  f"{yq/65536:.4f}) dq=({xq-sx:+d},{yq-sy:+d})")

    print("\n" + "=" * 72)
    rate = tot_subpix / tot_kp if tot_kp else 0
    if rate >= 0.95:
        print(f"VERDICT → (B): subpix byte-exact {rate:.1%} on the SAME image. "
              "The per-keypoint pipeline reproduces the chip; the 0/250 record\n"
              "mismatch was FRAME PAIRING (chip stored different selected "
              "frames). Next: run the real match gate (enroll_native_chip.py "
              "--match).")
        return 0
    print(f"VERDICT → (A): subpix byte-exact only {rate:.1%} on the SAME image. "
          "Our doh→nms→subpix diverges from the chip's; this shifts every\n"
          "descriptor. Root-cause subpix_refine_kp / the doh() response feeding "
          "it (see mismatch deltas above).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
