#!/usr/bin/env python3
"""Decode sec0_pre (the ws_body global section table) per sub_1800051f0's
serialization, and verify the inter-section alignment transforms.

sub_1800051f0 serializes the bdf0 pairwise table (*(obj+0x18)) into sec0_pre as:
  [TLV header][leads: edi bytes from *(obj+0)][blob: edi*4 bytes from *(obj+8)]
  [u8 obj[0x10]=N][u8 obj[0x11]]
  [UPPER-TRIANGLE matrix: for i<j, table[i][j] as an 18-byte record
     [x:u8][y:u8][a:i32][b:i32][tx:i32][ty:i32]]   (drops bdf0's +2 pad)

The transform is a rigid 2D similarity (Q16): R=[[a,-b],[b,a]], t=(tx,ty),
identity=(a=0x10000,b=0,0,0). Verified: every record has a^2+b^2 == 0x10000^2.

Usage: ./.venv-poc/bin/python dev/decode_sec0_pre.py [ws_body.bin]
"""
import sys, struct, math, glob

WS = sys.argv[1] if len(sys.argv) > 1 else sorted(glob.glob(
    "/media/sf_vbox-rw/finger/frida_dumps/ws_body_*.bin"))[-1]
ONE = 0x10000


def rigid(a, b, tol=0.05):
    return abs(a*a + b*b - ONE*ONE) < ONE*ONE*tol


def main():
    ws = open(WS, "rb").read()
    s0 = ws[64:309]
    print(f"{WS}\nsec0_pre [64..309) ({len(s0)}B)")
    # locate the 18-byte rigid-Q16 transform run
    best = (0, 0, [])
    for start in range(0, 60):
        recs, o = [], start
        while o + 18 <= len(s0):
            a, b, tx, ty = struct.unpack_from('<4i', s0, o + 2)
            if not rigid(a, b):
                break
            recs.append((s0[o], s0[o+1], a, b, tx, ty)); o += 18
        if len(recs) > len(best[2]):
            best = (start, o, recs)
    start, end, recs = best
    print(f"\nhead [0..{start}) (TLV hdr + leads + blob + N markers): {s0[:start].hex()}")
    print(f"\n{len(recs)} inter-section rigid-Q16 transforms @ sec0_pre+{start}:")
    for i, (x, y, a, b, tx, ty) in enumerate(recs):
        print(f"  rec{i}: anchor=({x:3},{y:3})  R[a={a/ONE:+.4f} b={b/ONE:+.4f}] "
              f"scale={math.hypot(a, b)/ONE:.4f} rot={math.degrees(math.atan2(b, a)):+5.1f}°  "
              f"t=({tx/ONE:+.2f},{ty/ONE:+.2f})")
    # a,b are int(cos·65536)/int(sin·65536), so a²+b² == 0x10000² up to integer
    # rounding (~3e-5 rel); 0.1% tolerance is the meaningful unit-scale check.
    bad = [i for i, r in enumerate(recs) if not rigid(r[2], r[3], 1e-3)]
    print(f"\nVERIFY: all {len(recs)} records unit-scale rigid (a²+b² ≈ 0x10000²)? "
          f"{'YES' if not bad else f'NO ({bad})'}")
    print(f"trailing after matrix: {s0[end:end+20].hex()} ... "
          f"(zeros to the section marker 04 00 b8 11 @ sec0_pre+{s0.find(bytes.fromhex('0400b811'))})")


if __name__ == "__main__":
    main()
