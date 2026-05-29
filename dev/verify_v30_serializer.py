#!/usr/bin/env python3
"""Byte-exact verification of validitysensor.moh_native.serialize_v30_section
against a captured ws_body (the ground-truth oracle).

Proves two things:
  (A) round-trip: extracting each section's (x,y,desc) and re-serializing
      reproduces the captured section byte-for-byte → the serializer format
      is correct ([x][y][16B], 250 slots, no header/lead-in).
  (B) sourcing: building a section from the minutia_table's x@+0x14 / y@+0x18
      plus the captured descriptors reproduces it → confirms x,y come from the
      minutia records (i.e. our detector's coords feed straight in).

Usage:
  ./.venv-poc/bin/python dev/verify_v30_serializer.py [ws_body.bin] [dumpdir]
"""
import sys, glob, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from validitysensor.moh_native import serialize_v30_section
from validitysensor.moh_opencv import find_v30_regions

DUMPDIR = sys.argv[2] if len(sys.argv) > 2 else "/media/sf_vbox-rw/finger/frida_dumps"
WS = sys.argv[1] if len(sys.argv) > 1 else \
    f"{DUMPDIR}/ws_body_1780084103036_23056.bin"
SEC = 4500  # 250 × 18


def extract_records(buf, base, n=250):
    """Pull (x, y, desc16) from a captured v30 section."""
    out = []
    for i in range(n):
        o = base + i * 18
        out.append((buf[o], buf[o + 1], bytes(buf[o + 2:o + 18])))
    return out


def main():
    ws = open(WS, "rb").read()
    regions = find_v30_regions(ws)
    print(f"ws_body: {WS} ({len(ws)}B); v30 regions: {regions}")

    # (A) round-trip every section
    all_ok = True
    for si, base in enumerate(regions):
        captured = ws[base:base + SEC]
        recs = extract_records(ws, base)
        rebuilt = serialize_v30_section(recs)
        ok = rebuilt == captured
        all_ok &= ok
        nz = sum(1 for r in recs if r[0] or r[1] or any(r[2]))
        print(f"  (A) section{si} @{base}: round-trip "
              f"{'OK byte-exact' if ok else 'MISMATCH'} "
              f"(len {len(rebuilt)}, {nz} nonzero records)")
        if not ok:
            d = next(i for i in range(SEC) if rebuilt[i] != captured[i])
            print(f"       first diff at +{d}: got {rebuilt[d]:#x} "
                  f"want {captured[d]:#x}")

    # (B) x,y sourced from minutia_table +0x14/+0x18 (+ captured descriptors)
    mts = sorted(glob.glob(f"{DUMPDIR}/minutia_table_17800840*_250.bin"))
    if mts:
        print(f"\n  (B) sourcing check vs {len(mts)} minutia_tables:")
        for si, base in enumerate(regions):
            descs = [bytes(ws[base + i * 18 + 2:base + i * 18 + 18])
                     for i in range(250)]
            best = (-1, None)
            for mi, mtf in enumerate(mts):
                mt = open(mtf, "rb").read()
                recs = [(mt[i * 32 + 0x14], mt[i * 32 + 0x18], descs[i])
                        for i in range(250)]
                if serialize_v30_section(recs) == ws[base:base + SEC]:
                    best = (mi, mtf)
                    break
            if best[1]:
                print(f"      section{si}: byte-exact from minutia_table #{best[0]} "
                      f"(x@+0x14,y@+0x18) + descriptors")
            else:
                print(f"      section{si}: no captured table reproduces it "
                      f"(likely an uncaptured selected frame)")

    print(f"\nRESULT: {'PASS — serializer reproduces every captured section byte-exact' if all_ok else 'FAIL'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
