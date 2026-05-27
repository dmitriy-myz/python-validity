#!/usr/bin/env python3
"""Isolation experiment: which part of v30 is load-bearing for MATCHING?

`extract_template` (our coords + our descriptors) stores but does not match.
This builds variants from a KNOWN-GOOD reference template (one that already
matches your finger) changing one field at a time, so a store+identify on
each tells us exactly what matters:

  control          reference unchanged (TID recomputed)   -> MUST match (sanity)
  zero_desc        real coords, descriptors zeroed         -> match? => desc irrelevant
  our_desc         real coords, OUR descriptor at those    -> match? => our desc good enough
                   (x,y) computed from the image           (fail => enhancement wall matters)
  our_both         our coords + our descriptors            -> = extract_template (expected fail)

Each variant gets a recomputed TID and is written as a 23136-byte .bin you
can store via the dev/MOH.md replay workflow, then identify().

Usage:
    .venv-poc/bin/python dev/splice_experiment.py REFERENCE.bin IMAGE_112x112.bin [OUTDIR]
"""
import struct
import sys

import cv2
import numpy as np

sys.path.insert(0, __file__.rsplit('/dev/', 1)[0])
from validitysensor import moh_opencv as mo
from validitysensor.moh_extract import compute_tid, _build_envelope

REF = sys.argv[1]
IMG = sys.argv[2]
OUTDIR = sys.argv[3] if len(sys.argv) > 3 else '.'
RL = mo.V30_RECORD_LEN


def load_ws(path):
    data = open(path, 'rb').read()
    subtype = struct.unpack_from('<H', data, 0)[0]
    ws = data[12:12 + mo.WS_SIZE]
    assert len(ws) == mo.WS_SIZE, f"{path}: WS is {len(ws)}B"
    return subtype, bytearray(ws)


def rewrite(ws, fn):
    """For every record in every v30 region, replace it via fn(x, y, desc)->18B."""
    out = bytearray(ws)
    for base in mo.find_v30_regions(bytes(ws)):
        i = base
        while i + RL <= len(out) and 0 < out[i] <= 112 and out[i + 1] <= 112:
            x, y, desc = out[i], out[i + 1], bytes(out[i + 2:i + RL])
            out[i:i + RL] = fn(x, y, desc)
            i += RL
    return bytes(out)


def main():
    subtype, ws = load_ws(REF)
    img = np.frombuffer(open(IMG, 'rb').read()[:112 * 112], np.uint8).reshape(112, 112)
    padded = cv2.copyMakeBorder(img, mo.PATCH_RADIUS, mo.PATCH_RADIUS, mo.PATCH_RADIUS,
                                mo.PATCH_RADIUS, cv2.BORDER_CONSTANT, value=mo.FILL_GRAY)
    tests = mo.brief_select_tests(scale=mo.PATCH_RADIUS, num_tests=128)
    R = mo.PATCH_RADIUS

    def our_desc_at(x, y):
        return mo.compute_brief_descriptor(padded, x + R, y + R, tests)

    variants = {
        'control':   bytes(ws),
        'zero_desc': rewrite(ws, lambda x, y, d: mo.build_v30_record(x, y, 0)),
        'our_desc':  rewrite(ws, lambda x, y, d: mo.build_v30_record(x, y, our_desc_at(x, y))),
        'our_both':  None,   # filled below via extract_template
    }
    variants['our_both'] = mo.extract_template(img, subtype=subtype,
                                               reference_template=open(REF, 'rb').read())

    for name, val in variants.items():
        if name == 'our_both':
            env = val
        else:
            env = _build_envelope(subtype, val, compute_tid(val))
        path = f"{OUTDIR}/variant_{name}.bin"
        open(path, 'wb').write(env)
        # report how much changed vs the control ws
        print(f"  {name:10s}: {len(env)}B -> {path}")
    print("\nStore each (dev/MOH.md replay) then identify(). Expected:")
    print("  control MUST match; zero_desc/our_desc/our_both reveal what's load-bearing.")


if __name__ == '__main__':
    main()
