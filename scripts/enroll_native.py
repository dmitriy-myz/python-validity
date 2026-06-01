"""End-to-end native enrollment: raw image → chip-storable 23136-byte template.

Two modes:
  --splice REF.bin   Use REF.bin's WS body as a scaffold and replace every
                     v30 record's descriptor with one computed by the byte-
                     exact native pipeline at the SAME (x, y). Recomputes
                     TID. Useful as a first smoke test — if the chip
                     accepts the result, the byte-exact pipeline matches
                     the DLL at given coordinates.

  --extract          (TODO) Build the WS body from scratch using detected
                     keypoints. Requires multi-frame accumulation + the
                     section-header decoding that's still partial.

The image must be a 112x112 uint8 grayscale binary (raw bytes; no header).
Internally we convert to Q16 (image << 16, mid-gray = 0x800000) which is
the format F250 receives.

Usage:
  ./.venv-poc/bin/python dev/enroll_native.py --splice REF.bin IMAGE.bin \\
      [-o OUT.bin]
"""
import argparse
import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from validitysensor.moh_native import (
    extract_frame_native, native_template_via_splice, build_v30,
)


def _load_image(path, w=112, h=112):
    raw = open(path, 'rb').read()
    if len(raw) < w * h:
        raise ValueError(f'image file is {len(raw)} bytes, need ≥ {w*h}')
    img_u8 = np.frombuffer(raw[:w * h], dtype=np.uint8).reshape(h, w)
    # Q16: image_q16 = u8 << 16 ; mid-gray (128) → 0x800000
    return img_u8.astype(np.int32) << 16


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--splice', metavar='REF.bin',
                    help='reference template to splice descriptors into')
    ap.add_argument('--extract', action='store_true',
                    help='build template from scratch (no reference; TODO)')
    ap.add_argument('image', help='112x112 uint8 raw image')
    ap.add_argument('-o', '--out', default='native_template.bin',
                    help='output template path (default native_template.bin)')
    args = ap.parse_args()

    img_q16 = _load_image(args.image)
    print(f'loaded image {args.image} ({img_q16.shape}, Q16 mid-gray check: '
          f'{img_q16[0,0]:#x})')

    if args.splice:
        ref = open(args.splice, 'rb').read()
        if len(ref) != 23136:
            print(f'WARN: reference is {len(ref)} bytes, expected 23136', file=sys.stderr)
        out = native_template_via_splice(img_q16, ref)
        print(f'splice complete: {len(out)} bytes')
    elif args.extract:
        # Self-contained build (no reference). Produces a v30 section but
        # NOT a complete WS body — still pending multi-frame + section
        # header decoding.
        kps = extract_frame_native(img_q16)
        print(f'extracted {len(kps)} keypoints')
        section = build_v30(kps)
        print(f'v30 section: {len(section)} bytes')
        print('NOTE: --extract emits a single v30 section only. Multi-frame '
              'accumulation + full WS body assembly is still WIP; the chip '
              'will not accept this without a captured WS scaffold. Use '
              '--splice REF.bin for a chip-storable template.')
        with open(args.out, 'wb') as f:
            f.write(section)
        print(f'wrote {args.out}')
        return 0
    else:
        ap.error('must specify --splice REF.bin or --extract')

    with open(args.out, 'wb') as f:
        f.write(out)
    print(f'wrote {args.out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
