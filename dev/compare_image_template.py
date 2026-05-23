"""Diagnostic: do raw image bytes appear in the Wine 4705 finger template?

Captures a fresh image via sensor.capture(), then searches for runs of
its bytes inside Wine's known-accepted 23136-byte finger payload. If we
find substantial overlap, the image lives inside the WS in some form. If
nothing matches, host-side processing (extraction or encryption) is in
between.

Run after open9x():
    exec(open('dev/compare_image_template.py').read())
    compare_capture_to_wine()
"""
import logging
from struct import unpack

import numpy as np
from PIL import Image

from validitysensor.sensor import sensor, CaptureMode

logging.basicConfig(level=logging.INFO)


def _capture() -> tuple:
    """Capture one frame; return (img_np_uint8, raw_bytes)."""
    print("Place finger for capture...")
    x, y, w1, w2, img_data = sensor.capture(CaptureMode.ENROLL)
    img = np.frombuffer(img_data, dtype=np.uint8).reshape(x, y)
    img = np.transpose(img)
    return img, bytes(img_data)


def _runs_of_overlap(haystack: bytes, needle: bytes, min_len: int = 6) -> list:
    """Find all positions where `needle` substrings of length >= min_len appear
    in `haystack`. Returns list of (needle_offset, haystack_offset, length).

    Brute-force-ish but tractable for ~10KB needle, 23KB haystack.
    """
    # Use a rolling-hash index: hash every min_len-byte substring of haystack
    # to a position list, then scan needle.
    from collections import defaultdict
    idx = defaultdict(list)
    for h_off in range(0, len(haystack) - min_len + 1):
        idx[haystack[h_off:h_off + min_len]].append(h_off)

    hits = []
    n_off = 0
    while n_off <= len(needle) - min_len:
        k = needle[n_off:n_off + min_len]
        if k in idx:
            for h_off in idx[k]:
                # Extend the match
                length = min_len
                while (n_off + length < len(needle) and
                       h_off + length < len(haystack) and
                       needle[n_off + length] == haystack[h_off + length]):
                    length += 1
                hits.append((n_off, h_off, length))
            n_off += 1  # don't skip, we want all overlaps
        else:
            n_off += 1
    return hits


def compare_capture_to_wine(wine_path='/tmp/wine_finger_fresh.bin',
                             min_overlap_len=6) -> None:
    img, img_bytes = _capture()
    print(f"image: shape={img.shape}, {len(img_bytes)} bytes")
    Image.fromarray(img).save("/tmp/capture_for_compare.png")

    with open(wine_path, 'rb') as f:
        wine = f.read()
    print(f"wine template: {len(wine)} bytes (loaded from {wine_path})")

    # Search for image-byte runs inside wine
    hits = _runs_of_overlap(wine, img_bytes, min_len=min_overlap_len)
    if not hits:
        print(f"\nNo runs of >= {min_overlap_len} bytes overlap between capture and Wine template.")
    else:
        # Sort by length descending
        hits.sort(key=lambda h: -h[2])
        print(f"\nFound {len(hits)} overlaps of >= {min_overlap_len} bytes:")
        print(f"{'wine_off':>8s} {'img_off':>8s} {'len':>5s}  preview")
        seen_wine_offs = set()
        for n_off, h_off, ln in hits[:30]:
            if h_off in seen_wine_offs:  # de-dup by wine offset
                continue
            seen_wine_offs.add(h_off)
            preview = img_bytes[n_off:n_off + min(16, ln)].hex()
            if ln > 16:
                preview += '...'
            print(f"  {h_off:6d}  {n_off:6d}  {ln:>4d}  {preview}")

    # Also search the REVERSE: img substrings, since image might be stored
    # with byte/pixel reordering
    print("\nReverse search (wine substrings in image):")
    rev_hits = _runs_of_overlap(img_bytes, wine, min_len=min_overlap_len)
    if rev_hits:
        rev_hits.sort(key=lambda h: -h[2])
        for n_off, h_off, ln in rev_hits[:5]:
            print(f"  wine[{n_off}:{n_off+ln}] == img[{h_off}:{h_off+ln}]: {wine[n_off:n_off+min(16, ln)].hex()}")

    # Entropy of the wine WS body (offset 16..18500 — the dense feature region)
    ws_body = wine[16:18500]
    import collections, math
    counts = collections.Counter(ws_body)
    entropy = -sum((c/len(ws_body)) * math.log2(c/len(ws_body)) for c in counts.values())
    print(f"\nEntropy of wine WS body (offsets 16..18500): {entropy:.3f} bits/byte (8.000 = perfect random)")

    # Entropy of the image (compare)
    img_counts = collections.Counter(img_bytes)
    img_entropy = -sum((c/len(img_bytes)) * math.log2(c/len(img_bytes)) for c in img_counts.values())
    print(f"Entropy of captured image:                   {img_entropy:.3f} bits/byte")
