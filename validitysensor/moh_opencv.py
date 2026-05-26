"""
OpenCV-based feature extractor for Match-on-Host devices (06cb:00a2).

Proof-of-concept implementation of the host-side enrollment pipeline,
using standard CV primitives (Sobel, Gaussian, Harris response, BRIEF).
This is NOT byte-identical to the Synaptics DLL output — the chip's
matcher is fuzzy by design, so an approximation may produce templates
the chip accepts and matches.

If this produces chip-acceptable templates, the port is done with a
fraction of the RE work. If not, the failure mode tells us what to refine.

Algorithm (Synaptics' actual structure, from RE):
  1. Pad image with mid-gray border (sub_180009F50)
  2. Compute gradients Ix, Iy (Sobel — sub_180010050 / sub_18000FDF0)
  3. Compute Ixx, Iyy, Ixy (smoothed by separable Gaussian)
  4. Harris response: det(M) = Ixx*Iyy - Ixy² (sub_18000CE80)
  5. Non-max suppression → top-N minutia positions
  6. BRIEF descriptor per minutia: 64 binary tests (sub_18000E6B0 + apply)
  7. Sort/dedup/store in 250-slot table
  8. Compute TID via the HMAC-SHA256 recipe in moh_extract.compute_tid
     (sub_1800E0A60 → sub_18004B710 chain, decoded from enroll-fresh.log
     lines 1570→1583)
  9. Build TLV envelope (sub_180036840 — already byte-exact)
 10. Send via db.new_finger (existing python-validity transport)

Dependencies: numpy, opencv-python
"""

from __future__ import annotations

import logging
from struct import pack
from typing import List, Optional, Tuple

import numpy as np
import cv2

from .moh_extract import (
    BRIEF_SEED_TABLE,
    MAX_MINUTIAE,
    SENSOR_DPI,
    SENSOR_W, SENSOR_H,
    _build_envelope,
    compute_tid,
    sub_18000E6B0 as brief_select_tests,
)


log = logging.getLogger(__name__)


# Tunable parameters. Initial guesses based on classical Harris/BRIEF
# defaults; the actual Synaptics DLL uses specific constants we haven't
# fully recovered. These are our first-pass approximations.
PATCH_RADIUS    = 16      # patch radius for BRIEF tests (the "scale" arg)
SOBEL_KSIZE     = 5       # 5-tap Sobel (the DLL uses a 5-cell separable kernel)
GAUSS_KSIZE     = 5
GAUSS_SIGMA     = 1.5
MIN_DIST_NMS    = 4       # minimum spacing between accepted minutiae
HARRIS_K        = 0.04    # standard Harris k; the DLL formula is plain det(M), no -k*trace²

# Edge fill value used by sub_180009F50 — mid-gray in 16.16 fixed-point.
# When we apply this in the float domain the equivalent is 128.0.
FILL_GRAY       = 128

# WINBIO_FINGER_UNSPECIFIED_POS_03 — the subtype Windows enrolled with on
# the captured trace. Stored as u16 LE so the wire byte order is `f7 00`.
DEFAULT_SUBTYPE = 0x00f7

# The first 40 bytes of the chip-view WS body. Layout decoded across 5
# captures (see dev/dissect_ws.py multi):
#
#   offset  size   field
#   ───────────────────────────────────────────────────────────────
#   0       4      ZEROS — natural leading padding (always 0x00*4)
#   4       4      u32 end_ptr — feature data end offset; 18496 for
#                  mode A (4 sections), 23036 for mode B (5 sections)
#   8       4      u32 header word 1 = 0x00050206 (stable across captures)
#   12      4      u32 header word 2 = 0x01080002 (stable across captures)
#   16      4      u32 header word 3 — mode discriminator:
#                  0x00010203 = mode A, 0x01020304 = mode B
#   20      4      u32 reserved = 0
#   24      16     four u32 section counts (one per main feature section)
#
# We target mode A (simpler, only 4 feature sections), and seed the counts
# with values observed in fresh.bin — these need to be replaced with the
# actual per-section feature counts once feature extraction is wired up.
WS_HEADER_MODE_A = (
    b'\x00\x00\x00\x00'                  # WS[0..4]   leading zeros
    + (18496).to_bytes(4, 'little')      # WS[4..8]   end_ptr (mode A)
    + (0x00050206).to_bytes(4, 'little') # WS[8..12]  header word 1
    + (0x01080002).to_bytes(4, 'little') # WS[12..16] header word 2
    + (0x00010203).to_bytes(4, 'little') # WS[16..20] header word 3 (mode A)
    + b'\x00\x00\x00\x00'                # WS[20..24] reserved
    # WS[24..40] = 4 u32 section counts, filled in by build_working_state
)
assert len(WS_HEADER_MODE_A) == 24

# Wire-trace working-state size on accepted Wine template
WS_SIZE = 23056


# ─── Step 1-4: image → Harris response map ─────────────────────────────

def compute_harris_response(image: np.ndarray) -> np.ndarray:
    """Returns the per-pixel Harris response map (det of structure tensor).

    Replicates the DLL's:
      Ix, Iy = Sobel
      Ixx, Iyy, Ixy = Gaussian-blurred squares/products
      response = Ixx * Iyy - Ixy²
    """
    img_f = image.astype(np.float32)
    Ix = cv2.Sobel(img_f, cv2.CV_32F, 1, 0, ksize=SOBEL_KSIZE)
    Iy = cv2.Sobel(img_f, cv2.CV_32F, 0, 1, ksize=SOBEL_KSIZE)
    Ixx = cv2.GaussianBlur(Ix * Ix, (GAUSS_KSIZE, GAUSS_KSIZE), GAUSS_SIGMA)
    Iyy = cv2.GaussianBlur(Iy * Iy, (GAUSS_KSIZE, GAUSS_KSIZE), GAUSS_SIGMA)
    Ixy = cv2.GaussianBlur(Ix * Iy, (GAUSS_KSIZE, GAUSS_KSIZE), GAUSS_SIGMA)
    return Ixx * Iyy - Ixy * Ixy


# ─── Step 5: NMS to extract top-N minutia positions ────────────────────

def extract_minutiae(response: np.ndarray, max_count: int,
                     border: int, min_distance: int) -> List[Tuple[int, int, float]]:
    """Return top-N peaks of the response map, NMS-suppressed.

    Returns list of (y, x, score) tuples, with positions in the *padded*
    coordinate system. Caller subtracts `border` to get original coords.
    """
    h, w = response.shape

    # Local-max via 3x3 dilation comparison
    local_max = cv2.dilate(response, np.ones((3, 3), dtype=np.float32))
    peaks_mask = (response == local_max) & (response > 0)

    # Strip border so all minutiae have valid surrounding patches
    peaks_mask[:border, :]  = False
    peaks_mask[-border:, :] = False
    peaks_mask[:, :border]  = False
    peaks_mask[:, -border:] = False

    ys, xs = np.where(peaks_mask)
    scores = response[ys, xs]

    # Sort by score, descending
    order = np.argsort(-scores)
    ys, xs, scores = ys[order], xs[order], scores[order]

    # NMS by minimum distance
    accepted: List[Tuple[int, int, float]] = []
    for y, x, s in zip(ys, xs, scores):
        too_close = any((y - ay) ** 2 + (x - ax) ** 2 < min_distance ** 2
                        for ay, ax, _ in accepted)
        if not too_close:
            accepted.append((int(y), int(x), float(s)))
            if len(accepted) >= max_count:
                break
    return accepted


# ─── Step 6: BRIEF descriptor per minutia ──────────────────────────────

def compute_brief_descriptor(image: np.ndarray, cx: int, cy: int,
                              tests: List[Tuple[int, int, int, int, int]]) -> int:
    """Apply 64 binary tests, return 64-bit descriptor.

    Each test: bit i = (image[cy+y1, cx+x1] < image[cy+y2, cx+x2]).
    """
    descriptor = 0
    for i, (_level, x1, y1, x2, y2) in enumerate(tests):
        p1 = image[cy + y1, cx + x1]
        p2 = image[cy + y2, cx + x2]
        if p1 < p2:
            descriptor |= (1 << i)
    return descriptor


# ─── Step 7: 32-byte minutia struct packing ────────────────────────────
# Field offsets recovered from qsort comparators in sub_18000a7c0/_a7e0/
# _a810/_a940. Tail bytes (+0x14..+0x1f) hold position; layout is a guess.

def pack_minutia(x: int, y: int, descriptor_64: int,
                 active: int = 1, flag9: int = 0,
                 quality: int = 0) -> bytes:
    """Pack one 32-byte minutia record."""
    # Split 64-bit descriptor into two signed int32 halves.
    # The qsort comparators sort by these as signed values, so we keep them signed.
    low  = descriptor_64 & 0xffffffff
    high = (descriptor_64 >> 32) & 0xffffffff
    score_c  = low  if low  < 0x80000000 else low  - 0x100000000
    score_10 = high if high < 0x80000000 else high - 0x100000000

    head    = pack('<HHHH', x & 0xffff, y & 0xffff, 0, 0)         # +0x00..+0x08
    middle  = pack('<BBxx', active, flag9)                          # +0x08..+0x0c
    scores  = pack('<ii', score_c, score_10)                        # +0x0c..+0x14
    tail    = pack('<HHHHHHHH', quality, 0, 0, 0, 0, 0, 0, 0)       # +0x14..+0x24
    record  = head + middle + scores + tail[:12]
    assert len(record) == 32, f"minutia is 32 bytes, got {len(record)}"
    return record


# ─── Step 8: build the working-state buffer ────────────────────────────

def build_working_state(records: List[bytes],
                         padded_image: np.ndarray) -> bytes:
    """Assemble the chip-view WS body (the TLV-1 payload).

    The result is 23056 bytes that go directly at envelope offset
    12..12+23056 (see moh_extract._build_envelope).

    Layout (decoded from captured Wine templates; see dev/MOH.md and
    dev/dissect_ws.py):

        WS[0..24]      WS_HEADER_MODE_A (24 bytes — see above)
        WS[24..40]     4 u32 section counts (one per main feature section)
        WS[40..223]    pre-section-4 region — feature data, currently zero
        WS[223..293]   70-byte section-4 trailer (anchor — verbatim)
        WS[293..4817]  section 5 feature data (variable per session)
        WS[4817..4876] section-5 trailer (anchor — verbatim)
        WS[4876..9421] section 6 feature data
        WS[9421..9437] section-6 trailer
        WS[9437..13961] section 7 feature data
        WS[13961..13977] section-7 trailer
        WS[13977..18508] section 8 (mode A: zero-pad through end_ptr=18496)
        WS[18508..23056] zero-pad through TID

    For now we drop our raw minutia records into section 5 (the largest
    bucket) and leave the others zero. The chip's matcher will reject
    until both the per-section anchor trailers are emitted with the
    right indices *and* the records inside each section match the
    chip's expected encoding (still unknown — see dev/MOH.md
    "Open questions"). This function is a scaffold.
    """
    # 250-slot minutia table (8000 bytes), padded to MAX_MINUTIAE entries
    pad_to_count = MAX_MINUTIAE - len(records)
    table = b''.join(records) + (b'\0' * 32) * pad_to_count
    assert len(table) == MAX_MINUTIAE * 32, "table is 250×32 = 8000 bytes"

    buf = bytearray(WS_SIZE)
    # WS[0..24] — fixed header (zeros, end_ptr, header words, reserved)
    buf[0:len(WS_HEADER_MODE_A)] = WS_HEADER_MODE_A
    # WS[24..40] — section counts. Placeholder values that should be
    # replaced with the actual number of records emitted into each
    # section once we know how to serialize records. Counts in
    # fresh.bin: (76, 90, 86, 89).
    counts = (len(records), 0, 0, 0)
    buf[24:40] = b''.join(c.to_bytes(4, 'little') for c in counts)
    # Drop the raw 32-byte minutia table into the start of section 5
    # (env offset 305 = WS offset 293). This is wrong format-wise (the
    # chip's matcher expects variable-length packed records, not
    # 32-byte fixed-stride entries) but is the best placeholder until
    # the per-record encoding is decoded.
    section5_start = 293
    buf[section5_start:section5_start + len(table)] = table
    return bytes(buf)


# ─── End-to-end: image → 23 KB envelope ────────────────────────────────

def extract_template(image: np.ndarray,
                     subtype: int = DEFAULT_SUBTYPE) -> bytes:
    """Run the full pipeline: 112×112 grayscale image → 23 KB blob.

    Returns bytes suitable for db.new_finger() → 0x47 new_record.
    """
    if image.ndim == 3:
        image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    assert image.shape == (SENSOR_H, SENSOR_W), \
        f"expected {SENSOR_H}×{SENSOR_W} grayscale, got {image.shape}"

    # 1. Pad with mid-gray border
    padded = cv2.copyMakeBorder(
        image, PATCH_RADIUS, PATCH_RADIUS, PATCH_RADIUS, PATCH_RADIUS,
        cv2.BORDER_CONSTANT, value=FILL_GRAY,
    )

    # 2-4. Compute Harris response over padded image
    response = compute_harris_response(padded)
    log.debug("Harris response range: [%.2f, %.2f]",
              float(response.min()), float(response.max()))

    # 5. NMS to extract top-N minutiae
    minutiae = extract_minutiae(response, MAX_MINUTIAE,
                                 border=PATCH_RADIUS,
                                 min_distance=MIN_DIST_NMS)
    log.info("extracted %d minutiae (cap %d)", len(minutiae), MAX_MINUTIAE)

    # 6-7. Compute BRIEF descriptor per minutia and pack into 32-byte records
    tests = brief_select_tests(scale=PATCH_RADIUS, num_tests=64)
    records: List[bytes] = []
    for (py, px, score) in minutiae:
        descriptor = compute_brief_descriptor(padded, px, py, tests)
        x = px - PATCH_RADIUS
        y = py - PATCH_RADIUS
        quality = int(min(max(score / 1000.0, 0), 0xffff))
        records.append(pack_minutia(x, y, descriptor, quality=quality))

    # 8. Build working state buffer + derive TID via the DLL's HMAC recipe
    ws = build_working_state(records, padded)
    template_id = compute_tid(ws)

    # 9. TLV envelope (already byte-exact)
    envelope = _build_envelope(subtype, ws, template_id)
    log.info("envelope size: %d bytes (ws=%d, tid=%d)",
             len(envelope), len(ws), len(template_id))

    return envelope


# ─── CLI/demo entry point ──────────────────────────────────────────────

def main():
    """Demo: read an image, run the extractor, print envelope summary."""
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <fingerprint.png>", file=sys.stderr)
        print("  Image must be 112×112 grayscale (or BGR).", file=sys.stderr)
        sys.exit(1)

    logging.basicConfig(level=logging.INFO,
                        format='%(levelname)s %(name)s: %(message)s')

    path = sys.argv[1]
    image = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
    if image is None:
        print(f"Could not read {path}", file=sys.stderr); sys.exit(1)
    if image.shape != (SENSOR_H, SENSOR_W):
        log.warning("resizing %s from %s to %d×%d",
                    path, image.shape, SENSOR_H, SENSOR_W)
        image = cv2.resize(image, (SENSOR_W, SENSOR_H))

    envelope = extract_template(image)
    print(f"\nEnvelope: {len(envelope)} bytes (expected 23136)")
    print(f"  header (first 16):  {envelope[:16].hex()}")
    ws_size = int.from_bytes(envelope[10:12], 'little')
    print(f"  TLV-1 data length:  {ws_size} (expected 23056)")
    print(f"  WS magic prefix:    {envelope[16:48].hex()}")
    tid_off = 16 + ws_size
    print(f"  TemplateId @ 0x{tid_off:04x}: {envelope[tid_off:tid_off+32].hex()}")
    print(f"  trailing 32 bytes:  {envelope[-32:].hex()}")


if __name__ == '__main__':
    main()
