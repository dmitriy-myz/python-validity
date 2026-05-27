#!/usr/bin/env python3
"""Diff harness: our moh_opencv orchestrator vs the DLL's feature buffer v30.

Why: the WS section's descriptor blob is the feature-extractor output `v30`
copied verbatim (see dev/MOH.md "section descriptor blob = v30"). So a
matchable native template requires our orchestrator
(validitysensor/moh_opencv.py) to emit byte-identical `v30`. This harness
loads captured `(image -> v30)` pairs from the gdb dumps, decodes the v30
structure, and runs our extraction on the same image so we can drive the
two outputs together and find the first divergence.

Capture the canonical pair on the Wine host with:
    GDB_DUMP_EXTRACT=1 gdb -p <PID> -x dev/gdb_dump.py
That writes extract_image_*/extract_v30_* (the sub_180001A50 in/out). If
those aren't present this falls back to packer_features_* for v30 (still
useful for structure analysis, but without the matching input image).

Usage:
    .venv-poc/bin/python dev/diff_v30.py [DUMP_DIR]

This is a SCAFFOLD: it nails down the v30 record format (the thing we must
reproduce) and reports our extractor's output beside it. Byte-exact match
is the goal we iterate toward; this surfaces where we stand each run.
"""
import glob
import math
import os
import re
import struct
import sys
from collections import Counter

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DUMP_DIR = (sys.argv[1] if len(sys.argv) > 1 else
            os.environ.get('FRIDA_DUMP_DIR', '/media/sf_vbox-rw/finger/frida_dumps'))


# ─── dump loading ───────────────────────────────────────────────────────

def newest_bucket(*patterns):
    """Newest run bucket (ts//100000) that has any of the given file kinds."""
    ts = []
    for pat in patterns:
        for f in glob.glob(os.path.join(DUMP_DIR, pat)):
            m = re.search(r'_(\d+)_call', os.path.basename(f))
            if m:
                ts.append(int(m.group(1)))
    return max(ts) // 100000 if ts else None


def load(kind, bucket):
    """{call_index: bytes} for one dump kind within a run bucket."""
    out = {}
    for f in glob.glob(os.path.join(DUMP_DIR, f'{kind}_*_call*.bin')):
        m = re.search(r'_(\d+)_call(\d+)', os.path.basename(f))
        if m and int(m.group(1)) // 100000 == bucket:
            out[int(m.group(2))] = open(f, 'rb').read()
    return out


def load_images(bucket):
    """extract_image files carry WxH in the tag: extract_image_<ts>_call<n>_<w>x<h>.bin"""
    out = {}
    for f in glob.glob(os.path.join(DUMP_DIR, 'extract_image_*_call*.bin')):
        m = re.search(r'_(\d+)_call(\d+)_(\d+)x(\d+)', os.path.basename(f))
        if m and int(m.group(1)) // 100000 == bucket:
            out[int(m.group(2))] = (open(f, 'rb').read(), int(m.group(3)), int(m.group(4)))
    return out


# ─── v30 structure analysis ─────────────────────────────────────────────

def entropy(b):
    if not b:
        return 0.0
    c = Counter(b)
    return -sum(v / len(b) * math.log2(v / len(b)) for v in c.values())


def decode_v30(buf):
    """v30 = [u16 tag][u16 len][8 zero bytes][body]. Returns (tag, length, body)."""
    if len(buf) < 12:
        return None, 0, b''
    tag, length = struct.unpack_from('<HH', buf, 0)
    end = 12 + length if 0 < length <= len(buf) - 12 else len(buf)
    return tag, length, buf[12:end]


def autocorr_strides(body, lo=4, hi=200):
    best = []
    for s in range(lo, hi):
        if s >= len(body):
            break
        n = len(body) - s
        hits = sum(1 for i in range(n) if body[i] == body[i + s])
        best.append((hits / n, s))
    best.sort(reverse=True)
    return best[:6]


def record_format(body, strides=(18, 54)):
    """Per-column entropy + coordinate-field detection for candidate record
    sizes. A coord field (image is 112px) shows as a column whose values
    stay within ~[0,112]. Returns the stride whose record count is most
    integer and its coord-like column offsets."""
    out = {}
    for s in strides:
        n = len(body) // s
        coord_cols, col_ent = [], []
        for j in range(s):
            col = [body[r * s + j] for r in range(n)]
            e = entropy(col)
            col_ent.append(e)
            if max(col) <= 115:          # plausible coordinate in a 112px frame
                coord_cols.append(j)
        out[s] = dict(n=n, leftover=len(body) % s,
                      coord_cols=coord_cols, mean_ent=sum(col_ent) / s)
    return out


def report_record_format(v30s):
    print("\n=== v30 record format (per-column analysis, frame 0) ===")
    body = decode_v30(v30s[sorted(v30s)[0]])[2]
    for s, info in record_format(body).items():
        print(f"  stride {s}B: {info['n']} records (leftover {info['leftover']}B), "
              f"mean col-entropy {info['mean_ent']:.2f}, "
              f"coord-like cols (max<=115): {info['coord_cols']}")
    print("  → records carry (x,y) coordinate fields + binary-descriptor bulk;"
          " matching needs bit-exact keypoints AND descriptors.")


def report_v30(v30s):
    print(f"\n=== v30 structure ({len(v30s)} frames) ===")
    for n in sorted(v30s):
        tag, length, body = decode_v30(v30s[n])
        print(f"  frame{n}: hdr tag=0x{tag:04x} len={length} "
              f"body={len(body)}B entropy={entropy(body):.2f} "
              f"head={v30s[n][:12].hex()}")
    # cross-frame: which body bytes are constant (structure) vs variable (data)?
    bodies = [decode_v30(v30s[n])[2] for n in sorted(v30s)]
    if len(bodies) >= 2:
        L = min(len(b) for b in bodies)
        const = sum(1 for i in range(L) if len({b[i] for b in bodies}) == 1)
        print(f"  cross-frame: {const}/{L} body bytes constant across frames "
              f"({100 * const / L:.1f}%) — constant = framing, variable = features")
    # record stride from autocorrelation of the first body
    if bodies:
        print(f"  autocorr strides (frame {sorted(v30s)[0]} body): "
              + ", ".join(f"{s}B={r:.3f}" for r, s in autocorr_strides(bodies[0])))


# ─── our orchestrator (moh_opencv) ──────────────────────────────────────

def run_opencv(image_bytes, w, h):
    """Run our feature extraction on the captured image; return a summary."""
    sys.path.insert(0, REPO_ROOT)
    import cv2
    import numpy as np
    from validitysensor import moh_opencv as mo

    img = np.frombuffer(image_bytes[:w * h], dtype=np.uint8).reshape(h, w)
    # same mid-gray border padding as moh_opencv.extract_template
    padded = cv2.copyMakeBorder(img, mo.PATCH_RADIUS, mo.PATCH_RADIUS,
                                mo.PATCH_RADIUS, mo.PATCH_RADIUS,
                                cv2.BORDER_CONSTANT, value=mo.FILL_GRAY)
    resp = mo.compute_harris_response(padded)
    mins = mo.extract_minutiae(resp, mo.MAX_MINUTIAE,
                               border=mo.PATCH_RADIUS, min_distance=mo.MIN_DIST_NMS)
    tests = mo.brief_select_tests(scale=mo.PATCH_RADIUS, num_tests=64)
    descs = [mo.compute_brief_descriptor(padded, x, y, tests) for (y, x, _s) in mins[:8]]
    return {
        'image': f'{w}x{h}',
        'harris_min': float(resp.min()), 'harris_max': float(resp.max()),
        'n_minutiae': len(mins),
        'top8': [(x - mo.PATCH_RADIUS, y - mo.PATCH_RADIUS, round(s, 1)) for y, x, s in mins[:8]],
        'desc8': [f'{d:016x}' for d in descs],
    }


def dll_keypoints(v30_buf):
    """Extract the DLL's keypoint (x,y) coords from a v30 buffer. Records are
    54 bytes; each carries coord pairs at byte offsets 17/18 and 35/36
    (x at the even offset, y at +1) — confirmed: (x,y) order scores 2x random
    on our Harris, swapped scores ~random. Returns a deduped, in-frame list."""
    body = decode_v30(v30_buf)[2]
    pts = set()
    for i in range(len(body) // 54):
        r = body[i * 54:(i + 1) * 54]
        for a in (17, 35):
            pts.add((r[a], r[a + 1]))
    return [p for p in pts if 0 < p[0] < 112 and 0 < p[1] < 112]


def compare_keypoints(v30s, images):
    """Grind metric: detection recall of our orchestrator vs the DLL's actual
    keypoints (recovered from v30). recall@N = fraction of DLL keypoints with
    one of ours within N px (L1). Drives the detector toward bit-exactness."""
    print("\n=== detection recall (our moh_opencv vs DLL v30 keypoints) ===")
    sys.path.insert(0, REPO_ROOT)
    try:
        import cv2
        import numpy as np
        from validitysensor import moh_opencv as mo
    except ImportError as e:
        print(f"  (skipped — needs .venv-poc: {e})")
        return
    for n in sorted(set(v30s) & set(images)):
        data, w, h = images[n]
        dll = dll_keypoints(v30s[n])
        img = np.frombuffer(data[:w * h], dtype=np.uint8).reshape(h, w)
        padded = cv2.copyMakeBorder(img, mo.PATCH_RADIUS, mo.PATCH_RADIUS,
                                    mo.PATCH_RADIUS, mo.PATCH_RADIUS,
                                    cv2.BORDER_CONSTANT, value=mo.FILL_GRAY)
        resp = mo.compute_harris_response(padded)
        mins = mo.extract_minutiae(resp, mo.MAX_MINUTIAE,
                                   border=mo.PATCH_RADIUS, min_distance=mo.MIN_DIST_NMS)
        ours = np.array([(x - mo.PATCH_RADIUS, y - mo.PATCH_RADIUS) for y, x, _ in mins])

        def recall(tol):
            if not len(ours) or not dll:
                return 0.0
            hit = sum(1 for x, y in dll
                      if np.min(np.abs(ours[:, 0] - x) + np.abs(ours[:, 1] - y)) <= tol)
            return hit / len(dll)
        print(f"  frame{n}: DLL kp={len(dll)} ours={len(ours)} | "
              f"recall@2px={recall(2):.2f} @5px={recall(5):.2f} @10px={recall(10):.2f}")


def compare_harris(bucket, images):
    """Diff the DLL's fixed-point response map (sub_18000CE80, GDB_DUMP_HARRIS)
    against our float Harris on the same image. Tells us whether the @2px gap
    is the OPERATOR (maps differ) or the NMS (maps match, peaks chosen
    differently)."""
    resp_files = sorted(glob.glob(os.path.join(DUMP_DIR, 'harris_resp_*_call*.bin')))
    resp_files = [f for f in resp_files
                  if int(re.search(r'_(\d+)_call', os.path.basename(f)).group(1)) // 100000 == bucket]
    if not resp_files:
        print("\n(no harris_resp_* — capture GDB_DUMP_HARRIS=1 to diff the response map)")
        return
    print("\n=== Harris response map: DLL (fixed-point) vs ours (float) ===")
    sys.path.insert(0, REPO_ROOT)
    import cv2
    import numpy as np
    from validitysensor import moh_opencv as mo
    for f in resp_files:
        m = re.search(r'call(\d+)_plane(\d+)_(\d+)x(\d+)', os.path.basename(f))
        call, plane, w, h = (int(m.group(i)) for i in range(1, 5))
        dll = np.frombuffer(open(f, 'rb').read(), dtype=np.int32)
        if dll.size < w * h:
            print(f"  call{call} plane{plane} {w}x{h}: short dump ({dll.size}/{w*h})")
            continue
        dll = dll[:w * h].reshape(h, w).astype(np.float64)
        line = f"  call{call} plane{plane} {w}x{h}: DLL resp range[{dll.min():.0f},{dll.max():.0f}]"
        if call in images:
            data, iw, ih = images[call]
            img = np.frombuffer(data[:iw * ih], dtype=np.uint8).reshape(ih, iw).astype(np.float32)
            # pad our image to the plane size if it's the padded working buffer
            pad = (w - iw) // 2
            src = cv2.copyMakeBorder(img, pad, h - ih - pad, pad, w - iw - pad,
                                     cv2.BORDER_CONSTANT, value=mo.FILL_GRAY) if pad >= 0 else img
            if src.shape == (h, w):
                ours = mo.compute_harris_response(src).astype(np.float64)
                a, b = dll.ravel(), ours.ravel()
                cc = np.corrcoef(a, b)[0, 1]
                line += f" | corr(DLL,ours)={cc:+.3f}"
            else:
                line += f" | (our {src.shape} != plane {(h, w)}, no align)"
        print(line)
    print("  → high corr ⇒ gap is NMS/localization; low corr ⇒ operator differs "
          "(likely the Q12 >>12 fixed-point quantization).")


def compare_gradin(bucket):
    """If the enhanced gradient-input image is captured (GDB_DUMP_GRADIN), run
    our operators on THAT image (not the raw frame) and correlate against the
    DLL's gradient/response buffers. High corr here = we've located the
    enhanced image and only the operator remains; still low = the buffers
    aren't simple derivatives of even the enhanced image."""
    gin = [f for f in glob.glob(os.path.join(DUMP_DIR, 'gradin_image_*_call*.bin'))
           if int(re.search(r'_(\d+)_call', os.path.basename(f)).group(1)) // 100000 == bucket]
    if not gin:
        print("\n(no gradin_image_* — capture GDB_DUMP_GRADIN=1 for the enhanced "
              "image the detector actually runs on)")
        return
    print("\n=== enhanced gradient-input image vs DLL buffers ===")
    sys.path.insert(0, REPO_ROOT)
    import cv2
    import numpy as np

    def at(call, kind, w, h):
        fs = [f for f in glob.glob(os.path.join(DUMP_DIR, f'harris_{kind}_*_call{call}_*.bin'))
              if int(re.search(r'_(\d+)_call', os.path.basename(f)).group(1)) // 100000 == bucket]
        if not fs:
            return None
        return np.frombuffer(open(fs[0], 'rb').read(), np.int32)[:w * h].reshape(h, w).astype(np.float64)

    def cc(a, b):
        return float(np.corrcoef(a.ravel(), b.ravel())[0, 1])

    for f in sorted(gin):
        m = re.search(r'call(\d+)_(\d+)x(\d+)', os.path.basename(f))
        call, w, h = int(m.group(1)), int(m.group(2)), int(m.group(3))
        img = np.frombuffer(open(f, 'rb').read(), np.int32)[:w * h].reshape(h, w).astype(np.float64)
        ixx, iyy, ixy = (at(call, k, w, h) for k in ('Ixx', 'Iyy', 'Ixy'))
        resp = at(call, 'resp', w, h)
        f32 = img.astype(np.float32)
        # first-derivative (Harris) and second-derivative (Hessian) products
        gx = cv2.Sobel(f32, cv2.CV_64F, 1, 0, ksize=3); gy = cv2.Sobel(f32, cv2.CV_64F, 0, 1, ksize=3)
        lxx = cv2.Sobel(f32, cv2.CV_64F, 2, 0, ksize=3); lyy = cv2.Sobel(f32, cv2.CV_64F, 0, 2, ksize=3)
        lxy = cv2.Sobel(f32, cv2.CV_64F, 1, 1, ksize=3)
        line = f"  call{call} {w}x{h}: img range[{img.min():.0f},{img.max():.0f}]"
        if ixx is not None:
            line += (f" | Harris Ix²->Ixx={cc(gx * gx, ixx):+.2f}"
                     f" | Hessian Lxx->Ixx={cc(lxx, ixx):+.2f} Lxy->Ixy={cc(lxy, ixy):+.2f}")
        if resp is not None:
            line += f" | DoH->resp={cc(lxx * lyy - lxy * lxy, resp):+.2f}"
        print(line)
    print("  → if Hessian corrs are high, port: enhance->this image, Sobel d2, DoH.")


def report_opencv(images):
    print(f"\n=== our moh_opencv extraction ({len(images)} images) ===")
    try:
        for n in sorted(images):
            data, w, h = images[n]
            try:
                r = run_opencv(data, w, h)
                print(f"  frame{n} ({r['image']}): {r['n_minutiae']} minutiae; "
                      f"harris=[{r['harris_min']:.1f},{r['harris_max']:.1f}]")
                print(f"     top kp (x,y,score): {r['top8']}")
                print(f"     brief[:8]: {r['desc8']}")
            except Exception as e:
                print(f"  frame{n}: extraction failed: {e!r}")
    except ImportError as e:
        print(f"  (moh_opencv import failed: {e} — run with .venv-poc/bin/python)")


# ─── main ───────────────────────────────────────────────────────────────

def main():
    print(f"dump dir: {DUMP_DIR}")
    bucket = newest_bucket('extract_v30_*_call*.bin', 'packer_features_*_call*.bin')
    if bucket is None:
        print("No v30 dumps found. Capture with GDB_DUMP_EXTRACT=1 (or GDB_DUMP_PACKER=1).")
        return 1
    print(f"newest run bucket: ~{bucket * 100}s")

    v30s = load('extract_v30', bucket)
    src = 'extract_v30 (sub_180001A50 output — canonical)'
    if not v30s:
        v30s = load('packer_features', bucket)
        src = 'packer_features (v30 as packer input — fallback)'
    print(f"v30 source: {src}")
    if v30s:
        report_v30(v30s)
        report_record_format(v30s)

    images = load_images(bucket)
    if images:
        compare_keypoints(v30s, images)
        compare_harris(bucket, images)
        compare_gradin(bucket)
        report_opencv(images)
    else:
        print("\n(no extract_image_* — capture GDB_DUMP_EXTRACT=1 for the matching "
              "input image to drive moh_opencv against v30)")

    print("\nNext: decode the v30 body record format (stride above), have "
          "moh_opencv emit that format, and diff byte-for-byte per frame.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
