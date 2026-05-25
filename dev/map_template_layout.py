"""Map the internal structure of the 23136-byte finger template.

By diffing two enrollments of (allegedly) the same finger we can separate:

- SERVICE bytes — stable between captures (header, IDs, hashes, sizes,
  format markers, padding). These tell us the layout.
- FEATURE bytes — vary between captures. Either real noise from finger
  placement variation, or session-keyed encryption / randomization.

Run anywhere with Python — no device needed. Needs the two captures at
/tmp/wine_finger_fresh.bin and /tmp/wine_finger_fresh2.bin.
"""
import collections
import math
import struct


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = collections.Counter(b)
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def map_layout(path1='/tmp/wine_finger_fresh.bin',
               path2='/tmp/wine_finger_fresh2.bin'):
    a = open(path1, 'rb').read()
    b = open(path2, 'rb').read()
    assert len(a) == len(b) == 23136
    n = len(a)

    # Per-byte stability mask (1 = same in both captures, 0 = differs)
    stable = bytearray(1 if a[i] == b[i] else 0 for i in range(n))

    # Find runs of stable bytes (>=4 in a row)
    runs = []
    i = 0
    while i < n:
        if stable[i] == 1:
            j = i
            while j < n and stable[j] == 1:
                j += 1
            if j - i >= 4:
                runs.append((i, j - i))
            i = j
        else:
            i += 1

    print(f"Total bytes: {n}")
    print(f"Stable bytes: {sum(stable)} ({100*sum(stable)/n:.1f}%)")
    print(f"Stable runs of >=4: {len(runs)}")
    print()

    # Annotate runs: classify as zero-run, value-run, or pattern-run
    def classify(off, length):
        seg_a = a[off:off+length]
        if all(byte == 0 for byte in seg_a):
            return f"zeros"
        if all(byte == seg_a[0] for byte in seg_a):
            return f"constant 0x{seg_a[0]:02x}"
        return f"value: {seg_a.hex()}"

    print(f"{'offset':>8s}  {'len':>5s}  {'kind':<24s}  detail")
    for off, ln in runs:
        kind = classify(off, ln)
        preview = a[off:off+min(24, ln)].hex()
        print(f"  {off:>6d}  {ln:>4d}  {kind:<24s}  {preview}{'...' if ln>24 else ''}")

    # Highlight the SERVICE area (top-of-template and bottom-of-template)
    print(f"\n=== Service area: first 64 bytes ===")
    print(f"  capture1: {a[:64].hex()}")
    print(f"  capture2: {b[:64].hex()}")
    print(f"  diff:     {''.join('--' if a[i]==b[i] else 'xx' for i in range(64))}")

    print(f"\n=== Service area: last 64 bytes (offsets {n-64}..{n}) ===")
    print(f"  capture1: {a[-64:].hex()}")
    print(f"  capture2: {b[-64:].hex()}")
    print(f"  diff:     {''.join('--' if a[i]==b[i] else 'xx' for i in range(n-64, n))}")

    # Entropy in sliding windows — find natural section boundaries
    print(f"\n=== Entropy by 1024-byte window (capture1) ===")
    print(f"{'offset':>8s}  {'entropy':>8s}  hint")
    for off in range(0, n, 1024):
        seg = a[off:off+1024]
        e = _entropy(seg)
        # 8.0 = perfectly random; 4-6 = structured/biometric features; <4 = many zeros / very structured
        if e < 4:
            hint = '<<< heavily structured'
        elif e > 7.9:
            hint = '>>> random/encrypted'
        elif e > 7.5:
            hint = '> high entropy'
        else:
            hint = ''
        print(f"  {off:>6d}  {e:>8.3f}  {hint}")

    # The "Service header" / "Feature payload" split — show byte-count of stable
    # bytes per zone
    print(f"\n=== Zone summary ===")
    zones = [
        ('outer header',   0, 16),
        ('inner header',  16, 48),         # incl. WS magic
        ('zone A (early)', 48, 256),
        ('zone B',        256, 4096),
        ('zone C',       4096, 9216),
        ('zone D',       9216, 16384),
        ('zone E',      16384, 18496),
        ('zone F (zeros?)', 18496, 23072),
        ('TID',         23072, 23104),
        ('trailing zeros', 23104, 23136),
    ]
    print(f"{'zone':<24s} {'range':>16s} {'stable':>8s} {'pct':>6s} {'entropy':>8s}")
    for name, lo, hi in zones:
        zone_stable = sum(stable[lo:hi])
        width = hi - lo
        e = _entropy(a[lo:hi])
        print(f"  {name:<22s} {lo:>6d}..{hi:<6d} {zone_stable:>6d}  {100*zone_stable/width:>5.1f}%  {e:>7.3f}")


if __name__ == '__main__':
    map_layout()
