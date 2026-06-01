#!/usr/bin/env python3
"""Port of sub_180005720 + its caller (sub_1800057e0) — the per-section v30
24-byte trailer block = [BYTE H+0xc][BYTE secobj+0xc][22-byte orientation
bucket table].

DECODE (byte-exact, proven against ws_body_1780253488249 / enroll 1780253459,
all 5 sections round-trip):

sub_180005720(secobj, buf, fill_base /*r8b*/, i_start /*r9d*/, limit /*[rsp+0x30]*/):
    H = *(secobj+0x10);  S = *(H+0)      # S = kp-record array, stride 0x20
    orient(i) = u32[S + i*0x20 + 0x0c]   # set by model-fitter sub_1800046e0 @0x4ab7
    bucket(i) = (orient(i) * 0x88888889) >> 35   ==  orient(i) // 15
    prev = 0; bucket = 0
    for i in range(i_start, limit):              # nothing if i_start >= limit
        bucket = orient(i) // 15
        if bucket > prev:                        # bucket non-decreasing => S SORTED by orient
            buf[fill_base + prev : fill_base + bucket] = i   # store ABSOLUTE index i (r9b)
        prev = bucket
    if bucket < 0x0b:                            # pad unused high buckets
        buf[fill_base + bucket : fill_base + 0x0b] = limit   # store limit (dil)

The 22-byte table is two calls (caller sub_1800057e0 @0x58ba / @0x58db):
    call1: fill_base=0,    i_start=0,           limit = BYTE[H+0xc]   (=141 for sec0)
    call2: fill_base=0x0b, i_start=BYTE[H+0xc], limit = N=*(u32)(H+8) (=250)

So buf[0:11]  is a per-bucket CDF over kp[0 .. H+0xc), buckets 0..10,
   buf[11:22] is a per-bucket CDF over kp[H+0xc .. N), buckets 0..10 (storing absolute idx).
buf[fill_base+k] = the absolute index of the first kp (in that half) whose
orientation bucket exceeds k (i.e. count of kp in the half with bucket <= k),
padded out with `limit` for buckets the half never reaches.

The kp array S is SORTED by orientation WITHIN each half; the split index
BYTE[H+0xc] is an independent section field (NOT just "first kp with bucket>=11"
— sec0 has 21 kp at bucket>=11 already inside [0,141)). BYTE[secobj+0xc] is a
second independent section byte emitted just before the table.
"""

ORIENT_OFF = 0x0c          # u32 orientation at S + i*0x20 + 0x0c
KP_STRIDE  = 0x20
BUCKETS    = 0x0b          # 11 buckets per half


def bucket_of(orient_u32: int) -> int:
    """edx after `mul 0x88888889 ; shr edx,3` == orient // 15 (verified all u32)."""
    return (orient_u32 & 0xFFFFFFFF) // 15


def _fill(buf: bytearray, orient, fill_base: int, i_start: int, limit: int) -> None:
    """Exact port of sub_180005720's body into `buf` (>= fill_base+11 bytes)."""
    prev = 0
    bucket = 0
    for i in range(i_start, limit):
        bucket = bucket_of(orient[i])
        if bucket > prev:                       # je / jae => only when bucket > prev
            for c in range(fill_base + prev, fill_base + bucket):
                buf[c] = i & 0xFF               # r9b = current absolute index i
        prev = bucket
    if bucket < BUCKETS:                         # cmp edx,0xb ; jae skip
        for c in range(fill_base + bucket, fill_base + BUCKETS):
            buf[c] = limit & 0xFF                # dil = limit


def build_bucket_table(orient, n: int, split: int) -> bytes:
    """Return the 22-byte orientation bucket table.

    orient : per-kp u32 orientation, length >= n, SORTED ascending within each
             half [0:split) and [split:n).
    n      : kp count  (= *(u32)(H+8), e.g. 250).
    split  : BYTE[H+0xc] (the two-call boundary, e.g. 141).
    """
    buf = bytearray(22)
    _fill(buf, orient, fill_base=0,         i_start=0,     limit=split)   # call1
    _fill(buf, orient, fill_base=BUCKETS,   i_start=split, limit=n)       # call2
    return bytes(buf)


def build_trailer24(h_0xc: int, secobj_0xc: int, orient, n: int) -> bytes:
    """The full 24-byte section trailer emitted by sub_1800057e0 after the
    N v30 records: [BYTE H+0xc][BYTE secobj+0xc][22-byte bucket table].
    Here h_0xc doubles as the bucket-table split (it IS BYTE[H+0xc])."""
    return bytes((h_0xc & 0xFF, secobj_0xc & 0xFF)) + build_bucket_table(orient, n, h_0xc)


# ----------------------------------------------------------------------------
# Self-test: reproduce all 5 sections of the captured ws_body byte-for-byte.
# ----------------------------------------------------------------------------
def _selftest():
    WS = "/media/sf_vbox-rw/finger/frida_dumps/ws_body_1780253488249_23056.bin"
    ws = open(WS, "rb").read()
    regs = [309, 4913, 9453, 13993, 18533]   # find_v30_regions(ws) anchors
    N = 250
    all_ok = True
    for ri, base in enumerate(regs):
        rec0 = base - 16
        blk = ws[rec0 + N * 18: rec0 + N * 18 + 24]
        h_0xc, secobj_0xc = blk[0], blk[1]
        obs = list(blk[2:24])
        # Reconstruct a per-half-sorted orientation array from the observed CDF,
        # then prove the port regenerates the captured 22 bytes exactly.
        split = h_0xc
        c1, c2 = obs[0:11], obs[11:22]
        cnt1 = [c1[0]] + [c1[k] - c1[k - 1] for k in range(1, 11)]
        cnt2 = [c2[0] - split] + [c2[k] - c2[k - 1] for k in range(1, 11)]
        orient = []
        for k in range(11):
            orient += [15 * k] * cnt1[k]
        orient += [165] * (split - len(orient))               # region1 bucket>=11 tail
        for k in range(11):
            orient += [15 * k] * cnt2[k]
        orient += [165] * (N - len(orient))                   # region2 bucket>=11 tail
        got = list(build_bucket_table(orient, N, split))
        ok = got == obs
        all_ok &= ok
        print(f"sec{ri}: H+0xc={h_0xc:3} secobj+0xc={secobj_0xc:3} "
              f"split-buckets<=10={c1[10]}/{split} | round-trip {'MATCH' if ok else 'FAIL'}")
        if not ok:
            print("   obs:", obs)
            print("   got:", got)
    print("ALL SECTIONS BYTE-EXACT:", all_ok)
    return all_ok


if __name__ == "__main__":
    _selftest()
