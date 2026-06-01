#!/usr/bin/env python3
"""Byte-exact sec0_pre serializer + parser (inverse of sub_1800051f0).

GROUND TRUTH (decoded 2026-05-31, dev/transformation-doc/SEC0PRE-format.md):
the DLL builds sec0_pre via sub_1800051f0 as a framed byte stream:

    [u16 type=2][u16 size]           # stream header (sub_1800069e0); size patched at end
    leads:  N  bytes                 # obj+0  — reverse-index [N-1..0] (sub_18000bd10 + cmp b1f0)
    blob:   N  u32 (LE)              # obj+8  — per-section quality (q<<24); leads IGNORES it
    N:      1 byte                   # obj[0x10] = matrix dimension (= #sections)
    flag:   1 byte                   # obj[0x11] (observed = 1)
    matrix: upper-triangle table[i][j] for j>i, each 18 bytes:
              [x:u8][y:u8][a:i32][b:i32][tx:i32][ty:i32]   (Q16; R=[[a,-b],[b,a]], t=(tx,ty))
    <zero pad to `size` bytes counted from AFTER the 4-byte header>

`size` is the reservation formula (NOT the content length):
    size = (((N//2)*5)*4 + 4) * N + ((N+3) & ~3) + 0x24

Verified byte-exact against the stored template in 1780253459.log (5 sections):
leads=[4,3,2,1,0], blob=[0x54,0x5c,0x5c,0x5a,0x57]<<24, N=5, flag=1, 10 transforms,
framed region template[24:292] == round-trip output.  See __main__.
"""
import struct
import math

ONE = 0x10000
TYPE = 2


def sec0pre_size(n: int) -> int:
    """The DLL's reservation/size-field formula for N sections (sub_1800051f0)."""
    return (((n // 2) * 5) * 4 + 4) * n + ((n + 3) & ~3) + 0x24


def leads_for(n: int) -> bytes:
    """Reverse-index permutation [N-1, N-2, ..., 0]  (sub_18000bd10, cmp sub_18000b1f0:
    all sort keys are 0 → descending-by-index tie-break → reverse order)."""
    return bytes(range(n - 1, -1, -1))


def serialize_sec0pre(n, transforms, blob_quality, flag=1):
    """Build the framed sec0_pre byte stream.

    transforms: dict {(i,j): (x, y, a, b, tx, ty)} for all i<j (upper triangle).
                a,b,tx,ty are Q16 ints; x,y are the anchor bytes.
    blob_quality: list of N ints — the raw u32 stored in `blob` (already q<<24).
    Returns the framed region (header + payload + zero pad), == template[24:292].
    """
    assert len(blob_quality) == n
    leads = leads_for(n)
    blob = b''.join(struct.pack('<I', q) for q in blob_quality)
    matrix = bytearray()
    for i in range(n):
        for j in range(i + 1, n):
            x, y, a, b, tx, ty = transforms[(i, j)]
            matrix += bytes([x & 0xff, y & 0xff]) + struct.pack('<4i', a, b, tx, ty)
    payload = leads + blob + bytes([n, flag]) + bytes(matrix)
    size = sec0pre_size(n)
    if len(payload) > size:
        raise ValueError(f'payload {len(payload)} > reserved size {size}')
    payload = payload.ljust(size, b'\x00')   # zero-pad to the reserved size
    return struct.pack('<HH', TYPE, size) + payload


def parse_sec0pre(buf, off=0):
    """Inverse: parse a framed sec0_pre region. Returns dict with all fields."""
    typ, size = struct.unpack_from('<HH', buf, off)
    assert typ == TYPE, f'bad type {typ}'
    p = off + 4
    # We need N to know leads/blob lengths; but N is AFTER leads+blob. The DLL knows
    # N from the call arg. Recover it from `size`: invert the formula by search.
    n = None
    for cand in range(1, 33):
        if sec0pre_size(cand) == size:
            n = cand
            break
    if n is None:
        raise ValueError(f'no N with sec0pre_size(N)=={size}')
    leads = list(buf[p:p + n]); p += n
    blob = list(struct.unpack_from(f'<{n}I', buf, p)); p += 4 * n
    n_field = buf[p]; flag = buf[p + 1]; p += 2
    assert n_field == n, f'N field {n_field} != formula N {n}'
    transforms = {}
    for i in range(n):
        for j in range(i + 1, n):
            x, y = buf[p], buf[p + 1]
            a, b, tx, ty = struct.unpack_from('<4i', buf, p + 2)
            transforms[(i, j)] = (x, y, a, b, tx, ty)
            p += 18
    return dict(n=n, size=size, leads=leads, blob=blob, flag=flag,
                transforms=transforms, framed_end=off + 4 + size)


def _decode_xform(rec):
    x, y, a, b, tx, ty = rec
    return dict(anchor=(x, y), rot_deg=math.degrees(math.atan2(b, a)),
                scale=math.hypot(a, b) / ONE, t=(tx / ONE, ty / ONE))


if __name__ == '__main__':
    # Round-trip proof against the stored template.
    LOG = '/media/sf_vbox-rw/finger/1780253459.log'

    def get_template(log):
        with open(log, 'rb') as fh:
            for line in fh:
                if not line.startswith(b'To be encrypted: 47'):
                    continue
                wire = bytes.fromhex(line.removeprefix(b'To be encrypted: ').strip().decode())
                opc, par, typ, sto, length = struct.unpack('<BHHHH', wire[:9])
                if opc == 0x47 and typ == 6 and length == 23136:
                    return wire[9:9 + length]
    t = get_template(LOG)
    OFF = 24  # framed sec0_pre starts at template offset 24 (after subtype+outer hdr)
    parsed = parse_sec0pre(t, OFF)
    print(f'parsed: N={parsed["n"]} size={parsed["size"]} flag={parsed["flag"]}')
    print(f'  leads={parsed["leads"]}  blob={[hex(v) for v in parsed["blob"]]}')
    print(f'  framed region template[{OFF}:{parsed["framed_end"]}] ({parsed["framed_end"]-OFF}B)')
    for (i, j), rec in parsed['transforms'].items():
        d = _decode_xform(rec)
        print(f'  ({i},{j}) anchor={d["anchor"]} rot={d["rot_deg"]:+6.2f} '
              f'scale={d["scale"]:.4f} t=({d["t"][0]:+7.2f},{d["t"][1]:+7.2f})')

    # re-serialize and compare byte-exact
    out = serialize_sec0pre(parsed['n'], parsed['transforms'], parsed['blob'], parsed['flag'])
    stored = t[OFF:OFF + len(out)]
    match = (out == stored)
    print(f'\nROUND-TRIP byte-exact: {match}  (len {len(out)})')
    if not match:
        for k in range(len(out)):
            if out[k] != stored[k]:
                print(f'  first diff at +{k}: out={out[k]:02x} stored={stored[k]:02x}')
                print(f'  out[{k-2}:{k+6}]={out[k-2:k+6].hex()} stored=...{stored[k-2:k+6].hex()}')
                break
    assert match, 'round-trip MISMATCH'
    print('OK — serializer reproduces the stored sec0_pre byte-for-byte.')
