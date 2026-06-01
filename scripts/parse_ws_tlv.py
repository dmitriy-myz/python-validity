#!/usr/bin/env python3
"""Decode the pre_v30 metadata of a captured ws_body as the TLV stream it is.

Reverse-engineered TLV format (see dev/PACKER-sub_180002240.md §9):
  record = { u16 tag, u16 len, payload[len] }
Known tags (all little-endian):
  0x03  u32 scalar    0x68  u32 scalar    0x6a  u32 scalar    0x6b  u32 scalar
  0x69  container 2×u32 (e.g. w,h)        0x6c  container 4×u32 (counts)
  0x01  terminator
Each section header = [8 ascending "pose-lead" bytes][optional count byte(s)]
[TLV records that CHANGED this section][section-content marker tag, len≈0x11b8].

Usage: ./.venv-poc/bin/python dev/parse_ws_tlv.py [ws_body.bin]
"""
import sys, struct

WS = sys.argv[1] if len(sys.argv) > 1 else \
    "/media/sf_vbox-rw/finger/frida_dumps/ws_body_1780084103036_23056.bin"

TAGNAME = {0x03: "tag03_u32", 0x68: "tag68_u32", 0x6a: "tag6a_u32",
           0x6b: "tag6b_u32", 0x69: "geom_69", 0x6c: "counts_6c", 0x01: "TERM"}
SCALAR = {0x03, 0x68, 0x6a, 0x6b}


def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]


def parse_tlv(z, start):
    """Walk TLV records from `start` until a tag looks like the section marker
    (len == 0x11b8) or bytes run out / look invalid. Returns (records, end)."""
    recs = []
    o = start
    while o + 4 <= len(z):
        tag, ln = u16(z, o), u16(z, o + 2)
        if ln == 0x11b8:                      # section-content marker
            recs.append((o, tag, ln, "SECTION-CONTENT-MARKER", None))
            return recs, o
        if tag not in TAGNAME or o + 4 + ln > len(z) or ln > 0x40:
            return recs, o                     # not a known small record → stop
        pay = z[o + 4:o + 4 + ln]
        if tag in SCALAR and ln == 4:
            val = u32(pay, 0)
        elif tag == 0x69 and ln == 8:
            val = (u32(pay, 0), u32(pay, 4))
        elif tag == 0x6c:
            val = tuple(u32(pay, i) for i in range(0, ln, 4))
        else:
            val = pay.hex()
        recs.append((o, tag, ln, TAGNAME[tag], val))
        o += 4 + ln
    return recs, o


def main():
    ws = open(WS, "rb").read()
    print(f"ws_body: {WS} ({len(ws)}B)\n")
    print("== fixed header [0..44) ==")
    print(f"  [0..4)  zeros          {ws[0:4].hex()}")
    print(f"  [4..8)  size_u32       {u32(ws,4)} (0x{u32(ws,4):x})")
    print(f"  [8..16) config         {ws[8:16].hex()}")
    print(f"  [16..24) id            {ws[16:24].hex()}")
    print(f"  [24..40) psc 4×u32     {struct.unpack_from('<4I', ws, 24)}")
    print(f"  [40..44) sec5cnt+flags {list(ws[40:44])}")
    print(f"  [44..64) geometry_stats {ws[44:64].hex()}")
    # as int32 LE (5×) and int16 LE (10×) to expose structure
    print(f"           as 5×i32: {struct.unpack_from('<5i', ws, 44)}")
    print(f"           as 10×i16: {struct.unpack_from('<10h', ws, 44)}")

    # section pre_v30 zones (offsets from inspect_ws / find_v30_regions)
    pre = [("sec0_pre", 64, 309), ("sec1_pre", 4809, 4905),
           ("sec2_pre", 9405, 9445), ("sec3_pre", 13945, 13993),
           ("sec4_pre", 18493, 18533), ("tail", 23033, 23056)]
    for name, a, b in pre:
        z = ws[a:b]
        print(f"\n== {name} [{a}..{b}) ({b-a}B) ==")
        leads = z[:8]
        asc = all(leads[i] <= leads[i+1] for i in range(7))
        print(f"  pose-leads[0..8): {leads.hex()}  ascending={asc}  vals={list(leads)}")
        # the 3-ish bytes after leads, then TLV
        # find the first known tag at offsets 8..14
        recs = None
        for s in range(8, 15):
            r, end = parse_tlv(z, s)
            if r:
                recs = (s, r, end); break
        if recs:
            s, r, end = recs
            print(f"  gap[8..{s}): {z[8:s].hex()}")
            for (o, tag, ln, nm, val) in r:
                print(f"    +{o:03x} tag=0x{tag:02x} len={ln:<2} {nm:24} = {val}")
            print(f"  trailing after TLV (+{end:#x}..): {z[end:].hex()}")
        else:
            print(f"  (no TLV records parsed) bytes[8..]: {z[8:].hex()}")


if __name__ == "__main__":
    main()
