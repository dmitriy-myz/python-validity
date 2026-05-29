#!/usr/bin/env python3
"""Find the C++ vtable(s) containing a given function VMA in a PE, then read a
slot at a byte offset. Used to resolve virtual-call targets statically.

Usage:
  find_vtable.py <dll> <func_vma_hex> [slot_off_hex]
    - locates every contiguous run of .text-pointers (a vtable) that contains
      func_vma, prints the run's base, the index of func_vma, and (if
      slot_off given) the pointer at base+slot_off.
"""
import sys, struct


def parse_pe(path):
    data = open(path, 'rb').read()
    e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
    assert data[e_lfanew:e_lfanew + 4] == b'PE\x00\x00', 'not PE'
    coff = e_lfanew + 4
    nsec = struct.unpack_from('<H', data, coff + 2)[0]
    opt_sz = struct.unpack_from('<H', data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from('<H', data, opt)[0]
    assert magic == 0x20b, 'not PE32+'
    image_base = struct.unpack_from('<Q', data, opt + 0x18)[0]
    sec = opt + opt_sz
    sections = []
    for i in range(nsec):
        off = sec + i * 40
        name = data[off:off + 8].rstrip(b'\x00').decode('latin1')
        # section header: +8 VirtualSize, +12 VirtualAddress, +16 SizeOfRawData, +20 PointerToRawData
        vsize, vaddr, rawsz, rawptr = struct.unpack_from('<IIII', data, off + 8)
        sections.append((name, vaddr, vsize, rawptr, rawsz))
    return data, image_base, sections


def vma_to_off(sections, image_base, vma):
    rva = vma - image_base
    for name, vaddr, vsize, rawptr, rawsz in sections:
        if vaddr <= rva < vaddr + max(vsize, rawsz):
            if rva - vaddr < rawsz:
                return rawptr + (rva - vaddr)
    return None


def text_range(sections, image_base):
    for name, vaddr, vsize, rawptr, rawsz in sections:
        if name == '.text':
            return image_base + vaddr, image_base + vaddr + vsize
    return None, None


def main():
    dll = sys.argv[1]
    target = int(sys.argv[2], 16)
    slot = int(sys.argv[3], 16) if len(sys.argv) > 3 else None
    data, base, sections = parse_pe(dll)
    tlo, thi = text_range(sections, base)
    rd = next(s for s in sections if s[0] == '.rdata')
    _, rva, vsize, rawptr, rawsz = rd
    rd_vma0 = base + rva
    blob = data[rawptr:rawptr + rawsz]

    def is_text(p):
        return tlo <= p < thi

    # find all qword offsets equal to target
    pat = struct.pack('<Q', target)
    hits = []
    i = blob.find(pat)
    while i != -1:
        if i % 8 == 0:
            hits.append(i)
        i = blob.find(pat, i + 1)

    print(f"image_base=0x{base:x} .text=[0x{tlo:x},0x{thi:x}) "
          f".rdata@0x{rd_vma0:x} size=0x{rawsz:x}")
    print(f"target 0x{target:x}: {len(hits)} aligned slot(s) in .rdata")

    for h in hits:
        # walk back while previous qword is a .text pointer
        b = h
        while b - 8 >= 0:
            prev = struct.unpack_from('<Q', blob, b - 8)[0]
            if is_text(prev):
                b -= 8
            else:
                break
        # walk forward while .text pointer
        e = h
        while e + 8 <= len(blob):
            cur = struct.unpack_from('<Q', blob, e)[0]
            if is_text(cur):
                e += 8
            else:
                break
        base_vma = rd_vma0 + b
        nptr = (e - b) // 8
        idx = (h - b) // 8
        rtti = struct.unpack_from('<Q', blob, b - 8)[0] if b - 8 >= 0 else 0
        print(f"\n  vtable base=0x{base_vma:x}  entries={nptr}  "
              f"target_index={idx} (off 0x{idx*8:x})  preceding_word=0x{rtti:x}")
        if slot is not None and b + slot + 8 <= len(blob):
            p = struct.unpack_from('<Q', blob, b + slot)[0]
            mark = '' if is_text(p) else '  (NOT a .text ptr!)'
            print(f"  >>> vtable[0x{slot:x}] (index {slot//8}) = 0x{p:x}{mark}")
        # context: a few entries around target and around the slot
        def dump(lo, hi, label):
            print(f"    {label}:")
            for k in range(max(0, lo), min(nptr, hi)):
                p = struct.unpack_from('<Q', blob, b + k * 8)[0]
                tag = '<<TARGET' if (b + k * 8) == h else ('<<SLOT' if slot is not None and k * 8 == slot else '')
                print(f"      [0x{k*8:02x}] (idx {k:2d}) = 0x{p:x} {tag}")
        dump(idx - 2, idx + 3, "around target")
        if slot is not None:
            dump(slot // 8 - 2, slot // 8 + 3, "around slot")


if __name__ == '__main__':
    main()
