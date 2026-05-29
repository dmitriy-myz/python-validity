#!/usr/bin/env python3
"""Split the objdump .text into per-function disassembly files.

Boundaries are detected via int3 (0xcc) padding runs: a function ends at the
last real instruction before a run of >=1 int3 that pads up to the next
16-byte-aligned address where a new instruction begins.

Usage:
  extract_funcs.py index            -> print addr,start_line,end_line,nbytes,ninstr for every func
  extract_funcs.py dump <addr>...   -> write /tmp/func_<addr>.S for each addr (hex, no 0x)
"""
import sys, re

SRC = "/tmp/syna_all.S"
LINE_RE = re.compile(r"^\s+([0-9a-f]+):\t([0-9a-f ]+?)\t\s*(.*)$")


def parse():
    """Return list of (lineno, addr, bytes_hex, mnemonic) for instruction lines."""
    rows = []
    with open(SRC) as f:
        for i, line in enumerate(f, 1):
            m = LINE_RE.match(line.rstrip("\n"))
            if not m:
                continue
            addr = int(m.group(1), 16)
            raw = m.group(2).strip()
            mnem = m.group(3).strip()
            rows.append((i, addr, raw, mnem))
    return rows


def is_int3(raw, mnem):
    return raw == "cc" and mnem.startswith("int3")


def build_funcs(rows):
    """Group instruction rows into functions split on int3-padding runs."""
    funcs = []  # (start_addr, start_line, end_line, end_addr, ninstr)
    cur = None  # dict with start_line, start_addr, last_real_line, last_real_addr, ninstr
    i = 0
    n = len(rows)
    while i < n:
        lineno, addr, raw, mnem = rows[i]
        if is_int3(raw, mnem):
            # close current function at the last real instruction seen
            if cur is not None:
                funcs.append((cur["start_addr"], cur["start_line"],
                              cur["last_real_line"], cur["last_real_addr"],
                              cur["ninstr"]))
                cur = None
            i += 1
            continue
        # real instruction
        if cur is None:
            cur = dict(start_addr=addr, start_line=lineno,
                       last_real_line=lineno, last_real_addr=addr, ninstr=0)
        cur["last_real_line"] = lineno
        cur["last_real_addr"] = addr
        cur["ninstr"] += 1
        i += 1
    if cur is not None:
        funcs.append((cur["start_addr"], cur["start_line"],
                      cur["last_real_line"], cur["last_real_addr"], cur["ninstr"]))
    return funcs


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    rows = parse()
    funcs = build_funcs(rows)
    by_addr = {f[0]: f for f in funcs}

    if sys.argv[1] == "index":
        print("addr,start_line,end_line,nbytes_approx,ninstr")
        for sa, sl, el, ea, ni in funcs:
            print(f"{sa:09x},{sl},{el},{ea-sa},{ni}")
        return

    if sys.argv[1] == "dump":
        # need full source lines to slice
        with open(SRC) as f:
            all_lines = f.readlines()
        for a in sys.argv[2:]:
            addr = int(a, 16)
            if addr not in by_addr:
                # find nearest function containing addr
                cand = [f for f in funcs if f[0] <= addr <= f[3]]
                if not cand:
                    print(f"!! {a}: not found", file=sys.stderr)
                    continue
                f = cand[0]
            else:
                f = by_addr[addr]
            sa, sl, el, ea, ni = f
            out = f"/tmp/func_{sa:09x}.S"
            with open(out, "w") as w:
                w.write(f"; func {sa:09x}-{ea:09x}  ({ea-sa} bytes, {ni} instrs)\n")
                w.writelines(all_lines[sl-1:el])
            print(f"{out}  ({sa:09x}-{ea:09x}, {ea-sa} bytes, {ni} instrs)")
        return

    print("unknown cmd", file=sys.stderr)


if __name__ == "__main__":
    main()
