"""GDB-based dumper for the MoH WS-body bit-packing reversal.

Frida can't attach to Wine (its bootstrapper crashes with SIGSTOP), but
gdb can: a Wine process is an ordinary Linux process, so gdb attaches,
breaks at the DLL's mapped addresses, and reads process memory directly.

This dumps the same two things dev/frida_dump.py would have:

  sub_1800A4900 @ RVA 0xA4900  — WS-body copy-out.
      Win64 calling convention: a1 (session) = RCX.
      WS body = *(u8*)(RCX+152), length *(u32*)(RCX+4).
      session+152 already holds the finished WS body at function ENTRY
      (this function only copies it out), so an entry breakpoint suffices.

  sub_18000AAB0 @ RVA 0xAAB0   — per-frame orchestrator.
      a2 (minutia context) = RDX.  table = *(void**)RDX, count = *(u32*)(RDX+8),
      32-byte records.  The table is finalized at function EXIT (it gets
      sorted/partitioned during the call), so we dump on RETURN via a
      FinishBreakpoint. Fires many times; the LAST dump before the
      WS-body dump is the final table.

Usage on the Wine host:
    # 1. allow ptrace:  sudo sysctl kernel.yama.ptrace_scope=0
    # 2. start the Wine enrollment app, find the WUDFHost PID
    # 3. gdb -p <PID> -x dev/gdb_dump.py
    #    (or: gdb -p <PID>  then  (gdb) source dev/gdb_dump.py )
    # 4. run a full enrollment. Dumps land in $FRIDA_DUMP_DIR (default
    #    /tmp/frida_dumps). Ctrl-C in gdb, then 'detach' / 'quit'.

Calling convention note: Wine runs the PE code natively with the
Microsoft x64 convention, so gdb's $rcx/$rdx hold the real arg0/arg1.

If the RVAs are wrong for your build (IDA image base assumed
0x180000000), edit RVA_* below.
"""
import os
import time

import gdb  # provided by the gdb python runtime

OUTDIR = os.environ.get('FRIDA_DUMP_DIR', '/tmp/frida_dumps')
DLL = 'synaWudfBioUsb.dll'

RVA_A4900 = 0xA4900   # WS-body copy-out (session in RCX)
RVA_AAB0 = 0xAAB0     # orchestrator (minutia ctx in RDX)
RVA_A5B0 = 0xA5B0     # stage 5 — descriptor computation (opt-in)
RVA_9FD20 = 0x9FD20   # frame-processor vtable dispatcher (resolves *(RCX+104))
RVA_2240 = 0x2240     # WS-body PACKER (opt-in) — see PackerEntryBP below
RVA_46E0 = 0x46E0     # per-minutia DESCRIPTOR builder (opt-in) — see DescEntryBP

MASK = (1 << 64) - 1

# WS-body packer hook is opt-in. sub_180002240 serializes the extracted
# feature buffer into the WS body. Win64 args:
#   sub_180002240(v26 algo, v34 ws_dest, v38 stats, v30 features, w, h)
#   RCX=v26  RDX=v34(ws+152)  R8=v38(stats,64B)  R9=v30(features in)
#   [RSP+0x28]=w  [RSP+0x30]=h
# We dump (features v30) + (ws BEFORE) on entry and (ws AFTER) on return,
# per good frame. ws_after - ws_before = exactly the bytes this frame's
# features produced — i.e. known-input -> packed-output pairs that crack
# the WS bit layout (the last blocker for native enrollment).
PACKER_ON = os.environ.get('GDB_DUMP_PACKER') == '1'
PACKER_MAX = int(os.environ.get('GDB_PACKER_MAX', '12'))
PACKER_WS = int(os.environ.get('GDB_PACKER_WS', '23056'))    # WS body size
PACKER_FEAT = int(os.environ.get('GDB_PACKER_FEAT', '32768'))  # v30 (size unknown; best-effort)

# Per-minutia descriptor builder hook is opt-in. sub_1800046E0 fills the
# 180-byte working record for one minutia from the image patch. Win64 args
# (5th+ on the stack, read at entry before the callee touches rsp):
#   sub_1800046E0(out, img=RDX, algo_img=R8, &cur=R9, &v44[rsp+0x28],
#                 record=v28[rsp+0x30], h[rsp+0x38], w[rsp+0x40], …, work=4004*i, …)
# We dump the 180-B record BEFORE/AFTER (delta = the computed minutia +
# descriptor) and the input image. Pair with the packer's section dumps to
# map record -> ~47-byte section slot. Fires once per minutia per frame.
DESC_ON = os.environ.get('GDB_DUMP_DESC') == '1'
DESC_MAX = int(os.environ.get('GDB_DESC_MAX', '40'))
DESC_REC = 180                                                # the 180-byte working record
DESC_IMG = int(os.environ.get('GDB_DESC_IMG', '16384'))      # input image (best-effort)

# Stage-5 hook is opt-in (it fires ~9 tiles × N frames). Enable with:
#   GDB_DUMP_STAGE5=1   and optionally  GDB_STAGE5_MAX=<n>  GDB_STAGE5_BUF=<bytes>
STAGE5_ON = os.environ.get('GDB_DUMP_STAGE5') == '1'
STAGE5_MAX = int(os.environ.get('GDB_STAGE5_MAX', '6'))
STAGE5_BUF = int(os.environ.get('GDB_STAGE5_BUF', '8192'))


def _reg(name):
    return int(gdb.parse_and_eval('$' + name)) & MASK


def _read(addr, n):
    return bytes(gdb.selected_inferior().read_memory(addr, n))


def _read_safe(addr, n):
    """Read up to n bytes, shrinking toward a page boundary if the tail is
    unmapped (the feature buffer's real size is unknown, so we over-ask)."""
    while n > 0:
        try:
            return bytes(gdb.selected_inferior().read_memory(addr, n))
        except gdb.MemoryError:
            n -= 0x1000
    return b''


def _u32(addr):
    return int.from_bytes(_read(addr, 4), 'little')


def _u64(addr):
    return int.from_bytes(_read(addr, 8), 'little')


def _save(kind, tag, data):
    os.makedirs(OUTDIR, exist_ok=True)
    fn = os.path.join(OUTDIR, f'{kind}_{int(time.time()*1000)}_{tag}.bin')
    with open(fn, 'wb') as f:
        f.write(data)
    print(f'[+] {kind} {len(data)} bytes -> {fn}')


def find_dll_base():
    pid = gdb.selected_inferior().pid
    base = None
    with open(f'/proc/{pid}/maps') as f:
        for line in f:
            if DLL.lower() in line.lower():
                start = int(line.split('-')[0], 16)
                if base is None or start < base:
                    base = start
    return base


class WSBodyBP(gdb.Breakpoint):
    """Entry breakpoint on sub_1800A4900: dump session+152."""
    def stop(self):
        try:
            session = _reg('rcx')
            size = _u32(session + 4)
            if 0 < size <= 0x20000:
                _save('ws_body', str(size), _read(session + 152, size))
            else:
                print(f'[!] A4900 odd size={size}')
        except Exception as e:
            print(f'[!] A4900 dump failed: {e}')
        return False   # keep running


class MinutiaFinishBP(gdb.FinishBreakpoint):
    """Fires at orchestrator RETURN: dump the finalized minutia table."""
    def __init__(self, ctx):
        super().__init__(internal=True)
        self.ctx = ctx

    def stop(self):
        try:
            table = _u64(self.ctx)
            count = _u32(self.ctx + 8)
            if table and 0 < count <= 250:
                _save('minutia_table', str(count), _read(table, count * 32))
        except Exception as e:
            print(f'[!] AAB0 finish dump failed: {e}')
        return False

    def out_of_scope(self):
        pass


class MinutiaEntryBP(gdb.Breakpoint):
    """Entry breakpoint on sub_18000AAB0: capture RDX, schedule exit dump."""
    def stop(self):
        try:
            ctx = _reg('rdx')
            MinutiaFinishBP(ctx)
        except Exception as e:
            print(f'[!] AAB0 entry failed: {e}')
        return False


# ─── Stage 5 (sub_18000A5B0) — descriptor computation (opt-in) ──────────
#
# Called per tile per frame:
#   sub_18000A5B0(v85, a2, v60, v59, | v90, v88, v79, v78, v49, &v97, a7)
# Win64 args: RCX=v85, RDX=a2(minutia ctx), R8=v60, R9=v59; stack:
#   [RSP+0x28]=v90 [+0x30]=v88 [+0x38]=v79 [+0x40]=v78(start slot)
#   [+0x48]=v49(end slot) ...
# v85 is the working buffer stage 5 writes descriptors into. We snapshot
# it before (entry) and after (return) so the DELTA reveals exactly what
# bytes stage 5 produced for minutia slots [v78..v49]. Pair that with the
# minutia table dump and we have (minutia -> descriptor bytes).

_stage5_calls = 0


class Stage5FinishBP(gdb.FinishBreakpoint):
    def __init__(self, before, base, n, lo, hi, idx):
        super().__init__(internal=True)
        self.before, self.base, self.n = before, base, n
        self.lo, self.hi, self.idx = lo, hi, idx

    def stop(self):
        try:
            after = _read(self.base, self.n)
            # save before+after concatenated; tag with slot range
            tag = f'slots{self.lo}-{self.hi}_call{self.idx}'
            _save('stage5_v85before', tag, self.before)
            _save('stage5_v85after', tag, after)
            ndiff = sum(1 for a, b in zip(self.before, after) if a != b)
            print(f'    stage5 call{self.idx} slots[{self.lo}..{self.hi}]: '
                  f'{ndiff}/{self.n} bytes changed in v85')
        except Exception as e:
            print(f'[!] stage5 finish failed: {e}')
        return False

    def out_of_scope(self):
        pass


class Stage5EntryBP(gdb.Breakpoint):
    def stop(self):
        global _stage5_calls
        if _stage5_calls >= STAGE5_MAX:
            return False
        try:
            rcx = _reg('rcx')          # v85 — descriptor target buffer
            rsp = _reg('rsp')
            lo = _u32(rsp + 0x40)      # v78 start slot
            hi = _u32(rsp + 0x48)      # v49 end slot
            print(f'[*] stage5 #{_stage5_calls}: v85=0x{rcx:x} slots[{lo}..{hi}]')
            before = _read(rcx, STAGE5_BUF)
            Stage5FinishBP(before, rcx, STAGE5_BUF, lo, hi, _stage5_calls)
            _stage5_calls += 1
        except Exception as e:
            print(f'[!] stage5 entry failed: {e}')
        return False


# ─── WS-body packer (sub_180002240) — known-input → packed-output ───────
_packer_calls = 0


class PackerFinishBP(gdb.FinishBreakpoint):
    def __init__(self, ws, idx):
        super().__init__(internal=True)
        self.ws, self.idx = ws, idx

    def stop(self):
        try:
            _save('packer_ws_after', f'call{self.idx}', _read_safe(self.ws, PACKER_WS))
        except Exception as e:
            print(f'[!] packer finish failed: {e}')
        return False

    def out_of_scope(self):
        pass


class PackerEntryBP(gdb.Breakpoint):
    """sub_180002240(a1 algo, a2=ws_dest[RDX], a3 stats[R8], a4=features[R9], w, h).
    Dump features (a4) + ws BEFORE on entry, ws AFTER on return. The delta is
    exactly the bytes this frame's feature buffer produced in the WS body."""
    def stop(self):
        global _packer_calls
        if _packer_calls >= PACKER_MAX:
            return False
        try:
            ws = _reg('rdx')       # a2 — WS body dest (ws+152)
            feat = _reg('r9')      # a4 — extracted feature buffer (input)
            i = _packer_calls
            print(f'[*] packer #{i}: ws=0x{ws:x} features=0x{feat:x}')
            _save('packer_features', f'call{i}', _read_safe(feat, PACKER_FEAT))
            _save('packer_ws_before', f'call{i}', _read_safe(ws, PACKER_WS))
            PackerFinishBP(ws, i)
            _packer_calls += 1
        except Exception as e:
            print(f'[!] packer entry failed: {e}')
        return False


# ─── Per-minutia descriptor builder (sub_1800046E0) ─────────────────────
_desc_calls = 0


class DescFinishBP(gdb.FinishBreakpoint):
    def __init__(self, rec, idx):
        super().__init__(internal=True)
        self.rec, self.idx = rec, idx

    def stop(self):
        try:
            _save('desc_record_after', f'call{self.idx}', _read_safe(self.rec, DESC_REC))
        except Exception as e:
            print(f'[!] desc finish failed: {e}')
        return False

    def out_of_scope(self):
        pass


class DescEntryBP(gdb.Breakpoint):
    """sub_1800046E0 entry: a6 (the 180-B minutia record) is at [rsp+0x30];
    the input image ptr is RDX. Dump record before/after (delta = computed
    descriptor) + the image per call."""
    def stop(self):
        global _desc_calls
        if _desc_calls >= DESC_MAX:
            return False
        try:
            rsp = _reg('rsp')
            rec = _u64(rsp + 0x30)     # a6 = v28, the 180-byte working record
            img = _reg('rdx')          # a2 = image data ptr
            i = _desc_calls
            print(f'[*] desc #{i}: record=0x{rec:x} img=0x{img:x}')
            _save('desc_record_before', f'call{i}', _read_safe(rec, DESC_REC))
            _save('desc_image', f'call{i}', _read_safe(img, DESC_IMG))
            DescFinishBP(rec, i)
            _desc_calls += 1
        except Exception as e:
            print(f'[!] desc entry failed: {e}')
        return False


class VtableResolveBP(gdb.Breakpoint):
    """One-shot: at sub_18009FD20 entry, resolve the indirect frame-processor
    target at *(RCX+104) and print its address + RVA. That target (a runtime
    vtable slot, invisible to static decompilation) is the real host-side
    processor that calls the orchestrator and packs the WS body."""
    def __init__(self, spec, base):
        super().__init__(spec)
        self.base = base
        self.done = False

    def stop(self):
        if self.done:
            return False
        try:
            a1 = _reg('rcx')
            target = _u64(a1 + 104)
            rva = target - self.base
            print(f'[*] sub_18009FD20 vtable target = 0x{target:x}  (RVA 0x{rva:x})'
                  f'  -> decompile sub_18{rva:06x}')
            # also dump a few neighboring slots for context
            for off in (96, 104, 112, 120):
                t = _u64(a1 + off)
                print(f'      a1+{off}: 0x{t:x} (RVA 0x{t-self.base:x})')
            self.done = True
        except Exception as e:
            print(f'[!] vtable resolve failed: {e}')
        return False


def main():
    base = find_dll_base()
    if base is None:
        print(f'[!] {DLL} not found in /proc/<pid>/maps — is it loaded in this PID?')
        return
    print(f'[*] {DLL} base = {hex(base)}')
    WSBodyBP('*' + hex(base + RVA_A4900))
    MinutiaEntryBP('*' + hex(base + RVA_AAB0))
    VtableResolveBP('*' + hex(base + RVA_9FD20), base)
    if STAGE5_ON:
        Stage5EntryBP('*' + hex(base + RVA_A5B0))
        print(f'[*] stage-5 descriptor hook ON (max {STAGE5_MAX} calls, '
              f'{STAGE5_BUF}B buffer)')
    if PACKER_ON:
        PackerEntryBP('*' + hex(base + RVA_2240))
        print(f'[*] WS-body packer hook ON (max {PACKER_MAX} calls, '
              f'ws={PACKER_WS}B feat<={PACKER_FEAT}B)')
    if DESC_ON:
        DescEntryBP('*' + hex(base + RVA_46E0))
        print(f'[*] descriptor-builder hook ON (max {DESC_MAX} calls, '
              f'rec={DESC_REC}B img<={DESC_IMG}B)')
    print(f'[*] breakpoints armed. dumps -> {OUTDIR}/')
    print('[*] run a full enrollment now, then Ctrl-C + detach.')
    gdb.execute('continue')


main()
