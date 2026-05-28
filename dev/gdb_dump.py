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
RVA_43D0 = 0x43D0     # descriptor-BLOB filler (opt-in) — see BlobEntryBP
RVA_1A50 = 0x1A50     # feature EXTRACTOR (opt-in) — see ExtractEntryBP
RVA_CE80 = 0xCE80     # Harris RESPONSE (opt-in) — see HarrisEntryBP
RVA_FDF0 = 0xFDF0     # gradient I_x — its input is the ENHANCED image (opt-in)
RVA_F250 = 0xF250     # DoH chain wrapper — rcx=tile (Q10) at entry, pre-smoothed
                       #   in-place + DoH response builder. Hook captures the RAW
                       #   tile that becomes the descriptor gradient (opt-in).
RVA_10380 = 0x10380   # one separable filter pass (CC20 calls it 5×) (opt-in)
RVA_CF90 = 0xCF90     # NMS / keypoint extractor (opt-in) — see NmsEntryBP
RVA_D920 = 0xD920     # orientation per keypoint (opt-in) — see OrientEntryBP
RVA_E090 = 0xE090     # oriented BRIEF descriptor (opt-in) — see DescBriefEntryBP
RVA_E5D0 = 0xE5D0     # inside E090: right after `r10 = [rsp+0x58]` — see DescSamplesBP

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

# Descriptor-blob filler hook is opt-in. sub_1800043D0 fills record[26..]
# and (we believe) the per-keypoint work area that becomes the section's
# high-entropy descriptor blob. Call from sub_1800046E0:
#   sub_1800043D0(record+104, image, image2, pose, accumulator, h, w, work, a13)
# Win64: RCX=record+104  RDX=image  R8=image2  R9=pose
#        [RSP+0x28]=accumulator  [RSP+0x30]=h  [RSP+0x38]=w  [RSP+0x40]=work
# We dump record[26..] (RCX) + the work area before/after (deltas = what it
# computed) + the pose (R9) + the image once. Pair the work-area delta with
# the section descriptor blob to crack the per-keypoint feature encoding.
BLOB_ON = os.environ.get('GDB_DUMP_BLOB') == '1'
BLOB_MAX = int(os.environ.get('GDB_BLOB_MAX', '40'))
BLOB_REC = 76                                                 # record[26..44] (RCX = record+104)
BLOB_WORK = int(os.environ.get('GDB_BLOB_WORK', '4096'))     # the 4004-byte work area
BLOB_IMG = int(os.environ.get('GDB_BLOB_IMG', '16384'))      # input image (best-effort)

# Feature-extractor hook is opt-in. sub_180001A50 turns the working image
# into the feature buffer v30 that the packer copies verbatim into the WS
# section. Call (from sub_1800D89C0):
#   sub_180001A50(algo, v30_OUT, image_IN, w, h, dpi=363, …)
#   RCX=algo  RDX=v30 (output buffer, filled during the call)  R8=image
#   R9=w  [RSP+0x28]=h  [RSP+0x30]=dpi
# Dump the input image (R8, w*h) at entry and the feature buffer (RDX) at
# return — the canonical (image -> v30) pair to diff moh_opencv.py against
# (see dev/diff_v30.py).
EXTRACT_ON = os.environ.get('GDB_DUMP_EXTRACT') == '1'
EXTRACT_MAX = int(os.environ.get('GDB_EXTRACT_MAX', '8'))
EXTRACT_V30 = int(os.environ.get('GDB_EXTRACT_V30', '8192'))   # feature buffer (best-effort)

# Harris-response hook is opt-in. sub_18000CE80(ctx=RCX, _, flag=R8d) computes,
# per plane, out[i] = (Ixx[i]>>12)*(Iyy[i]>>12) - (Ixy[i]>>12)^2  (int32, Q12).
# Plane list at *(ctx+0x50), count *(ctx+0x58), stride 0x70; per plane:
#   +0=width(i32) +4=height(i32) +0x30=Ixx +0x38=Ixy +0x40=Iyy +0x50=response.
# Dump each plane's response (+ the 3 gradient buffers, plane 0) at return, to
# diff the DLL's fixed-point response map against our float Harris.
HARRIS_ON = os.environ.get('GDB_DUMP_HARRIS') == '1'
HARRIS_MAX = int(os.environ.get('GDB_HARRIS_MAX', '4'))

# Gradient-input hook is opt-in. sub_18000FDF0(a1=img, a2=dst, w=R8d, h=R9d)
# copies a1 -> a2 (w*h*4 bytes, int32 pixels) then runs the separable
# gradient passes. So RCX at entry is the ENHANCED image the detector
# actually works on (57x57 int32) — the missing piece: our operator run on
# THIS image should correlate with the DLL gradients/response, turning the
# unknown enhancement into a decodable image->image transform.
GRADIN_ON = os.environ.get('GDB_DUMP_GRADIN') == '1'
GRADIN_MAX = int(os.environ.get('GDB_GRADIN_MAX', '8'))

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


# ─── Descriptor-blob filler (sub_1800043D0) ─────────────────────────────
_blob_calls = 0


# The work-area arg's exact stack slot was ambiguous (vararg trace), so we
# scan every stack-arg slot and dump each one that holds a *readable*
# pointer. The per-keypoint descriptor source is whichever slot's region
# changes across the call — match its delta to the section blob.
BLOB_SLOTS = (0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58)


class BlobFinishBP(gdb.FinishBreakpoint):
    def __init__(self, rec, cands, idx):
        super().__init__(internal=True)
        self.rec, self.cands, self.idx = rec, cands, idx

    def stop(self):
        try:
            _save('blob_record_after', f'call{self.idx}', _read_safe(self.rec, BLOB_REC))
            for off, ptr in self.cands:
                _save(f'blob_arg{off:#x}_after', f'call{self.idx}', _read_safe(ptr, BLOB_WORK))
        except Exception as e:
            print(f'[!] blob finish failed: {e}')
        return False

    def out_of_scope(self):
        pass


class BlobEntryBP(gdb.Breakpoint):
    """sub_1800043D0 entry: RCX=record+104, RDX=image, R9=pose. The work
    area is one of the stack args — scan BLOB_SLOTS, dump every readable
    pointer's region before/after. The slot whose region changes (and whose
    delta matches the section blob) is the per-keypoint descriptor source."""
    def stop(self):
        global _blob_calls
        if _blob_calls >= BLOB_MAX:
            return False
        try:
            rec = _reg('rcx')          # record+104
            img = _reg('rdx')          # image data
            pose = _reg('r9')          # 4-dword pose struct
            rsp = _reg('rsp')
            i = _blob_calls
            cands = []
            for off in BLOB_SLOTS:
                ptr = _u64(rsp + off)
                if len(_read_safe(ptr, 64)) >= 64:   # readable -> a real pointer
                    cands.append((off, ptr))
            print(f'[*] blob #{i}: rec+104=0x{rec:x} pose=0x{pose:x} '
                  f'ptr-args=' + ' '.join(f'+{o:#x}=0x{p:x}' for o, p in cands))
            _save('blob_record_before', f'call{i}', _read_safe(rec, BLOB_REC))
            _save('blob_pose', f'call{i}', _read_safe(pose, 16))
            _save('blob_image', f'call{i}', _read_safe(img, BLOB_IMG))
            for off, ptr in cands:
                _save(f'blob_arg{off:#x}_before', f'call{i}', _read_safe(ptr, BLOB_WORK))
            BlobFinishBP(rec, cands, i)
            _blob_calls += 1
        except Exception as e:
            print(f'[!] blob entry failed: {e}')
        return False


# ─── Feature extractor (sub_180001A50) — canonical (image -> v30) pair ──
_extract_calls = 0


class ExtractFinishBP(gdb.FinishBreakpoint):
    def __init__(self, v30, idx):
        super().__init__(internal=True)
        self.v30, self.idx = v30, idx

    def stop(self):
        try:
            _save('extract_v30', f'call{self.idx}', _read_safe(self.v30, EXTRACT_V30))
        except Exception as e:
            print(f'[!] extract finish failed: {e}')
        return False

    def out_of_scope(self):
        pass


class ExtractEntryBP(gdb.Breakpoint):
    """sub_180001A50 entry: RDX=v30 out buffer, R8=image, R9=w, [rsp+0x28]=h.
    Dump the input image (w*h) now and the v30 buffer (RDX) on return."""
    def stop(self):
        global _extract_calls
        if _extract_calls >= EXTRACT_MAX:
            return False
        try:
            v30 = _reg('rdx')          # output feature buffer (filled during call)
            img = _reg('r8')           # input working image
            w = _reg('r9') & 0xffffffff
            h = _u32(_reg('rsp') + 0x28)
            i = _extract_calls
            n = w * h if 0 < w * h <= 0x40000 else EXTRACT_V30
            print(f'[*] extract #{i}: image=0x{img:x} {w}x{h} v30=0x{v30:x}')
            _save('extract_image', f'call{i}_{w}x{h}', _read_safe(img, n))
            ExtractFinishBP(v30, i)
            _extract_calls += 1
        except Exception as e:
            print(f'[!] extract entry failed: {e}')
        return False


# ─── Harris response (sub_18000CE80) — fixed-point response maps ────────
_harris_calls = 0


class HarrisFinishBP(gdb.FinishBreakpoint):
    def __init__(self, ctx, idx):
        super().__init__(internal=True)
        self.ctx, self.idx = ctx, idx

    def stop(self):
        try:
            base = _u64(self.ctx + 0x50)
            count = _u32(self.ctx + 0x58)
            if not (0 < count <= 32):
                print(f'[!] harris: implausible plane count {count}')
                return False
            for p in range(count):
                pl = base + p * 0x70
                w, h = _u32(pl), _u32(pl + 4)
                if not (0 < w <= 512 and 0 < h <= 512):
                    continue
                n = w * h * 4
                resp = _u64(pl + 0x50)
                _save('harris_resp', f'call{self.idx}_plane{p}_{w}x{h}', _read_safe(resp, n))
                if p == 0:   # also the gradient inputs for the main plane
                    for off, tag in ((0x30, 'Ixx'), (0x38, 'Ixy'), (0x40, 'Iyy')):
                        _save(f'harris_{tag}', f'call{self.idx}_plane{p}_{w}x{h}',
                              _read_safe(_u64(pl + off), n))
                print(f'    harris plane{p}: {w}x{h} resp@0x{resp:x}')
        except Exception as e:
            print(f'[!] harris finish failed: {e}')
        return False

    def out_of_scope(self):
        pass


class HarrisEntryBP(gdb.Breakpoint):
    """sub_18000CE80 entry: RCX=ctx, R8d=flag (0 = the response-writing path).
    Dump each plane's response map (+ gradients) at return."""
    def stop(self):
        global _harris_calls
        if _harris_calls >= HARRIS_MAX:
            return False
        try:
            if _reg('r8') & 0xffffffff:   # nonzero flag = different path, skip
                return False
            ctx = _reg('rcx')
            print(f'[*] harris #{_harris_calls}: ctx=0x{ctx:x} '
                  f'planes={_u32(ctx + 0x58)}')
            HarrisFinishBP(ctx, _harris_calls)
            _harris_calls += 1
        except Exception as e:
            print(f'[!] harris entry failed: {e}')
        return False


# ─── Separable filter pass (sub_180010380) — CC20's per-pass intermediates ─
# sub_180010380(dst=RCX, src=RDX, type_x=R8d, type_y=R9d, scale, w, h, image).
# CC20 calls it 5× per block to build Ixx/Iyy/Ixy. Dumping dst before+after each
# call gives (input → output) per pass to find the first divergence from the
# Python port (dev/port_gradient.py cc20()). The actual filtered buffer is
# `src` if src!=0 (FDF0 copies dst→src then filters src), else `dst` in-place.
G380_ON = os.environ.get('GDB_DUMP_G380') == '1'
G380_MAX = int(os.environ.get('GDB_G380_MAX', '12'))
_g380_calls = 0


class G380FinishBP(gdb.FinishBreakpoint):
    def __init__(self, out, n, idx, tx, ty):
        super().__init__(internal=True)
        self.out, self.n, self.idx, self.tx, self.ty = out, n, idx, tx, ty

    def stop(self):
        try:
            _save('g380_after', f'call{self.idx}_t{self.tx}{self.ty}',
                  _read_safe(self.out, self.n))
        except Exception as e:
            print(f'[!] g380 finish failed: {e}')
        return False

    def out_of_scope(self):
        pass


class G380EntryBP(gdb.Breakpoint):
    def stop(self):
        global _g380_calls
        if _g380_calls >= G380_MAX:
            return False
        try:
            dst = _reg('rcx'); src = _reg('rdx')
            tx = _reg('r8') & 0xffffffff; ty = _reg('r9') & 0xffffffff
            rsp = _reg('rsp')
            w = _u32(rsp + 0x30); h = _u32(rsp + 0x38)   # args 6,7 (after retaddr)
            out = src if src else dst                     # filtered buffer
            if not (0 < w <= 512 and 0 < h <= 512):
                return False
            n = w * h * 4
            i = _g380_calls
            _save('g380_before', f'call{i}_t{tx}{ty}_{w}x{h}', _read_safe(out, n))
            print(f'[*] g380 #{i}: dst=0x{dst:x} src=0x{src:x} type=({tx},{ty}) {w}x{h}')
            G380FinishBP(out, n, i, tx, ty)
            _g380_calls += 1
        except Exception as e:
            print(f'[!] g380 entry failed: {e}')
        return False


# ─── NMS / keypoint extractor (sub_18000CF90) ───────────────────────────
# sub_18000CF90(out_kp=RCX, ctx=RDX, capacity=R8d, …) -> count (EAX). Reads the
# response plane at *(ctx+0x50)+0x50 and thresholds ctx+0x20/+0x24/+0x48, runs
# 8-neighbour NMS + distance-dedup, writes `count` 32-byte keypoint records to
# out_kp. We dump: the response plane + the 3 thresholds (at entry) and the
# keypoint records (at return) — to validate moh_native's NMS port per tile.
NMS_ON = os.environ.get('GDB_DUMP_NMS') == '1'
NMS_MAX = int(os.environ.get('GDB_NMS_MAX', '12'))
_nms_calls = 0


class NmsFinishBP(gdb.FinishBreakpoint):
    def __init__(self, out, idx):
        super().__init__(internal=True)
        self.out, self.idx = out, idx

    def stop(self):
        try:
            count = _reg('rax') & 0xffffffff
            if count > 4096:
                count = 0
            _save('nms_kp', f'call{self.idx}_n{count}', _read_safe(self.out, count * 0x20))
            print(f'    nms #{self.idx}: {count} keypoints')
        except Exception as e:
            print(f'[!] nms finish failed: {e}')
        return False

    def out_of_scope(self):
        pass


class NmsEntryBP(gdb.Breakpoint):
    def stop(self):
        global _nms_calls
        if _nms_calls >= NMS_MAX:
            return False
        try:
            out = _reg('rcx'); ctx = _reg('rdx')
            t20 = _u32(ctx + 0x20); t24 = _u32(ctx + 0x24); t48 = _u32(ctx + 0x48)
            base = _u64(ctx + 0x50)                      # plane list
            pl = base                                    # plane 0
            w, h = _u32(pl), _u32(pl + 4)
            i = _nms_calls
            if 0 < w <= 512 and 0 < h <= 512:
                resp = _u64(pl + 0x50)
                _save('nms_resp', f'call{i}_{w}x{h}', _read_safe(resp, w * h * 4))
            # thresholds as a tiny 3×i32 blob
            import struct
            _save('nms_thr', f'call{i}', struct.pack('<3i', _s32(t20), _s32(t24), _s32(t48)))
            print(f'[*] nms #{i}: ctx=0x{ctx:x} thr=({_s32(t20)},{_s32(t24)},{_s32(t48)}) {w}x{h}')
            NmsFinishBP(out, i)
            _nms_calls += 1
        except Exception as e:
            print(f'[!] nms entry failed: {e}')
        return False


def _s32(v):
    return v - (1 << 32) if v & 0x80000000 else v


# ─── Orientation per keypoint (sub_18000D920) ────────────────────────────
# D920(rcx=kp_ptr, rdx=ctx, r8=buf) — writes orientation/quality into the 32-byte
# keypoint record (field +0xc and others). Dumping the record before+after each
# call reveals exactly which fields it sets, for porting + byte-validating.
ORIENT_ON = os.environ.get('GDB_DUMP_ORIENT') == '1'
ORIENT_MAX = int(os.environ.get('GDB_ORIENT_MAX', '1024'))
_orient_calls = 0


class OrientFinishBP(gdb.FinishBreakpoint):
    def __init__(self, kp, idx):
        super().__init__(internal=True)
        self.kp, self.idx = kp, idx

    def stop(self):
        try:
            _save('orient_after', f'kp{self.idx:04d}', _read_safe(self.kp, 32))
        except Exception as e:
            print(f'[!] orient finish failed: {e}')
        return False

    def out_of_scope(self):
        pass


class OrientEntryBP(gdb.Breakpoint):
    def stop(self):
        global _orient_calls
        if _orient_calls >= ORIENT_MAX:
            return False
        try:
            kp = _reg('rcx'); ctx = _reg('rdx'); arg3 = _reg('r8')
            i = _orient_calls
            _save('orient_before', f'kp{i:04d}', _read_safe(kp, 32))
            # also dump the ctx struct (r13/rdx) and arg3 buffers, once per ctx.
            # D920 reads ctx[+0x48] (u32) and ctx[+0x50] (pointer to gradient buf);
            # 0x80 bytes covers the plane-struct layout (same shape as CC20's).
            if ctx not in _orient_ctx_seen:
                _orient_ctx_seen.add(ctx)
                _save('orient_ctx', f'ctx{len(_orient_ctx_seen)-1:03d}', _read_safe(ctx, 0x80))
                # follow ctx+0x50 to dump the gradient buffer pointed to (size from
                # ctx+0..4 = w,h if it's a plane struct; clamp to <=64KB to be safe)
                try:
                    buf_ptr = _u64(ctx + 0x50)
                    w = _u32(ctx); h = _u32(ctx + 4)
                    if 0 < w <= 512 and 0 < h <= 512 and buf_ptr:
                        n = min(w * h * 4, 0x10000)
                        _save('orient_buf50', f'ctx{len(_orient_ctx_seen)-1:03d}_{w}x{h}',
                              _read_safe(buf_ptr, n))
                except Exception:
                    pass
            OrientFinishBP(kp, i)
            _orient_calls += 1
        except Exception as e:
            print(f'[!] orient entry failed: {e}')
        return False


_orient_ctx_seen = set()


# ─── Oriented BRIEF descriptor (sub_18000E090) ───────────────────────────
# E090(rcx=kp_ptr, rdx=ctx, r8=?, r9=desc_out_ptr). Reads kp[+0xc]=orient_q16,
# kp[+0x14]=x_q16, kp[+0x18]=y_q16; writes a 16-byte (128-bit) descriptor at r9.
# Dumps kp (with orientation pre-filled) and the 16B descriptor after the call.
DESC_BRIEF_ON = os.environ.get('GDB_DUMP_DESC_BRIEF') == '1'
DESC_BRIEF_MAX = int(os.environ.get('GDB_DESC_BRIEF_MAX', '1024'))
_db_calls = 0


class DescBriefFinishBP(gdb.FinishBreakpoint):
    def __init__(self, kp, idx):
        super().__init__(internal=True)
        self.kp, self.idx = kp, idx

    def stop(self):
        try:
            # the descriptor buffer pointer is *(u64*)kp_ptr (per e665: `mov r8,[rbx]`
            # then `[r9+r8] |= bit`); dereference to capture the 16B descriptor.
            kp_after = _read_safe(self.kp, 64)    # also widen to 64B in case the
            _save('descbrief_kp_after', f'kp{self.idx:04d}', kp_after)
            if len(kp_after) >= 8:
                desc_ptr = int.from_bytes(kp_after[:8], 'little')
                _save('descbrief_desc', f'kp{self.idx:04d}', _read_safe(desc_ptr, 16))
        except Exception as e:
            print(f'[!] descbrief finish failed: {e}')
        return False

    def out_of_scope(self):
        pass


class DescBriefEntryBP(gdb.Breakpoint):
    def stop(self):
        global _db_calls, _db_last_grad_sig, _db_tile_seq
        if _db_calls >= DESC_BRIEF_MAX:
            return False
        try:
            kp = _reg('rcx'); ctx = _reg('rdx'); r8 = _reg('r8')
            i = _db_calls
            _save('descbrief_kp_before', f'kp{i:04d}', _read_safe(kp, 64))
            if ctx not in _db_ctx_seen:
                _db_ctx_seen.add(ctx)
                _save('descbrief_ctx', f'ctx{len(_db_ctx_seen)-1:03d}', _read_safe(ctx, 0x80))
                # also dump the BRIEF index-pair table at ctx[+0x70] (each entry
                # is 2 i32 indices into the pre-sampled buffer; inner loop count
                # is ctx[+0x2c], but an outer loop runs multiple times to fill
                # 128 bits — be generous with the size)
                try:
                    tbl_ptr = _u64(ctx + 0x70)
                    if tbl_ptr:
                        _save('descbrief_brieftbl', f'ctx{len(_db_ctx_seen)-1:03d}',
                              _read_safe(tbl_ptr, 16 * 1024))
                except Exception:
                    pass
            # E090's r8 is a scratch-pool descriptor (6 qwords: count, arena_ptr,
            # arena_end, flags, 0, 0) — sub_180003320 carves rotated_gx/gy slices
            # out of it. NOT the gradient buffer.
            # The actual gradient lives at *(ctx[+0x50]): a struct {i32 stride@+0,
            # i32 height@+4, qword gradX_ptr@+0x20, qword gradY_ptr@+0x28}. The
            # sampling loop reads gradX[y*stride+x] / gradY[y*stride+x] per pixel.
            # The aggregation table at *(ctx[+0x60]) holds 29 × 12 bytes
            # (3 i32 per entry: window_size_idx, dy_offset, dx_offset).
            if r8 and r8 not in _db_grad_seen:
                _db_grad_seen.add(r8)
                # Keep a smaller r8 dump (scratch arena descriptor + adjacent state).
                _save('descbrief_scratch', f'grad{len(_db_grad_seen)-1:03d}',
                      _read_safe(r8, 4 * 1024))
            # Dedupe by gradient CONTENT (first 32 bytes hash) — the ctx ADDRESS
            # is reused across tiles, but the gradient buffer the struct points
            # to gets overwritten per tile.  Capture whenever the content
            # changes; tag the file with the kp index where the change was
            # first observed, so the validation harness can map each kp to
            # the right gradient via `kp_idx >= grad_kp_tag`.
            try:
                gs_ptr = _u64(ctx + 0x50)
                if gs_ptr:
                    gs = _read_safe(gs_ptr, 0x100)     # extended: CC20 reads at +0x5c/+0x60
                    if len(gs) >= 0x30:
                        stride = int.from_bytes(gs[0:4], 'little', signed=True)
                        height = int.from_bytes(gs[4:8], 'little', signed=True)
                        gx_ptr = int.from_bytes(gs[0x20:0x28], 'little')
                        gy_ptr = int.from_bytes(gs[0x28:0x30], 'little')
                        # Also try the "+0x48" buffer that CC20 reads (likely
                        # the pre-smoothed image — same pre-pass input that
                        # the descriptor gradients are derived from).
                        in_ptr = int.from_bytes(gs[0x48:0x50], 'little') if len(gs) >= 0x50 else 0
                        n = max(0, stride) * max(0, height) * 4
                        # Signature = (height, stride, full gradX content hash).
                        # The leading bytes alone don't catch every transition
                        # (top-edge pixels can be near-constant); hash the
                        # whole buffer for an unambiguous change signal.
                        sig = b''
                        if 0 < n <= 256 * 256 * 4 and gx_ptr:
                            import hashlib
                            raw = _read_safe(gx_ptr, n)
                            sig = (f'{stride}x{height}|'.encode()
                                   + hashlib.sha1(raw).digest())
                        if sig and sig != _db_last_grad_sig:
                            _db_last_grad_sig = sig
                            tile_seq = _db_tile_seq
                            _db_tile_seq += 1
                            tag = f't{tile_seq:02d}_kp{i:04d}'
                            _save('descbrief_gradstruct', tag, gs)
                            if 0 < n <= 256 * 256 * 4 and gx_ptr:
                                _save('descbrief_gradX', f'{tag}_{stride}x{height}',
                                      _read_safe(gx_ptr, n))
                            if 0 < n <= 256 * 256 * 4 and gy_ptr:
                                _save('descbrief_gradY', f'{tag}_{stride}x{height}',
                                      _read_safe(gy_ptr, n))
                            if 0 < n <= 256 * 256 * 4 and in_ptr:
                                _save('descbrief_gradIn', f'{tag}_{stride}x{height}',
                                      _read_safe(in_ptr, n))
                # Aggregation table: capture once per unique ctx (the table
                # itself is rebuilt by E6B0 — see sub_18000A5B0 — but identical
                # contents across tiles, so address-dedupe is fine here).
                if ctx not in _db_gradstruct_seen:
                    _db_gradstruct_seen.add(ctx)
                    aggr_ptr = _u64(ctx + 0x60)
                    if aggr_ptr:
                        _save('descbrief_aggrtbl',
                              f'ctx{len(_db_gradstruct_seen)-1:03d}',
                              _read_safe(aggr_ptr, 1024))
            except Exception as e:
                print(f'[!] grad/aggr dump failed: {e}')
            DescBriefFinishBP(kp, i)
            _db_calls += 1
        except Exception as e:
            print(f'[!] descbrief entry failed: {e}')
        return False


_db_ctx_seen = set()
_db_grad_seen = set()
_db_gradstruct_seen = set()
_db_last_grad_sig = b''
_db_tile_seq = 0


# ─── BRIEF pre-sampled values buffer (inside E090 at 0x18000E5D0) ────────
# Right after `mov r10, QWORD PTR [rsp+0x58]` (e5cb), r10 holds the per-keypoint
# pre-sampled gradient values buffer that the BRIEF compare loop reads. Dump
# its contents (generous 16KB; _read_safe shrinks if unmapped) so we have the
# DLL's exact comparison inputs.
DESC_SAMPLES_ON = os.environ.get('GDB_DUMP_DESC_SAMPLES') == '1'
DESC_SAMPLES_MAX = int(os.environ.get('GDB_DESC_SAMPLES_MAX', '1024'))
_ds_calls = 0


class DescSamplesBP(gdb.Breakpoint):
    def stop(self):
        global _ds_calls
        if _ds_calls >= DESC_SAMPLES_MAX:
            return False
        try:
            buf = _reg('r10')
            i = _ds_calls
            _save('descbrief_samples', f'kp{i:04d}', _read_safe(buf, 16 * 1024))
            _ds_calls += 1
        except Exception as e:
            print(f'[!] desc samples failed: {e}')
        return False


# ─── Gradient input (sub_18000FDF0) — the enhanced image ────────────────
_gradin_calls = 0


F250_ON = os.environ.get('GDB_DUMP_F250') == '1'
F250_MAX = int(os.environ.get('GDB_F250_MAX', '64'))
_f250_calls = 0


class F250EntryBP(gdb.Breakpoint):
    """sub_18000F250 entry: RCX=image (Q10 i32 in-place), RDX=w, R8d=h, R9=ctx.
    Captures the RAW tile that becomes ctx[+0x50]+0x48 (= gradX_ptr) after
    F250's in-place Gaussian smooth. Pair with descbrief_gradIn to derive the
    pre-smoothing kernel byte-exact."""
    def stop(self):
        global _f250_calls
        if _f250_calls >= F250_MAX:
            return False
        try:
            img = _reg('rcx')
            w = _reg('rdx') & 0xffffffff
            h = _reg('r8') & 0xffffffff
            i = _f250_calls
            if 0 < w <= 512 and 0 < h <= 512:
                _save('f250_raw_tile', f'call{i:03d}_{w}x{h}',
                      _read_safe(img, w * h * 4))
            _f250_calls += 1
        except Exception as e:
            print(f'[!] F250 entry failed: {e}')
        return False


class GradinEntryBP(gdb.Breakpoint):
    """sub_18000FDF0 entry: RCX=input image, R8d=w, R9d=h (int32 pixels).
    Dump the enhanced image the detector actually runs on."""
    def stop(self):
        global _gradin_calls
        if _gradin_calls >= GRADIN_MAX:
            return False
        try:
            img = _reg('rcx')
            w = _reg('r8') & 0xffffffff
            h = _reg('r9') & 0xffffffff
            i = _gradin_calls
            if not (0 < w <= 512 and 0 < h <= 512):
                print(f'[!] gradin #{i}: implausible {w}x{h}, skipping')
                return False
            print(f'[*] gradin #{i}: img=0x{img:x} {w}x{h} (int32)')
            _save('gradin_image', f'call{i}_{w}x{h}', _read_safe(img, w * h * 4))
            _gradin_calls += 1
        except Exception as e:
            print(f'[!] gradin entry failed: {e}')
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
    if BLOB_ON:
        BlobEntryBP('*' + hex(base + RVA_43D0))
        print(f'[*] descriptor-blob hook ON (max {BLOB_MAX} calls, '
              f'rec={BLOB_REC}B work<={BLOB_WORK}B img<={BLOB_IMG}B)')
    if EXTRACT_ON:
        ExtractEntryBP('*' + hex(base + RVA_1A50))
        print(f'[*] feature-extractor hook ON (max {EXTRACT_MAX} calls, '
              f'v30<={EXTRACT_V30}B)')
    if HARRIS_ON:
        HarrisEntryBP('*' + hex(base + RVA_CE80))
        print(f'[*] Harris-response hook ON (max {HARRIS_MAX} calls)')
    if GRADIN_ON:
        GradinEntryBP('*' + hex(base + RVA_FDF0))
        print(f'[*] gradient-input hook ON (max {GRADIN_MAX} calls)')
    if F250_ON:
        F250EntryBP('*' + hex(base + RVA_F250))
        print(f'[*] F250 raw-tile hook ON (max {F250_MAX} calls)')
    if G380_ON:
        G380EntryBP('*' + hex(base + RVA_10380))
        print(f'[*] sub_180010380 per-pass hook ON (max {G380_MAX} calls)')
    if NMS_ON:
        NmsEntryBP('*' + hex(base + RVA_CF90))
        print(f'[*] NMS/keypoint hook ON (max {NMS_MAX} calls)')
    if ORIENT_ON:
        OrientEntryBP('*' + hex(base + RVA_D920))
        print(f'[*] orientation hook ON (max {ORIENT_MAX} calls)')
    if DESC_BRIEF_ON:
        DescBriefEntryBP('*' + hex(base + RVA_E090))
        print(f'[*] BRIEF descriptor hook ON (max {DESC_BRIEF_MAX} calls)')
    if DESC_SAMPLES_ON:
        DescSamplesBP('*' + hex(base + RVA_E5D0))
        print(f'[*] BRIEF samples hook ON at E5D0 (max {DESC_SAMPLES_MAX} calls)')
    print(f'[*] breakpoints armed. dumps -> {OUTDIR}/')
    print('[*] run a full enrollment now, then Ctrl-C + detach.')
    gdb.execute('continue')


main()
