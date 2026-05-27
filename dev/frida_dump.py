"""Frida host: dump the in-memory minutia table and the finished WS body
from a live Wine enrollment, so we can reverse the bit-packed WS-body
encoding with KNOWN inputs.

Why this works where black-box analysis failed: the WS-body feature
sections are bit-packed (entropy ~7.86 bits/byte, no byte-aligned
coordinate fields findable at any stride — see dev/dissect_ws.py and
dev/MOH.md). You cannot reverse a bit-packing from the output alone.
But we already decoded the in-memory 32-byte minutia record layout
(flag9=tile, score_c@+0x0c, score_10@+0x10, x@+0x14, y@+0x18). If we
capture BOTH the structured in-memory table AND the bit-packed WS body
from the same enrollment, the packing falls out: we know exactly which
(x, y, score, tile) values went in, so we can see how they map to the
output bits.

Two hooks (offsets are RVAs; IDA image base assumed 0x180000000):

  sub_1800A4900  @ RVA 0xA4900  — WS-body copy-out.
      a1 = session pointer.  WS body = *(u8*)(a1+152), length *(u32*)(a1+4).
      Dumped at function exit (the body is fully assembled by then).

  sub_18000AAB0  @ RVA 0xAAB0   — the per-frame orchestrator.
      a2 = minutia context.  table = *(void**)a2, count = *(u32*)(a2+8),
      each record is 32 bytes.  Dumped at exit (table is sorted/finalized).
      Fires many times; the LAST dump before the WS-body dump is the
      one that corresponds to the final template.

Prereqs on the Wine host:
    pip install frida   (matching the frida-tools version; or frida-tools)

Usage:
    # 1. Start the Synaptics enrollment under Wine (don't touch sensor yet).
    # 2. Find the PID that loaded synaWudfBioUsb.dll:
    #      ps aux | grep -iE 'WUDF|wineserver'
    # 3. Attach:
    #      python dev/frida_dump.py <pid|process-name>
    # 4. Run a full enrollment. Dumps land in /tmp/frida_dumps/.
    # 5. Ctrl-D / Ctrl-C to detach.

Then correlate: take the newest minutia_table_*.bin (the final table) and
the ws_body_*.bin from the same run, and look at how each known record's
fields appear in the packed body. See the analysis sketch at the bottom.
"""
import os
import sys
import time

OUTDIR = os.environ.get('FRIDA_DUMP_DIR', '/tmp/frida_dumps')
DLL = 'synaWudfBioUsb.dll'

# RVAs relative to the IDA image base 0x180000000. If your build's base
# differs, adjust here. Module.findBaseAddress() resolves the real runtime
# base (handles ASLR), so only the *offsets* matter.
JS = r"""
const DLL = 'synaWudfBioUsb.dll';
const RVA = {
    A4900: 0xA4900,   // WS-body copy-out (session in a1)
    AAB0:  0xAAB0,    // orchestrator (minutia ctx in a2)
    ED60:  0x1ED60,   // EnrollmentGetTemplate (marks "template requested")
};

const base = Module.findBaseAddress(DLL);
if (base === null) {
    send({type: 'error', msg: DLL + ' not loaded in this process'});
} else {
    send({type: 'info', msg: 'base = ' + base});

    // --- WS body (the bit-packed output we want to reverse) ---
    try {
        Interceptor.attach(base.add(RVA.A4900), {
            onEnter(args) { this.session = args[0]; },
            onLeave(retval) {
                try {
                    const sess = this.session;
                    const size = sess.add(4).readU32();
                    if (size > 0 && size <= 0x20000) {
                        const ws = sess.add(152).readByteArray(size);
                        send({type: 'ws_body', size: size}, ws);
                    } else {
                        send({type: 'info', msg: 'A4900 odd size=' + size});
                    }
                } catch (e) { send({type: 'error', msg: 'A4900 leave: ' + e}); }
            }
        });
        send({type: 'info', msg: 'hooked sub_1800A4900 (WS body)'});
    } catch (e) { send({type: 'error', msg: 'hook A4900: ' + e}); }

    // --- In-memory minutia table (the known structured input) ---
    try {
        Interceptor.attach(base.add(RVA.AAB0), {
            onEnter(args) { this.ctx = args[1]; },   // a2
            onLeave(retval) {
                try {
                    const ctx = this.ctx;
                    const table = ctx.readPointer();
                    const count = ctx.add(8).readU32();
                    if (!table.isNull() && count > 0 && count <= 250) {
                        const bytes = table.readByteArray(count * 32);
                        send({type: 'minutia_table', count: count}, bytes);
                    }
                } catch (e) { send({type: 'error', msg: 'AAB0 leave: ' + e}); }
            }
        });
        send({type: 'info', msg: 'hooked sub_18000AAB0 (minutia table)'});
    } catch (e) { send({type: 'error', msg: 'hook AAB0: ' + e}); }

    // --- Marker: enrollment template requested ---
    try {
        Interceptor.attach(base.add(RVA.ED60), {
            onEnter(args) { send({type: 'info', msg: '>> EnrollmentGetTemplate'}); }
        });
    } catch (e) { send({type: 'error', msg: 'hook ED60: ' + e}); }

    send({type: 'info', msg: 'all hooks armed — run an enrollment now'});
}
"""


def on_message(message, data):
    if message.get('type') == 'send':
        p = message['payload']
        t = p.get('type')
        if t == 'info':
            print('[*]', p['msg'])
        elif t == 'error':
            print('[!]', p['msg'])
        elif t in ('ws_body', 'minutia_table') and data:
            ts = int(time.time() * 1000)
            tag = p.get('count', p.get('size'))
            fn = os.path.join(OUTDIR, f'{t}_{ts}_{tag}.bin')
            with open(fn, 'wb') as f:
                f.write(data)
            print(f'[+] {t}: {len(data)} bytes  ->  {fn}')
    elif message.get('type') == 'error':
        print('[!] JS error:', message.get('description'))
        if message.get('stack'):
            print(message['stack'])


def main():
    try:
        import frida
    except ImportError:
        print('frida not installed. On the Wine host: pip install frida', file=sys.stderr)
        sys.exit(1)

    if len(sys.argv) < 2:
        print('usage: python dev/frida_dump.py <pid|process-name>', file=sys.stderr)
        print('  e.g.  python dev/frida_dump.py WUDFHost.exe', file=sys.stderr)
        sys.exit(1)

    os.makedirs(OUTDIR, exist_ok=True)
    target = sys.argv[1]
    try:
        target = int(target)
    except ValueError:
        pass

    session = frida.attach(target)
    script = session.create_script(JS)
    script.on('message', on_message)
    script.load()
    print(f'[*] attached to {target}; dumps -> {OUTDIR}/')
    print('[*] run a full enrollment in Wine now. Ctrl-C to detach.')
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    session.detach()


if __name__ == '__main__':
    main()


# ─── Correlation sketch (run offline once you have the dumps) ───────────
#
# The newest ws_body_*.bin is the final template's WS body (matches the
# 23056-byte body inside the corresponding 0x47 wire record). The newest
# minutia_table_*.bin before it is the final 250-slot table.
#
# Each in-memory record (32 bytes) decodes as:
#     +0x00  head (8 bytes, opaque)
#     +0x08  active (u8)
#     +0x09  flag9  (u8)  = tile index 0..8
#     +0x0c  score_c  (i32)
#     +0x10  score_10 (i32)
#     +0x14  x (i32, quantized)
#     +0x18  y (i32, quantized)
#
# To reverse the bit-packing:
#   1. Pick one section of the WS body (e.g. the count[i] records).
#   2. For a known minutia with coordinate x, search the section's BIT
#      stream (not byte stream) for the value x at every bit offset and
#      candidate width (10..16 bits). The DLL coords span 0..1126 so
#      ~11 bits. Where x, then y, then the next record's x... line up at
#      a consistent bit stride, you've found the packing.
#   3. Repeat per field (score, tile, descriptor) until the record's bit
#      layout is fully mapped.
#
# Because the INPUT values are known exactly, this is a tractable search
# (unlike the output-only black-box scans, which failed).
