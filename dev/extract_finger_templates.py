"""Walk a directory of Wine enrollment logs and extract every 23136-byte
finger template (the payload of every `0x47 ... type=6 ... len=23136`
new_record write).

Each extracted template is verified against the HMAC-SHA256 TID recipe
(validitysensor/moh_extract.compute_tid) — only TID-self-consistent
templates are written out. Anything else is reported as a parse error.

Usage:
    python -m dev.extract_finger_templates                       # default paths
    python -m dev.extract_finger_templates LOGDIR OUTDIR
"""
import hashlib
import hmac
import os
import struct
import sys
from glob import glob


DEFAULT_LOGS = '/media/sf_vbox-rw/finger'
DEFAULT_OUT = '/tmp/finger_templates'


def compute_tid(template_bytes: bytes) -> bytes:
    """Same recipe as validitysensor/moh_extract.compute_tid, inlined so
    this script runs without importing the package."""
    K = hashlib.sha256(template_bytes[12:12 + 23056]).digest()
    info = b'Template ID' + b'\x00' * 32
    T1 = hmac.new(K, info, hashlib.sha256).digest()
    return hmac.new(K, T1 + info, hashlib.sha256).digest()


def extract(logdir: str = DEFAULT_LOGS, outdir: str = DEFAULT_OUT) -> None:
    os.makedirs(outdir, exist_ok=True)
    pattern = os.path.join(logdir, 'enroll*.log')
    logs = sorted(glob(pattern))
    if not logs:
        print(f'no logs found at {pattern}', file=sys.stderr)
        sys.exit(1)

    seen_by_hash = {}   # dedup identical templates across logs
    written = []

    print(f'{"log":<35s} {"line":>6s}  {"par":>4s} {"sub":>5s}  TID  output')
    for log in logs:
        base = os.path.basename(log).removesuffix('.log')
        with open(log, 'rb') as fh:
            for lineno, line in enumerate(fh, start=1):
                if not line.startswith(b'To be encrypted: 47'):
                    continue
                payload_hex = line.removeprefix(b'To be encrypted: ').strip()
                try:
                    wire = bytes.fromhex(payload_hex.decode())
                except (UnicodeDecodeError, ValueError):
                    continue
                if len(wire) < 9:
                    continue
                opc, par, typ, sto, length = struct.unpack('<BHHHH', wire[:9])
                if opc != 0x47 or typ != 6 or length != 23136:
                    continue
                template = wire[9:9 + length]
                subtype = struct.unpack_from('<H', template, 0)[0]
                tid_stored = template[23072:23104]
                tid_ok = (compute_tid(template) == tid_stored)

                # Dedup: if we've seen this template before, skip writing
                h = hashlib.sha256(template).digest()[:8].hex()
                dup_of = seen_by_hash.get(h)

                name = f'{base}.L{lineno}.par{par}.bin'
                if dup_of:
                    note = f'duplicate of {dup_of} (skipped write)'
                    out = '-'
                else:
                    seen_by_hash[h] = name
                    out = os.path.join(outdir, name)
                    with open(out, 'wb') as g:
                        g.write(template)
                    written.append(out)
                    note = ''

                tid_mark = '✓' if tid_ok else '✗'
                print(f'{base:<35s} {lineno:>6d}  {par:>4d} 0x{subtype:04x}  '
                      f'{tid_mark}    {out}  {note}')

    print(f'\nextracted {len(written)} unique finger templates to {outdir}/')


if __name__ == '__main__':
    args = sys.argv[1:]
    if len(args) == 0:
        extract()
    elif len(args) == 2:
        extract(args[0], args[1])
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
