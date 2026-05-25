"""Store a finger template, read it back via db.get_record_value, diff.

Tells us whether the chip stores the 23136 bytes verbatim or transforms
them on write.

Run inside the prototype.py REPL after open9x():
    exec(open('dev/store_then_read.py').read())
    store_then_read()
"""
from struct import pack, unpack
from validitysensor.tls import tls
from validitysensor.db import db
from validitysensor.flash import call_cleanups
from validitysensor.util import assert_status
import validitysensor.blobs_a2 as blobs


def store_then_read(data_path='/tmp/wine_finger_fresh.bin',
                    trailer_path='/tmp/wine_finger_fresh.trailer',
                    parent=5):
    """Store the fresh-enroll capture, read it back, byte-diff.

    Returns (sent_bytes, read_back_bytes, dbid). Removes the record on exit.
    """
    with open(data_path, 'rb') as f:
        sent = f.read()
    with open(trailer_path, 'rb') as f:
        trailer = f.read()
    assert len(sent) == 23136
    assert len(trailer) == 1
    print(f"sending {len(sent)} bytes, trailer=0x{trailer.hex()}")

    typ, storage = 6, 3
    opcode_msg = (pack('<BHHHH', 0x47, parent, typ, storage, len(sent))
                  + sent + trailer)

    db.db_info()
    assert_status(tls.cmd(blobs.db_write_enable))
    recid = None
    try:
        rsp = tls.cmd(opcode_msg)
        status = unpack('<H', rsp[:2])[0]
        if status != 0:
            print(f"store FAILED: 0x{status:04x}")
            return None
        recid = unpack('<H', rsp[2:4])[0]
        print(f"stored as dbid={recid}")
    finally:
        call_cleanups()

    # Read it back
    try:
        rec = db.get_record_value(recid)
        read_back = rec.value
        print(f"read back: dbid={rec.dbid} type={rec.type} storage={rec.storage} value_len={len(read_back)}")
        print(f"  first 32: {read_back[:32].hex()}")
        print(f"  last 32:  {read_back[-32:].hex()}")
        with open('/tmp/read_back.bin', 'wb') as f:
            f.write(read_back)
        print("  saved to /tmp/read_back.bin")
    finally:
        try:
            db.del_record(recid)
            print(f"deleted dbid={recid}")
        except Exception as e:
            print(f"del_record failed: {e!r}")

    # Diff
    if len(sent) == len(read_back):
        diffs = sum(a != b for a, b in zip(sent, read_back))
        print(f"\nByte diff (same length): {diffs}/{len(sent)} ({100*diffs/len(sent):.2f}%)")
        if diffs == 0:
            print("  IDENTICAL — chip stores verbatim")
        else:
            # Show first 5 differing positions
            print("  First 10 differing offsets:")
            shown = 0
            for i in range(len(sent)):
                if sent[i] != read_back[i]:
                    print(f"    offset {i}: sent=0x{sent[i]:02x}  read=0x{read_back[i]:02x}")
                    shown += 1
                    if shown >= 10:
                        break
    else:
        print(f"\nLength mismatch: sent {len(sent)} vs read {len(read_back)} (diff {len(read_back) - len(sent)} bytes)")
        # Try to find where read_back starts within sent (or vice versa)
        # Common offsets to check
        for delta in (-8, -4, -1, 0, 1, 4, 8, 12, 16):
            n = min(len(sent), len(read_back)) - abs(delta)
            if n <= 0: continue
            a = sent[max(0, delta):max(0, delta) + n]
            b = read_back[max(0, -delta):max(0, -delta) + n]
            diffs = sum(x != y for x, y in zip(a, b))
            print(f"  delta={delta:+d}: {diffs}/{n} ({100*diffs/n:.1f}%) differ")

    return sent, read_back, recid
