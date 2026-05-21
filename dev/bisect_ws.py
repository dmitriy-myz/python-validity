"""Bisection: find which portions of Wine's working state are load-bearing.

Approach: take Wine's known-accepted finger data, replace portions with
zeros (or our OpenCV output), and see what makes the chip reject.

Two ways to run:
  1. Standalone: `python -m dev.bisect_ws` — opens the sensor itself.
  2. Inside the prototype.py REPL: `exec(open('dev/bisect_ws.py').read())`
     — reuses the already-open sensor.

Each accepted variant creates a new db record. Inspect with db.dump_all()
between runs and delete junk via db.del_record() if you hit a slot limit.
"""
import logging
from struct import pack, unpack

from validitysensor.tls import tls
from validitysensor.db import db
from validitysensor.flash import call_cleanups
from validitysensor.util import assert_status
import validitysensor.blobs_a2 as blobs

logging.basicConfig(level=logging.INFO)


def _ensure_sensor_open():
    """Idempotent: opens the sensor if it isn't already."""
    from validitysensor.usb import usb
    if usb.dev is None:
        from validitysensor.init import open as open9x
        open9x()


WINE_FINGER_DATA = open('/tmp/wine_finger_data.bin', 'rb').read()
assert len(WINE_FINGER_DATA) == 23136
WINE_WS  = WINE_FINGER_DATA[16:16+23056]
WINE_TID = WINE_FINGER_DATA[23072:23104]


def send_finger(template_bytes: bytes, label: str) -> int:
    """Send a 23136-byte template via the new_finger pipeline. Returns chip status."""
    assert len(template_bytes) == 23136, f"{label}: bad size {len(template_bytes)}"
    parent, typ, storage = 5, 6, 3
    opcode_msg = (pack('<BHHHH', 0x47, parent, typ, storage, len(template_bytes))
                  + template_bytes + b'\x11')
    db.db_info()
    assert_status(tls.cmd(blobs.db_write_enable))
    try:
        rsp = tls.cmd(opcode_msg)
        status = unpack('<H', rsp[:2])[0]
        if status == 0:
            recid = unpack('<H', rsp[2:4])[0]
            print(f"  [{label}] ACCEPTED — dbid={recid}")
        else:
            print(f"  [{label}] rejected: 0x{status:04x}")
        return status
    finally:
        call_cleanups()


def make_envelope(ws: bytes, tid: bytes,
                  subtype: int = 0x00f7, version: int = 3,
                  trailing: bytes = None) -> bytes:
    """Build a 23136-byte envelope. `ws` must be 23056 bytes."""
    assert len(ws) == 23056
    assert len(tid) == 32
    if trailing is None:
        trailing = b'\0' * 32
    assert len(trailing) == 32

    payload_size = 8 + len(ws) + len(tid)
    buf = bytearray(16 + 23056 + 32 + 32)
    buf[0:2]   = pack('<H', subtype)
    buf[2:4]   = pack('<H', version)
    buf[4:6]   = pack('<H', payload_size)
    buf[6:8]   = pack('<H', 32)
    buf[8:10]  = pack('<H', 1)
    buf[10:12] = pack('<H', 23056)
    # buf[12:16] zero
    buf[16:16+23056] = ws
    buf[16+23056:16+23056+32] = tid
    buf[-32:] = trailing
    return bytes(buf)


def baseline_wine():
    """A: Send Wine's exact bytes through our pipeline. Must accept."""
    return send_finger(WINE_FINGER_DATA, "A: Wine verbatim")


def test_wine_via_our_builder():
    """B: Same WS+TID but built via make_envelope. Confirms envelope code is right."""
    env = make_envelope(WINE_WS, WINE_TID)
    diff = sum(a != b for a, b in zip(env, WINE_FINGER_DATA))
    print(f"  [B prep] envelope vs Wine: {diff} differing bytes")
    return send_finger(env, "B: Wine WS+TID via builder")


def test_zero_tid():
    """C: Wine WS but zero TID. If accepted, TID isn't validated."""
    env = make_envelope(WINE_WS, b'\0' * 32)
    return send_finger(env, "C: Wine WS + zero TID")


def test_zero_ws():
    """D: zero WS + Wine TID. If accepted, WS content isn't validated."""
    env = make_envelope(b'\0' * 23056, WINE_TID)
    return send_finger(env, "D: zero WS + Wine TID")


def test_partial_ws(keep_first: int):
    """E: keep only first `keep_first` bytes of Wine WS, rest zeros."""
    ws = WINE_WS[:keep_first] + b'\0' * (23056 - keep_first)
    env = make_envelope(ws, WINE_TID)
    return send_finger(env, f"E: WS[:{keep_first}] + zeros")


def test_zero_first(zero_first: int):
    """F: zero the first `zero_first` bytes of Wine WS, keep the rest."""
    ws = b'\0' * zero_first + WINE_WS[zero_first:]
    env = make_envelope(ws, WINE_TID)
    return send_finger(env, f"F: zero[:{zero_first}] + WS[{zero_first}:]")


if __name__ == '__main__':
    # Run sequentially. Clean db between runs if you hit a slot limit.
    print("=== Bisection: find what in WS makes the chip accept ===")
    _ensure_sensor_open()
    baseline_wine()                          # A
    test_wine_via_our_builder()              # B — must match A
    test_zero_tid()                          # C
    test_zero_ws()                           # D
    test_partial_ws(keep_first=148)          # E — keep just the first dense block
    test_partial_ws(keep_first=32)           # E — keep only magic prefix
    test_zero_first(32)                      # F — zero only magic prefix
