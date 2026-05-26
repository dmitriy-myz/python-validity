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


def send_finger(template_bytes: bytes, label: str,
                cleanup_on_success: bool = True,
                trailer: bytes = b'\x11') -> int:
    """Send a 23136-byte template via the new_finger pipeline. Returns chip status.

    On success, optionally del_record the newly-created entry so subsequent
    tests aren't rejected as duplicates of this one.

    The wire trace shows a 1-byte trailer after the data that varies per
    enrollment (0x11 in enroll.log, 0x86 in enroll-fresh.log) — let callers
    override it when replaying captured templates.
    """
    assert len(template_bytes) == 23136, f"{label}: bad size {len(template_bytes)}"
    assert len(trailer) == 1
    parent, typ, storage = 5, 6, 3
    opcode_msg = (pack('<BHHHH', 0x47, parent, typ, storage, len(template_bytes))
                  + template_bytes + trailer)
    db.db_info()
    assert_status(tls.cmd(blobs.db_write_enable))
    recid = None
    try:
        rsp = tls.cmd(opcode_msg)
        status = unpack('<H', rsp[:2])[0]
        if status == 0:
            recid = unpack('<H', rsp[2:4])[0]
            print(f"  [{label}] ACCEPTED — dbid={recid}")
        else:
            print(f"  [{label}] rejected: 0x{status:04x}")
    finally:
        call_cleanups()
    if recid is not None and cleanup_on_success:
        try:
            db.del_record(recid)
            print(f"  [{label}] cleaned up dbid={recid}")
        except Exception as e:
            print(f"  [{label}] WARNING: del_record({recid}) failed: {e}")
    return status


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


def enroll_and_match_under(parent: int,
                            data_path: str,
                            trailer_path: str,
                            cleanup_on_match: bool = True,
                            override_subtype: int = None) -> None:
    """Store the given template under the specified parent (user dbid),
    then attempt identify(). Useful for testing whether a template from
    one Wine session matches a live finger when re-parented to a
    different user.

    override_subtype: if set, patch bytes [0..2] of the template with this
    little-endian u16. Use a different value than the live record's
    subtype to avoid 0x04c3 (per-(user, subtype) duplicate detection).
    """
    from validitysensor.sensor import sensor
    with open(data_path, 'rb') as f:
        data = bytearray(f.read())
    with open(trailer_path, 'rb') as f:
        trailer = f.read()
    assert len(data) == 23136
    assert len(trailer) == 1
    if override_subtype is not None:
        data[0:2] = pack('<H', override_subtype)
        print(f"  (subtype patched to 0x{override_subtype:04x})")
    print(f"template: subtype=0x{data[0]:02x}{data[1]:02x} trailer=0x{trailer.hex()} → parent={parent}")
    data = bytes(data)

    # Use send_finger but force parent
    typ, storage = 6, 3
    opcode_msg = (pack('<BHHHH', 0x47, parent, typ, storage, len(data))
                  + data + trailer)
    db.db_info()
    assert_status(tls.cmd(blobs.db_write_enable))
    recid = None
    try:
        rsp = tls.cmd(opcode_msg)
        status = unpack('<H', rsp[:2])[0]
        if status == 0:
            recid = unpack('<H', rsp[2:4])[0]
            print(f"  ACCEPTED — dbid={recid}")
        else:
            print(f"  rejected: 0x{status:04x}")
            return
    finally:
        call_cleanups()

    print("\n  Place the finger you want to test (the one originally enrolled in this template)...")
    def _cb(e): print(f"  capture retry: {e!r}")
    try:
        result = sensor.identify(_cb)
        print(f"  identify result: {result}")
    except Exception as e:
        print(f"  identify raised: {e!r}")

    if cleanup_on_match and recid is not None:
        try:
            db.del_record(recid)
            print(f"  cleaned up dbid={recid}")
        except Exception as e:
            print(f"  cleanup failed: {e!r}")


def enroll_and_match_fresh(data_path: str = '/tmp/wine_finger_fresh.bin',
                            trailer_path: str = '/tmp/wine_finger_fresh.trailer',
                            cleanup_on_match: bool = True) -> None:
    """End-to-end: store the fresh-enroll capture, ask user to place finger,
    call match_finger(). Useful to check whether the chip's matcher actually
    recognises the live finger that was enrolled in this fresh Wine session.

    Different from the bisection tests because we DON'T cleanup on success
    before matching (the record must exist for the matcher to find it).
    """
    from validitysensor.sensor import sensor   # imported lazily so script remains importable

    with open(data_path, 'rb') as f:
        data = f.read()
    with open(trailer_path, 'rb') as f:
        trailer = f.read()
    assert len(data) == 23136
    assert len(trailer) == 1
    print(f"fresh enroll: subtype=0x{data[0]:02x}{data[1]:02x} trailer=0x{trailer.hex()}")

    # Send the template (no cleanup — we need the record present for matching)
    status = send_finger(data, "fresh: enroll", cleanup_on_success=False, trailer=trailer)
    if status != 0:
        print("  enroll failed; cannot try matching")
        return

    print("\n  Place the SAME finger you enrolled in the fresh Wine capture...")
    # identify() = capture(IDENTIFY) + match_finger(); match_finger alone
    # doesn't capture an image so we'd never have anything to match.
    def _cb(e):
        print(f"  capture retry due to: {e!r}")
    try:
        result = sensor.identify(_cb)
        print(f"  identify result: {result}")
    except Exception as e:
        print(f"  identify raised: {e!r}")

    if cleanup_on_match:
        # Find the record we just created. db.dump_all() walks the tree but
        # we want the dbid we just got — easiest: refetch & take the newest.
        try:
            from validitysensor.db import db as _db
            stg = _db.get_user_storage(name='StgWindsor')
            usrs = [_db.get_user(u['dbid']) for u in stg.users]
            # Find the latest finger we just added (highest dbid under user 5)
            for u in usrs:
                if u.dbid == 5 and u.fingers:
                    recid = max(f['dbid'] for f in u.fingers)
                    _db.del_record(recid)
                    print(f"  cleaned up dbid={recid}")
                    break
        except Exception as e:
            print(f"  cleanup failed: {e!r}")


def test_trailer_sweep(values=(b'\x00', b'\x11', b'\x86', b'\x70', b'\xa9', b'\xff')):
    """G: does the 1-byte wire trailer matter?

    Sends the same Wine-captured template with several trailer values.
    Each success is del_record'd before the next attempt so duplicate
    (parent, subtype) deduplication doesn't interfere.

    Three possible outcomes:
      - All values accepted (status 0x0000) → trailer value is irrelevant;
        the byte must be present but any value works.
      - Some accepted, some rejected → trailer is validated in some way;
        rejected status code tells us what kind of check.
      - All rejected → chip state is degraded; recover via Wine re-enroll.
    """
    print("=== G: trailer-value sweep against Wine verbatim ===")
    results = []
    for t in values:
        status = send_finger(WINE_FINGER_DATA, f"G: trailer=0x{t.hex()}",
                             cleanup_on_success=True, trailer=t)
        results.append((t.hex(), status))
    print("\nSummary:")
    for hex_val, status in results:
        verdict = 'ACCEPTED' if status == 0 else f'rejected 0x{status:04x}'
        print(f"  trailer=0x{hex_val}  →  {verdict}")
    return results


if __name__ == '__main__':
    import sys

    _ensure_sensor_open()

    mode = sys.argv[1] if len(sys.argv) > 1 else 'bisect'

    if mode == 'bisect':
        # The original bisection — verify chip-acceptance of WS variants.
        print("=== Bisection: find what in WS makes the chip accept ===")
        baseline_wine()                          # A
        test_wine_via_our_builder()              # B — must match A
        test_zero_tid()                          # C
        test_zero_ws()                           # D
        test_partial_ws(keep_first=148)          # E — keep just the first dense block
        test_partial_ws(keep_first=32)           # E — keep only magic prefix
        test_zero_first(32)                      # F — zero only magic prefix
    elif mode == 'match-fresh':
        # End-to-end match test against the fresh enrollment capture.
        print("=== Enroll fresh-capture finger + try matching ===")
        enroll_and_match_fresh()
    elif mode == 'trailer-sweep':
        # Does the trailer byte matter? Replay Wine-verbatim with varied trailers.
        test_trailer_sweep()
    else:
        print(f"unknown mode: {mode!r}")
        print(f"usage: python -m dev.bisect_ws [bisect|match-fresh|trailer-sweep]")
        sys.exit(2)
