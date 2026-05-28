"""End-to-end native enrollment ON THE ACTUAL CHIP.

Captures a frame from the connected 06cb:00a2 sensor, runs the byte-exact
native pipeline against a reference template scaffold, stores the result
on the chip via the normal db.new_finger() path, then optionally tries
to identify the finger to verify the chip accepts our descriptors.

Run on a machine with the sensor plugged in and python-validity
initialised (i.e., the usual `validity-sensors-firmware` & TLS handshake
have already been done — same prerequisites as the existing `enroll`
script in this repo).

Usage:
  sudo ./.venv-poc/bin/python dev/enroll_native_chip.py \\
      --ref REF.bin \\
      --subtype 0xf5 \\
      [--user 'S-1-5-21-...-1001'] \\
      [--match]                          # try to identify after enroll

  --ref REF.bin   a 23136-byte template captured from THIS sensor; its
                  v30 (x, y) coords are reused; its descriptors are
                  replaced with ours. Generate one via the normal
                  Wine-based enroll, or copy from a prior capture.

  --subtype N     WinBio subtype (= finger position). Defaults to 0xf5
                  (right index, common test). Look at validitysensor/
                  winbio_constants.py for the full list.

  --match         after storing, capture a fresh frame and ask the chip
                  to identify (sensor.match_finger). If the chip matches
                  it back to the userid we just enrolled, the pipeline
                  is end-to-end working.
"""
import argparse
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--ref', required=True, help='reference template (23136B)')
    ap.add_argument('--subtype', default='0xf5',
                    help='WinBio subtype, hex or decimal (default 0xf5)')
    ap.add_argument('--parent', type=int, default=5,
                    help='parent user dbid (use db.dump_raw() to list; '
                         'default 5 matches dev/bisect_ws.py DEFAULT_PARENT)')
    ap.add_argument('--trailer', default='0x11',
                    help='1-byte record-type marker appended to the wire '
                         'payload (default 0x11; per bisect_ws trailer-sweep '
                         'results, any value works)')
    ap.add_argument('--match', action='store_true',
                    help='after enroll, capture again and try to identify')
    ap.add_argument('--dry-run', action='store_true',
                    help='build the envelope but DO NOT store on chip; '
                         'write it to /tmp/native_envelope.bin instead')
    ap.add_argument('--store-ref', action='store_true',
                    help='isolation test: store the reference template VERBATIM '
                         '(via the proven typ=6/storage=3+trailer path). If '
                         'this fails, the problem is not our envelope.')
    ap.add_argument('--list-users', action='store_true',
                    help='dump the chip DB tree (db.dump_raw) and exit; '
                         'use to find a real parent dbid to pass via --parent')
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s')
    log = logging.getLogger('enroll_native_chip')

    # Imports that need the venv + libusb actually wired
    from validitysensor.init import open as open_device
    from validitysensor.sensor import sensor as Sensor, RebootException
    from validitysensor.db import db

    subtype = int(args.subtype, 0)
    parent = args.parent
    trailer = bytes([int(args.trailer, 0) & 0xFF])

    with open(args.ref, 'rb') as f:
        ref = f.read()
    log.info(f'reference template: {args.ref} ({len(ref)} bytes)')

    try:
        open_device()
    except RebootException:
        log.info('sensor rebooted — re-opening')
        open_device()

    if args.list_users:
        log.info('chip user storage + enrolled users (find parent dbid here):')
        try:
            stg = db.get_user_storage(name='StgWindsor')
            log.info(f'  StgWindsor: dbid={stg.dbid}, '
                      f'{len(stg.users)} user(s)')
            for u_meta in stg.users:
                udbid = u_meta['dbid']
                try:
                    u = db.get_user(udbid)
                    log.info(f'    user dbid={udbid} '
                              f'identity={u.identity!r} '
                              f'fingers={len(u.fingers)}')
                    for f in u.fingers:
                        log.info(f'      finger dbid={f["dbid"]} '
                                  f'subtype=0x{f["subtype"]:02x}')
                except Exception as e:
                    log.info(f'    user dbid={udbid} (could not parse: {e})')
        except Exception as e:
            log.error(f'get_user_storage failed: {e}')
            log.info('try dumping all roots 1..16:')
            for r in range(1, 17):
                try:
                    rec = db.get_record_value(r)
                    val = bytes(rec.value)
                    log.info(f'  root {r}: type={rec.type} '
                              f'val[:32]={val[:32].hex()}')
                except Exception as ex:
                    pass
        return 0

    if args.dry_run:
        # Capture + build envelope but don't talk to the chip.
        from validitysensor.sensor import CaptureMode, glow_start_scan, glow_end_scan
        from validitysensor.moh_native import native_template
        import numpy as np
        glow_start_scan()
        log.info('place finger now (dry-run, will not store)')
        x, y, w1, w2, img_data = Sensor.capture(CaptureMode.ENROLL)
        glow_end_scan()
        img = np.frombuffer(img_data, dtype=np.uint8).reshape(x, y)
        img = np.transpose(img)
        if img.shape != (112, 112):
            try:
                import cv2
                img112 = cv2.resize(img, (112, 112), interpolation=cv2.INTER_LINEAR)
            except ImportError:
                ys = (np.arange(112) * img.shape[0] // 112)
                xs = (np.arange(112) * img.shape[1] // 112)
                img112 = img[ys[:, None], xs[None, :]]
        else:
            img112 = img
        img_q16 = img112.astype(np.int32) << 16
        envelope = native_template(img_q16, ref, subtype=subtype)
        with open('/tmp/native_envelope.bin', 'wb') as f:
            f.write(envelope)
        log.info(f'✓ wrote /tmp/native_envelope.bin ({len(envelope)} bytes)')
        diff = sum(1 for a, b in zip(envelope, ref) if a != b)
        log.info(f'  diff against ref: {diff}/{len(envelope)} bytes '
                  f'({100*diff/len(envelope):.1f}%)')
        return 0

    if args.store_ref:
        from struct import pack, unpack
        from validitysensor.tls import tls
        from validitysensor.flash import call_cleanups
        from validitysensor import blobs
        from validitysensor.util import assert_status
        log.info(f'ISOLATION TEST: storing reference template verbatim '
                  f'(typ=6, storage=3, parent={parent}, trailer=0x{trailer.hex()})')
        db.db_info()
        assert_status(tls.cmd(blobs.db_write_enable()))
        try:
            msg = pack('<BHHHH', 0x47, parent, 6, 3, len(ref)) + ref + trailer
            rsp = tls.cmd(msg)
            status, = unpack('<H', rsp[:2])
            if status != 0:
                log.error(f'chip rejected ref verbatim: status=0x{status:04x}')
                return 2
            recid, = unpack('<H', rsp[2:4])
            log.info(f'✓ ref stored verbatim, recid={recid}')
        finally:
            call_cleanups()
        return 0

    log.info(f'enrolling subtype 0x{subtype:x} under parent dbid {parent} ...')
    log.info('place finger now')
    recid = Sensor.enroll_native(parent, subtype, ref, trailer=trailer)
    log.info(f'✓ native enrollment stored, recid={recid}')

    if args.match:
        log.info('now place the SAME finger to verify the chip matches ...')
        usrid, subtype_out, hsh = Sensor.match_finger()
        log.info(f'✓ chip matched: usrid={usrid}, subtype=0x{subtype_out:x}')
        log.info(f'  → native pipeline produces chip-acceptable templates!')

    return 0


if __name__ == '__main__':
    sys.exit(main())
