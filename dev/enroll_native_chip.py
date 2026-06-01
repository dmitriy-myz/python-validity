"""End-to-end native enrollment ON THE ACTUAL CHIP.

Captures a frame from the connected 06cb:00a2 sensor, runs the byte-exact
native pipeline against a reference template scaffold, stores the result
on the chip via the normal db.new_finger() path, then optionally tries
to identify the finger to verify the chip accepts our descriptors.

Run on a machine with the sensor plugged in and python-validity
initialised (i.e., the usual `validity-sensors-firmware` & TLS handshake
have already been done — same prerequisites as the existing `enroll`
script in this repo).

Usage (fully reference-free — no template needed):
  sudo ./.venv-poc/bin/python dev/enroll_native_chip.py \\
      --subtype 0xf5 \\
      [--match]                          # try to identify after enroll

  --ref REF.bin   OPTIONAL. A 23136-byte template captured from THIS sensor,
                  used ONLY for its WS-body framing. If omitted (the default),
                  a baked-in framing scaffold (validitysensor/native_ws_scaffold.bin)
                  is used instead, so the whole template — keypoints AND framing —
                  comes from us with no captured reference. Pass --ref only to
                  override the framing with a specific captured template.

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


def _capture_frame_q16(Sensor, log):
    """Capture one ENROLL frame → (112,112) int32 Q16 image."""
    from validitysensor.sensor import CaptureMode, glow_start_scan, glow_end_scan
    import numpy as np
    glow_start_scan()
    log.info('    place finger ...')
    try:
        x, y, w1, w2, img_data = Sensor.capture(CaptureMode.ENROLL)
    finally:
        glow_end_scan()
    # NO transpose: the DoH/F250 feature frame is the raw row-major image.
    # (enroll()'s np.transpose was for human-viewable JPEGs; it put keypoints in
    # a transposed frame so they never aligned with the chip's verify capture —
    # verified: identity orientation gives 242-250/250 keypoint overlap with the
    # DLL's stored sections, transpose gives ~11/250.)
    img = np.frombuffer(img_data, dtype=np.uint8).reshape(x, y)
    if img.shape != (112, 112):
        try:
            import cv2
            img = cv2.resize(img, (112, 112), interpolation=cv2.INTER_LINEAR)
        except ImportError:
            ys = (np.arange(112) * img.shape[0] // 112)
            xs = (np.arange(112) * img.shape[1] // 112)
            img = img[ys[:, None], xs[None, :]]
    return img.astype(np.int32) << 16


def _try_match(log):
    """Capture a fresh frame and ask the chip to identify. Returns True on a
    match, False on 'not recognized' (logged cleanly, no traceback)."""
    from validitysensor.sensor import sensor as Sensor
    log.info('LIFT FINGER, then place the SAME finger to verify the chip matches ...')
    try:
        usrid, subtype_out, hsh = Sensor.identify(
            lambda e: log.warning(f'identify capture retry: {e}'))
        log.info(f'✓ CHIP MATCHED: usrid={usrid}, subtype=0x{subtype_out:x}')
        return True
    except Exception as e:
        log.warning(f'✗ NO MATCH ({e})')
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--ref', default=None,
                    help='OPTIONAL reference template (23136B). If omitted, a '
                         'baked-in framing scaffold is used (fully reference-free).')
    ap.add_argument('--subtype', default='0xf5',
                    help='WinBio subtype, hex or decimal (default 0xf5)')
    ap.add_argument('--parent', type=int, default=5,
                    help='parent user dbid (use db.dump_raw() to list; '
                         'default 5 matches dev/bisect_ws.py DEFAULT_PARENT)')
    ap.add_argument('--trailer', default='0x11',
                    help='1-byte record-type marker appended to the wire '
                         'payload (default 0x11; per bisect_ws trailer-sweep '
                         'results, any value works)')
    ap.add_argument('--frames', type=int, default=1,
                    help='number of frames to capture and combine (default 1; '
                         'try 4 to fill all v30 sections with distinct frame '
                         'data — a real DLL enroll uses 8)')
    ap.add_argument('--match', action='store_true',
                    help='after enroll, capture again and try to identify')
    ap.add_argument('--identity-sec0pre', action='store_true',
                    help='patch the template inter-section transforms to '
                         'near-identity so a single replicated frame is '
                         'self-consistent (test whether one frame can match)')
    ap.add_argument('--multiframe', action='store_true',
                    help='capture 4 DISTINCT frames, build a real multi-frame '
                         'template with OUR geometrically-computed sec0_pre '
                         '(dev/build_multiframe_template.py), then store. '
                         'Combine with --match to verify.')
    ap.add_argument('--dry-run', action='store_true',
                    help='build the envelope but DO NOT store on chip; '
                         'write it to /tmp/native_envelope.bin instead')
    ap.add_argument('--store-ref', action='store_true',
                    help='isolation test: store the reference template VERBATIM '
                         '(via the proven typ=6/storage=3+trailer path). If '
                         'this fails, the problem is not our envelope.')
    ap.add_argument('--match-only', action='store_true',
                    help='do NOT enroll; just run the chip 0x5e identify against '
                         'whatever is already stored. Control: if even a known-'
                         'good Wine-enrolled finger does not match, the 0x5e '
                         '(match-on-chip) path is dead on this MoH chip.')
    ap.add_argument('--delete-dbid', type=int, default=None,
                    help='delete the FINGER record with this dbid (see '
                         '--list-users), then exit. Use to remove the Wine '
                         'finger so a --match-only cleanly tests OUR template. '
                         'Refuses to delete a USER record (would orphan fingers) '
                         'unless --force.')
    ap.add_argument('--force', action='store_true',
                    help='allow --delete-dbid to delete a non-finger record')
    ap.add_argument('--user-sid', default=None,
                    help='enroll under this user SID, creating the user if it '
                         'does not exist (self-contained: no Wine-made user '
                         'needed). Overrides --parent.')
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

    if args.ref:
        with open(args.ref, 'rb') as f:
            ref = f.read()
        log.info(f'reference template: {args.ref} ({len(ref)} bytes)')
    else:
        ref = None
        log.info('reference-free: using baked-in WS-body framing scaffold')

    try:
        open_device()
    except RebootException:
        log.info('sensor rebooted — re-opening')
        open_device()

    if args.delete_dbid is not None:
        try:
            rec = db.get_record_value(args.delete_dbid)
            rtype = rec.type
        except Exception:
            rtype = None
        if rtype is not None and rtype != 6 and not args.force:
            log.error(f'dbid={args.delete_dbid} is type {rtype} '
                      f'({"USER" if rtype == 5 else "non-finger"}), not a FINGER '
                      f'(type 6). Deleting it would orphan its children. Pick a '
                      f'FINGER dbid from --list-users, or pass --force.')
            return 2
        log.info(f'deleting record dbid={args.delete_dbid} (type {rtype}) ...')
        try:
            db.del_record(args.delete_dbid)
            log.info(f'✓ deleted dbid={args.delete_dbid}')
        except Exception as e:
            log.error(f'delete failed: {e}')
            return 2
        return 0

    if args.match_only:
        ok = _try_match(log)
        log.info('MATCH-ONLY (chip 0x5e identify against stored fingers): '
                 + ('MATCHED → 0x5e works on this chip.'
                    if ok else
                    'NO MATCH. If a known-good Wine finger is enrolled and this '
                    'still fails, 0x5e (match-on-chip) is dead here → matching '
                    'must be done host-side (port sub_18000c6a0).'))
        return 0 if ok else 3

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
        img = np.frombuffer(img_data, dtype=np.uint8).reshape(x, y)  # NO transpose (feature frame)
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
        # DIAGNOSTIC (live-enroll no-match debug): log stats + save the frame.
        # Reference DLL working image: 112x112, min=0 max=255 mean~135 std~75.
        log.info(f'  CAPTURE: raw dims {x}x{y} ({len(img_data)}B); 112x112 '
                 f'min={int(img112.min())} max={int(img112.max())} '
                 f'mean={float(img112.mean()):.1f} std={float(img112.std()):.1f}')
        for _p in (f'/tmp/native_capture_{x}x{y}.bin',
                   f'/media/sf_vbox-rw/finger/native_capture_{x}x{y}.bin'):
            try:
                open(_p, 'wb').write(img112.astype(np.uint8).tobytes())
                log.info(f'  saved capture -> {_p}')
            except Exception:
                pass
        from validitysensor.moh_native import extract_frame_native as _ext
        log.info(f'  pipeline on live frame: {len(_ext(img_q16))} keypoints')
        envelope = native_template(img_q16, ref, subtype=subtype,
                                   near_identity_sec0pre=args.identity_sec0pre)
        with open('/tmp/native_envelope.bin', 'wb') as f:
            f.write(envelope)
        log.info(f'✓ wrote /tmp/native_envelope.bin ({len(envelope)} bytes)')
        if ref is not None:
            diff = sum(1 for a, b in zip(envelope, ref) if a != b)
            log.info(f'  diff against ref: {diff}/{len(envelope)} bytes '
                      f'({100*diff/len(envelope):.1f}%)')
        return 0

    if args.store_ref:
        if ref is None:
            log.error('--store-ref requires --ref (it stores the reference '
                      'template verbatim as an isolation test)')
            return 2
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
        if args.match:
            # CONTROL: does a KNOWN chip-accepted template (stored via the
            # SAME raw 0x47 path) match the live finger? If YES, the raw path
            # is matchable and our template CONTENT is the issue; if NO, the
            # raw-write path itself isn't matchable (needs an enrollment
            # session / commit) — independent of our descriptors.
            ok = _try_match(log)
            log.info('CONTROL RESULT: known-good template via raw 0x47 path '
                     + ('MATCHED → raw path is matchable; investigate our '
                        'template content.'
                        if ok else
                        'did NOT match → raw-write path is not matchable; '
                        'native enroll must go through the session/commit path.'))
            return 0 if ok else 3
        return 0

    if args.user_sid:
        usr = db.lookup_user(args.user_sid)
        if usr is None:
            parent = db.new_user(args.user_sid)
            log.info(f'created user {args.user_sid!r} → dbid {parent}')
        else:
            parent = usr.dbid
            log.info(f'using existing user {args.user_sid!r} → dbid {parent}')

    if args.multiframe:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from build_multiframe_template import build_multiframe
        from validitysensor.moh_native import extract_frame_native, _load_ws_scaffold
        from validitysensor.moh_opencv import WS_SIZE
        from validitysensor.tls import tls
        from validitysensor.flash import call_cleanups
        from validitysensor import blobs
        from validitysensor.util import assert_status
        from struct import pack, unpack
        scaffold_ws = ref[12:12 + WS_SIZE] if ref else _load_ws_scaffold()
        log.info('MULTIFRAME: capturing 4 distinct frames (move finger slightly '
                 'between each) ...')
        frames = []
        for f in range(4):
            log.info(f'  frame {f + 1}/4:')
            img = _capture_frame_q16(Sensor, log)
            kps = extract_frame_native(img)
            frames.append([(gx, gy, desc) for (gx, gy, _o, desc) in kps])
            log.info(f'    {len(kps)} keypoints')
        envelope, report = build_multiframe(frames, scaffold_ws, subtype)
        log.info('  sec0_pre geom transforms: ' + '  '.join(
            f'{i}->{j}:rot{t[0]:+.1f},ov{t[3]}' for off, i, j, t in report if t))
        log.info(f'  envelope {len(envelope)} bytes; storing under parent {parent} ...')
        db.db_info()
        assert_status(tls.cmd(blobs.db_write_enable()))
        try:
            msg = pack('<BHHHH', 0x47, parent, 6, 3, len(envelope)) + envelope + trailer
            rsp = tls.cmd(msg)
            status, = unpack('<H', rsp[:2])
            if status != 0:
                log.error(f'chip rejected multiframe template: status=0x{status:04x}')
                return 2
            recid, = unpack('<H', rsp[2:4])
            log.info(f'✓ multiframe native enrollment stored, recid={recid}')
        finally:
            call_cleanups()
        if args.match:
            return 0 if _try_match(log) else 3
        return 0

    log.info(f'enrolling subtype 0x{subtype:x} under parent dbid {parent} '
              f'with {args.frames} frame(s)...')
    recid = Sensor.enroll_native(parent, subtype, ref, trailer=trailer,
                                   num_frames=args.frames,
                                   near_identity_sec0pre=args.identity_sec0pre)
    log.info(f'✓ native enrollment stored, recid={recid}')

    if args.match:
        # identify() = capture(IDENTIFY) (waits for finger-present) + match.
        if _try_match(log):
            log.info('  → native pipeline produces chip-acceptable templates!')
            return 0
        return 3

    return 0


if __name__ == '__main__':
    sys.exit(main())
