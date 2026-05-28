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
    ap.add_argument('--user', default=None,
                    help='SID to enroll under (defaults to a fresh test SID)')
    ap.add_argument('--match', action='store_true',
                    help='after enroll, capture again and try to identify')
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s')
    log = logging.getLogger('enroll_native_chip')

    # Imports that need the venv + libusb actually wired
    from validitysensor.init import open_device
    from validitysensor.sensor import sensor as Sensor, RebootException
    from validitysensor.sid import SidIdentity

    subtype = int(args.subtype, 0)
    user_sid = args.user or 'S-1-5-21-111111111-1111111111-1111111111-2000'
    identity = SidIdentity(user_sid)

    with open(args.ref, 'rb') as f:
        ref = f.read()
    log.info(f'reference template: {args.ref} ({len(ref)} bytes)')

    try:
        open_device()
    except RebootException:
        log.info('sensor rebooted — re-opening')
        open_device()

    log.info(f'enrolling subtype 0x{subtype:x} under SID {user_sid} ...')
    log.info('place finger now')
    recid = Sensor.enroll_native(identity, subtype, ref)
    log.info(f'✓ native enrollment stored, recid={recid}')

    if args.match:
        log.info('now place the SAME finger to verify the chip matches ...')
        usrid, subtype_out, hsh = Sensor.match_finger()
        log.info(f'✓ chip matched: usrid={usrid}, subtype=0x{subtype_out:x}')
        log.info(f'  → native pipeline produces chip-acceptable templates!')

    return 0


if __name__ == '__main__':
    sys.exit(main())
