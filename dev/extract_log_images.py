"""Extract the 8-frame enrollment images from a Wine TLS capture log.

The Wine driver logs every TLS message in plaintext. For each
IOCTL_BIOMETRIC_CAPTURE_DATA exchange the chip returns the raw 112×112
8-bpp image. Format (sensor.py:721):

  status u16 | size u32 | x u16 | y u16 | w1 u16 | w2 u16 | err u32 | img

The image is sent in <=8192-byte chunks; first chunk includes the 12-byte
header, subsequent chunks are pure image bytes. A 112×112=12544-byte image
comes as one 8192 chunk (12 hdr + 8180 img) + a 4364-byte chunk.

Decrypted bodies in the log are AES-GCM/CBC-padded and have an extra TLS
content type + a MAC trailer — but the structured header (`7000 7000
4d01 0800 00000000`) makes the image-start unambiguous, and the length
field tells us exactly how many bytes to read.

Usage:
  ./.venv-poc/bin/python dev/extract_log_images.py <log> [-o out_dir]
"""
import argparse
import os
import re
import struct
import sys

IMG_W = IMG_H = 112
IMG_SIZE = IMG_W * IMG_H            # 12544
CHUNK_MAX = 8192
HEADER_SIG = bytes.fromhex('7000700' '04d010800000000' '00')   # 12-byte signature


def parse_decrypted(line):
    m = re.match(r'^Decrypted:\s*([0-9a-fA-F]+)\s*$', line)
    if not m:
        return None
    return bytes.fromhex(m.group(1))


def is_image_start(data):
    """Return (size_l, image_first_chunk) if `data` begins an image response,
    else None. Format: status u16 | size_l u32 | [x y w1 w2 err][img...]."""
    if len(data) < 2 + 4 + 12:
        return None
    if data[0:2] != b'\x00\x00':
        return None
    size_l = struct.unpack('<I', data[2:6])[0]
    if size_l != CHUNK_MAX:        # first chunk of a 112x112 image is always 8192
        return None
    hdr = data[6:18]
    x, y, w1, w2, err = struct.unpack('<HHHHL', hdr)
    if (x, y, w1, w2, err) != (IMG_W, IMG_H, 0x14d, 8, 0):
        return None
    # img starts at byte 18, runs CHUNK_MAX-12 = 8180 bytes
    img1 = data[18 : 18 + (CHUNK_MAX - 12)]
    if len(img1) != CHUNK_MAX - 12:
        return None
    return size_l, img1


def is_continuation(data, expected_size):
    """Return image bytes if `data` is a chunk continuation matching expected
    image-bytes-remaining, else None."""
    if len(data) < 2 + 4:
        return None
    if data[0:2] != b'\x00\x00':
        return None
    size_l = struct.unpack('<I', data[2:6])[0]
    if size_l != expected_size:
        return None
    body = data[6 : 6 + size_l]
    if len(body) != size_l:
        return None
    return body


def extract_images(log_path):
    images = []
    # The log has CRLF terminators AND occasional stray CRs inside long
    # encrypted-payload lines (multi-KB hex blobs). Python's text mode
    # treats lone \r as a line break, which splits Decrypted lines in two
    # and breaks parsing. Read in binary, split only on b'\r\n'.
    with open(log_path, 'rb') as f:
        raw = f.read()
    lines = [b.decode('latin1') for b in raw.split(b'\r\n')]

    pending_remaining = 0  # bytes still needed for current image
    current = bytearray()  # current image buffer

    for ln, line in enumerate(lines, 1):
        data = parse_decrypted(line)
        if data is None:
            continue

        # If we're mid-image, only a continuation is allowed.
        if pending_remaining > 0:
            body = is_continuation(data, pending_remaining)
            if body is None:
                # mismatch — abort current image, fall through to maybe-start
                print(f'  line {ln}: continuation expected {pending_remaining}B '
                      f'but did not match — abandoning partial image '
                      f'({len(current)}B so far)')
                pending_remaining = 0
                current = bytearray()
            else:
                current += body
                pending_remaining = 0
                if len(current) == IMG_SIZE:
                    images.append((ln, bytes(current)))
                    print(f'  line {ln}: image #{len(images)} complete ({IMG_SIZE}B)')
                else:
                    print(f'  line {ln}: unexpected image size {len(current)}')
                current = bytearray()
                continue

        # Try image-start
        start = is_image_start(data)
        if start is None:
            continue
        size_l, img1 = start
        current = bytearray(img1)
        pending_remaining = IMG_SIZE - len(current)   # = 4364
        print(f'  line {ln}: image-start; first chunk {len(img1)}B, '
              f'expecting {pending_remaining}B continuation')

    return images


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('log', help='Wine driver TLS log (1780...log)')
    ap.add_argument('-o', '--out', default='/tmp/log_images',
                    help='output directory for extracted images')
    args = ap.parse_args()

    print(f'parsing {args.log}')
    images = extract_images(args.log)
    print(f'extracted {len(images)} full 112×112 images')

    os.makedirs(args.out, exist_ok=True)
    for i, (ln, data) in enumerate(images):
        fn = os.path.join(args.out, f'frame{i:02d}_line{ln}.bin')
        with open(fn, 'wb') as f:
            f.write(data)
        print(f'  wrote {fn}')


if __name__ == '__main__':
    main()
