"""Run our native pipeline on log-extracted images and compare to DLL dumps.

Pipeline: extract_frame_native(image_q16) -> 250 keypoints (gx, gy, orient, desc).
Oracle: minutia_table_<ts>_250.bin = 250×32B DLL records at AAB0 return.
         Layout: +0x08 flag, +0x09 tile_id, +0x0a qual, +0x0c orient_q16,
                 +0x10 resp, +0x14 gx (i32, post-A910), +0x18 gy (i32).

We pair each enrollment image (frame00..frame07) with the minutia_table dump
that corresponds to its AAB0 invocation. Timestamps in the dump filenames
are sorted; first 8 minutia_tables = the 8 enrollment frames; the 9th is
the post-enrollment identify check.
"""
import argparse
import glob
import os
import struct
import sys
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from validitysensor.moh_native import extract_frame_native

DUMP_DIR = '/media/sf_vbox-rw/finger/frida_dumps'


def load_minutia(path):
    """Return list of 250 dicts with the DLL kp fields we care about."""
    with open(path, 'rb') as f:
        data = f.read()
    n = len(data) // 32
    out = []
    for i in range(n):
        r = data[i*32 : (i+1)*32]
        flag, tile_id, qual, _ = r[8], r[9], r[10], r[11]
        orient = struct.unpack('<I', r[0x0c:0x10])[0]
        resp = struct.unpack('<i', r[0x10:0x14])[0]
        gx = struct.unpack('<i', r[0x14:0x18])[0]
        gy = struct.unpack('<i', r[0x18:0x1c])[0]
        out.append({'i': i, 'flag': flag, 'tile_id': tile_id, 'qual': qual,
                    'orient': orient, 'resp': resp, 'gx': gx, 'gy': gy})
    return out


def run_pipeline(image_bytes):
    """Convert 112×112 uint8 image to Q16 i32 and run our pipeline."""
    img = np.frombuffer(image_bytes, dtype=np.uint8).reshape(112, 112)
    img_q16 = img.astype(np.int64) << 16
    kps = extract_frame_native(img_q16)
    return kps


def compare(my_kps, dll_kps, label):
    my_set = {(k[0], k[1]) for k in my_kps}
    dll_set = {(k['gx'], k['gy']) for k in dll_kps}
    both = my_set & dll_set
    only_mine = my_set - dll_set
    only_dll = dll_set - my_set
    print(f'  {label}: my={len(my_kps)} dll={len(dll_kps)} '
          f'common={len(both)} only_mine={len(only_mine)} only_dll={len(only_dll)}')
    if only_dll:
        # show DLL-kept kps we're missing, with their resp (to understand
        # why ours dropped them)
        by_resp = sorted(only_dll)
        print(f'    only_dll first 5 (sorted by gx,gy): {by_resp[:5]}')
    if only_mine:
        by_resp = sorted(only_mine)
        print(f'    only_mine first 5 (sorted by gx,gy): {by_resp[:5]}')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--images-dir', default='/tmp/log_images')
    ap.add_argument('--dump-dir', default=DUMP_DIR)
    ap.add_argument('--max-frames', type=int, default=8)
    args = ap.parse_args()

    image_files = sorted(glob.glob(os.path.join(args.images_dir, 'frame*.bin')))
    minutia_files = sorted(glob.glob(os.path.join(args.dump_dir, 'minutia_table_178002*_250.bin')))

    print(f'images: {len(image_files)}')
    print(f'minutia_tables: {len(minutia_files)}')
    if not image_files or not minutia_files:
        sys.exit(1)

    n_pairs = min(len(image_files), len(minutia_files), args.max_frames)
    print(f'pairing first {n_pairs} frames\n')

    for fi in range(n_pairs):
        img_path = image_files[fi]
        oracle_path = minutia_files[fi]
        print(f'frame{fi:02d}  image={os.path.basename(img_path)}  '
              f'oracle={os.path.basename(oracle_path)}')

        with open(img_path, 'rb') as f:
            img_bytes = f.read()

        my_kps = run_pipeline(img_bytes)
        dll_kps = load_minutia(oracle_path)

        compare(my_kps, dll_kps, label='final (gx,gy) set')


if __name__ == '__main__':
    main()
