"""
Host-side feature-extraction pipeline for Match-on-Host Synaptics sensors.

For 06cb:00a2 ("Metallica MOH") and family, the chip captures the image and
the chip matches fingers, but the host has to extract features and serialize
the template that goes via 0x47 new_record. This module is a Python port of
the proprietary CEohMohEIV pipeline in synaWudfBioUsb.dll.

Status: scaffold. The qsort comparators, tuning constants, and Minutia layout
are implemented. The 8 per-frame stage functions inside sub_18000AAB0 are
stubs awaiting decompile output. The 23 KB template serializer is unmapped.

Reference function addresses in synaWudfBioUsb.dll (Lenovo n1cgn10w build):
    sub_180001A50    feature-extract coordinator             (have body)
    sub_180004C10    250-slot init + param block             (have body)
    sub_18000AAB0    9-stage orchestrator (478 lines)        (have call list)
    sub_180003320    stage 1 (82 lines)                      [NEED decompile]
    sub_180003460    stage 2 (9 lines, trivial)              [NEED decompile]
    sub_1800095C0    qsort (CRT, generic)                    use sorted()
    sub_18000A4B0    stage 4 (61 lines)                      [NEED decompile]
    sub_18000A5B0    stage 5 (122 lines)                     [NEED decompile]
    sub_18000A850    stage 6 (40 lines, 1 mul)               [NEED decompile]
    sub_18000A8E0    stage 7 (16 lines, no calls)            [NEED decompile]
    sub_18000A910    stage 8 (13 lines, shift-heavy)         [NEED decompile]
    sub_18000A960    stage 9 (91 lines, 5 jumps)             [NEED decompile]
    sub_18004B710    CryptHashData wrapper -> SHA-256        (have body)

qsort comparators (all 32-byte minutia records):
    sub_18000A7C0    asc by score_10                          DECODED
    sub_18000A7E0    asc by (active, score_10)                DECODED
    sub_18000A810    asc by flag9, desc by score_10           DECODED
    sub_18000A940    asc by score_c                           DECODED
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass, field
from struct import pack, unpack
from typing import List, Optional, Tuple

log = logging.getLogger(__name__)


# Tuning constants from sub_180004C10's stack-allocated param block,
# passed to sub_18000AAB0 each frame.
MAX_MINUTIAE     = 250    # 0xfa
GRID_X           = 10     # 0x0a
GRID_Y           = 7      # 0x07
COORD_RANGE_X    = 1126   # 0x466
COORD_RANGE_Y    = 671    # 0x29f
BLOCK_SIZE_SMALL = 16     # 0x10
BLOCK_SIZE_LARGE = 128    # 0x80
COORD_SCALE      = 500    # 0x1f4

# Sensor parameters (a2 device)
SENSOR_DPI = 363
SENSOR_W   = 112
SENSOR_H   = 112

# Per-enrollment limits from sub_1800D89C0
MAX_BAD_FRAMES = 6
MOH_MODE_FLAG  = 101      # vtbl(this)[+24] == 101

# Output format selectors used by sub_18004E640
TEMPLATE_FORMAT_SHA256 = 0   # 32 bytes
TEMPLATE_FORMAT_SHA1   = 1   # 20 bytes
TEMPLATE_FORMAT_MD5    = 2   # 16 bytes

# Session-buffer header from sub_1800D89C0
SESSION_MAGIC      = 0x4C4F4356   # "VCOL" little-endian
SESSION_VERSION    = 8
SESSION_HEADER_LEN = 152          # minutia table starts at session + 152


# ─── Minutia record (32 bytes) ────────────────────────────────────────
# Field offsets recovered from the 4 qsort comparators. Bytes 0..7 and
# 0x14..0x1f are consumed by stages we haven't decompiled yet — likely
# (x, y, theta, type, quality) attributes.

@dataclass
class Minutia:
    head:     bytes = field(default_factory=lambda: bytes(8))   # +0x00..0x07
    active:   int = 0                                            # +0x08
    flag9:    int = 0                                            # +0x09
    pad_a_b:  bytes = field(default_factory=lambda: bytes(2))   # +0x0a..0x0b
    score_c:  int = 0                                            # +0x0c int32
    score_10: int = 0                                            # +0x10 int32
    tail:     bytes = field(default_factory=lambda: bytes(12))  # +0x14..0x1f

    def __bytes__(self) -> bytes:
        return (self.head
                + pack('<BB', self.active & 0xff, self.flag9 & 0xff)
                + self.pad_a_b
                + pack('<ii', self.score_c, self.score_10)
                + self.tail)

    @classmethod
    def from_bytes(cls, b: bytes) -> 'Minutia':
        assert len(b) == 32, f"Minutia is 32 bytes, got {len(b)}"
        active, flag9 = unpack('<BB', b[8:10])
        score_c, score_10 = unpack('<ii', b[12:20])
        return cls(head=b[0:8], active=active, flag9=flag9,
                   pad_a_b=b[10:12], score_c=score_c, score_10=score_10,
                   tail=b[20:32])

    def is_active(self) -> bool:
        return self.active != 0


# ─── qsort comparators (sub_18000A7C0/_A7E0/_A810/_A940) ──────────────
# sub_1800095C0 is the CRT qsort itself; we use Python's sorted() with
# these key functions instead. Each key reproduces the comparator's
# sign convention.

def cmp_score_10_asc(m: Minutia) -> Tuple[int, ...]:
    return (m.score_10,)

def cmp_active_then_score_10(m: Minutia) -> Tuple[int, ...]:
    return (m.active, m.score_10)

def cmp_flag9_then_score_10_desc(m: Minutia) -> Tuple[int, ...]:
    return (m.flag9, -m.score_10)

def cmp_score_c_asc(m: Minutia) -> Tuple[int, ...]:
    return (m.score_c,)


# ─── Frame context (the 250-slot working table + per-frame state) ─────

class FrameContext:
    def __init__(self):
        self.minutiae: List[Minutia] = [Minutia() for _ in range(MAX_MINUTIAE)]
        self.quality: int = 0
        self.progress_pct: int = 0
        self.frame_count: int = 0


# ─── Stage functions ──────────────────────────────────────────────────
# Six of nine decoded directly from disassembly. All decoded ones are
# pure data-shaping plumbing — the actual biometric work happens in
# the unknown callees they invoke.

def sub_180003460(dest: bytearray, ptr: int, size: int) -> None:
    """Stream descriptor builder. dest is 0x30 bytes:
        [+0]   uint32 size
        [+8]   qword  base ptr
        [+0x10] qword cursor ptr  (== base initially)
        [+0x18..+0x30] secondary slot, zeroed
    """
    dest[0:4]   = pack('<I', size)
    dest[8:16]  = pack('<Q', ptr)
    dest[16:24] = pack('<Q', ptr)
    dest[24:48] = b'\0' * 24


def sub_18000A8E0(out4: bytearray, y: int, x: int,
                  height: int, width: int) -> None:
    """Edge-flag computer. out4[0..4] = (top, bottom, left, right)."""
    out4[0] = 1 if y <= 0 else 0
    out4[1] = 1 if y == height - 1 else 0
    out4[2] = 1 if x <= 0 else 0
    out4[3] = 1 if x == width - 1 else 0


def sub_18000A910(dx: int, dy: int,
                  x_high: int, y_high: int,
                  x_lo: int, y_lo: int) -> Tuple[int, int]:
    """Coordinate quantize-and-offset. Reproduces the
    ((diff << 16) + off) >> 16 arithmetic-shift sign-extension trick."""
    def _q(diff: int, off: int) -> int:
        v = ((diff << 16) + (off & 0xffffffff)) & 0xffffffff
        if v & 0x80000000:
            v |= ~0xffffffff
        return v >> 16
    return _q(x_high - x_lo, dx), _q(y_high - y_lo, dy)


def sub_180001010(handle) -> int:
    """Algorithm-ready gate. Returns 1 when ready, else HRESULT error."""
    if handle is None:                 return 0x80000030
    if getattr(handle, 'f8', 0) == 0:  return 0x80000032
    return 1 if getattr(handle, 'f30', 0) != 0 else 0x80000002


def sub_1800031E0(dst: bytearray, src: bytes, length: int) -> None:
    """Custom memcpy with dword fast-path. Python equivalent is plain slice."""
    dst[:length] = src[:length]


def sub_1800032C0(dest: bytearray, arg2: bytearray,
                  consumed: int, src_ptr: int,
                  cap_qword: int, cap_dword: int) -> None:
    """Stream-descriptor advance with bounds check. Resets dest's
    secondary slot and re-sets primary {size, ptr} after 8-byte align."""
    # Set qword at +8, zero everything else
    dest[8:16]   = pack('<Q', cap_qword)
    dest[0:4]    = b'\0\0\0\0'
    dest[16:24]  = b'\0' * 8
    dest[24:32]  = b'\0' * 8
    dest[32:40]  = b'\0' * 8
    dest[40:48]  = b'\0' * 8
    if consumed <= cap_dword:
        arg2[0:8] = pack('<Q', src_ptr)
        new_ptr = (consumed + src_ptr + 7) & ~7
        leftover = (consumed - new_ptr) - consumed + cap_dword
        dest[16:24] = pack('<Q', new_ptr & 0xffffffffffffffff)
        dest[0:4]   = pack('<i', leftover)


def stage_3_180003320(*args) -> None:
    """sub_180003320 — stream-advance dispatcher. Calls sub_1800032C0
    (now decoded). Routes to primary or secondary cursor."""
    raise NotImplementedError("Decoded structure; needs Python integration")


def stage_4_18000A4B0(*args) -> None:
    """sub_18000A4B0 — two-stage glue:
        sub_18000A1B0 (197 insn structural) → sub_18000F300 (94 insn SIMD).
    F300 is where per-feature SIMD work lives."""
    raise NotImplementedError("Need sub_18000A1B0 and sub_18000F300")


def stage_5_18000A5B0(*args) -> None:
    """sub_18000A5B0 (122 insn). NOT YET DECOMPILED."""
    raise NotImplementedError("Need decompile output for sub_18000A5B0")


def stage_6_18000A850_row_loop(dst: bytearray, dst_stride: int, height: int,
                                src: bytes,
                                src_stride_lo: int, src_stride_hi: int) -> None:
    """Row-iteration loop. Calls sub_1800031E0 (now decoded as memcpy)
    once per row. So this is just an image-blit with potentially
    different src/dst strides."""
    src_stride = src_stride_lo * src_stride_hi
    if height <= 0: return
    s_off = 0; d_off = 0
    for _ in range(height):
        dst[d_off:d_off+dst_stride] = src[s_off:s_off+dst_stride]
        s_off += src_stride
        d_off += dst_stride


def stage_9_18000A960(*args) -> None:
    """sub_18000A960 (91 insn, 1 call). NOT YET DECOMPILED."""
    raise NotImplementedError("Need decompile output for sub_18000A960")


# Hardcoded LFSR-like seed table used by sub_18000E6B0 to deterministically
# select 64 binary tests from a 162-pair candidate database. These 128 values
# are baked into the binary; they're the "learned" random walk that defines
# which BRIEF-like point-pair tests this algorithm uses.
BRIEF_SEED_TABLE = [
     3382,  4039, 29605,  1734, 19683,  2304, 17019, 16644,
    10030, 26447, 18237,  7668, 28663,  2663,  4319,  9870,
    10986, 19346,  9877, 19462, 12277, 24659, 28646, 32662,
    29695, 20554, 25346, 30589, 18903,   601, 27989, 17736,
    12138,  9477, 19036,  8528, 31546, 30239, 15544,  3972,
    32267, 11683, 23937, 16744, 27871,  4064, 30172, 22878,
    10021, 27353,  5840, 29477, 11566,   748, 25429,  5535,
    23264, 12977, 16558, 29143, 15022, 16933, 24825,  4930,
     1224, 14600, 23557, 25925,  7822, 12419, 19043, 12792,
    11851, 26638,  5824, 32298,  5920,  8593, 31090, 26277,
    28990,  2249, 21072, 25266, 21080, 10734, 21703,  4064,
    31321, 15251, 14890, 27394, 14418, 16333, 28234,  6775,
     7094, 16535, 27207, 11694, 17865, 11125, 12709, 30184,
    28502,  4184,  9634, 23616, 30368, 18370,  8903, 22761,
     2460, 17450,  7358, 28600, 16477,  4770, 11363, 21986,
    15312, 20151, 17437,  9478,  7337,  3481, 32367,     0,
]
assert len(BRIEF_SEED_TABLE) == 128, "seed table is exactly 128 entries"


# The fill value used for image padding by sub_180009F50. In 16.16 fixed-point
# this is 128.0 — mid-gray, neutral for gradient/filter operations.
PADDING_FILL_VALUE = 0x800000


def sub_180009F50(workspace_a: bytearray, fill_value: int,
                  scale: int, dim_y: int, dim_x: int,
                  pixel_buf: bytes, scratch_strip: bytearray,
                  width: int, height: int,
                  edge_flags: bytes) -> None:
    """Image padding. Builds workspace_a as the input image with mid-gray
    padding on the four edges that touch the sensor boundary.

    Per-edge padding size is `scale` if that edge is touched (per
    edge_flags from sub_18000A8E0), else 0. Centered patches get no
    padding; sensor-edge patches get padding on the affected sides.
    """
    top    = scale if edge_flags[0] else 0
    bottom = scale if edge_flags[1] else 0
    left   = scale if edge_flags[2] else 0
    right  = scale if edge_flags[3] else 0

    # Pre-fill the scratch strip with the fill value (for left/right margins)
    n = scale * dim_y
    for i in range(n):
        struct_pack_into = pack('<i', fill_value)
        scratch_strip[i*4:(i+1)*4] = struct_pack_into

    # Left margin block
    workspace_a[:left * dim_y * 4] = scratch_strip[:left * dim_y * 4]

    # Right margin block (positioned after the data area)
    off = (height + left) * dim_y * 4
    workspace_a[off:off + right * dim_y * 4] = scratch_strip[:right * dim_y * 4]

    # Per-row interior: top-pad + image row + bottom-pad
    rows = (dim_x - bottom) - top
    if rows <= 0:
        return

    # Pointers (offsets into workspace_a; pixel_buf is the source image)
    # The exact memory layout of the three target slots is determined by the
    # caller-set strides; we replicate the row-by-row composition here.
    row_stride = dim_y * 4
    pixel_stride = width * 4
    dst_top    = left * dim_y * 4
    dst_pixel  = dst_top + top * 4
    dst_bot    = dst_pixel + width * 4
    src_pixel  = 0

    for _ in range(rows):
        workspace_a[dst_top:dst_top + top * 4]     = scratch_strip[:top * 4]
        workspace_a[dst_pixel:dst_pixel + width*4] = pixel_buf[src_pixel:src_pixel + width*4]
        workspace_a[dst_bot:dst_bot + bottom * 4]  = scratch_strip[:bottom * 4]
        dst_top   += row_stride
        dst_pixel += row_stride
        dst_bot   += row_stride
        src_pixel += pixel_stride


def sub_18000E6B0(scale: int, num_tests: int = 64) -> List[Tuple[int, int, int, int, int]]:
    """Generate the 64 binary tests used by the per-minutia descriptor.

    Returns 64 tuples of (level, x1, y1, x2, y2) where:
      - level ∈ {0, 1, 2} (= grid_size - 2; grid_size ∈ {2, 3, 4})
      - (x1, y1) and (x2, y2) are pixel-offset coordinates relative to
        the minutia center, scaled into [-scale, +scale]

    These tests are applied to a local patch: each test produces a bit
    by comparing the pixels at (x1, y1) and (x2, y2). 64 bits form the
    per-minutia binary descriptor.
    """
    # Phase 1: build all candidate pairs across 3 grid resolutions
    pairs: List[Tuple[int, int, int, int, int]] = []
    for grid_size in (2, 3, 4):
        level = grid_size - 2
        scale_factor = int(scale * 2.0 / grid_size + 0.999)
        n = grid_size * grid_size
        for i in range(n):
            for j in range(i + 1, n):
                pairs.append((
                    level,
                    scale_factor * (i % grid_size) - scale,
                    scale_factor * (i // grid_size) - scale,
                    scale_factor * (j % grid_size) - scale,
                    scale_factor * (j // grid_size) - scale,
                ))
    # 6 + 36 + 120 = 162

    # Phase 2: select 64 pairs deterministically using the seed table
    selected = []
    remaining = list(pairs)
    for i in range(min(num_tests, len(remaining))):
        if i < 6:
            pick = i
        else:
            pick = BRIEF_SEED_TABLE[i] % len(remaining)
        selected.append(remaining[pick])
        remaining[pick] = remaining[-1]
        remaining.pop()
    return selected


# ─── Per-frame orchestrator (sub_18000AAB0) ───────────────────────────

def orchestrate(image: bytes, w: int, h: int, ctx: FrameContext) -> int:
    """sub_18000AAB0. Runs the 9-stage pipeline on one frame.

    Outer-call shape (from sub_180004C10's setup):
        zero_minutia_table(ctx)
        params = {f0=500, f4=250, f8=10, fc=7, f10=1126,
                  f14=671, f18=16, f1c=128, f20=0}
        sub_18000AAB0(image, ctx.algo, w, h, desc, ctx.sub, params)

    Returns 1 on success. Real output is in `ctx` (minutia table updated).
    """
    for m in ctx.minutiae:
        m.head = bytes(8); m.active = 0; m.flag9 = 0; m.pad_a_b = bytes(2)

    # stage_1_pre_process(image, w, h, ctx)
    # stage_2_build_descriptor(...)
    # ctx.minutiae.sort(key=cmp_score_10_asc)          # qsort call 1
    # stage_4_18000A4B0(...)
    # ctx.minutiae.sort(key=cmp_active_then_score_10)  # qsort call 2
    # stage_5_18000A5B0(...)
    # ctx.minutiae.sort(key=cmp_flag9_then_score_10_desc)  # qsort call 3
    # stage_6_18000A850(...)
    # stage_7_18000A8E0(...)
    # stage_8_18000A910(...)
    # ─ partition: count leading active minutiae, sort each range by score_c ─
    # n_active = next((i for i, m in enumerate(ctx.minutiae)
    #                    if not m.is_active()), len(ctx.minutiae))
    # ctx.minutiae[:n_active] = sorted(ctx.minutiae[:n_active], key=cmp_score_c_asc)
    # ctx.minutiae[n_active:] = sorted(ctx.minutiae[n_active:], key=cmp_score_c_asc)
    # stage_9_18000A960(...)

    raise NotImplementedError(
        "orchestrate(): pending decompile output for stages 1-9. "
        "See module docstring for the function addresses."
    )


# ─── Feature-extraction coordinator (sub_180001A50) ───────────────────

def extract_features(image: bytes, w: int, h: int, ctx: FrameContext,
                     dpi: int = SENSOR_DPI) -> bytes:
    """sub_180001A50. Runs the per-frame pipeline, returns the 32-byte TemplateId.

    The TemplateId is HMAC-SHA256 chained over the assembled WS body —
    see compute_tid() for the verified recipe. Note that this function
    is still a scaffold: it can't return the chip-accepted TID until
    orchestrate() actually fills ctx into a full 23056-byte WS body.
    """
    if w > 255:
        w = 255

    orchestrate(image, w, h, ctx)

    ws_body = _serialize_for_hash(ctx)
    if len(ws_body) != 23056:
        # Placeholder until orchestrate() emits the full chip-view WS body
        # (23056 bytes starting with 4 zeros). Returning a SHA-256 here
        # keeps callers running but the chip's matcher will not accept
        # the resulting template.
        log.warning("WS body is %d bytes, expected 23056 — TID will not be chip-valid",
                    len(ws_body))
        return hashlib.sha256(ws_body).digest()
    return compute_tid(ws_body)


def _serialize_for_hash(ctx: FrameContext) -> bytes:
    """Produce the WS body bytes (TLV-1 payload of the finger template).

    Provisional: emit the 250×32-byte minutia slot table only (8000 bytes).
    The chip-accepted WS body is 23056 bytes, so this is short by 15056
    bytes of feature/calibration data we haven't reverse-engineered yet.
    To be filled in as orchestrate()'s stage outputs are decoded.
    """
    return b''.join(bytes(m) for m in ctx.minutiae)


# ─── Per-enrollment session driver (sub_1800D89C0) ────────────────────

class EnrollmentSession:
    """One enrollment session. Accept frames until enough quality data
    has accumulated, then finalize() to emit the chip-storable bytes.
    """

    def __init__(self):
        self.ctx = FrameContext()
        self.template_id: Optional[bytes] = None
        self.frame_count = 0
        self.bad_frame_count = 0

    def process_frame(self, image: bytes,
                      w: int = SENSOR_W, h: int = SENSOR_H) -> dict:
        self.frame_count += 1

        # TODO sub_1800D8100 quality pre-check:
        # if not _quality_ok(image, w, h):
        #     self.bad_frame_count += 1
        #     if self.bad_frame_count > MAX_BAD_FRAMES:
        #         return {'state': 'give-up', 'progress': self.ctx.progress_pct}
        #     return {'state': 'bad-frame', 'progress': self.ctx.progress_pct}

        self.template_id = extract_features(image, w, h, self.ctx)

        # TODO: decide 'final' vs 'progressing' based on accumulated quality
        return {'state': 'progressing', 'progress': self.ctx.progress_pct}

    def finalize(self) -> bytes:
        """Emit the ~23 KB byte blob that goes via db.new_finger() / 0x47.

        Format decoded from sub_180036840 (vfmAuth.c):

            [8-byte envelope header]
            [TLV  tag=1, len=ws_size, data=working_state_buffer]   # ≈ 22.9 KB
            [TLV  tag=2, len=32,      data=SHA256_TemplateId]      # 32 bytes
            [32 trailing zero bytes]

        The working_state_buffer is session+152..session+152+ws_size --
        the buffer the 9-stage pipeline writes into during EnrollmentUpdate.
        TemplateId is SHA-256 over (some subset of) that buffer.
        """
        if not self.template_id:
            raise RuntimeError("no template yet; process_frame() must be called first")

        ws = _serialize_for_hash(self.ctx)   # placeholder; this is also the TLV-1 content
        tid = self.template_id
        subtype_u16 = 0xf75a                  # echoed at envelope header bytes 0..1

        return _build_envelope(subtype_u16, ws, tid)


def _build_envelope(subtype: int, ws_body: bytes, template_id: bytes,
                    version: int = 3) -> bytes:
    """Wire-exact envelope for new_record type=6, byte-identical to
    sub_180036840 in synaWudfBioUsb.dll.

    Layout:
        offset  size   field
        ────────────────────────────────────────────────────────────
        0       2      u16 subtype           (e.g. 0x00f7)
        2       2      u16 version           (= 3)
        4       2      u16 payload_size      (= 4 + ws_size + 4 + tid_size)
        6       2      u16 trailing          (= 32)
        8       2      u16 tlv1_tag          (= 1)
        10      2      u16 tlv1_len          (= ws_size)
        12      n      bytes ws_body[n]      ← chip-view WS body starts here
        12+n    2      u16 tlv2_tag          (= 2)
        14+n    2      u16 tlv2_len          (= tid_size)
        16+n    32     bytes template_id
        48+n    32     bytes trailing zeros

    For ws_size = 23056 and tid_size = 32, total envelope is 23136 bytes
    with the TID at envelope offset 23072..23104 and the TLV2 header
    immediately preceding it at 23068..23072.

    Caller contract: pass the chip-view WS body, NOT the
    "envelope[16..23072]" slice. The chip-view WS body is 23056 bytes
    that go from envelope offset 12 to 12+23056. In any captured
    template it always begins with 4 natural-zero bytes
    (template[12..16]) and ends with 4 bytes of feature-data tail
    (template[23064..23068]); the TLV2 header that sits at template
    offset 23068..23072 is NOT part of ws_body — this function writes
    it explicitly.
    """
    assert len(template_id) == 32
    ws_size = len(ws_body)
    tid_size = len(template_id)
    trailing = 32
    payload_size = 4 + ws_size + 4 + tid_size   # TLV1 hdr + ws + TLV2 hdr + TID
    total = 8 + payload_size + trailing

    buf = bytearray(total)
    # Outer header (8 bytes)
    buf[0:2]   = pack('<H', subtype)
    buf[2:4]   = pack('<H', version)
    buf[4:6]   = pack('<H', payload_size & 0xffff)
    buf[6:8]   = pack('<H', trailing)
    # Inner TLV1 header (4 bytes, no reserved field — that's the first 4
    # bytes of ws_body itself, naturally zero)
    buf[8:10]  = pack('<H', 1)
    buf[10:12] = pack('<H', ws_size & 0xffff)
    # WS body (starts at envelope offset 12)
    buf[12:12 + ws_size] = ws_body
    # Inner TLV2 header (4 bytes after WS body)
    off = 12 + ws_size
    buf[off:off + 2]     = pack('<H', 2)
    buf[off + 2:off + 4] = pack('<H', tid_size & 0xffff)
    # TID
    buf[off + 4:off + 4 + tid_size] = template_id
    # Trailing 32 zeros already zero from bytearray init
    return bytes(buf)


# ─── TID derivation (sub_1800E0A60 → sub_18004B710 chain) ───────────────

# The literal context string the DLL feeds to its TID HMAC, padded with
# zeros to 43 bytes. Captured verbatim from enroll-fresh.log line 1573.
_TID_INFO = b'Template ID' + b'\x00' * 32
assert len(_TID_INFO) == 43


def compute_tid(ws_body: bytes) -> bytes:
    """Compute the 32-byte TemplateId for a Match-on-Host finger template.

    Recipe verified end-to-end against a Wine-captured enrollment
    (enroll-fresh.log lines 1570→1583) and against the stored TID at
    envelope offset 23072..23104 of every captured template:

        K   = SHA-256(ws_body)
        T1  = HMAC-SHA256(K, "Template ID" ‖ 32×0x00)
        TID = HMAC-SHA256(K, T1 ‖ "Template ID" ‖ 32×0x00)

    K is derived from the WS body itself, so there is no device-bound
    secret involved. Anyone with the WS body can recompute the TID. See
    dev/MOH.md "TID derivation".

    Args:
        ws_body: 23056-byte chip-view WS body. In a captured envelope
            this is the slice template[12:12+23056] — the bytes the
            chip parses as the TLV1 payload. Always begins with 4
            natural-zero bytes and ends with feature data tail; does
            NOT include the TLV2 header that lives between the WS body
            and the TID at envelope offset 23068.

    Returns:
        The 32-byte TID, identical to template[23072:23104] for any
        valid captured template.
    """
    if len(ws_body) != 23056:
        raise ValueError(f"ws_body must be 23056 bytes, got {len(ws_body)}")

    K = hashlib.sha256(ws_body).digest()
    T1 = hmac.new(K, _TID_INFO, hashlib.sha256).digest()
    return hmac.new(K, T1 + _TID_INFO, hashlib.sha256).digest()
