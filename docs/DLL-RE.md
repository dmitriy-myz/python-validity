# Reverse-engineering `synaWudfBioUsb.dll` — image → template pipeline

Notes on the host-side feature-extraction code that the Synaptics Windows
driver runs to convert a captured fingerprint image into the encrypted
~23 KB template that ends up on the chip via `0x47 new_record`.

DLL inspected: **`synaWudfBioUsb.dll`** (Lenovo `n1cgn10w` build),
x86-64 PE. Disassembly via IDA Pro / objdump.

The work here is incomplete: about half the pipeline has been mapped
byte-exactly; the actual feature transforms are partially understood;
the **per-slot minutia tail bytes and the trailing feature/calibration
region of the WS body** are still un-decoded (see Open Questions). The
previously-listed "unknown encryption pass" turned out not to exist —
the WS body is plaintext signed-int feature data, and the high entropy
comes from the dynamic range of those values.

---

## High-level architecture

The DLL exposes two C++ extractor classes that share the WUDF biometric
plumbing but route differently for the two device families:

| Class           | Devices | Where features live |
|-----------------|---------|---------------------|
| `CEocMocEIV`    | Match-on-Chip Synaptics sensors | extracted **inside the chip** |
| `CEohMohEIV`    | Match-on-Host (06cb:00a2 etc.)   | extracted **in this DLL**, sent via 0x47 |

For the MoH path, the chip captures the image (~13 KB per frame on the
wire) and hands it back to the DLL. The DLL runs the feature-extraction
pipeline below, wraps the output in the chip's expected envelope, and
sends the result via `new_record`.

The MoH pipeline appears to be Synaptics' internal **`vcsmRidgeMatcher`**
algorithm: classical computer-vision keypoint detection plus binary
descriptors, with the assembled template authenticated by a self-MAC
TID (HMAC-SHA256 chained over the WS body — see TID-derivation notes
below). No symmetric encryption is applied to the WS body itself; the
only cipher in play is the TLS-layer AES-256-CBC wrapping the wire
record.

---

## Pipeline overview

```
                              [image]
                                 │
                                 ▼
       sub_180009F50 ─ pad with mid-gray border (4-edge aware)
                                 │
                                 ▼
       sub_180010050 ─ Sobel gradients Ix, Iy           ┐
       sub_18000FDF0 ─ horizontal pass                  │  classical
       sub_18000CE80 ─ Harris response Ixx·Iyy − Ixy²   │  CV
                                 │                       │
                                 ▼                       │
                       Non-max suppression               │
                       → top-N (≤250) keypoints          │
                                 │                       ┘
                                 ▼
       sub_18000E6B0 ─ choose 64 BRIEF test pairs (deterministic)
                                 │
                                 ▼
       per-keypoint BRIEF descriptor (64 bits)
       packed into 32-byte minutia records
                                 │
                                 ▼
       sub_18000AAB0 ─ 9-stage orchestrator (reshape, qsort, dedup)
                                 │
                                 ▼
       [TID] ─ TID = HMAC²-SHA256(K=SHA256(WS), "Template ID")
               (recipe verified in moh_extract.compute_tid; the exact DLL
                function is unconfirmed — NOT sub_1800E0A60, which is memset)
                                 │
                                 ▼
       sub_180036840 ─ serialize envelope: 8-byte outer hdr + 4-byte TLV1 hdr
                       + 23056-byte ws_body + 4-byte TLV2 hdr + 32-byte TID
                       + 32 trailing zeros  (= 23136 bytes total)
                                 │
                                 ▼
                       23136-byte template
                                 │
                                 ▼
                       sent via 0x47 new_record
```

**No encryption pass is applied to the WS body.** The ~7.7 bits/byte
entropy of the stored template reflects the dynamic range of signed
int32 feature values (sign-extended small numbers fill the byte
distribution evenly), not encryption. The 96% inter-capture byte diff
is feature-extraction noise — slightly different image captures of the
same finger produce different minutiae, coordinates, scores, and
descriptors. See `MOH.md` "TL;DR" and "TID derivation".

---

## Function reference

Addresses are from the Lenovo `n1cgn10w` build. Where we have a clean
Python port it lives in `validitysensor/moh_extract.py`.

### Outer flow / class machinery

| VA              | Role                                                  | Status |
|-----------------|-------------------------------------------------------|--------|
| `sub_180001A50` | `CEohMohEIV` feature-extract coordinator              | body decompiled |
| `sub_180004C10` | 250-slot context init + 9-tuple param block setup     | body decompiled |
| `sub_1800D89C0` | **THE per-frame processor** (reached via object `+104` fn-ptr slot, dispatched by `sub_18009FD20`). Runs feature-extract + WS-pack per frame; its first-frame branch is the session-buffer setup that writes `0x4C4F4356` ("VCOL") + version 8 + 152-byte header, body at session+152. Bad-frame cap 6; DPI forced 363; `144×144` input → `116×116` working. | DECODED |
| `sub_18009FD20` | Validation + dispatcher to the `+104` slot: `arg0->fnptr[0x68](arg0, …)`. The `+96/104/112/120` slots form a fn-ptr interface table (`sub_1800D8980/D89C0/D9790/DA060`). | DECODED |
| `sub_18001D130` | Provides `(this+24) == 101` to dispatch into MoH path  | body decompiled |
| `sub_18001E750` | Enrollment update wrapper. Calls feature-extract per frame; tracks "bad frame" counter (cap = 6). | body decompiled |
| `sub_18001F070` | Per-frame entry from the WUDF enrollment update FSM   | body decompiled |
| `sub_180031470` | Frame counter / "progress %" accessor                 | body decompiled |
| `sub_1800E0A60` | **`memset`** (broadcast byte ×8, switch for n<16, SIMD fill; 123 call sites). NOT the TID function — earlier label was wrong. `sub_1800031C0(p,v,n)` is the guarded wrapper `if(n>0) memset(p,v,n)`. | DECODED |
| `sub_180001010` | Algorithm-ready gate. Returns HRESULT 0x80000030/0x80000032/0x80000002 if not ready, else 1. Replicated in `moh_extract.py`. | DECODED |

### Image preprocessing (stage 0)

| VA              | Role                                                  | Status |
|-----------------|-------------------------------------------------------|--------|
| `sub_180009F50` | **Image padding.** Wraps the input image with mid-gray border (`0x800000` = 128.0 in 16.16 fixed-point). Border per edge is either `scale` or 0, depending on `edge_flags` from `sub_18000A8E0` (i.e. whether the patch touches the sensor boundary). | DECODED — `moh_extract.py:sub_180009F50` |
| `sub_18000A8E0` | **Edge-flag computer.** Given `(y, x, height, width)` returns 4 bytes `(top, bottom, left, right)` — 1 if that edge is at the sensor boundary, 0 otherwise. | DECODED — `moh_extract.py:sub_18000A8E0` |
| `sub_18000A910` | **Coordinate quantize-and-offset.** Sign-extending arithmetic shift trick: `((diff << 16) + (off & 0xFFFFFFFF)) >> 16`. Used to map coordinates between scales. | DECODED — `moh_extract.py:sub_18000A910` |

### Gradient / Harris response

| VA              | Role                                                  | Status |
|-----------------|-------------------------------------------------------|--------|
| `sub_180010050` | Sobel-style gradient (vertical pass / I_y)            | body present, not ported |
| `sub_18000FDF0` | Sobel-style gradient (horizontal pass / I_x)          | body present, not ported |
| `sub_18000CE80` | Response: `(buf30>>12)·(buf40>>12) − (buf38>>12)²` in **Q12 fixed-point**, int32. Operates per *plane* (list at ctx+0x50, count ctx+0x58, stride 0x70; per plane +0=w +4=h +0x30/0x38/0x40=tensor +0x50=response). | DECODED |

#### Detector diagnosis (GDB_DUMP_HARRIS capture, `scripts/diff_v30.py compare_harris`)

Hooking `sub_18000CE80` and diffing its dumps against `moh_opencv`:

- **Half resolution.** The response plane is **57×57** (≈112/2): the detector
  downsamples the 112×112 frame before computing gradients.
- **Response formula confirmed.** `(buf30>>12)·(buf40>>12) − (buf38>>12)²`
  reproduces the dumped `resp` at **corr +0.949** (24% byte-exact; the rest
  is rounding/overflow detail). So the `AB−C²` decode is correct.
- **NOT Harris on the raw image.** `buf30` ("Ixx") holds large **negative**
  values (`[-4.1M,+2.7M]`) — not a squared gradient `Ix²`, so this is a
  **2nd-order / Hessian-like** operator (det-of-Hessian shape), not the
  first-derivative structure tensor our PoC uses.
- **Input is a TILE, not an enhanced image (CORRECTED).** The 57×57 plane is
  a **tile of the working image**, not a downsample/enhancement. Proven:
  `gradin/1024` matches a 57×57 window of `extract_image` at **corr 1.000**
  (call0 → offset (−10,−10); call6 → (−10,27)). The orchestrator
  `sub_18000AAB0` tiles the image into a 3×3 grid (step `h/3`=37, size
  `2·GRID_X+h/3`=57, 20px overlap, mid-gray pad) and runs DoH per tile. The
  earlier "~0 corr / ridge-enhanced / wall" claim was an artifact of
  comparing `gradin` to a *resize/center-crop* of the whole frame instead of
  the actual off-origin tile. **There is no enhancement.**

**Front-end call tree (located via Hex-Rays — supersedes earlier objdump
guess that put the enhancement in sub_18000F250; that was a bad disasm
range).** Decoded from the C of `sub_18000A1B0` and `sub_18000F250`:

```
sub_18000A1B0 (orchestrator stage-4 glue) — input a2 = already ~57² image
  ├─ img_q16[i] = a2[i] << 16                     uint8 -> Q16
  ├─ sub_180009F50(v41, 0x800000, …, img_q16, …)  PAD ONLY (mid-gray border,
  │                                               0x800000=128.0 Q16; no filter)
  ├─ sub_18000A120(a9, …)                         setup
  ├─ sub_18000C920(…, a9, v41, a1, …) -> a1       builds DoH context (feeds CE80's a5)
  └─ sub_18000F250(v41, w, h, a9, a1, …)          DETECTOR:
        ├─ img >>= 6 ; sub_1800101C0(img,…) ; img <<= 6   gradients on v41
        └─ sub_18000CE80(a9, a1, …)               DoH response — DECODED
```

So `gradin = v41 >> 6`, `v41 = pad(a2)`, and **`a2` (stage-4 input) is a
57×57 TILE** of the working image (NOT an enhanced image). The orchestrator
`sub_18000AAB0` does the tiling:

```
sub_18000AAB0: 3×3 grid over the working image
  for each tile (i,j):
    sub_18000A850  blit image[i*37-10:+57, j*37-10:+57] → v85 (mid-gray pad)
    sub_18000A4B0 → sub_18000A1B0   DoH detector on the tile
  merge keypoints; sub_18000A910 quantize tile-local→global coords
  (second 9-tile pass) sub_18000A5B0  per-keypoint DESCRIPTOR (stage 5)
  sub_1800095C0 qsorts / dedup → 250 minutiae → v30
```

So there is **no enhancement** to reverse. The detector input is plain
tiling + mid-gray pad (reproducible). The remaining unknown for native
enrollment is the **descriptor**: decompile `sub_18000A5B0` (stage 5, the
per-keypoint descriptor) and nail the exact DoH (now feasible — input is a
known tile). `sub_18000A850` (blit) and `sub_18000A910` (coord quantize) are
already DECODED in `moh_extract.py`.

**Operator confirmed = Determinant of Hessian** (GDB_DUMP_GRADIN capture of
the enhanced image, `sub_18000FDF0`'s RCX input, 57×57 int32 Q10 in
`[0,255·1024]`). Running our **2nd-derivative** `Lxx` (Sobel-5) on that
captured enhanced image correlates **+0.89..+0.92** with the DLL's `Ixx`
buffer (vs ~0 for first-derivative `Ix²`). So the detector is DoH
(`Lxx·Lyy − Lxy²`), not Harris — `DLL-RE.md`'s old "Harris" label is
wrong in operator, right in formula shape.

**The remaining wall = the enhancement transform** (raw 112² frame → the
enhanced 57² image). It is NOT recoverable from the endpoints by simple
means: the enhanced image correlates ~0 with the resized raw frame (all
interps, inverted, CLAHE, rank/value remap), a rotation sweep peaks at only
0.08, and ECC affine registration fails (ecc 0.19). ⇒ it is a genuine
content transform — orientation-field ridge enhancement / oriented filtering
that restructures the frame into a canonical ridge image — i.e. the
proprietary fingerprint front-end, upstream of the now-decoded detector.
Going further would require RE'ing that filter bank + orientation estimation
(`sub_180001A50`'s internals before the gradient stage), a large effort.

### Descriptor algorithm — FULLY DECODED (oriented BRIEF on gradients)

Per minutia, `sub_18000F350` calls two passes (`a2+80` holds the tile's
gradient buffers: `+32`=Ix, `+40`=Iy, Q-scaled; `a2+52`=patch radius):

**1. Orientation — `sub_18000D920`** → writes `record[+12]` (orientation) and
`record[+10]` (quality byte):
- Sample Gaussian-weighted gradients over a **radius-6 circular patch**
  (mask `dx²+dy²<36`). Weight = `dword_180120C00[|dy|][|dx|]` (7×7 quarter
  of a 13×13 window; center 1669 → edge 0). Values dumped:
  `[[1669,1541,1212,812,464,226,94],[1541,1422,1119,750,428,208,86],
    [1212,1119,880,590,337,164,68],[812,750,590,395,226,110,46],
    [464,428,337,226,129,63,26],[226,208,164,110,63,31,13],
    [94,86,68,46,26,13,0]]`.
- Per sample: angle = `sub_1800030A0(gy,gx)` (atan2). Build a **42-bin
  orientation histogram** weighted by gradient, smeared over 7 adjacent bins
  (mod 42). Dominant bin via `sub_18000D850` → orientation
  `record[+12] = sub_180003150(Σgy, Σgx)` (atan2, Q16 radians, full-scale
  `π·65536 = 205887.4`). Quality `record[+10]` from the peak energy.

**2. Descriptor — `sub_18000E090`** → packs bits into `*a1` (the descriptor):
- Read orientation; `idx = (record[+12]/205887.4)·180` → `cos = dword_180131050[idx]`,
  `sin = dword_1801315F0[idx]` (both `·65536`, idx 0..180, ridge orient mod 180).
- **Rotate** the sampling grid by (cos,sin), sample the Ix/Iy gradients at the
  rotated positions (OOB → `0x800000`), project onto the rotated frame
  (`gx·cos+gy·sin`, `gy·cos−gx·sin`), aggregate into blocks (`a2+52` patch,
  `a2+96`/`a2+104` block table).
- Apply **binary test pairs** `a2+112` (count `a2+44`; built by
  `sub_18000E6B0` from `BRIEF_SEED_TABLE`): bit set if
  `block[pair[0]] > block[pair[1]]`. Pack bits LSB-first into `*a1` →
  the 128-bit descriptor.

Tables (file offsets, `.rdata` VMA 0x18010a000 → file 0x108c00):
`dword_180120C00` @ file 0x11f800 (49 i32); `dword_180131050` (cos·65536) and
`dword_1801315F0` (sin·65536) are just `round(cos/sin(deg)·65536)`, 181 i32.
The BRIEF pairs come from `sub_18000E6B0` (`moh_extract.BRIEF_SEED_TABLE`).

**This completes the pipeline RE.** Everything from raw frame to `v30` is now
classical CV with known tables — see `NEXT-SESSION.md` for the
implementation plan (port + validate against captured `v30`).

### Gradient kernel chain (decoded; the bit-exact leaves remain)

`sub_18000F250` → `sub_1800101C0` → `sub_180010050` build the `Ixx/Iyy/Ixy`
tensor buffers from the tile:

- `sub_1800101C0`: scale `a5` → odd kernel sizes `v8,v9` (`size ∝ scale`,
  `218453≈(10/3)·65536`), delegates to `sub_180010050`.
- `sub_180010050`: allocs 1D kernel buffers; `sub_18000FFE0` fills them;
  `sub_18000FDF0(img, …, kx, ky, …, 12)` applies them (separable).
- `sub_18000FFE0` → `sub_18000FF00` (×2): builds a **normalized 1D Gaussian**
  kernel — taps centered (step 1024 = 1px Q10), width coeff `−2²⁹/σ²`,
  σ-proxy `(157184·size+367309)>>10`, tap value via `sub_18000FEC0` (an
  **exp lookup** into `unk_180130F80`), normalized to constant sum.
- So the kernels are **Gaussian smoothing**; the derivative + per-pass
  Q-truncation live in `sub_18000FDF0`/`sub_18000F460`/`sub_18000F840`.

Empirical (from `gradin>>6` → buffers): `Ixx`,`Iyy` recover as **7×7 linear**
kernels at corr **0.998** (Gaussian-smoothed 2nd-difference). `Ixy` does NOT
(corr 0.19) — explained by the passes:

**`sub_18000F460` (horizontal) / `sub_18000F840` (vertical)** = the separable
1D convolution. The load-bearing detail: each accumulates
`acc += (pixel · tap) >> a8` with **`a8 = 12`** — every tap product is
**truncated `>>12` before summing** (per-term, not at the end). That
truncation is nonlinear and compounds across the two perpendicular passes,
which is why `Ixy` (x-pass then y-pass) won't recover as a single linear
kernel while `Ixx`/`Iyy` (truncation-dominated by one axis) nearly do. Both
passes handle left/middle/right edges explicitly with a rotating buffer.

**RESOLVED (disassembly, this session — objdump on `/tmp/syna.dll`).** The
whole DoH detector chain is now decoded; the derivative enters as a
**finite-difference stencil in a separate 3-tap kernel builder**, not in the
Gaussian taps. Full chain:

```
gradin (57×57 Q10)
 └ sub_18000F250:  per-pixel img >>= 6                       (Q10 → Q4)
     ├ sub_1800101C0 → sub_180010050:  Gaussian PRE-SMOOTH    (shift 12)
     │     two Gaussian kernels (FFE0/FF00/FEC0), σ ∝ scale, sum→4096 (Q12)
     ├ per-pixel img <<= 6                                    (Q4 → Q10)
     └ sub_18000CE80:
         ├ sub_18000CC20:  build 3 Hessian planes via sub_180010380×  (shift 10)
         │     per call sub_180010280 builds the (kx,ky) pair by type flag:
         │        type 0 (smoothing): [c, c·0xd55>>10, c]  ≈ [1, 3.33, 1]
         │        type 1 (derivative): [1024, 0, -1024]     = central diff [1,0,-1] Q10
         │     planes: Ixx(+0x30), Ixy(+0x38), Iyy(+0x40); ·scale / ·scale² normalize
         │     (Ixy = [1,0,-1]_x ⊗ [1,0,-1]_y — the per-tap >>10 in BOTH passes
         │      is exactly why Ixy never recovered as a single linear kernel)
         └ resp(+0x50) = (Ixx>>12)·(Iyy>>12) − (Ixy>>12)²
         └ sub_18000CF90:  8-neighbour NMS + thresh([+0x20],[+0x24]) + dist-dedup → kp
```

Key bit-exact facts (all from disasm, ready to port):
- **`unk_180130F80`** = 52-entry exp table, `table[i]=round(65536·exp(-0.19531·i))`,
  `table[51]=0`. (A separate cos-style table follows it in `.rdata`.)
- **`sub_18000FEC0`** (Gaussian tap): `t=(coef·x²>>10)`; `idx=((t·0x51eb851f)>>35,
  rounded)>>13`; returns `table[-idx]` (indexed backward). `coef=−2²⁹/σ²`,
  `x`=tap pos Q10 (step 1024=1px).
- **`sub_18000FF00`** (1D Gaussian): σ-proxy `(157184·n+367309)>>10`; tap=`FEC0>>4`;
  normalize `tap·(2³⁰/sum>>3)>>15` → kernel sums ~4096 (Q12).
- **`sub_18000F460`/`F840`** (separable apply): `out[x]=Σ (in[x+k]·kernel[k])>>shift`,
  per-term truncation; explicit left/middle/right edge regions w/ a scratch row.
- **shift is 12 for the Gaussian smooth (`sub_180010050`) and 10 for the
  derivative planes (`sub_180010380`)** — note the two regimes.

**Response formula VALIDATED bit-exact + capture note.** `harris_resp_*` and
`harris_Ixy_*` are byte-identical (all px, call0-3) because the DLL computes the
response **in-place over the Ixy buffer** (`+0x50` and `+0x38` are the same
allocation; the dump only fires on the `flag=0` path, so the response DID run).
Both files therefore hold the **real response map** — a valid oracle. Proof:
`(Ixx>>12)·(Iyy>>12) − resp` is a non-negative PERFECT SQUARE at every pixel
(3249/3249, call0-3) ⇒ `resp = (Ixx>>12)(Iyy>>12) − (Ixy>>12)²` exactly, and the
plane labels (`+0x30`=Ixx, `+0x40`=Iyy) are confirmed. Consequences:
- `harris_resp`/`harris_Ixy` = the real response (bit-exact oracle).
- there is NO separate raw-Ixy capture (it was overwritten in-place), but
  `|Ixy>>12|` is recoverable as `sqrt((Ixx>>12)(Iyy>>12) − resp)`.
(The earlier "resp corr 0.949" undershot only because it compared a *computed*
resp against this map without an exact gradient; the formula was always right.)

**`sub_18000CC20` dataflow — DECODED (Hex-Rays).** Per block (struct stride
0x70, base `B = ctx[+0x50] + i·0x70`):
```
scale v9 = (ctx[+0x18]·B[+0x5c] >> B[+0x60] + 0x80000) >> 20 ;  v10 = v9²
# sub_180010380(dst, src, type_x, type_y, v9, w, h, image):
#   in-place separable filter on dst (src!=0 ⇒ copy dst→src, filter src);
#   each pass = dst>>=6 ; F460(kx=type_x) ; F840(ky=type_y) shift 10 ; dst<<=6
#   type 0 = smooth [c,3.33c,c]  type 1 = deriv [1024,0,-1024]  (taps at ±v9)
prep1: (buf48, buf28, 0,1)        prep2: (buf48, 0, 1,0)     # build Dx,Dy
norm1: buf20[*] *= v9 ; buf28[*] *= v9
plane: (buf20, buf38, 0,1)  → Ixy=Dy(buf20)
       (buf20, 0,     1,0)  → Ixx=Dx(buf20)        # +0x30 ≡ buf20
       (buf28, 0,     0,1)  → Iyy=Dy(buf28)        # +0x40 ≡ buf28
norm2: Ixx[*]*=v10 ; Ixy[*]*=v10 ; Iyy[*]*=v10
```
⇒ `Ixx=v9³·DxDx`, `Iyy=v9³·DyDy`, `Ixy=v9³·DyDx` of the Gaussian-pre-smoothed
tile, each pass deriv on one axis + smooth on the other, per-pass >>6/<<6.

**PORT STATUS (scripts/port_gradient.py): BYTE-EXACT** ✅ — `Ixx`/`Iyy`/`Ixy`
reproduce the per-pass `GDB_DUMP_G380` captures with **0 mismatches** (interior;
edges pending the exact L/M/R region logic). The per-pass dumps cracked three
details that blind reconstruction missed:
1. **smoothing `c = 0x100000/(scale·0x2aaa)`** uses `scale` (=v9), NOT
   `n=2·scale+1` ⇒ scale 1 → c=96, and `mid = round(c·0xd55/1024) = 320`
   (the DLL ROUNDS, `(c·0xd55+512)>>10`), so the smoothing 3-tap is
   **[96,320,96]** (sum 512, gain 0.5) — earlier [32,106,32] was ÷3 too small
   (the spurious "~591/3.01×" factor).
2. **F460/F840 are true CONVOLUTIONS (kernel reversed)**, so the derivative is
   `in[x+1]−in[x−1]` (not `in[x−1]−in[x+1]`). Sign cancels in Dx∘Dx (why the
   final planes still positively-correlated) but shows up in single-deriv passes.
3. chaining confirmed from the dumps: `call3_before == call1_after` ⇒ for these
   tiles **v9=1** (norm1/norm2 are identity).
**Gaussian PRE-SMOOTH now BYTE-EXACT too** (combined gradin+g380 run): CC20's
input = `<<6( Gaussian₅(tile, shift 12) )` — Gaussian size 5, applied to the Q10
tile directly (NOT >>6 first), shift 12, then <<6. 0 mismatches (border 2) vs
g380 call1_before. ⇒ **the whole DoH front-end `gradin → Ixx/Iyy/Ixy/resp` is
byte-exact end-to-end** (scripts/port_gradient.py `doh()`; 0 mismatches at border 5).
This also validates the FF00/FEC0 Gaussian-builder port. The Gaussian size (5
here) comes from ctx[+0x14] via sub_1800101C0's size calc — parametrize when a
varying-scale tile appears. REMAINING for full-tile (not interior) exactness:
the F460/F840 edge-region (L/M/R) logic — my replicate-edge diverges within ~5px
of the boundary (pre-smooth±2 ⊗ derivatives); the interior is exact and NMS
excludes borders anyway.

REMAINING = pure implementation: port the two builders + the separable apply +
the 3-plane dataflow in `sub_18000CC20`, then validate **bit-exact** against the
captured `harris_Ixx/Iyy/Ixy/resp` planes (57×57) in `$FRIDA_DUMP_DIR` (already
on disk; `scripts/diff_v30.py compare_harris`). The exact per-plane source/dest
buffer wiring in `sub_18000CC20` (struct offsets +0x20/+0x28/+0x30/+0x38/+0x40/
+0x48/+0x50) and the scale params from the ctx struct ([+0x18],[+0x5c],[+0x60])
are the only thing to read off carefully during the port. See
`NEXT-SESSION.md`.

### BRIEF descriptor selection

| VA              | Role                                                  | Status |
|-----------------|-------------------------------------------------------|--------|
| `sub_18000E6B0` | **BRIEF test selection.** Builds 162 candidate `(x1,y1,x2,y2)` test pairs across 3 grid resolutions (2x2, 3x3, 4x4 — pairs counts 6+36+120=162). Selects 64 tests deterministically using a 128-entry hardcoded LFSR-like seed table. First 6 always picked sequentially; remaining 58 picked by `seed[i] mod len(remaining)`. | DECODED — `moh_extract.py:sub_18000E6B0`, table is `BRIEF_SEED_TABLE` |

The 128 hardcoded seeds are the "learned" random walk that defines this
algorithm's specific test set. They are: 3382, 4039, 29605, 1734, 19683,
2304, 17019, 16644, 10030, ... (see `BRIEF_SEED_TABLE` in
`moh_extract.py` for the full list).

### 9-stage orchestrator `sub_18000AAB0`

Called once per frame. 478 lines of disassembly, 9 internal stages.
Parameter block from `sub_180004C10`:

```
{ f0=500 (COORD_SCALE), f4=250 (MAX_MINUTIAE),
  f8=10  (GRID_X),     fc=7   (GRID_Y),
  f10=1126 (X range), f14=671 (Y range),
  f18=16 (small block), f1c=128 (large block), f20=0 }
```

| Stage VA          | Stage name                              | Status |
|-------------------|-----------------------------------------|--------|
| `sub_180003320`   | stage 1 — stream-advance dispatcher     | calls `sub_1800032C0` (decoded); routes to primary/secondary cursor |
| `sub_180003460`   | stage 2 — stream descriptor builder. 0x30 bytes: u32 size, u64 base ptr, u64 cursor ptr, 24 zeros | DECODED |
| `sub_1800095C0`   | qsort (CRT generic) — invoked with the 4 comparators below | use Python `sorted()` |
| `sub_18000A4B0`   | stage 4 — two-stage glue: `sub_18000A1B0` (197 insn, structural) → `sub_18000F300` (94 insn, SIMD; per-feature work) | not ported |
| `sub_18000A5B0`   | stage 5 — 122 insns                     | not decompiled |
| `sub_18000A850`   | stage 6 — row-iteration loop. Calls `sub_1800031E0` (memcpy) per row; effectively an image blit with strides | DECODED — `moh_extract.py:stage_6_18000A850_row_loop` |
| `sub_18000A8E0`   | stage 7 — edge flags (already covered above) | DECODED |
| `sub_18000A910`   | stage 8 — coord quantize (already covered above) | DECODED |
| `sub_18000A960`   | stage 9 — 91 insns                      | not decompiled |

### qsort comparators (all operate on 32-byte minutia records)

All four were decoded; Python uses `sorted(key=...)` to reproduce each:

| VA              | Sort order                              | Python key                          |
|-----------------|-----------------------------------------|-------------------------------------|
| `sub_18000A7C0` | asc by `score_10` (int32 at +0x10)      | `cmp_score_10_asc`                  |
| `sub_18000A7E0` | asc by `active` then `score_10`         | `cmp_active_then_score_10`          |
| `sub_18000A810` | asc by `flag9` then **desc** by `score_10` | `cmp_flag9_then_score_10_desc`   |
| `sub_18000A940` | asc by `score_c` (int32 at +0x0C)       | `cmp_score_c_asc`                   |

### Minutia record (32 bytes)

Layout inferred from the qsort comparator field references:

```
offset  size  field           notes
0       8     head            (x, y, theta?, type? — bytes we didn't crack)
0x08    1     active          0/1 flag
0x09    1     flag9           0/1 flag
0x0A    2     pad             zero
0x0C    4     score_c         int32, signed (qsort key)
0x10    4     score_10        int32, signed (qsort key)
0x14    12    tail            unknown trailing fields
```

The 250-slot minutia table is at session+152 in the session buffer
(see `sub_1800D89C0`).

### Memory plumbing

| VA               | Role                                          | Status |
|------------------|-----------------------------------------------|--------|
| `sub_180003460`  | Stream descriptor builder (30 lines)          | DECODED |
| `sub_1800031E0`  | Custom memcpy with dword fast-path            | DECODED (Python: slice assign) |
| `sub_1800032C0`  | Stream descriptor advance with bounds check   | DECODED |

### Crypto / hashing

| VA               | Role                                          | Status |
|------------------|-----------------------------------------------|--------|
| `sub_18004B710`  | CryptHashData wrapper → SHA-256               | body decompiled |
| `sub_18004E640`  | Hash output format selector. Returns 32 (SHA-256), 20 (SHA-1), or 16 (MD5) depending on `select` arg | body decompiled |
| `sub_1800A4AD0`  | Probably CryptDecrypt/CryptDuplicateKey path — touches `bcrypt.dll`, key handles | not fully decompiled |

The 32-byte TID at template offset 23072 is a **two-iteration
HMAC-SHA256 chain** with a key derived from the WS body itself,
not plain SHA-256 of WS. (The exact DLL function is unconfirmed — the
earlier "sub_1800E0A60 orchestrator" attribution was wrong; that's memset.
`sub_18004B710` = a CryptHashData/SHA-256 wrapper is plausibly involved, but
unverified.) The recipe itself is empirically verified end-to-end; full
reference implementation: `MOH.md` "TID derivation" and
`validitysensor/moh_extract.compute_tid()`.

### WS-body packer chain (DECODED — the descriptor serialization path)

The WS body is a **TLV container**, written per-frame by this chain.
Full byte layout + live validation in `MOH.md` "WS body layout".

| VA              | Role                                                  | Status |
|-----------------|-------------------------------------------------------|--------|
| `sub_180001A50` | Feature extraction: image → feature buffer. Calls `sub_180004C10` → orchestrator `sub_18000AAB0`. | body decompiled |
| `sub_180002240` | **WS-body packer.** `(algo, ws, &stats, features, w, h)`. Builds a stream cursor over `ws`, runs `sub_180001FE0`, appends one ~4540-B section per accepted frame via the `sub_18005xx`/codec writers. | DECODED |
| `sub_180001FE0` | Builds **180-byte working records** (45 dwords); record fields +0 (quality, `3000−1200·q/1024`), +6/+10 (u16 → stats), +136 (coverage). Calls `sub_180008F10` to write the section payload. | body decompiled |
| `sub_180008F10` | **Descriptor-write engine** (435 insn) — writes the section payload from the 180-B records / features. *The remaining unknown for native enrollment.* | not decompiled |
| `sub_180003320` | **Enrollment accumulator** — returns the persistent 180-B record stream; new region zeroed via `(*(algo+9))()`. (Resolves the old "accumulator between orchestrator and serializer".) | DECODED |
| `sub_180006A80` | TLV record writer: header dword `tag\|(len<<16)` (len → mult of 4), then memcpy `len` payload bytes (`sub_1800031E0`). | DECODED |
| `sub_180006890` | Keyed slot manager: find/insert by tag, grow via `sub_180006970` (byte shift). Makes the container keyed, not flat-append. | not decompiled |
| `sub_180006B80` | Thin field writer → `sub_180006A80` with `{tag, len=4, value}`. | DECODED |
| `sub_1800056C0` | Field writer → TLV `{tag = v+3, payload = buf}`. | DECODED |
| `sub_180005B70` | Field writer → TLV `{tag=3, len=4, value}`. | DECODED |

### 180-byte working record (the per-minutia descriptor builder output)

`sub_1800046E0` fills one 180-byte record (45 dwords) per minutia from the
image patch. Decoded from a 12-minutia live capture (`scripts/gdb_dump.py
GDB_DUMP_DESC=1`, dumping the record at `[rsp+0x30]` before/after the call).
The input image is **128×128 8-bit grayscale** (confirmed by row
correlation; `desc_image_*` dumps). Builder writes dwords `[1–4], [23–35],
[38–40]`:

| dword | observed range | role (inferred) |
|-------|----------------|-----------------|
| `[1],[2],[4]` | signed, ±3M, sign-extended | signed feature vector (orientation/gradient sums or sub-pixel offset). **NOT a binary descriptor** — popcount scatters 18..43, values are signed. |
| `[3]` | ~65536 | normalization (1.0 in 16.16) |
| `[23,24,26,27]` | 7..41 | small params; `[25]` = const 25 |
| `[28]=[32], [33], [29,30,31]` | 71..8180 | response block (Harris / scale-extrema magnitudes; the high-entropy source) |
| `[34]=[40]` | 62..172 | position-like (scaled/padded space, not raw 0..128 pixels) |
| `[35]` | 46..95 | position-like (y, fits 0..128) |
| `[38]` | 3..7 | scale / octave |
| `[39]` | 334..498 | orientation-ish |

After the call, `sub_180008F10` shuffles 5 of these into output slots
(`v28[36]=v28[26]`, `[37]=[34]`, `[41]=[39]`, `[42]=[38]`, `[43]=[40]`).

**`sub_1800046E0` is actually a per-keypoint pose/model FITTER** (the full
decompile shows it collecting ≤25 candidate 28-byte keypoints, qsorting via
`sub_180004600`, solving with `sub_180007480`), not a descriptor extractor.
`record[1..4]` = the solver pose `a1`; `[23]`=quality, `[24]`=inlier count.
`sub_1800043D0(record+104, …)` fills `[26..43]`.

**record→section mapping (from a combined DESC+PACKER capture):** the pose
`record[1],[2]` serializes **verbatim** as int32 into 18-byte section pose
records (`[3B flags][i32 pose1][i32 pose2][i32 field][3B tail]`, pose1@+3
pose2@+7). The first frame's reference pose goes to the WS header
(offset 49/53/57). After the ~276-byte header/pose region, **the rest of
each section is the packer's input feature buffer `v30` copied verbatim**
(98.9% byte-identity at shift 280) — i.e. the output of `sub_180001A50` →
orchestrator `sub_18000AAB0`. `sub_1800043D0` only fills `record[26..40]`
metadata + samples image patches into scratch; it does NOT produce the
section blob. So native enrollment reduces to reproducing `v30` bit-for-bit
(see `MOH.md` "Implication for native enrollment").

### Envelope serialization (the final write step)

| VA               | Role                                                 | Status |
|------------------|------------------------------------------------------|--------|
| `sub_180036840`  | **Envelope serializer.** 8-byte outer header + 4-byte TLV1 header + ws_body + 4-byte TLV2 header + TID + 32 trailing zeros. | DECODED — `moh_extract.py:_build_envelope` |
| `sub_18003D7C0`  | Caller pass-through; effectively identity            | DECODED — no-op |
| `sub_180036590`  | Validation wrapper that forwards to `sub_180036840` with a constant 5th arg (110, used as a default error code on alloc failure). | body decompiled |
| `sub_180031CD0`  | Caching wrapper around `sub_180036590`. Memoizes the envelope output keyed on `(a2_buf, a3_buf)` so identical inputs don't re-serialize. | body decompiled |

The byte-exact envelope structure (verified against five distinct
chip-accepted Wine captures, see `scripts/extract_finger_templates.py`) is:

```
offset      size    field
─────────────────────────────────────────────────────────────────
[0..2]      2       u16 subtype
[2..4]      2       u16 version  (= 3)
[4..6]      2       u16 payload_size  (= 4 + ws_size + 4 + tid_size)
[6..8]      2       u16 trailing  (= 32)
[8..10]     2       u16 tlv1_tag  (= 1)
[10..12]    2       u16 tlv1_len  (= ws_size)
[12..12+n]  n       ws_body  (chip-view; first 4 bytes always 0x00*4)
[12+n..14+n] 2      u16 tlv2_tag  (= 2)
[14+n..16+n] 2      u16 tlv2_len  (= tid_size = 32)
[16+n..48+n] 32     TemplateId (HMAC-SHA256 chain over ws_body)
[48+n..80+n] 32     trailing zeros

total = 8 + 4 + ws_size + 4 + 32 + 32  =  ws_size + 80
      = 23136 when ws_size = 23056
```

**Critical correction:** earlier versions of this doc described an
8-byte inner header (TLV1 tag + len + "4 reserved zeros") followed by a
23056-byte WS body at envelope offset 16, and the TID written raw at
envelope offset 23072. That model produces correct output bytes by
coincidence — the "reserved zeros" we wrote happen to overlap with the
first 4 bytes of the real WS body (which the chip also reads as zeros),
and the "WS body tail" we thought we were writing actually contained the
TLV2 header. The serializer's real layout has the WS body starting at
offset 12 and the TID introduced by a TLV2 header at offset 23068. See
`MOH.md` "Wire format" for the full table.

---

## Constants and magic values found

| Name                  | Value           | From                       |
|-----------------------|-----------------|----------------------------|
| `MAX_MINUTIAE`        | 250 (0xfa)      | `sub_180004C10` param block |
| `GRID_X` / `GRID_Y`   | 10 / 7          | `sub_180004C10` param block |
| `COORD_RANGE_X` / `_Y`| 1126 / 671      | `sub_180004C10` param block |
| `COORD_SCALE`         | 500             | `sub_180004C10` param block |
| `BLOCK_SIZE_SMALL`    | 16              | `sub_180004C10` param block |
| `BLOCK_SIZE_LARGE`    | 128             | `sub_180004C10` param block |
| `SENSOR_DPI`          | 363             | derived from MoH device specs |
| `SENSOR_W` / `SENSOR_H` | 112 / 112     | wire trace image size      |
| `MAX_BAD_FRAMES`      | 6               | `sub_1800D89C0` cap        |
| `MOH_MODE_FLAG`       | 101             | vtbl(this)[+24] dispatch   |
| `SESSION_MAGIC`       | 0x4C4F4356 ("VCOL") | `sub_1800D89C0`         |
| `SESSION_VERSION`     | 8               | `sub_1800D89C0`            |
| `SESSION_HEADER_LEN`  | 152             | `sub_1800D89C0`            |
| `PADDING_FILL_VALUE`  | 0x800000        | `sub_180009F50` (16.16 fp) |
| `BRIEF_SEED_TABLE`    | 128 u16 values  | hardcoded in `sub_18000E6B0` |

---

## What we proved at the protocol level (no DLL needed)

Detailed in `MOH.md`. Summary:

- **Storage** path: chip stores any 23136-byte template with no content
  validation; only structure (size + envelope framing) is checked.
- **Match**: chip can match a Wine-captured template against a live finger
  *across reboots, across Linux sessions, regardless of which user the
  template is re-parented under or what subtype byte is patched into the
  header*. → encryption is **device-bound**, not session-bound.
- **Identify-hash**: stable per-enrollment ID, deterministic function of
  the stored WS bytes; useful as auth primitive.
- **Trailer byte**: appears after the data, outside the u16 length field.
  Varies per template (`0x11`, `0x70`, `0x86`, `0xa9` observed). Probably
  a record-type marker; semantics unknown.

---

## Open questions / dead ends

1. **What is the per-field bit layout of the WS-body feature sections?**
   THE blocker for native enrollment. Black-box analysis is exhausted
   (see "WS body feature encoding (black-box findings)" in `MOH.md`):
   the sections are **bit-packed** (entropy 7.86), **not an image** at
   any (skip, width) — a 93k-combination correlation sweep peaks at 0.485
   vs 0.81 for a real frame — and **not byte-aligned records**. The
   packing period is **36 bytes (two 144-bit units)**. Going from
   "36-byte packed units" to "bits a..b = x, bits c..d = y, …" needs
   **known inputs**: dump the in-memory minutia table beside the WS body
   via `scripts/frida_dump.py` and search for known field values inside the
   36-byte records of a clean mid-section.
2. **What is the trailer byte?** Hash byte? Subtype-related? Per-record
   counter encoded in single byte? Captured values: `0x11`, `0x70`,
   `0x86`, `0xa9`.
3. **What do offsets 4845, 9433, 13973 in the WS actually represent?**
   Stable structured anchors with an index (4,5,6,7,8) and constant
   `0xfa = 250` — section trailers separating the bit-packed feature
   sub-blocks.
4. **The 4 high bytes of the in-memory minutia head** (+0..+7) and the
   tail bytes: probably (x, y, theta, type, quality). NOTE: this is the
   *in-memory* 32-byte working record. The WS body does NOT store these
   32-byte records — it serializes them into the bit-packed form above.

### Resolved (originally listed open questions, now answered)

- ~~**Where is the encryption step?**~~ Likely no symmetric encryption
  pass. The Wine crypto trace shows the only cipher covering the finger
  record is the TLS-layer AES-256-CBC wrap of the whole wire payload,
  which the chip's TLS endpoint decrypts — leaving the WS body verbatim
  for storage (`db.dump_raw` confirms). CAVEAT: the main feature sections
  are bit-packed high-entropy data (7.86 bits/byte), not "plaintext
  signed-int feature data" as earlier drafts claimed — that only held
  for the low-entropy prelude. The byte skew (0x44 ~3.5× uniform) argues
  against AES (which is uniform) and for bit-packed binary descriptors.
  So: not symmetric-encrypted, but also not trivially readable — it's a
  bit-packed serialization. See `MOH.md` "WS body feature encoding".

- ~~**How is the 32-byte TID at offset 23072 derived?**~~ HMAC-SHA256
  chain with a self-derived key, decoded from `enroll-fresh.log` lines
  1570→1583:

  ```
  K   = SHA-256(ws_body)              # ws_body = template[12:12+23056]
  T1  = HMAC-SHA256(K, "Template ID" ‖ 32×0x00)
  TID = HMAC-SHA256(K, T1 ‖ "Template ID" ‖ 32×0x00)
  ```

  No device-bound or session-bound secret. Reference implementation:
  `validitysensor/moh_extract.compute_tid()`. Verified end-to-end
  against fresh.bin's stored TID. The "host-derived vs chip-generated"
  hypothesis pair from the previous version of this question is
  resolved in favour of **host-derived** — the host computes the TID
  from the WS body and writes it into the envelope before sending.

---

## Files in this repo to look at

- `validitysensor/moh_extract.py` — Python ports of decoded functions:
  constants, qsort keys, Minutia struct, BRIEF seed table, envelope
  serializer, and `compute_tid()` (the verified HMAC-SHA256 chain).
- `validitysensor/moh_opencv.py` — OpenCV-based PoC (Sobel + Harris +
  BRIEF + envelope + compute_tid). Now produces structurally-valid
  envelopes with correct TIDs; the open question is whether the
  feature-extraction approximation is close enough to the DLL's that
  the chip's matcher accepts our minutiae. Test by running, storing,
  then identifying — see `MOH.md` "Why the OpenCV PoC didn't match".
- `MOH.md` — protocol-side findings, replay workflow, TID recipe.
