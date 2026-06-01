# Per-section metadata synthesis — the 24-byte v30 trailer + header geometry_stats/blob

> **HARDWARE VERDICT (2026-06-01): the per-section trailer is NOT load-bearing.**
> A/B on a live from-scratch enroll: matched with the trailer REGENERATED *and*
> with it COPIED STALE (`--no-regen-trailer`). So `sub_18000c6a0` verify scores
> only `[x][y]` grid occupancy + `sec0_pre`; this metadata is enroll-only
> bookkeeping. Regeneration (`build_section_trailer24`, wired into
> `native_template`/`enroll_native`) is correct/honest but OPTIONAL. Load-bearing
> content = v30 `[desc][x][y]` records + `sec0_pre` (identity suffices).

Scope: the finger-DEPENDENT per-section metadata that currently gets **copied
from a stale scaffold** (`validitysensor/native_ws_scaffold.bin`) instead of
generated for OUR keypoints. Two artefacts:

1. the **24-byte per-section v30 trailer** (`[H+0xc][secobj+0xc][22-byte
   orientation CDF]`), emitted by `sub_1800057e0` right after each section's
   v30 record area;
2. the **WS-body header** zones — `per_section_counts` `[24:40)`,
   `sec5cnt+flags` `[40:44)`, `geometry_stats` `[44:64)` — plus the related
   per-section **quality blob** (`[0x54,0x5c,0x5c,0x5a,0x57]<<24`) inside
   `sec0_pre`.

Cross-refs: `scripts/bucket_table_180005720.py` (proven byte-exact port of #1),
`decode_sub_180008f10.md` §8/§9, `SCORER-sub_18000c6a0.md`,
`PRE_V30-decode.md`, `V30-emitter-and-layout.md`.

---

## 0. Where everything lives in the template (byte map)

Envelope = `[2B subtype][...][12B prefix] + WS_BODY(23056) + TID`. All offsets
below are **into the WS body** (`ws_body = envelope[12:12+23056]`).

```
[0  : 4 )  zeros                                            CONST
[4  : 8 )  size_u32 (0x59fc=23036)                          CONST (formula)
[8  :16 )  config  06 02 05 00 02 00 08 01                  CONST
[16 :24 )  id      04 03 02 01 00 00 00 00                  CONST
[24 :40 )  per_section_counts  4×u32                        VARIANT (session accumulator)
[40 :44 )  sec5cnt + flags  [b0=5th count][b1=#sec][b2,b3]  PARTIAL/VARIANT
[44 :64 )  geometry_stats   5×i32 (signed)                  VARIANT  <-- header pose stats
[64 :309) sec0_pre  (TLV: leads + quality-blob + N markers
          + upper-triangle 18B rigid-Q16 transforms + marker) VARIANT (multi-frame)
...
per v30 SECTION i (record area at anchor_i − 16):
   [ N × 18B v30 records: [16B desc][x:u8][y:u8] ]          CONTENT (we build this)
   [ 24B TRAILER ]:                                          <-- artefact #1
       +0   u8  H+0xc      (the bucket-table split index)
       +1   u8  secobj+0xc (a second per-section byte)
       +2 .. +24  22B orientation-bucket CDF (two 11-byte halves)
```

**find_v30_regions anchors** for the shipped scaffold = `(309, 4913, 9453,
13993)` — note the scaffold has only **4** sections (a mode-A `fresh.bin`),
whereas the byte-exact capture used for decode (`ws_body_1780253488249`) had
**5** sections at anchors `(309,4913,9453,13993,18533)`. The trailer of section
`i` sits at `anchor_i − 16 + N×18`. With the standard `N=250` that is
`anchor_i − 16 + 4500`.

---

## 1. Definitive spec of the two artefacts

### 1A. The 24-byte per-section v30 trailer — FULLY DECODED, byte-exact

Emitted by the v30 serializer `sub_1800057e0` (`/tmp/func_1800057e0.S`) at the
tail of each section, after the `N × 18` records:

| trailer byte(s) | source | meaning |
|---|---|---|
| `+0` (u8) | `BYTE[H+0xc]` (`0x180005887`) | **split index**: boundary between the two CDF halves. An independent per-section field (NOT derivable from orientation; sec0 has 21 kp at bucket≥11 *inside* `[0,141)`). |
| `+1` (u8) | `BYTE[secobj+0xc]` (`0x180005893`) | a second independent per-section byte. |
| `+2 .. +24` (22 B) | two `sub_180005720` calls | **orientation-bucket CDF**, two halves of 11 buckets. |

**Generating algorithm** (`sub_180005720`, byte-exact in
`scripts/bucket_table_180005720.py`; self-test `ALL SECTIONS BYTE-EXACT: True`):

- Per keypoint `i` the source array `S` (stride `0x20`) holds the orientation at
  `u32[S + i*0x20 + 0x0c]`. `bucket(i) = orient // 15` (DLL magic
  `0x88888889 >> 35`, verified ≡ `//15` over all u32).
- The 22 bytes are a **per-bucket CDF storing absolute kp indices**, split into
  two halves:
  - `buf[0:11]` = call1, over kp `[0, split)`, `fill_base=0`;
  - `buf[11:22]` = call2, over kp `[split, N)`, `fill_base=0x0b`.
- `buf[fill_base+k]` = absolute index of the first kp in that half whose bucket
  exceeds `k` (= count of kp in the half with bucket ≤ k). Buckets the half
  never reaches are padded with the half's `limit` (`split` for call1, `N` for
  call2).
- **Precondition: `S` must be sorted ascending by orientation WITHIN each
  half** — the fill only advances on bucket increases, so the output is only
  valid (monotone) if bucket is non-decreasing. The captured sequences are
  strictly monotone, confirming the chip sorts.

Observed sec0 (enroll 1780253459): `[141,84, 21,28,29,31,42,68,92,105,109,112,
120, 157,164,164,164,174,200,220,224,225,227,233]`. Reproduced verbatim.

### 1B. Header `geometry_stats` `[44:64)` (5×i32) + the sec0_pre quality blob

Two DISTINCT artefacts that the prior notes conflated:

**(a) `[rec+0x38]` frame-selection quality (0..3000)** — produced by
`sub_180008980` (`decode_sub_180008f10.md` §9). The clamp/quantize stage and
its 17-channel `[base,denom]` table `@0x18011fb90` are byte-exact; but the final
scalar comes from a learned regression (`sub_180002d20`) whose coefficient
matrix lives in a **runtime ctx object**, so `[rec+0x38]` is **not statically
reproducible**. This value is compared to `0x699=1689` to pick the best frame —
it is *internal frame selection*, NOT a template byte.

**(b) sec0_pre quality blob `[0x54,0x5c,0x5c,0x5a,0x57]<<24`** (bytes
84,92,92,90,87) — one u32 per section, written into the pose-object blob array
(`obj+8`) by the **matcher path** `sub_18000c6a0`/`sub_18000bdf0`, appended
one-per-section across the 5 serializer calls, then serialized into `sec0_pre`
by `sub_1800051f0` (`[blob: edi*4 bytes from *(obj+8)]`, see
`PRE_V30-decode.md` §"sec0_pre serialization"). It is a per-section quality
**byte**, NOT `[rec+0x38]` (which is 0..3000 and cannot fit `<<24`). Deriving it
from scratch needs the `c6a0`/`bdf0` blob-byte logic, which is not decoded.

**(c) `geometry_stats` `[44:64)` (5×i32)** — UNRESOLVED. Candidate: a 5-element
projection of the `sub_180008980` quantized 34-element pose vector (the
`/1024` 16.10 fixed-point reference vector), but this is **not byte-confirmed**.
The pose vector itself needs the runtime regression context. In the shipped
scaffold these 5 ints are large signed values
`(16746787, -1030656, -394568705, -396257793, -1407088385)` — clearly a packed
fixed-point / multi-frame product, NOT something a single native frame yields.

**(d) `per_section_counts` `[24:40)` + `[40:44)`** — session cross-frame
consensus accumulators (tag-`0x6c` family, `algo+0x130..`); a single-frame
native template has no cross-frame consensus, so these are not naturally
producible either. Scaffold values: `(76, 90, 86, 89)` + `[0,4,1,123]`.

---

## 2. Generation plan (moh_native.py style)

The clean artefact is #1 (the 24-byte trailer). The header/blob artefacts
(#1B b/c/d) are **multi-frame matcher products** that a single native frame
cannot reproduce. Plan accordingly.

### 2A. NEW module helper — port the trailer generator into the package

Promote the proven `scripts/bucket_table_180005720.py` into the package (or import
it) and add a per-section trailer builder that consumes OUR per-section kp list.
Our `extract_frame_native` already yields `(gx, gy, orient_q16, desc)` tuples;
the trailer needs `orient_q16` (the same field `S+0xc`).

```python
# validitysensor/moh_native.py  (new section)

ORIENT_BUCKET_DIV = 15
TRAILER_BUCKETS   = 11   # per half

def _bucket_of(orient_u32):                 # == orient // 15 (DLL 0x88888889>>35)
    return (orient_u32 & 0xFFFFFFFF) // ORIENT_BUCKET_DIV

def _fill_cdf(buf, orient, fill_base, i_start, limit):   # exact sub_180005720
    prev = bucket = 0
    for i in range(i_start, limit):
        bucket = _bucket_of(orient[i])
        if bucket > prev:
            for c in range(fill_base + prev, fill_base + bucket):
                buf[c] = i & 0xFF
        prev = bucket
    if bucket < TRAILER_BUCKETS:
        for c in range(fill_base + bucket, fill_base + TRAILER_BUCKETS):
            buf[c] = limit & 0xFF

def build_section_trailer24(section_records, split=None, secobj_byte=None):
    """24-byte v30 trailer for ONE section's kp list.

    section_records: list of (x, y, desc, orient_q16) for the N kp that went
        into this section's v30 record area, ALREADY SORTED ascending by
        orient_q16 within each half (see note). N = len(section_records).
    split: BYTE[H+0xc]. If None, use the self-consistent natural split =
        count of kp with bucket <= 10 (orient < 165). secobj_byte: BYTE
        secobj+0xc; if None copy the scaffold's byte (independent field).
    """
    n = len(section_records)
    orient = [r[3] & 0xFFFFFFFF for r in section_records]
    if split is None:
        split = sum(1 for o in orient if _bucket_of(o) <= 10)
    buf = bytearray(22)
    _fill_cdf(buf, orient, 0,              0,     split)   # call1
    _fill_cdf(buf, orient, TRAILER_BUCKETS, split, n)      # call2
    return bytes((split & 0xFF, (secobj_byte or 0) & 0xFF)) + bytes(buf)
```

### 2B. Where it plugs into `native_template()`

`serialize_v30_section()` already emits `N×18` bytes and the caller writes them
at `start = base - V30_DESC_LEN`. The trailer goes **immediately after**:

```python
for base in target_regions:
    start = base - V30_DESC_LEN
    ws_body[start:start + len(section)] = section            # existing
    # NEW: regenerate the 24-byte trailer for OUR keypoints
    tr_off = start + len(section)                            # = anchor - 16 + N*18
    trailer = build_section_trailer24(
        our_section_records,                                 # the kp that fed `section`
        split=None,                                          # natural split
        secobj_byte=ws_body[tr_off + 1])                     # keep scaffold's +1 byte
    ws_body[tr_off:tr_off + 24] = trailer
```

Two practical wrinkles, both addressable:

1. **Sort order.** `build_v30`/`serialize_v30_section` currently write records
   in detection order, but the trailer CDF requires the records to be sorted by
   `orient` within each half. Either (a) sort the section's kp list by
   `orient_q16` before serializing both the v30 records AND the trailer (the
   safest self-consistent choice — the v30 record order and the CDF must agree
   on absolute indices), or (b) keep detection order but compute a permutation.
   Recommend (a): sort each section's records ascending by `orient_q16`, then
   `serialize_v30_section` and `build_section_trailer24` see the same ordering.
   The `split` then = count with `orient < 165`.

2. **`N < 250`.** Our detector yields a culled count (the per-tile counts
   `29,27,17,33,36,33,30,26,19`), not 250. `serialize_v30_section` zero-pads to
   250; **the trailer's `N` must be the live record count actually written**,
   not 250, and the zero-pad records (orient 0 → bucket 0) must NOT be counted.
   Pass the real (unpadded) kp list to `build_section_trailer24`.

### 2C. Reproducibility scorecard

| artefact | offset | reproducible for our kp? | action |
|---|---|---|---|
| 24-byte trailer CDF `[+2:+24]` | per-section | **YES — byte-exact** | generate via `build_section_trailer24` |
| trailer split byte `[+0]` (H+0xc) | per-section | YES (natural split = #kp with orient<165) | generate; verify against scaffold-derived value if a real ref exists |
| trailer byte `[+1]` (secobj+0xc) | per-section | NO (independent upstream field) | copy from scaffold/ref (low risk; see §3) |
| `geometry_stats` `[44:64)` | header | NO (runtime regression pose vector) | copy from scaffold or zero (test both) |
| sec0_pre quality blob `<<24` | sec0_pre | NO (matcher c6a0/bdf0 byte) | copy from scaffold |
| `per_section_counts` `[24:40)`/`[40:44)` | header | NO (cross-frame consensus) | copy from scaffold |
| sec0_pre rigid-Q16 transforms | sec0_pre | NO (multi-frame alignment) | already handled (`patch_pre_v30_near_identity`) |

---

## 3. LOAD-BEARING assessment — is each piece read at MATCH time?

The key question per artefact: does the matcher `sub_18000c6a0` (verify path)
re-read it, or is it enrollment-only bookkeeping that storage tolerates?

**What the matcher actually consumes (from `SCORER-sub_18000c6a0.md`):** the
verify path is a **120×120 spatial voting grid** over **rigid-similarity
transforms** of keypoint coordinates. Its inputs are:
- the **candidate/query keypoint records** (the `[x][y]` + per-pair transform
  matrices) — i.e. the v30 record area + the pairwise alignment table;
- it materializes the grid from `srcBlob` (the template), votes candidate
  alignments, counts occupied cells, argmax. **No descriptor bytes, no
  orientation CDF, and no header geometry_stats appear in the grid math.**

Crucially, `sub_18000c6a0` **builds** the section by *calling* `sub_1800057e0`
(at `0x18000c8b1`) on the EMIT path — i.e. `sub_1800057e0` (and therefore the
24-byte trailer) is **written by the matcher**, on the side that *produces* a
matched record after a win, **not consumed as a scoring input**. The trailer is
a *serialization output* of a confirmed match, downstream of the
occupied-cell-count decision.

| artefact | likely read by matcher at verify? | justification | safe action |
|---|---|---|---|
| **v30 records `[16B][x][y]`** | **YES (critical)** | the grid votes the candidate keypoints' `[x][y]` through the rigid transform; this is the entire score input | already generated byte-exact |
| **24-byte trailer CDF** | **LIKELY NO at verify** | it is *written by* `sub_1800057e0` on the emit/serialize tail, not read by the grid voter (`bfd0`/`c270`/`c240`/`c510`). It is an orientation-index acceleration structure for *enroll-time* section assembly | regenerating it correctly is **harmless and cheap**; copying a stale one is the *risk* (mismatched indices vs our records) — so **generate it** |
| **trailer byte `[+1]` (secobj+0xc)** | NO (same as above) | independent enroll-time field | copy is fine |
| **sec0_pre rigid-Q16 transforms** | **MAYBE** | the grid is *materialized from the template blob* (`sub_180003320(src=srcBlob, len=0x3840)`); if the per-pair transforms seed the candidate alignments, stale/wrong values bias voting. But for a single-frame template (identical sections) the correct transform is near-identity, which `patch_pre_v30_near_identity` already provides | keep near-identity patch |
| **sec0_pre quality blob `<<24`** | NO (bookkeeping) | a per-section quality stat appended by the matcher; not in the grid metric | copy is fine |
| **header `geometry_stats` `[44:64)`** | **PROBABLY NO** | a pose/quality summary; not referenced by the grid voter's inputs. It is read during template *parse/setup*, not the per-cell vote | copy or zero; **disambiguate by test (§4)** |
| **`per_section_counts`** | NO (consensus bookkeeping) | session accumulators; storage metadata | copy is fine |

**Net read of the call structure:** the matcher's decision is purely
`count_occupied_cells(grid)` over rigid-transformed `[x][y]`. The 24-byte
trailer and the header geometry/quality fields are *serialization outputs* on
the emit side of `c6a0`, not voting inputs. So:

- The **24-byte trailer** is *almost certainly* enroll-time-only — but because
  copying a STALE one yields a CDF that indexes the WRONG keypoints (its
  absolute indices point past/into different records than ours), the *correct*
  move is to **regenerate it** (cheap, byte-exact, removes a known
  inconsistency). The scaffold today carries STALE trailer high-halves (e.g.
  sec0 `...,158,159,188,216,...`) over zeroed records — definitively wrong for
  our keypoints.
- The **header geometry_stats/blob/counts** are the genuinely unresolvable
  pieces; the load-bearing question for them is empirical (§4).

---

## 4. Cheap HARDWARE test to disambiguate the live-enroll no-match

Goal: determine whether the per-section metadata is load-bearing at verify, by
A/B-ing two templates built from the **same** native keypoints, differing ONLY
in the metadata, then running the on-chip match.

**Setup (one capture, same finger image):** detect once with
`extract_frame_native`, then build two envelopes:

- **T_copy** — current behavior: our v30 records + **stale** scaffold trailer +
  stale header `geometry_stats`/blob/counts. (today's `native_template`.)
- **T_regen** — our v30 records + **regenerated** 24-byte trailer
  (`build_section_trailer24`, §2) + everything else identical to T_copy.

Run on hardware:
```
sudo ./.venv-poc/bin/python scripts/enroll_native_chip.py --subtype 0xf5 --match   # T_copy
# then rebuild with the trailer regen patch applied and re-run --match         # T_regen
```

**What to compare:**

1. **Enrollment store result** (chip cmd 0x47 status / error code). If T_copy
   stores but T_regen errors (e.g. `0x04b3`/`0x04b5`, see MEMORY chip error
   codes), the chip *validates* the trailer at store time → load-bearing for
   storage. If both store identically, the trailer is not store-validated.
2. **Match/identify verdict** (`c6a0` match-flag path → CheckForDuplicate /
   verify result). The decisive comparison:
   - if **T_regen matches and T_copy does not** → the trailer (or its
     consistency with our records) **is** read at verify → must be correct;
   - if **both match (or both fail) identically** → the trailer is NOT the
     no-match cause; the blocker is elsewhere (most likely the v30 records / the
     cull stage `sub_18000A1B0`, or the sec0_pre transforms).

**Tightest single-variable test (recommended first):** because regenerating the
trailer is cheap and provably correct, also build a **third** variant
**T_zero** (our records + 24-byte trailer ZEROED) to bracket the behavior:
T_copy (stale) vs T_regen (correct) vs T_zero (absent). Three points reveal
whether the chip (a) ignores the trailer (all three identical), (b) needs it
*present and self-consistent* (T_regen wins, T_zero/T_copy fail), or (c) only
needs it well-formed regardless of values (T_copy==T_regen, T_zero fails).

**Even cheaper signal without three enrollments:** run the gdb verify hook
(`scripts/gdb_dump.py`) breaking at `0x18000c789` (the second `c240` occupied-count)
and `0x18000c7ed` (the match gate) during a verify of T_copy. If the occupied
cell `count1`/`count2` and the `*(rbx)` best-index are computed entirely from
the v30 `[x][y]` records — with no read touching `anchor + N*18` (the trailer)
or `[44:64)` — that directly proves the metadata is not a verify input, and the
no-match must be in the keypoint/transform data, not this metadata. Set a gdb
**read watchpoint** on the trailer offset (`ws_buf + anchor - 16 + N*18`, 24 B)
and on `ws_buf + 44` (geometry_stats) across the `0x1800094c5`/`c6a0` verify
call: **zero read hits = definitively not load-bearing at verify.**

---

## 5. Bottom line

- The **24-byte per-section trailer is fully decoded and reproducible
  byte-exact** for our keypoints (`build_section_trailer24`, §2). Today the
  scaffold ships a STALE trailer over our records; regenerating it is cheap,
  correct, and removes a guaranteed inconsistency — **do it** regardless of the
  load-bearing verdict. The only non-derivable trailer field is the single
  `secobj+0xc` byte at `+1` (copy it).
- The **header `geometry_stats` `[44:64)`, the sec0_pre quality blob, and
  `per_section_counts`** are **multi-frame matcher/regression products** that a
  single native frame cannot synthesize (regression coeffs + cross-frame
  consensus live in runtime ctx, not statically resolvable). Copy from the
  scaffold for now.
- **Load-bearing read:** the verify-time matcher (`sub_18000c6a0`) scores via a
  120×120 rigid-transform voting grid over the v30 `[x][y]` records; the trailer
  and header stats are written on its *emit* tail, not read as voting inputs —
  so they are **most likely enroll-time bookkeeping**, with the sec0_pre rigid
  transforms the only header-side field plausibly seeding the grid (already
  handled by `patch_pre_v30_near_identity`). The §4 A/B/Z hardware test (plus
  the cheap gdb watchpoint) settles it empirically. The probable real no-match
  cause remains the **keypoint cull `sub_18000A1B0`** (per MEMORY), not this
  metadata.
```
