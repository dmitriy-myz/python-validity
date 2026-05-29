# Next RE session — decompile the WS body builder

Resume point: native enrollment template construction. The feature
pipeline (image → 250 kps + descriptors) is **byte-exact validated**.
The remaining blocker is the WS body **container format**: ~260
session-variant bytes whose derivation we don't understand. Black-box
hypothesis testing (`dev/decode_variants.py`) hit a dead end — none of
the simple per-frame minutia statistics fit. Time to disassemble the
DLL functions that BUILD the WS body and trace where each byte zone
comes from.

## Where we are (verified)

| stage | status | gate |
|---|---|---|
| Image → 250 kps | ✅ 244-250/250 byte-exact | `dev/diff_log_pipeline.py` |
| Per-tile gradient | ✅ 9/9 byte-exact | `dev/diff_descriptors.py` Stage A |
| 16-B BRIEF descriptor | ✅ 250/250 byte-exact | `dev/diff_descriptors.py` Stage B |
| WS body container | ❌ ~260 unknown bytes | this session |
| Chip identify() match | ❌ fails | end-to-end |

## What we KNOW about the WS body (from `dev/inspect_ws.py` + `extract_skeleton.py`)

Layout (23056 bytes, 5 v30 sections — NOT 4 as our stale reference template
implied):

```
[0..4)        zeros                                CONST
[4..8)        size_u32 = 23036 = 0x59fc            CONST (likely sizeof(payload))
[8..16)       06 02 05 00 02 00 08 01              CONST (config code)
[16..24)      04 03 02 01 00 00 00 00              CONST (sensor/algo identifier;
                                                          NOT "accepted_frame_ids"
                                                          as earlier memory claimed)
[24..40)      per_section_counts u32 × 4           VARIANT (consolidated minutia counts
                                                            for sections 0..3)
[40..44)      byte 40 = 5th-section count (96?)    PARTIAL (byte 0 likely count,
              + 3 bytes flags                              bytes 1-3 unknown)
[44..64)      geometry_stats                       VARIANT 14/20 (unknown derivation)
[64..309)     section 0 pre-v30 (245 B)            VARIANT 132/245 (global section
                                                                    table + POSE)
[309..4809)   section 0 v30 records (4500 B)       CONTENT (250 × [u8 x][u8 y][16B desc])
[4809..4905)  section 1 pre-v30 (96 B)             VARIANT 24/96 (mostly constant
                                                                  TLV skeleton)
[4905..9405)  section 1 v30 records                CONTENT
[9405..9453)  section 2 pre-v30 (48 B)             VARIANT 40/48
[9453..13953) section 2 v30 records                CONTENT
[13953..13993) section 3 pre-v30 (40 B)            VARIANT 35/40
[13993..18493) section 3 v30 records               CONTENT
[18493..18533) section 4 pre-v30 (40 B)            VARIANT 24/40
[18533..23033) section 4 v30 records               CONTENT
[23033..23056) tail (23 B)                         VARIANT 8/23
```

Total: ~260 variant bytes to derive, ~22800 constant skeleton.

Cross-capture diff signal (`dev/extract_skeleton.py`, two captures A and B
different fingers same sensor):
- Constant zones can be COPIED verbatim from any Wine capture (proven
  sensor-stable across enrollments).
- Each section's pre-v30 starts with 8 ascending bytes (e.g., A's section 1:
  `a4 a8 bf ce d9 db db e4`) — these vary per-session and per-section.
  They are NOT simple quantiles of any minutia field we capture.

## Decompile target — call tree

The WS body is built incrementally per frame. Entry is via the per-frame
processor `sub_1800D89C0` (RVA 0xD89C0) which calls the packer:

```
sub_1800D89C0  per-frame processor
  ├─ sub_180001A50      feature extractor (image → 250 kps in v30 buf) [DONE — byte-exact]
  └─ sub_180002240      WS-body PACKER (v30 features → WS body sections) [DECOMPILE THIS]
       ├─ sub_180001FE0 180-B working record builder (per-kp)
       │    └─ sub_180008F10  descriptor engine (writes section payload)
       ├─ sub_180003320 struct-copy utility (NOT the accumulator, confirmed
       │                this session — small generic copy fn)
       └─ sub_18005xx → sub_180006A80 / B80 / 890   TLV codec
```

The actual MULTI-FRAME ACCUMULATOR (= what merges 8 frames into 5
consolidated sections) was NOT identified yet. It is likely:
- Inside `sub_180002240`'s body (called per frame; accumulates state in
  WS body @ session+152 across frames), OR
- Inside the per-frame driver `sub_180031470` (RVA 0x31470), OR
- Inside `sub_18001F070` (= `EnrollmentUpdate` per memory).

## Priority decode order

### Phase 1 — what writes which bytes (the easy half)

For each variant zone, find the DLL function that writes the bytes. Use:

```
objdump -d /tmp/syna.dll | grep -B1 -A5 "imm value matching variant content"
```

Or in IDA: look up cross-refs for the WS body pointer (= session+152, where
session is arg1 to several functions). Track every `mov [session+152+OFFSET], ...`
or memcpy into that range.

Targets ranked by simplicity:

1. **`[4..8) size_u32`** — likely a hardcoded constant 23036 = 0x59fc the DLL
   writes during template finalize. Look for `mov dword [...], 0x59fc` in the
   disasm. Probably trivial to port.

2. **`[16..24) sensor identifier`** — appears constant across captures. Find
   where this 8-byte value `04 03 02 01 00 00 00 00` is written. May be a
   constant in `.rdata` (search for it).

3. **`[24..44) per_section_counts`** — written when each accumulated section
   "completes" (each frame contributes some count, the SECTION count is the
   consolidated final). Likely written near the end of accumulation, by some
   function that finalizes the WS body. Search for stores of small (60-100
   range) u32 values to offsets 24, 28, 32, 36, 40.

4. **`[44..64) geometry_stats`** — 20 bytes. Per memory note says "geometry/
   stats" but no specific function identified. Likely written by the same
   finalize function as per_section_counts (right before the sections).

### Phase 2 — section pre-v30 metadata

Each section's pre-v30 area (40-245 bytes) is written DURING that section's
construction, between v30 records of frame N-1 ending and frame N's
records starting. Some bytes:

- **Section 0 pre-v30** (245 B) is the LARGEST — likely contains a "section
  table" with offsets/sizes for all 5 sections. Look for stores during the
  very first WS body build (initialize_packer / init_ws_body).

- **Section 1-4 pre-v30** (40-96 B) — each section's "section header" (TLV
  framing + POSE records + per-section stats). The constant ~16-byte marker
  `[id u32][TLV 00 b8 11 00][padding][cap 0xfa]` we identified is likely
  written by a common section-init helper.

- **The 8 ascending bytes at each section's start** — primary mystery.
  Hypothesis: these are POSE record bytes from `sub_1800046E0` (per-keypoint
  MODEL FITTER, decoded earlier). Memory note: "First frame's reference pose
  → WS header offset 49/53/57." So poses from frame 0 land at WS header
  offsets 49/53/57. Similar pose data per section may explain these bytes.

### Phase 3 — the accumulator (= consolidation logic)

The 250 kps per frame become ~95 per section, after dedupe across frames.
This logic LIVES SOMEWHERE in the WS body packer call tree. Find it by:

1. Hook `sub_180002240` entry/exit per frame (similar to the A5B0 hook we
   built). Dump the WS body BEFORE and AFTER each frame. The DELTA shows
   what that frame's processing wrote.

2. After 8 frames, each section should be filled. Compare the per-frame
   delta to figure out: when does section[i] get populated? Is it
   appended-to per frame, or filled-then-finalized at specific frame?

3. The 8-byte ascending lead may be intermediate state that gets
   incrementally updated each frame.

## Tools at your disposal

- `/tmp/syna_all.S` — 16 MB full objdump of `synaWudfBioUsb.dll`
- `/tmp/syna.dll` — the binary (use for IDA / Ghidra if needed)
- `dev/inspect_ws.py` — full byte-zone annotator of a captured ws_body
- `dev/extract_skeleton.py` — diffs two captures, extracts constant skeleton
- `dev/decode_variants.py` — hypothesis-testing framework (skeleton works,
  needs new hypotheses informed by disasm)
- `dev/gdb_dump.py` — capture hooks; add a `GDB_DUMP_PACKER_WS=1` hook on
  `sub_180002240` entry/exit to capture per-frame WS body deltas
- `dev/diff_template_structure.py` — diffs OUR native_template against
  captured Wine ws_body to track progress
- Existing captures in `/media/sf_vbox-rw/finger/frida_dumps/`:
  - 2× Wine ws_body (different fingers)
  - 1024× per-kp descriptors (byte-exact validated)
  - 15× minutia_table dumps (8 + 7 per session — final AAB0 outputs)
  - 144× F250 raw tiles, 37 gradstructs, etc.

## Concrete next steps (recommended order)

1. **Decompile `sub_180002240`** end-to-end. This is THE WS body packer
   and probably writes the majority of variant bytes. Map every write to
   the WS body offset it targets.

2. **Find the multi-frame accumulator.** Inside or around 180002240.
   Hook with gdb (add `GDB_DUMP_PACKER_WS` hook), capture per-frame WS body
   delta, see how sections grow.

3. **Decompile `sub_1800046E0`** (per-keypoint model fitter). Already partly
   decoded (180-byte working record). The output may include the POSE
   records that explain the 8-byte section leads.

4. **Decompile the finalize/sealer** function. Look for the function that
   writes `size_u32 = 23036` at WS body+4. Walk backwards from there to find
   where `per_section_counts` and `geometry_stats` are written.

5. **Build `validitysensor/moh_native_v2.py`** with `native_template_from_scratch(per_frame_kps)`
   that uses an embedded constant skeleton + the newly-decoded derivations.
   Test against `dev/diff_template_structure.py` (byte-by-byte vs captured
   Wine ws_body — should converge as decode work progresses).

6. **End-to-end gate:** `dev/enroll_native_chip.py --match` against a real
   finger. Success = chip's matcher accepts our purely-from-scratch template.

## What NOT to do

- Don't try more pure black-box hypothesis testing. The space is too large;
  the 8-byte ascending leads alone could be any of hundreds of possible
  derivations. Without disasm we can't constrain the search.
- Don't add more empirical thresholds or magic constants like the removed
  `RESP_CULL_THRESHOLD`. Every constant must trace back to a specific DLL
  instruction or be marked TODO with a reference to which function should
  produce it.
- Don't keep using `/tmp/wine_finger_fresh.bin` as a scaffold. It's from an
  older Wine version with 4 sections, not 5. The constant skeleton should
  come from a current capture (or be embedded in the repo once extracted
  via `dev/extract_skeleton.py`).

## Commit chain (current branch `moh-opencv-poc`)

- `8986a16` ← HEAD  (dev/decode_variants.py — hypothesis tester)
- `3168a1f`  (dev/extract_skeleton.py + 5-section finding)
- `5cf3ea5`  (dev/inspect_ws.py annotator)
- `601238d`  (dev/diff_template_structure.py)
- `be0a4eb`  (RESP_CULL_THRESHOLD removed)
- `81fe2bd`  (dev/extract_log_images, diff_log_pipeline, diff_a5b0kp)
- `60f44ab`  (A5B0 boundary hook — ruled out A5B0 as cull)
- `cccb426`  (FILL=0x800000 + corner-tile gy tightening)
