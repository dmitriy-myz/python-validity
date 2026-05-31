# Next session — close the native-enrollment match gate

Resume point: the **from-scratch native enrollment template**. The entire WS-body
format is reverse-engineered + byte-verified and the feature/descriptor pipeline
is byte-exact on ground-truth inputs. One well-defined validation stands between
here and `enroll_native_chip.py --match`. **Read `~/.claude` memory
`native-pipeline-readiness`, `ws-packer-decode`, `ws-pre-v30-decode`,
`moh-matcher`, `moh-enrollment-ops` first** (or the dev/ reports they point to).

## DONE (this session, all committed + pushed on `moh-opencv-poc`)

- **WS-body packer `sub_180002240`** fully decompiled + adversarially verified —
  it's a per-frame TLV-stream section appender; accumulator lives in
  `*(algo+8)`. `dev/PACKER-sub_180002240.md`.
- **Section/descriptor builder `sub_180008f10`** + serializer `sub_1800057e0`
  decoded. `dev/decode_sub_180008f10.md`.
- **Matcher `sub_18000c6a0`** = Hough geometric-voting inlier counter (120×120
  grid, rigid Q16 transforms). `bdf0`/`180006da0` inverse-transform math
  byte-verified. `dev/SCORER-sub_18000c6a0.md`.
- **EnrollmentCheckForDuplicate chain** (`sub_18001e5f0`→vtable[0x78]→
  `CeivMode::IdentifyUser`) resolved. `dev/find_vtable.py`,
  `dev/ENROLLMENT-checkforduplicate.md`.
- **WS-body layout**: v30 record = `[x:u8][y:u8][16B desc]` (ground-truth
  confirmed 250/250). `sec0_pre` = inter-section rigid-Q16 alignment transforms
  (`dev/parse_ws_tlv.py`, `dev/decode_sec0_pre.py`, `dev/PRE_V30-decode.md`).
  `serialize_v30_section()` byte-exact (`dev/verify_v30_serializer.py`).
- **Cull confirmed DONE**: `sub_18000A1B0` is the per-frame FEATURE BUILDER, the
  cull is `sub_18000CF90` (= our `nms()`, byte-exact: t_lo=671,t_hi=168,
  dedup_q=72064,margin=10). `dev/CULL-sub_18000CF90.md`.
- **Descriptor pipeline byte-exact on ground truth**: `descriptor_gradient`
  reproduces the chip's gradX/gradY byte-exact; `tile_image`==F250 (diff 0);
  `orient_d920` 60/60; chain (`_descriptor_at`) 40/40. Harness
  `dev/validate_descriptor_gradient.py`.

## STEP 1 — RESOLVED 2026-05-31 → cause (B), pipeline is byte-exact

Was: full-pipeline template vs chip `ws_body` matched 233/250 (x,y) but 0/250
exact 18-byte records, with two candidate causes — (A) our `subpix_refine_kp` /
`doh()` differs from the chip's, or (B) frame-selection mismatch (the chip's
`ws_body` sections store its own *selected best frames*, so "our frameN vs chip
sectionN" compares different images).

**The clean same-image test settled it decisively: cause (B).**
`dev/validate_same_image.py` runs our full per-tile detection on the chip's
EXACT F250 input tile (session 1780170; 34 chip gradient tiles paired to F250
raw tiles by interior byte-exact `descriptor_gradient` match) and compares
against the chip's `descbrief_kp_before` (subpix @+0x14/+0x18, orient @+0xc) +
`descbrief_desc`:

```
SUBPIX byte-exact:     1024/1024
  orient byte-exact:   1024/1024
  descriptor byte-exact (Hamming 0): 1024/1024
  chip kps with NO matching NMS peak in our detection: 0
```

So `doh → nms → subpix_refine_kp → orient_d920 → _descriptor_at` reproduces the
chip **bit-for-bit on the same image, every keypoint.** The 0/250 was purely
that each chip section is a DIFFERENT selected frame — a byte-identical template
was never the requirement (matching is geometric Hough voting, `moh-matcher`).

- Gotcha (cost an early 89.5% false-negative): the chip's gradX/gradY `_save`
  timestamps drift ~1 ms, so resolve the gradY file by its `_t##_kp####_<dims>`
  TAG — do NOT string-replace the gradX filename. The 34 gradient tags (not the
  content-dedup kp ranges) define the kp→tile grouping cleanly here.
- The earlier "subpix differs" hypothesis in `native-pipeline-readiness` memory
  is now REFUTED and the memory is updated.

## REFERENCE-FREE enrollment — DONE 2026-05-31

`native_template` no longer needs a captured reference template. The WS-body
framing now comes from a baked-in scaffold `validitysensor/native_ws_scaffold.bin`
(genuine chip-accepted fresh.bin framing with the v30 record areas ZEROED — no
real descriptors shipped). At runtime we overlay OUR v30 records into the 4
pinned regions `(309, 4913, 9453, 13993)` and recompute the TID, so the entire
template — keypoints AND framing — is ours, with no reference file. Verified
byte-faithful: `dev/verify_reference_free.py` (22/22 checks) confirms the
framing is byte-identical to fresh.bin outside the v30 areas, the TID validates,
the explicit-`--ref` path still works (regression), and the real pipeline runs
end-to-end. `native_template(img)`, `Sensor.enroll_native(...)`, and
`enroll_native_chip.py` all default to reference-free (`--ref` is now optional).

Caveat (the honest gap): the scaffold's pre-v30 metadata (sec0_pre pose table,
per-section counts/leads) still describes fresh.bin's frames, not ours — full
first-principles pre-v30 synthesis is blocked by NEEDS-HOOK rows in
`dev/PACKER-sub_180002240.md`. Whether the matcher needs pre-v30 to describe OUR
geometry is exactly what the match gate (below) settles.

## STEP 2 — match gate RESULT (2026-05-31): NO MATCH → cause is CONTENT

Ran on hardware: enroll stored fine (finger dbid=8 subtype 0xf6 under real
StgWindsor user dbid=6, 250 kp) but the chip `0x5e` matcher returned no-match.
Root-caused WITHOUT more hardware:

- **Plumbing RULED OUT.** `dev/extract_finger_templates.py` over the captured
  `enroll*.log`s shows the DLL stores the finger with parameters BYTE-IDENTICAL
  to ours: `0x47 parent=<user> typ=6 storage=3 len=23136` + 1 random trailer.
  (And `0x68`/`0x6b` session enrollment is MoC-only → `0x0401` here, so raw
  `0x47` is the only path — ours is correct.)
- **Real cause = template CONTENT.** The DLL template is **4 DISTINCT frames**
  (sections differ 96–97%) with **non-identity `sec0_pre` transforms** (rot
  −3.6°/+1.3°/+0.7°, t ±19px). Our reference-free template wrote ONE frame
  replicated into all 4 sections → inconsistent with the baked (fresh.bin)
  pre-v30 → the geometric matcher can't align it.

### BLOCKER: chip in `0x04b5` "bad state"
Repeated raw `0x47` writes degraded the chip; it now rejects writes with
`0x04b5`. Only documented recovery (dev/MOH.md "Chip-state recovery") is a
**Wine re-enroll** — which also re-creates a matchable finger and a fresh
capturable DLL template for field-by-field diffing.

### STEP 2-NEXT ← YOU ARE HERE  (chip recovered via Wine log 1780232416)
**`sec0_pre` is LOAD-BEARING** (SCORER §1: the matcher votes the stored 20-byte
`[x][y][a,b,tx,ty]` geometry records as candidate alignments) → multi-frame
alone won't fix it; we must compute correct `sec0_pre` for our frames.

Full OFFLINE ground truth now in hand from Wine log `1780232416.log`:
- matchable DLL template `/tmp/ft/wine_1780232416_0.bin` — **mode-B, 5 sections**,
  8 `sec0_pre` transforms, TID OK (our scaffold is mode-A/4-section = wrong
  shape+geometry).
- the **8 source frame images** (`0x0278`, 13776 B each) are in the log too.

Plan:
1. **Cheap de-risk (optional, low odds):** `--frames 4 --match --subtype 0xf7`
   on the healthy chip. If it matches, the descriptor-correspondence shortcut
   suffices; if not (expected), `sec0_pre` synthesis is required.
2. **Build `sec0_pre` synthesis** (the real fix), verifiable OFFLINE: extract
   the 8 images + the 5 DLL sections; run our pipeline on the images; compute
   pairwise rigid transforms and check they reproduce the DLL's stored
   `sec0_pre`. CAVEAT: SCORER decoded transform SCORING, not GENERATION —
   confirm where enrollment first computes the transforms (correspondence →
   hypothesis) before committing; may need more RE/capture.
3. Assemble a self-consistent **mode-B/5-section** template (our v30 + our
   `sec0_pre`) and re-test. Chip hygiene: delete stale native records between
   attempts; Wine-recover if `0x04b5` recurs.

## DATA / TOOLS

- Captures in `/media/sf_vbox-rw/finger/frida_dumps/` (session 1780170xxx has it
  ALL: F250 raw tiles, descbrief gradX/gradY/desc/kp, ws_body, minutia_tables;
  log `1780170395.log`). Extract images: `dev/extract_log_images.py <log> -o DIR`.
- `/tmp/syna_all.S` (objdump), `dev/extract_funcs.py` (per-function splitter →
  `/tmp/func_<addr>.S`), `dev/find_vtable.py` (virtual-call resolver).
- Pipeline: `validitysensor/moh_native.py` (extract_frame_native, nms,
  descriptor_gradient, subpix_refine_kp, orient_d920, _descriptor_at,
  serialize_v30_section, native_template). venv: `./.venv-poc/bin/python`.

## WORKFLOW RULES (do not repeat past mistakes)

- **Frida does NOT work under Wine — gdb only** (`dev/gdb_dump.py` via
  `GDB_DUMP_<HOOK>=1 gdb -p <PID> -x dev/gdb_dump.py`).
- **ALWAYS `git push` immediately after every commit** — the Wine capture box
  pulls from origin; local-only commits run stale code (cost: wasted sessions).
- **The capture box must `git pull` before a capture run.**

## Commit chain (branch `moh-opencv-poc`)
```
106a15e cull decode (A1B0=feature builder, cull=CF90 already ported)
2acfffe E090 descriptor pipeline confirmed BYTE-EXACT
f07a86d validate_descriptor_gradient.py
450032c 51f0 sec0_pre serialization byte-verified
0690b92 sec0_pre = inter-section pose table; bdf0 Q16 math
878de65 v30 serializer + pre_v30 TLV decode
8c0d84a sub_18000c6a0 matcher
bfb7185 sub_180008f10 builder + CheckForDuplicate chain
9b448f6 sub_180002240 packer
```
