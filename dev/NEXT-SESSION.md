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

## THE ONE OPEN QUESTION

Full-pipeline template vs chip `ws_body`: **233/250 (x,y) match but 0/250 exact
18-byte records** — descriptors differ for every keypoint, even though every
descriptor component is byte-exact *given the chip's subpix*. Two unresolved
candidate causes:

- **(A)** our `subpix_refine_kp` (or the `doh()` response it refines on) differs
  from the chip's in the full pipeline → shifts every descriptor.
- **(B)** frame-selection mismatch — the chip's `ws_body` sections store its
  *selected best frames* (`sub_180008980` 0x699 gate), so "our frameN vs chip
  sectionN" compares **different images** (233/250 overlap = same finger, not
  necessarily the same frame). The per-tile test (subpix 13/14 byte-exact on a
  gradient-matched tile) leans toward (B).

## STEP 1 — the clean same-image test (resolves A vs B)

Run our full per-tile pipeline on a **specific F250 tile** (the chip's exact
input) and compare ALL outputs to the chip's ground truth for THAT tile:

1. Find an F250 tile X with `descriptor_gradient(F250_X) == descbrief_gradX_tY`
   byte-exact (34/71 are reproducible — see `validate_descriptor_gradient.py`).
2. On `F250_X`: `doh(tile>>6)` → `nms()` → `subpix_refine_kp` → `orient_d920` →
   `_descriptor_at`.
3. Match our kps to the chip's `descbrief_kp` for tile Y (by rounded tile-local
   subpix) and compare **subpix (x_q16@+0x14, y_q16@+0x18), orient (@+0xc), and
   the 16-B descriptor** byte-for-byte.
   - WRINKLE: descbrief gradients are **content-deduped across frames**, so the
     `t##_kp####` → kp-range mapping is messy (this confounded an earlier 25/111
     attempt). Match by subpix WITHIN the gradient-matched tile rather than
     trusting kp ranges.
- **subpix byte-exact ⇒ (B):** pipeline is byte-exact; 0/250 was frame pairing.
  Go to Step 2.
- **subpix differs ⇒ (A):** fix `subpix_refine_kp` (moh_native.py) / the `doh()`
  response feeding it; re-validate.

## STEP 2 — just run the match gate (byte-identity is NOT required)

Matching is geometric (the matcher votes spatial consensus of rigid-aligned
keypoints + descriptor correspondences); the chip stored DIFFERENT frames, so a
byte-identical template was never the requirement. If Step 1 confirms the
pipeline is byte-exact on the same image, build a template from OUR frames
(`native_template`, v30 records byte-exact for our kps) and run the real gate:

```
dev/enroll_native_chip.py --match    # needs the physical chip + finger (you-run-it)
```

Success = the chip's matcher accepts our purely-from-scratch template.

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
