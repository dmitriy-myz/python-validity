# Next RE session — capture the TLV stream & decode the v30 content writer

Resume point: native enrollment template construction. The feature pipeline
(image → 250 kps + descriptors) is **byte-exact validated**. The WS-body
**packer `sub_180002240` is now fully decompiled + adversarially verified**
(2026-05-29) — see `dev/PACKER-sub_180002240.md` (read it in full first).
The container turned out to be a **concatenated TLV stream**, not fixed-offset
writes, so the remaining work is (a) a runtime capture that attributes each
TLV record to its byte range, and (b) decoding the writer of the bulk v30
content.

## Where we are (verified)

| stage | status | gate |
|---|---|---|
| Image → 250 kps | ✅ byte-exact | `dev/diff_log_pipeline.py` |
| Per-tile gradient + 16-B descriptor | ✅ byte-exact | `dev/diff_descriptors.py` |
| WS packer `sub_180002240` decode | ✅ decompiled+verified | `dev/PACKER-sub_180002240.md` |
| WS body TLV offset→writer map | ⚠️ static partial; NEEDS-HOOK | this session |
| WS body v30 content (5×4500 B) writer | ❌ unresolved | this session |
| Chip identify() match | ❌ fails | end-to-end |

## What the decode established (don't re-derive)

- `sub_180002240(algo=RCX, ws_dest=RDX, stats=R8, features=R9, w, h)` — **one
  section per call**, straight-line, no internal frame loop. Caller
  `sub_1800D89C0` loops the frames.
- **Accumulator is the persistent object** `rbx = sub_180001000(*(algo+8))`:
  `[rbx+0x144]` first-frame guard, `[rbx+0x130]++` reject counter,
  `[rbx+0x138]` section buffer; plus the `sub_180003320` 180B-record stream.
- **WS body = TLV stream** built via a 16-byte cursor at `[rsp+0x50]`
  (node=`*(rsp+0x50)`, data=`*(rsp+0x58)`, running len=`*(u32*)(node+4)`).
  TLV = `{u16 tag, u16 len, payload}`; container counter u32 at hdr+4.
- **`size_u32`=23036 is a formula** (`sub_180001750` id-6, CONFIRMED):
  `(20*(n/2)+4544)*n+((n+3)&~3)+0x80`, n=5 → 23056 total / 23036 payload.
- **TLV tag map** (u32 scalars via `sub_180006b80`/`sub_180006930`):
  0x03/0x68/0x6a/0x6b scalars; 0x6c = 4-u32 container (algo `+0x154/+0x150/+0x144/+0x130`,
  per_section_counts family); 0x69 = container with (h,w).
- **POSE leads are an argsort index permutation** (`sub_18000bd10`), NOT sorted
  scores. `sub_1800051f0` emits a per-section TABLE (≤5×5 matrix), NOT the
  4500-B content.

## Concrete next steps (recommended order)

1. **Run the two new gdb captures** (need a Wine enroll with a physical finger;
   hooks already wired in `dev/gdb_dump.py`, opt-in):
   - `GDB_DUMP_PACKER_EMIT=1` — snapshots the `[rsp+0x50]` TLV stream before
     each of the 9 emit-block codec calls + post (per frame). Diffing
     consecutive `packer_emit_stream_*` dumps gives the **exact byte delta each
     codec call appends** → resolves every PARTIAL/NEEDS-HOOK row in the
     offset→writer map (incl. where `size_u32`/per_section_counts/geometry land,
     and which call emits the 4500-B content).
   - `GDB_DUMP_POSE=1` — dumps `*(obj+0)`/`*(obj+8)`/obj header before & after
     the `sub_18000bd10` argsort, to link the index permutation to real pose
     scores (`obj+0x8`/`obj+0x11`).
   - Write an analyzer (extend `dev/inspect_ws.py` / `dev/diff_template_structure.py`)
     that consumes `packer_emit_*` dumps and labels each WS range with its
     emitting callee.

2. **Decode `sub_180008f10`** (descriptor engine driven by the worker
   `sub_180001fe0`). It owns the 5×4500-B v30 content. Trace how the worker
   writes the per-section records into the persistent `[rbx+0x138]` buffer and
   how that buffer reaches the WS stream (memcpy vs put-N).

3. **Decode the first-frame header init** `sub_1800068f0` → `sub_1800067e0`
   (13-B thunk). Candidate writer of `[0..16)` (zeros + config `06 02 05 00…`)
   and possibly the `size_u32` store site. Confirm with the EMIT capture
   (frame-0 stream snapshot at `0x180002540`).

4. **Build `validitysensor/moh_native_v2.py`** with a TLV-stream emitter that
   mirrors the codec cluster (open record / put-u32 / put-N / close-flush with
   4-byte alignment) keyed by the decoded tag map, fed by our byte-exact
   features. Test against `dev/diff_template_structure.py` (vs a captured Wine
   ws_body) — should converge record-by-record.

5. **End-to-end gate:** `dev/enroll_native_chip.py --match` against a real
   finger. Success = chip's matcher accepts our from-scratch template.

## Tools at your disposal

- `/tmp/syna_all.S` — 16 MB objdump; `dev/extract_funcs.py` splits it into
  per-function files (`extract_funcs.py index` lists all 2571 funcs;
  `extract_funcs.py dump <addr>…` writes `/tmp/func_<addr>.S`). NOTE: jump-table
  data fools the int3 splitter (e.g. `0x180001750`, `0x180001750`'s `call
  0x1730018a4` is a misparse) — verify boundaries near `(bad)` lines.
- `dev/PACKER-sub_180002240.md` — the authoritative packer decode + §9
  verification addendum + §10 corrections.
- `dev/wf_decompile_packer.js` / `dev/wf_verify_packer.js` — the workflow
  scripts that produced the decode (re-runnable for other functions).
- `dev/gdb_dump.py` — capture hooks incl. the new `GDB_DUMP_PACKER_EMIT` /
  `GDB_DUMP_POSE`.
- `dev/inspect_ws.py`, `extract_skeleton.py`, `diff_template_structure.py`,
  `decode_variants.py` — WS body annotators / diffs.

## What NOT to do

- Don't treat WS offsets as fixed — it's a TLV stream; absolute positions are
  emission-order dependent. Always reason in terms of records + the running
  `node+4` counter.
- Don't add empirical thresholds/constants. Every constant must trace to a DLL
  instruction (e.g. `size_u32` ← `sub_180001750` id-6 formula) or be marked
  TODO with the function that should produce it.
- Don't pursue more pure black-box hypothesis testing on variant bytes — the
  EMIT capture gives ground truth per record.

## Commit chain (branch `moh-opencv-poc`)

- HEAD ← this session: `dev/extract_funcs.py`, `dev/wf_decompile_packer.js`,
  `dev/wf_verify_packer.js`, `dev/PACKER-sub_180002240.md`, gdb_dump.py hooks,
  NEXT-SESSION.md.
- prior: `6c2dbaf` (old NEXT-SESSION), `8986a16` (decode_variants), … (see git log)
