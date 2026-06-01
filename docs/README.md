# MoH (06cb:00a2) reverse-engineering & from-scratch enrollment

Reverse-engineering notes (`docs/`) + tooling (`scripts/`) for reproducing the
Synaptics 06cb:00a2 "Match-on-Host" fingerprint enrollment template entirely in
Python (no `synaWudfBioUsb.dll`). The enrollment capability itself lives in the
package (`validitysensor/moh_native.py`, `sensor.py`); this folder is the docs
index, `scripts/` holds the CLIs/ports/capture tooling.

**Status: SOLVED + hardware-confirmed.** A live finger captured by our pipeline
builds a template the chip's `0x5e` matcher accepts — reference-free and
placement-robust. Run it:

```bash
sudo ./.venv-poc/bin/python scripts/enroll_native_chip.py --identity-sec0pre --match --parent <user_dbid>
```
(`--frames 4` is the default; vary placement between captures. All dev tooling
runs via `./.venv-poc/bin/python` — it has numpy/cv2; base python3 does not.)

## What was load-bearing (the whole hunt in one paragraph)
The blocker was a single byte-order bug: the v30 record is **`[16B descriptor][x][y]`**
(descriptor first), not `[x][y][descriptor]`. The load-bearing template content is
just the **v30 `[desc][x][y]` records** + **`sec0_pre`** (and **identity `sec0_pre`
suffices** — no inter-frame transform generation / registration / consolidation).
Everything else (per-section orientation-CDF trailer, header pose/quality stats,
quality blob) is enroll-only bookkeeping the verify matcher never reads
(A/B-confirmed). Multi-frame (`--frames N`, distinct placements, one per v30
section) broadens placement coverage because the matcher argmaxes grid occupancy
over the candidate transforms.

## Template build pipeline (who does what)
```
live capture ──► extract_frame_native (moh_native: doh→nms→subpix→D920→E090)
              ──► serialize_v30_section  ([desc][x][y] records, descriptor-first)
              ──► build_section_trailer24 (per-section orientation-CDF; sub_180005720 port)
              ──► identity sec0_pre (patch_pre_v30_near_identity) + framing scaffold
              ──► compute_tid + _build_envelope  ──► raw 0x47 store ──► chip 0x5e match
```
Core code lives in the package (`validitysensor/moh_native.py`, `moh_opencv.py`,
`moh_extract.py`, `sensor.py`); `scripts/` holds the CLIs, byte-exact ports,
builders, and the capture/extract tooling; `docs/` holds these decode notes.

## Scripts (keepers)
**CLIs**
- `enroll_native_chip.py` — main hardware CLI: capture → build → store → `--match`. Flags: `--identity-sec0pre`, `--frames N`, `--ref`, `--store-ref`, `--no-regen-trailer`, `--dry-run`, `--delete-dbid`, `--list-users`.
- `enroll_native.py` — thin enroll CLI wrapper.

**Byte-exact serializers / ports** (each has a self-test in `__main__`)
- `sec0pre_serialize.py` — `sec0_pre` serializer+parser (sub_1800051f0); round-trips a stored template.
- `bucket_table_180005720.py` — the 24-byte per-section orientation-CDF trailer (sub_180005720); reproduces all captured sections.

**Template builders / experiments**
- `build_diagnostic_template.py` — T0 (exact DLL template) + T1 (our v30 + DLL `sec0_pre`) from a Wine enroll log; isolates the v30-content variable.
- `build_singleframe_template.py` — T2/T3: our v30 + **identity** `sec0_pre` (single / multi-frame).
- `build_multiframe_template.py` — mode-A 4-section assembler with geometric `sec0_pre`.
- `sec0pre_register.py` — `geom_register` (ported model-fitter math + offline study). NB: geometric registration can't reproduce the DLL's transforms (and isn't needed — identity works).

**Capture / extract / parse tooling**
- `gdb_dump.py` — the Wine gdb capture harness (`GDB_DUMP_<HOOK>=1 gdb -p <PID> -x scripts/gdb_dump.py`). Frida does NOT work under Wine — use this.
- `extract_funcs.py` — split objdump `.text` into per-function `.S` (for decoding).
- `extract_log_images.py` — pull the `0x0278` source frames (112×112 working images) from a Wine enroll log.
- `extract_finger_templates.py` — pull TID-valid `0x47 typ=6` finger templates from enroll logs.
- `parse_ws_tlv.py` — decode the ws-body TLV stream.

## Docs
**Current (load-bearing decodes)**
- `PER-SECTION-METADATA.md` — the 24B trailer (sub_180005720) + pose/quality (sub_180008980); load-bearing verdict (NOT read at verify).
- `V30-emitter-and-layout.md` — the v30 record emitter (sub_1800057e0); `[desc][x][y]` layout.
- `MULTIFRAME-EXPERIMENT.md` — placement-robustness protocol/result.
- `SCORER-sub_18000c6a0.md` — the verify matcher (positional Hough grid voting).
- `PACKER-sub_180002240.md`, `decode_sub_180008f10.md`, `CULL-sub_18000CF90.md` — packer / section orchestrator / cull decodes.
- `transformation-doc/` — 55 model-fitter / `sec0_pre`-registration function decodes (+ README index). Geometric registration; not needed for matching but documents the math.
- `PRE_V30-decode.md`, `ENROLLMENT-checkforduplicate.md` — pre-v30 TLV structure / enrollment dedup.

**Reference**
- `DLL-RE.md`, `MOH.md` — master RE notes (gradient kernel chain, protocol, TID derivation, chip-state recovery).

**Historical (superseded — kept for context)**
- `NEXT-SESSION.md` — a mid-investigation handoff, now superseded by this README + memory.

(A `CONSOLIDATION-capture-plan.md` once existed for a "multi-frame consolidation"
that turned out to be an artifact of the layout bug — there is no consolidation —
so it was dropped. The v30 emitter it analyzed is documented in
`V30-emitter-and-layout.md` + `PER-SECTION-METADATA.md`.)

> ~39 one-off investigation/diff/validate scripts were removed in the cleanup
> (`moh-opencv-cleanup`); they remain recoverable from the `moh-opencv-poc`
> branch history if a specific check ever needs revisiting.
