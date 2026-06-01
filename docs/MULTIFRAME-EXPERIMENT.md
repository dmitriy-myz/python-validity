# Multi-frame robustness experiment (06cb:00a2 native enrollment)

Single-frame from-scratch enrollment WORKS (live, hardware-confirmed 2026-06-01),
but a single frame only covers one finger placement, so a verify capture placed
differently can miss. This experiment tests whether **multi-frame** enrollment
(N distinct placements, one per v30 section) makes matching robust to placement —
**without** needing real `sec0_pre` transforms.

## Hypothesis (from the `sub_18000c6a0` matcher decode)
The matcher tries each `sec0_pre` candidate transform and takes the **argmax grid
occupancy** vs the query. With **identity** `sec0_pre` and N distinct-placement
sections, each section's 250 keypoints sit at their own image coords; the query
overlaps whichever section's placement it's closest to, and the other sections'
keypoints land in *different* grid cells (they don't dilute the winning vote).
⇒ N sections = N chances for the query to overlap → **broader coverage, no
registration needed.** (Confirmed offline: multi-frame build is structurally valid
— each section holds its distinct frame's `[desc][x][y]` records, identity
`sec0_pre`, per-section trailer regenerated, TID valid.)

If instead the chip needs the distinct frames CONSOLIDATED into one coordinate
frame (real `sec0_pre`), multi-frame+identity will not help (or will only match
the placements it stored) — that result tells us we'd need the registration port.

## Method
`enroll_native` already captures `--frames N` and round-robins them across the v30
sections (with the layout fix + per-section trailer regen). The flow:

1. **Recover/clean** (chip may be in 0x04b5 from prior writes → Wine enroll to reset):
   ```bash
   sudo ./.venv-poc/bin/python scripts/enroll_native_chip.py --list-users
   sudo ./.venv-poc/bin/python scripts/enroll_native_chip.py --delete-dbid <native_finger_dbid>
   ```

2. **Baseline (single frame)** — reference-free:
   ```bash
   sudo ./.venv-poc/bin/python scripts/enroll_native_chip.py \
     --identity-sec0pre --frames 1 --match --parent 6
   ```
   Then probe placement robustness — verify several times, each with a DELIBERATELY
   different finger placement (shift/roll up–down–left–right):
   ```bash
   for i in 1 2 3 4 5; do
     sudo ./.venv-poc/bin/python scripts/enroll_native_chip.py --match-only; done
   ```
   Record how many of the varied placements matched.

3. **Multi-frame** — delete the baseline finger, then enroll 4 DISTINCT placements
   (IMPORTANT: shift/roll the finger between the 4 "place finger" prompts so they
   cover different regions):
   ```bash
   sudo ./.venv-poc/bin/python scripts/enroll_native_chip.py --delete-dbid <baseline_dbid>
   sudo ./.venv-poc/bin/python scripts/enroll_native_chip.py \
     --identity-sec0pre --frames 4 --match --parent 6
   for i in 1 2 3 4 5; do
     sudo ./.venv-poc/bin/python scripts/enroll_native_chip.py --match-only; done
   ```
   Record matches across the same varied placements.

## Read-out
- **Multi-frame matches MORE varied placements than single-frame** → hypothesis
  confirmed; robust from-scratch enrollment achieved with identity `sec0_pre`.
  (Recommended default: `--frames 4`.)
- **No improvement / fewer** → the chip wants consolidated geometry; we'd then need
  the `sec0_pre` registration port (the model-fitter, `transformation-doc/`),
  which is the only remaining hard piece.

## Notes
- Use the SAME finger throughout; vary only the placement.
- mode: reference-free uses the baked mode-A scaffold (4 v30 sections); `--frames 4`
  fills all 4 with distinct frames. Pass `--ref <template>` to use a 5-section
  (mode-B) framing instead (round-robins 4 frames into 5 sections).
- `0x04b5` mid-experiment = chip bad-state from repeated writes → Wine re-enroll to
  recover, then resume.
