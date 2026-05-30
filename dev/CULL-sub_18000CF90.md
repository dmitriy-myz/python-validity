Dump dir is not currently mounted, but the constants are already baked into `moh_native.py` (t_lo=671, t_hi=168, dedup_q=72064, margin=10) and the comments state they were validated set/count/order-exact. I have everything needed for the report.

# Decode synthesis — sub_18000A1B0 and the per-tile keypoint cull

## TL;DR for this codebase
The cull is **already ported and validated** in `validitysensor/moh_native.py` (`nms()` = `sub_18000CF90`, plus the A960 + 250-cap + tile_id re-sort in `extract_frame_native()`). This new disasm **confirms** that port byte-for-byte and pins down the remaining open offsets. The task premise that A1B0 *is* the cull is wrong — A1B0 is the per-frame feature builder; the cull is `sub_18000CF90`, reached via `sub_18000A4B0 → sub_18000F300 → sub_18000D340 → sub_18000CF90`.

## (1) What A1B0 does per tile (NOT the cull)
`sub_18000A1B0` is the per-frame/per-scale **feature builder**. No keypoint-reduction loop exists in it. Its calls:
- `0x18000a269` `sub_18000a0e0` — padded tile-grid dims from 4 pad-flags.
- `0x18000a3f6` `sub_180009f50` — edge-replicate pad of the image plane.
- `0x18000a413` `sub_18000a120` — **config init** that writes the cull constants into the ctx struct: `+0x24=0xA8` (t_hi), `+0x20=sensor[+0x14]` (t_lo), `+0x48=(sensor[+0x10]<<10)>>4` (dedup_q), plus tile geometry (`+0x38=0x57`, `+0x18/+0x1c=0x400`).
- `0x18000a436` `sub_18000c920` — builds the per-tile region table (0x70 stride, count@`+0x58`); copies each tile's **image plane** via memcpy `sub_1800e0ca0`. Runs *before* DoH, so no keypoints exist yet — confirmed not a cull.
- `0x18000a482` `sub_18000f250` — DoH response requantize (`>>6`, Hessian-det `sxx*syy−sxy²` with `>>0xc`, `<<6`), producing the signed-i32 response map the cull later reads.

The parent `sub_18000A4B0` then calls `sub_18000F300` (`0x18000a58b`), which runs the actual cull (`D340→CF90`) and the subpix/orient pass (`D5D0`).

## (2) THE CULL RULE — `sub_18000CF90` (exact, reimplementable)
For each tile's signed-i32 DoH response map `R[y*W+x]`, scanning `y,x ∈ [border, dim−border)` (`border` = `r9`/`[rsp+0xc0]` arg = **10** on this HW), a pixel is kept iff **all** hold, in this order:

1. **Two hard scalar thresholds** (`q` = signed response):
   - `q > t_lo`  — `0x18000d0d8` `cmp edx,[r12+0x20]; jle`. `t_lo` = ctx`+0x20` = `sensor[+0x14]` (runtime noise floor; **671** captured).
   - `q >= t_hi` — `0x18000d0e3` `cmp edx,[r12+0x24]; jl`. `t_hi` = ctx`+0x24` = **0xA8 = 168** (constant, set in A120 `0x18000a17c`).
2. **Strict 8-neighbour NMS** — `q` must be strictly `>` all 8 spatial neighbours (eight `cmp …; jle reject` at `0x18000d0ee, d0f7, d0ff, d109, d112, d11c, d125, d133`). Score used downstream is `|q|` (`0x18000d13c`).
3. **Adaptive squared-distance dedup** against already-accepted kps (`0x18000d170–d198`): radius `r2 = ((dedup_q>>6)²) >> 20`, `dedup_q` = ctx`+0x48` = `(sensor[+0x10]<<10)>>4` (computed `0x18000d142` sar6 / `d15d` imul / `d161` sar20). If `dx²+dy² <= r2` for any accepted kp: **replace** that kp iff strictly stronger (`0x18000d2f1 cmp edx,[r8+r14+0x10]; jle keep-old`, else overwrite `0x18000d30a`), else **append** (`0x18000d1ee`). With the captured `dedup_q=72064`, `r2 = 1`, so the dedup is effectively a no-op (strict-`>` NMS already excludes adjacent equals).
4. **Sign/branch flag** from two sign maps (`signA@+0x30`, `signB@+0x40`) → record flag byte (`0x18000d1bc–d1d7`).
5. **Append** a 0x20 record (`0x18000d1ee–d210`): layout `[0,0,0,0, |q|, x, y, 0]` as i32 — quality/coords filled later. `accepted++` (`0x18000d1f1`).
6. **Global accepted cap** (NOT per-tile): `CAP = D340 5th-arg >> 2` (`sub_18000D340 0x18000d380 shr esi,2`), stored `[rsp+0x50]`; `0x18000d21e cmp rsi,[rsp+0x50]; je exit` ends the **entire** scan. This = the already-ported **250** for this frame geometry.

This is **(b) adaptive threshold + (c) min-distance dedup + strict NMS, bounded by a single global cap** — explicitly **NOT** (a) a fixed per-tile top-N and **NOT** (d) area-derived.

Python equivalent is exactly `nms(resp, t_lo=671, t_hi=168, dedup_q=72064, margin=10)` at `moh_native.py:254`, which the file documents as validated set/count/order-exact across all 12 tiles.

## (3) Why the counts are 29,27,17,33,36,33,30,26,19
These are **not** a quota. Each tile independently yields whatever survives `q>671 && q>=168 && strict-8nb-max` (dedup ~no-op at r2=1). The variation tracks ridge content per tile. The **global** 250-cap (`shr >>2`) only truncates the *frame* total — for frame-0 the sum (250) sits at the cap, after which the ported pipeline does a global qsort by `|resp|` desc, caps to 250, then **re-sorts by (tile_id ASC, |resp| DESC)**; the per-tile group sizes of that capped+regrouped pool reproduce `[29,27,17,33,36,33,30,26,19]` exactly. Confirmed by `dev/validate_cull.py` (uses `nms_kp`/`nms_resp` captures, asserts against `EXPECTED = [29,27,17,33,36,33,30,26,19]`).

Note the subtlety: in the DLL the global cap lives one level up (the 250-cap + tile_id re-sort are post-CF90, already ported); CF90 itself only enforces the cap as a hard scan-stop. The validated Python models the post-CF90 stages explicitly (Phases 2–4 of `extract_frame_native`), which is the faithful net result.

## (4) Port + validation status
Already present and validated in `/home/dev/projects/own/python-validity/validitysensor/moh_native.py`:
- `nms()` (line 254) = CF90: thresholds, strict 8-nb NMS, dedup. Constants baked: `t_lo=671, t_hi=168, dedup_q=72064, margin=10`.
- `subpix_refine_kp()` / `subpix_refine_kps()` (lines 315/351) = D5D0+D4C0 reject-on-|off|>0x80.
- `_a960_passes_global_edge()`, `FRAME_KP_CAP=250` (line 850), global qsort + tile_id re-sort = Phases 1–4 of `extract_frame_native()` (line 891).

Validate against the `minutia_table` / `nms_*` dumps:
- Producer: `dev/gdb_dump.py` — `NmsEntryBP` (RVA `0xCF90`) saves `nms_kp_*_call{idx}_n{count}.bin` (0x20-stride records), `nms_resp_*_call{idx}_{w}x{h}.bin` (i32 response map), `nms_thr_*_call{idx}` (the `<3i` = t_lo,t_hi,distp triple), and `minutia_table` (count × 32) at `sub_18000A5B0`.
- Harness: `./.venv-poc/bin/python dev/validate_cull.py` reloads per-tile `nms_kp`+`nms_resp`, replays Phases 1–3, and asserts per-tile survivor counts == `[29,27,17,33,36,33,30,26,19]`.
- To re-confirm the constants whenever the dump dir (`/media/sf_vbox-rw/finger/frida_dumps`) is remounted: parse any `nms_thr_*call0*` with `struct.unpack('<3i', …)` and assert it equals `(671, 168, 72064)`.

## (5) Still NEEDS-HOOK / open
- **Confirm CF90's `rdx` struct identity.** A120 initializes a config struct; C920 fills the per-tile table; both expose `+0x50`/`+0x58`. Threshold values hold either way (copied), but capture the live `rdx` base into CF90 (boundary hook at `0x18000cf90`) to prove `+0x20/+0x24/+0x48` read the A120 config, not the tile table.
- **Confirm the live `dedup_q` and CAP arg.** Captured `dedup_q=72064 → r2=1` (dedup inert) and `CAP = D340-arg>>2`; re-derive the D340 5th arg numerically to prove it equals 250 (`mov`/`shr` trace at `0x18000d37c–d391`). If a different sensor ever yields `r2>1`, the replace-if-stronger dedup becomes live and must be exercised — current Python already implements it, but it is untested at `r2>1`.
- **Threshold timing vs requantize** is resolved: CF90 runs after F250 in the same `A1B0→F300` chain, so thresholds apply to the `>>6<<6` requantized response — matches the Python (`doh(tile>>6)`).
- Record x/y storage offsets (`x@+0x14`, `y@+0x18` in the final minutia layout vs CF90's transient `[rsp+0x14..0x1c]`) are confirmed against the validated `<8i` CF90 layout `[0,0,0,0,|q|,x,y,0]`.

No code change is required — this decode is a confirming audit of an already byte-exact port. The only NEEDS-HOOK item that could change behavior is a non-inert `dedup_q` (`r2>1`) on other sensor revisions.