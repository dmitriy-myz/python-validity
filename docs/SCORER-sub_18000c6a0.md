# sub_18000c6a0 (120×120 voting-grid match scorer) — decompilation

Shared per-tile match/score routine in the Synaptics MoH fingerprint DLL
(`/tmp/syna.dll`). Called by **both** sides of the matcher:

- enrollment section-build via `sub_180008f10` (see `decode_sub_180008f10.md`)
- identify / duplicate-check via `CeivMode::IdentifyUser` `sub_180027540`
  (the `EnrollmentCheckForDuplicate` gate — see `ENROLLMENT-checkforduplicate.md`)

It is the **wiring** around a 0x3840 = 14400-byte = **120×120-cell spatial voting
grid** (1 byte/cell). It materializes the grid from a template, votes the
candidate's keypoint alignments into it, measures occupancy, runs the real
scorer, lands the verdict in two OUT pointers, and on a win serializes the
matched v30 record + a geometry/match table.

All addresses below are confirmed against `objdump -d` of `/tmp/syna.dll`
(.text VMA `0x180001000`, file offset `0x400`; file_off = vma − 0x1000 + 0x400).

---

## 1. Signature & role

```c
// MSVC rax-alias incoming-arg pattern: 5 pushes (0x28) + sub rsp,0xe0
//   => rax = rsp_cur + 0x108; arg5 = [rsp+0x130] ... arg14 = [rsp+0x178].
int sub_18000c6a0(
    void*    obj_lo   /*rcx  arg1*/,   // 0x30-byte caller object, span-copied to seed GD descriptor
    void*    obj_hi   /*rdx  arg2*/,   //   (paired home with arg1)
    void*    candidate/*r8   arg3*/,   // r14: CANDIDATE / enrolled-side records (5th arg to bfd0/c510/bdf0)
    KpRecs*  query    /*r9   arg4*/,   // rdi: QUERY records; esi = BYTE[r9+0x10] = tile id / count N
    /*arg5  [rsp+0x130]*/ ...,
    Dims2*   dims     /*arg6 [rsp+0x138]*/,  // r12: {i32 w @+0, i32 h @+4}
    GridCtx* grid     /*arg7 [rsp+0x140]*/,  // rbx: GRID/CTX buffer; *(rbx) = OUT best-index
    uint8_t  a9       /*arg8 [rsp+0x148]*/,  // -> bdf0 r9d (tile byte)
    /*arg9  [rsp+0x150]*/ ...,
    uint8_t  a10      /*arg10[rsp+0x158]*/,  // -> c510 [rsp+0x48]
    int      refTileN /*arg11[rsp+0x160]*/,  // COMPARISON reference tile count (the equality gate)
    int*     matchFlag/*arg12[rsp+0x168]*/,  // r13: OUT MATCH-FLAG
    void*    srcBlob  /*arg13[rsp+0x170]*/,  // template/blob for both span-copies + TLV ctx
    int      a14      /*arg14[rsp+0x178]*/); // -> c510 edx ([rsp+0x58])
// returns EAX = 1 if a matched record was emitted, 0 otherwise.
```

Key roles:

| element | what it is |
|---|---|
| **query** (`rdi`, r9) | the probe / query keypoint-alignment records; v30 serialize source. `BYTE[rdi+0x10]` = tile id `N` (also bumped in the merge arm). |
| **candidate** (`r14`, r8) | the enrolled-side / candidate records voted into the grid. |
| **grid** (`rbx`, arg7) | the 120×120 grid/context buffer. **Its first dword aliases the OUT best-index.** Same pointer is `rcx` to bfd0 (fill), c240 (count ×2), c1a0 (cleanup), c510 (score). |
| **`*(rbx)`** = OUT **best-index** | init `0xffffffff` at `c6da`; set by scorer (equal arm) or to `tileN` (compare arm, `c802`). The −1 sentinel is c6a0's own match gate. |
| **`*(r13)`** = OUT **match-flag** | init `0` at `c6e0`; set `1` at `c7f6` = "same finger / duplicate". |
| return EAX | `1` = emitted (`c8f3`), `0` = no emit (`c8fa`). |

c6a0 itself holds **NO numeric score threshold** — the numeric scoring is in
`sub_18000c510`, the per-cell saturation in `sub_18000bfd0`, the argsort in
`sub_18000bdf0`. c6a0's decision is the sentinel test `*(rbx) != −1`.

Confirmed instructions:
`c6da mov [rbx],0xffffffff`; `c6e0 mov [r13+0x0],0x0`;
`c6e8 movzx esi,BYTE PTR [r9+0x10]`;
`c791 cmp esi,[rsp+0x160]` / `c798 jne c800`;
`c7ed cmp [rbx],0xffffffff` / `c7f6 mov [r13+0x0],0x1`;
`c800 cmp eax,ebp` / `c802 mov [rbx],esi` / `c804 jl c8fa` / `c80a add BYTE PTR [rdi+0x10],0x1`;
`c80e cmp [rbx],0xffffffff` / `c811 je c8fa`; `c8f3 mov eax,0x1`.

---

## 2. The grid-voting match ALGORITHM (KEY)

The matcher is a **Hough / 2-D spatial-consensus voting accumulator** over the
120×120 grid. A cell does NOT hold a descriptor — it holds a count of how many
keypoints land in that 8-px spatial bucket after a candidate rigid alignment.
The match metric is the **occupied-cell count** (spatial inlier count), not a
peak-bin magnitude.

### Step A — materialize the grid from a template (`c701`)

`sub_180003320(dst=rsp+0xa8, src=srcBlob, len=0x3840, &slot)` span-builds the
0x3840-byte (120×120) grid from the template and returns a 0x30-byte span header
in `rax`; that header is copied into the local **GD** descriptor at `[rsp+0x78]`
(`GD[0]` = grid data pointer). Each match thus starts from a known template
state. *(The 0x3840 dst cannot fit the 0xe0 frame, so 180003320 returns a real
data pointer in rax rather than copying into the local — confirm allocation
behavior from its own decode.)*

### Step B — VOTE the candidate keypoints into the grid (`c759`, `sub_18000bfd0`)

```c
int sub_18000bfd0(uint8_t* grid /*120x120*/, int N, int xExtent, int yExtent,
                  Record20* records /*[rsp+0x28]*/);
```

Concrete vote algorithm (confirmed constants `0x3c`/`0x3840`/`0x78`/`0x77`/`0x64`/`0x63`):

1. **Grid origin / centering.** `r14d = 0x3c − round((xExtent/2) >> 3)` and
   `r13d = 0x3c − round((yExtent/2) >> 3)`. `0x3c = 60` = half of 120; `>>3` =
   image→cell `/8` scale. The tile is centered at cell (60,60).
   (`c0` for `mov r13d,0x3c` at `c0bfe6`; `0x3840` memset len at `bff5`.)
2. **Clear grid:** `sub_1800031c0` = guarded `memset(grid, 0, 0x3840)` (`c025`).
3. **Outer loop** over `N` records (stride **0x14 = 20** bytes), `r12 = rec+4`.
   Per record `sub_18000bfb0(rec)` = validity predicate: keep iff
   `dword[rec+0xc] != 0 || dword[rec+0x10] != 0` (the (tx,ty) of the transform).
4. **Inner 8×8-subsampled lattice** over the tile extent: `j = 0..yExtent step 8`,
   `i = 0..xExtent step 8`. For each lattice point call
   `sub_180006bc0(out_cx, out_cy, i, j, matrix=rec+4)` =
   the **Q16 (16.16) fixed-point 2-D similarity transform**:
   `out_x = (a·i − b·j + tx + 0x8000) >> 16`,
   `out_y = (b·i + a·j + ty + 0x8000) >> 16`,
   where the 4 matrix dwords are `a@rec+4, b@rec+8, tx@rec+0xc, ty@rec+0x10`
   (`a = s·cos`, `b = s·sin`).
5. **Cell index:** `col = r14d + round(out_cx >> 3)`, `row = r13d + round(out_cy >> 3)`.
   Bounds: if `col > 0x77 (119) || row > 0x77` skip (`c0db`/`c0e0`). Linear
   index = `col + row*0x78` (`imul ...,0x78` at `c0ea`).
6. **Cast the vote (saturating):** `if (cell < 0x64) cell += 0x64;`
   (confirmed `c0f6 cmp al,0x64` / `c0fa add al,0x64`). So each valid record
   stamps **+100 once** into the single cell its alignment lands in, capped at 100.
7. **Normalization sweep** over all 120×120 cells: `if (cell >= 0x64) cell -= 0x63;`
   (confirmed `c136 cmp cl,0x64` / `c13b sub cl,0x63`). This collapses every
   stamped 100 → **1** while leaving any sub-100 residue untouched — turning the
   saturated stamps into clean per-cell vote counts.

Returns 1 iff ≥1 record voted. **Net: cell = number of candidate alignments
whose transform lands a tile keypoint in that 8-px spatial bin.**

### Step C — first occupancy count (`c769`, `sub_18000c240` → `count1`/`ebp`)

`sub_18000c240(grid)` scans exactly **0x3840** bytes and returns how many are
non-zero. `count1` = template-footprint occupied cells after the fill.

### Step D — second coverage pass (`c77c`, `sub_18000c1a0`)

```c
void sub_18000c1a0(uint8_t* grid, int probe_w /*=[r12+0]*/, int probe_h /*=[r12+4]*/);
```

Same centering math (`0x3c − (extent/2)/8`) but it walks the probe image's
**rectangular bounding box** on an 8-unit lattice and does `grid[cell] += 1`
**unclamped, no bounds check, no transform** (these are image extents, not
keypoint coords). Cells covered by **both** template and probe become 2;
probe-only cells become 1. This is the union-coverage / normalization stamp.

### Step E — second occupancy count (`c789`, `sub_18000c240` → `count2`/`eax`)

`count2` = occupied cells of the union after the c1a0 pass.

### Step F — branch on tile identity (`c791`: `cmp esi,[rsp+0x160]`; `c798 jne`)

**EQUAL arm — true SCORER (identify / CheckForDuplicate side):** call
`sub_18000c510(grid, edx=count1, r8d=count2, r9d=tileN, [rsp+0x20]=&best, +0x28=candidate, +0x30=query, +0x38=dims.h, +0x40=dims.w, +0x48=a10, +0x50=&GD, +0x58=a14)` at `c7e8`.

`sub_18000c510` is a per-candidate **argmax-consensus** scorer:

- Copies the grid template into a local working grid (`sub_180003320`), sets
  `*(out_best) = 0xffffffff`, seeds running-best `edi = count1`.
- **Fast path:** if `[rsp+0x108]!=0 && r8d>edi`, call `sub_18000c3d0` (per-cell
  histogram lookup over an existing correspondence list; returns a record index
  whose `(x,y,flag)` matches, or −1). If ≥0 it stores it and returns — the
  "already have a correspondence table" shortcut.
- **Main loop** over `ebp` candidate records: for each *valid*
  (`sub_18000bfb0`) record:
  1. `sub_18000c270` = the voter: transform each keypoint (`sub_180006bc0`),
     bounds-check vs `0x77`, **stamp `grid[row*0x78+col] = 0xff`** and log the
     linear cell id into a coord list; `*(rdi)` = number stamped.
  2. `sub_18000c240` = count non-zero cells = **this candidate's score** (`r11d`).
  3. `sub_18000c4e0(grid, coord_list, len)` = post-increment each logged cell
     (`grid[offsets[k]] += 1`) — the scatter-vote primitive that rebuilds the
     grid for the next pass.
  4. **Compare:** `cmp r11d,edi; jl skip` — if `score >= running_best`, set
     `edi = score` and `*(out_best) = candidate_index`.
- Returns (via `*(rbx)`) the index of the candidate alignment producing the
  **most occupied cells**, provided it ≥ the incoming best.

Back in c6a0: `c7ed cmp [rbx],0xffffffff; je c8fa` — if the scorer left −1 (no
candidate cleared the running-best bar), **return 0, match-flag stays 0**.
Otherwise `c7f6 mov [r13+0x0],0x1` — **MATCH FLAG SET = same finger / duplicate**.

**NOT-EQUAL arm — compare-only / enrollment merge (`c800`):**
`cmp eax,ebp` (count2 vs count1); `c802 mov [rbx],esi` sets best-index = tileN
**unconditionally**; `c804 jl c8fa` — if `count2 < count1` (the c1a0 union
coverage shrank vs the template footprint) → reject, return 0, no emit. The kept
condition is **`count2 >= count1`**. On keep, `c80a add BYTE PTR [rdi+0x10],0x1`
bumps the query tile hit counter. This arm does **not** set the match-flag.

### Step G — common merge gate (`c80e cmp [rbx],0xffffffff; c811 je c8fa`)

Both arms reconverge. If best-index is still the −1 sentinel → return 0, no
record. Otherwise fall through to EMIT.

### THE MATCH DECISION — exact landing

- **Value(s) compared:** in the equal/scorer arm, candidate occupied-cell
  `score (r11d) vs running-best (edi)` inside c510 (seeded from `count1`), then
  c6a0's gate `*(rbx) (best-index) vs 0xffffffff (−1)`. In the compare-only arm,
  `count2 (eax) vs count1 (ebp)`, keep on `>=`.
- **Constant compared in c6a0:** `0xffffffff` (−1) at `c7ed`, `c80e`, `c811`.
  There is **no FAR/score magic constant in c6a0** — the effective threshold is
  the dynamic running-best inside c510 (no literal score cutoff was found there
  either; `0x12c=300` and `0x333=819` are bdf0 argsort caps/seeds, not thresholds).
- **Where the verdict lands:** `*(r13)` (arg12) = match-flag (0 init / 1 on
  match); `*(rbx)` (arg7 first dword) = best matched index; EAX = 1 if emitted.

**To reimplement:** build a 120×120 byte grid centered at (60,60); for each
candidate alignment record (20-byte: `[x:u8][y:u8][pad][a,b,tx,ty: i32 Q16]`),
project an 8-px lattice of the tile through the Q16 similarity into the grid,
saturating-stamp the hit cell, normalize 100→1; the **score is the number of
non-zero cells**; the winner is the argmax candidate whose score ≥ the running
best (seeded from `count1`); declare a match when a winner exists. The
enrollment-merge variant instead keeps the tile iff union-coverage ≥ footprint.

---

## 3. Call map

| callee | role | grid / score function | conf |
|---|---|---|---|
| `0x180003320` (`c701`) | span-build / materialize the 0x3840 grid template → GD header | makes the grid (copy#1) | high |
| `0x18000bfd0` (`c759`) | FILL / voter: saturating +100 stamp per valid record into 1 cell | **fills grid** | high |
| `0x18000c240` (`c769`) | count non-zero cells → `count1` (ebp) | **score primitive** | high |
| `0x18000c1a0` (`c77c`) | in-place probe-bbox coverage stamp `+1` unclamped | grid mutation | high |
| `0x18000c240` (`c789`) | count non-zero cells again → `count2` (eax) | **score primitive** | high |
| `0x18000c510` (`c7e8`) | SCORER: argmax candidate by occupied-cell count; writes `*(rbx)` | **the scorer** | medium |
| `0x18000c270` (in c510) | voter: stamp `0xff` per keypoint, log cell ids | grid vote | medium |
| `0x18000c4e0` (in c510) | scatter `+1` into logged cells | grid vote | high |
| `0x18000c3d0` (in c510) | fast-path correspondence-list histogram lookup | score shortcut | low |
| `0x180006bc0` (in bfd0/c270) | Q16 16.16 similarity transform (x,y)→cell | coord map | high |
| `0x18000bfb0` (in bfd0/c510) | record validity: `dw[+0xc]!=0 \|\| dw[+0x10]!=0` | filter | high |
| `0x180003320` (`c835`) | span-build 0x11bc (4540B) emit scratch from srcBlob | emit (copy#2) | high |
| `0x1800066a0` (`c884`) | TLV open-record; record-id = `*best_index + 4` | emit | high |
| `0x1800057e0` (`c8b1`) | v30 RECORD SERIALIZER (8B hdr + u8 count + N×18B `[16B desc][x][y]`) | emit | high |
| `0x180006a80` (`c8c3`) | TLV close / length backpatch | emit | high |
| `0x18000bdf0` (`c8ee`) | 20-byte geometry/match TABLE builder + argsort (N=0x12c=300) | post-match geometry | high |

---

## 4. The 20-byte geometry/match table (`sub_18000bdf0`) + argsort

Runs **only on the EMIT path**, after a tile is already declared a match. It does
**not** touch the grid or compute a score. Inputs are products of the grid stage:
`best_idx = *(rbx)` (winning alignment) and `N` (count of voted pairs).

Record layout (stride **0x14 = 20**): `byte@+0 = cell-x`, `byte@+1 = cell-y`,
2 pad, then the 16-byte similarity transform as 4× u32 at `+0x4`
(`a@+4, b@+8, tx@+0xc, ty@+0x10`) — the **same** matrix `sub_180006bc0` consumes
for grid voting.

For each matched keypoint `i` of the winning hypothesis, bdf0 builds **two
reciprocal per-tile tables** in `*(r14+0x18)[*]`:

- off-diagonal/unmatched & `i==best` slots get the **identity sentinel**
  `{0x10000,0,0,0}` with `byte0=0, byte1=0xff` (`sub_180007a70`; tested by
  `sub_18000b420`).
- the valid, non-identity entry `i` stores the **forward** transform `T` in
  `table[i][best]`, and its **inverse** `T⁻¹` (via `sub_180006da0`, negate-b
  inversion) in `table[best][i]`. So if record `i` maps query→ref by `T`, the
  reciprocal slot stores ref→query.

Then `sub_18000bd10` ARGSORTS: it re-reads `BYTE[r14+0x10]` = tile N, builds a
2-byte `{key,index}` array with **every key = 0**, and sorts (`0x1800095c0`,
comparator `0x18000b1f0`: primary `BYTE[+0]` descending, tie-break `BYTE[+1]`).
With a constant key this yields the **identity permutation** — a stable-sort
scaffold whose score key is currently held at 0 (`0x12c=300` and `0x333=819` are
passed but not consumed by bd10's own loops).

So this table = the **geometry of the confirmed match** (per-correspondence
forward + inverse alignment transforms of the winning vote cluster), in two
reciprocal per-tile tables, persisted for record/section build — not a score.

---

## 5. Duplicate detection vs identify/verify — same code, different inputs

Both `EnrollmentCheckForDuplicate` (`sub_18001e5f0 → sub_18001f670 →
CeivMode::IdentifyUser sub_180027540`) and the enrollment section-builder
(`sub_180008f10`) call **this same `sub_18000c6a0`**. The two arms of the
`cmp esi,[rsp+0x160]` branch are the two use modes:

- **Identify / CheckForDuplicate (EQUAL arm):** caller passes the probe tile id
  equal to `refTileN`, so the true scorer `sub_18000c510` runs, computes the
  occupied-cell consensus score, and on a winner sets `*(r13)=1`. **A match here
  means "same finger already enrolled" → duplicate.** This is the path the
  CheckForDuplicate gate consumes (`out[0x4d] = valid flag`, per
  `ENROLLMENT-checkforduplicate.md`).
- **Enrollment section-build / merge (NOT-EQUAL arm):** the probe tile id differs
  from `refTileN`, so it skips the scorer and just compares union-coverage
  (`count2 >= count1`), records the tile index, and bumps `BYTE[rdi+0x10]`. This
  is the in-memory template accumulate during `EnrollmentUpdate`, **not** a
  same-finger verdict (it never sets the match flag).

Same grid math, same emit/serialize tail; the caller's `refTileN` (arg11) and
the tile id `BYTE[query+0x10]` select which behavior fires.

---

## 6. Contradictions / low-confidence items

- **No literal score threshold anywhere on this path.** The "threshold" is the
  dynamic running-best inside c510 (seeded from `count1`) plus the
  `*(rbx) != −1` sentinel. The FAR/decision constant — if one exists — must be in
  c510's caller seed or higher up in `IdentifyUser`. `0x12c=300`/`0x333=819` are
  bdf0 argsort caps/seeds, **not** thresholds; `0x64/0x63` are bfd0 saturation.
- **c510 confidence = medium.** Grid geometry, the `0x64/0x63/0x77/0x78/0x3840`
  constants, and the vote→count-occupied→argmax scoring are firm; the c3d0
  fast-path correspondence semantics and the exact in/out lifetime of
  `best_score` across the c6a0→c510 boundary are **inferred**, not fully traced.
  The bdf0 argsort key is held at 0 (identity permutation) — whether a real key
  is written elsewhere (e.g. via the forwarded `[rsp+0x20]`/`[rsp+0xa8]` ctx) is
  open.
- **180003320 grid allocation.** The 0x3840 dst (`rsp+0xa8`) cannot fit the
  0xe0 frame, so 180003320 must return a real data pointer in `rax` (GD[0])
  rather than copy into the local. Confirm heap/borrow behavior from its decode.
- **Arg semantics** of `a9` (`[rsp+0x148]`→bdf0 r9d), `a10` (`[rsp+0x158]`→c510),
  and `a14` (`[rsp+0x178]`→c510 edx) are likely flags/mode/table-id but are set
  by c510/bdf0, not c6a0.
- **`sub_18000c270` vs `sub_18000bfd0` voting differ:** bfd0 stamps `+0x64`
  saturating then normalizes; c270 stamps `0xff` and id-logs, then c4e0 does
  `+1`. They build the grid differently (fill vs per-candidate re-vote) but both
  feed the same `c240` occupied-count metric — consistent, just two stages.
- **Enrollment-only vs identify-only arm assignment** is inferred from the
  caller contracts; worth confirming directly against `sub_180008f10` (build)
  and `sub_180027540` (identify) call sites that they pass `refTileN` the way
  this model predicts.

---

## 7. Recommended next steps + gdb hook to confirm score/threshold

1. **Read c510's own decode** for any literal score cutoff and the c3d0
   fast-path; the report above treats the threshold as the dynamic running-best,
   which is the only mechanism visible in c6a0. Full c510 notes in
   `/tmp/c510_analysis.json`.
2. **Confirm the score at runtime under Wine + gdb** (the project already uses
   `scripts/gdb_dump.py` for this kind of capture; base image is `/tmp/syna.dll`).
   The two highest-value breakpoints:
   - **`0x18000c789`** (the second `call sub_18000c240`): break here and read
     `ebp` (= `count1`) and, after stepping over, `eax` (= `count2`). These are
     the two occupancy scores driving both arms.
   - **`0x18000c7ed`** (`cmp DWORD PTR [rbx],0xffffffff`, equal arm only): break
     here and dump `DWORD[rbx]` (the winning index the scorer chose) and the
     `edi` running-best that c510 returned through. Then watch whether
     `0x18000c7f6` (`mov [r13],0x1`) is reached — that single store is the
     literal "duplicate / same finger" verdict.
   - Optionally **`0x18000c510`** entry: dump `edx` (seed best/threshold),
     `r9d` (candidate count), and the grid pointer `rcx`; then dump the
     0x3840-byte grid before/after each `sub_18000c270`/`c240` pair to see the
     per-candidate occupied-cell scores directly and recover the effective
     decision boundary empirically.
   - To watch the emitted geometry table, break **`0x18000c8ee`** (`call bdf0`)
     and dump `*(r14+0x18)[best]` (the 20-byte records) after return.
3. Cross-check the two callers (`sub_180008f10` build vs `sub_180027540`
   identify) to confirm the EQUAL-arm = identify/CheckForDuplicate and
   NOT-EQUAL-arm = enrollment-merge assignment, and to capture what `refTileN`
   (arg11) each passes.

---

*Cross-refs: `decode_sub_180008f10.md` (section orchestrator / build side),
`ENROLLMENT-checkforduplicate.md` (CheckForDuplicate dispatch chain),
`MOH.md` / `DLL-RE.md` (template architecture). v30 serializer
`sub_1800057e0`, argsort `sub_18000bd10`, span-copy `sub_180003320`, TLV
`sub_1800066a0`/`sub_180006a80` decoded previously.*

---

## Addendum — `sub_18000c270` decoded (the inner per-candidate voter)

`sub_18000c270` (612 B) was re-decoded directly (high confidence). **It corrects
the "per-keypoint voting" framing:** it does NOT iterate keypoints. It is a
**dense forward-warp coverage paint** of one candidate alignment.

Signature: `c270(grid /*rcx*/, record_index /*edx*/, width_x /*r8d*/, height_y /*r9d*/, record_base /*[rsp+0x28]*/, cellid_log /*[rsp+0x30]→r13*/, out_count /*[rsp+0x38]→rdi*/)`.

Behavior (cite addrs): it picks the transform matrix of match-record
`#record_index` (`record_base + idx*0x14 + 4`, `c2fa`–`c309`), then **double-loops
a sample lattice over the source tile rectangle** `in_y ∈ [0,height) , in_x ∈
[0,width)` in **steps of 8** (`c2f0`/`c310`, `+8` at `c38b`/`c3a6`). For each
sample it calls the 16.16 similarity `sub_180006bc0`:

```
OUT_X = (a·in_x − b·in_y + tx + 0x8000) >> 16     // matrix [[a,−b],[b,a]] + (tx,ty)
OUT_Y = (a·in_y + b·in_x + ty + 0x8000) >> 16
A(col) = OUT_X/8 + (60 − width/16)                // c330–c33d
B(row) = OUT_Y/8 + (60 − height/16)               // c33f–c357
```

then bounds-checks `A,B ∈ 0..0x77` (`c358`/`c362`), stamps
`grid[B*0x78 + A] += 0xff` (`c37c`, NO saturation — unlike `bfd0`'s `+0x64` cap),
appends the linear cell id `B*120+A` to `cellid_log[*out_count]` and increments
`*out_count` (`c380`–`c388`). It computes **no** score/threshold — the caller
`sub_18000c510` reads the painted grid via `sub_18000c240` (count non-zero) for
the argmax, and `sub_18000c4e0` replays the cell-id log to clear/prep between
candidates.

**Refined picture:** the per-candidate score is the **count of distinct 120×120
cells covered when the source tile footprint is forward-warped through that
candidate's similarity transform** — i.e. a geometric coverage/consensus measure
over candidate alignments (RANSAC/Hough-like), `argmax` kept by `c510`. (`bfd0`
seeds the grid with the template-side occupancy and `c1a0` overlays the probe
bbox; `c270` is the per-hypothesis re-vote.) Only call is `sub_180006bc0`; no
`.rdata` refs; constants `0x3c`=60, `0x78`=120/`0x77`=119, step 8, `/16` recenter,
`0xff` stamp.

The one residual low-confidence item is the exact division of labour between
`bfd0` (template seed) and `c270` (per-candidate re-vote) — both use the same
lattice-warp idiom; a `GDB_DUMP` grid dump per candidate (`0xc510` entry) settles it.

---

## Addendum — `sub_18000bdf0` pairwise Q16 transform math (decoded)

`sub_18000bdf0(obj /*rcx→r14*/, self_idx /*edx→r12*/, rec /*r8*/, r9, N /*[rsp+0xa0]*/, out_ts /*[rsp+0xa8]*/)`
builds the **symmetric pairwise section-alignment table** at `*(r14+0x18)` (an array
of per-section row pointers). For each other-section `j = 0..N`:

- **forward** (`0x18000be96`): copy the matcher's transform record (`rec`, 20-byte
  `[x:u8][y:u8][2][a:u32][b:u32][tx:u32][ty:u32]`) into `table[j][self*20]` —
  `a@+4, b@+8, tx@+0xc, ty@+0x10, y@+1=rec[0], x@+0=rec[-1]`. Guarded by
  `sub_18000b420(rec)!=0` (skip if identity).
- **inverse** (`0x18000beeb`): `sub_180006da0(&inv, rec)` → store `inv` into
  `table[self][j*20]`.

Slots are pre-initialized by `sub_180007a70`/`a80` to `[x=0][y=0xff][identity]`
(`0xff` y = unmatched sentinel). Afterwards `sub_18000bd10` argsorts the rows
(section indices). `51f0` later serializes this table into `sec0_pre`.

### The transform (rigid 2D similarity, Q16)

Forward (matches `sub_180006bc0` used by the voter `c270`):
```
p' = ( (a·px − b·py + tx + 0x8000) >> 16 ,
       (b·px + a·py + ty + 0x8000) >> 16 )      R = [[a,−b],[b,a]] , t=(tx,ty)
```
**Identity = (a=0x10000, b=0, tx=0, ty=0)** (a = cos·65536; unit scale, so
a²+b² = 0x10000²). `sub_18000b420` tests exactly this 4-field identity.

### The inverse (`sub_180006da0`, integer, byte-exact)

```
inv_a  = a
inv_b  = −b
inv_tx = −( (a·tx + b·ty) >> 16 )     ; impl: −(((a>>1)(tx>>9) + (b>>1)(ty>>9)) >> 6)
inv_ty = −( (a·ty − b·tx) >> 16 )     ; impl: −(((a>>1)(ty>>9) − (b>>1)(tx>>9)) >> 6)
```
= inverse of a unit-scale similarity: inverse rotation = transpose `[[a,b],[−b,a]]`
(stored as `inv_a=a, inv_b=−b` so re-applying the forward formula gives Rᵀ),
inverse translation = `−Rᵀ·t`. No `/det` — assumes pure rotation (a²+b²=1), i.e.
the matcher emits rigid (rotation+translation) alignments, no scale.

### Verification status

The MATH is confirmed from the disasm (identity sentinel `0x10000,0,0,0` from
`b420` pins a,b,tx,ty as Q16). NOT yet byte-verified against `sec0_pre` because
`sec0_pre` is `51f0`'s *serialization* of this in-memory table (leads + blob +
matrix), not the raw 20-byte records — a naive 20-byte read of `sec0_pre` gives
non-unit a,b (layout differs). To byte-verify: decode `51f0`'s serialization of
`*(r14+0x18)`, or hook `*(r14+0x18)` directly (`GDB_DUMP` at `0x18000c8ee`). The
forward transforms themselves originate in the matcher `c6a0` (the per-pair
best-voting alignment hypothesis), so deriving the *values* from scratch needs
the cross-frame keypoint correspondences, not just this function.
