# sub_180008f10 (section/descriptor orchestrator) — decompilation

> Synaptics `synaWudfBioUsb.dll` (md5-stable build, `/media/sf_vbox-rw/finger/synaWudfBioUsb.dll`, image base `0x180000000`).
> RVA `0x8f10`. Called once per WS section-build from the per-frame worker `sub_180001fe0` at `0x18000215b`.
> Disassembly: `/tmp/func_180008f10.S`. Decode date 2026-05-29. Loop bounds and call sites below re-verified byte-for-byte against the `.S`.

This is the **per-section DESCRIPTOR/section ORCHESTRATOR**. It does *not* contain the per-keypoint `[x][y][16B]` emit loop. The "250" appears only as a single scalar `r14` (keypoint count) computed once and handed wholesale to heavy callees. The actual 4500-byte v30 record area is materialized downstream.

---

## 1. Signature & role

```c
int64 sub_180008f10(
    void*  rec_base   /*rcx = r12*/,   // <== DEST: persistent 180-byte working-record array, stride 0xb4. Packer's [rbx+0x138]-class buffer.
    void*  a2         /*rdx*/,         // spilled [rsp+0x10], unused thereafter
    int    a3         /*r8d*/,         // count/flag; gated eax=(isref?0:a3) -> [rsp+0x1b0]/[rsp+0x70], fed to model-fitter as arg15
    void*  a4         /*r9*/,          // spilled [rsp+0x20], reused as scratch
    void*  geom       /*[rsp+0x1c0]=rbp*/,  // per-frame GEOM/dims: +0=w(i32) +4=h(i32) +0xc=byte flag +0x10=subobj(.+8=u32 index-map len)
    void*  ctx        /*[rsp+0x1c8]=r13*/,  // TLV/codec CONTEXT (rcx for every TLV thunk)
    int    mode7      /*[rsp+0x1d0]*/, // 0 => full emit via sub_1800082a0 ; !=0 => light path sub_180008e80
    int    flag8      /*[rsp+0x1d8]*/, // gates merge sub_180008ec0 + final emit
    void*  alloc9     /*[rsp+0x1e0]*/, // arena handle for sub_180003320 (r14*20 geom buffer)
    void*  p10        /*[rsp+0x1e8]*/, // sub_180008980 stack arg
    void*  p11        /*[rsp+0x1f0]*/, // sub_180008980 stack arg
    void*  v30src     /*[rsp+0x1f8]*/, // <== V30 FEATURE/KEYPOINT SOURCE base. Per-frame = v30src + edi*0xfa4 (stride 4004).
    void*  idxmap     /*[rsp+0x200]*/, // optional INDEX-MAP, stride 0x10
    int    isref      /*[rsp+0x208]=r15d*/, // is-reference / first-frame BOOL
    void*  p15        /*[rsp+0x210]*/, // sub_180008980 stack arg
    int    flag16     /*[rsp+0x218]*/, // >0 enables sub_180008ec0 merge AND the fallback sub_1800051f0 emit
    /*...*/
    void*  out        /*[rsp+0x1a8]*/, // OUT struct: +0=status, +4=tag-0x6b counter, +8=[rsp+0xa0]
    int*   outerr     /*[rsp+0x1b8]*/  // optional OUT i32 = [rsp+0x84] error flag
) -> RAX = section/emit status
```

| Question | Answer |
|---|---|
| **DEST buffer** | `arg1 = rcx = r12` — the persistent 180-byte (`0xb4`) working-record array. Indexed per-frame as `r12 + edi*0xb4`. This is the packer's `[rbx+0x138]`-class section working buffer. |
| **v30 feature SOURCE** | `arg12 = [rsp+0x1f8]`. Per-frame record = `arg12 + edi*0xfa4` (stride 4004, `imul r11,r11,0xfa4` @ `0x1800091fc`; `add r11,[rsp+0x1f8]` @ `0x18000920a`). Fed to model-fitter `sub_1800046e0`. |
| **keypoint count "250"** | `r14 = sub_180005d00(ctx)` (get tag `0x6b`) at `0x180008f9b`, `mov r14d,eax` @ `0x180008fa8`. A *single scalar*, never a loop counter for emit. |

---

## 2. Control flow + pseudocode skeleton

Frame: 7 callee-saved pushes (`rbp,rsi,rdi,r12-r15`) + `sub rsp,0x160`. There are **two** inline loops, **neither is a per-keypoint emit loop**.

### LOOP A — pose-record init (`0x180009114`–`0x180009127`)
- `test r14d,r14d; je 0x18000912b` guard; `rdi = r14` counts down; `rbx` walks `r12` at stride `+0xb4`.
- Body: `sub_180007980(rbx)` (sentinel-init 180-byte record), `rbx += 0xb4`, `--rdi`, `jne 0x180009114`.
- Runs **r14 (~250)** times. Afterward `ebx := 0`.
- Optional inner loop `0x180009150`–`0x180009160`: clears `idxmap[k]` for `k in [0, geom[0x10][+8])`, stride `0x10`.

### LOOP B — per-ACCEPTED-FRAME loop (`0x180009183`–`0x1800093a8`)
- **BOUND = `(BYTE)[rsp+0x80]`**, i.e. the low byte of the `get-0x68` result (accepted-frame count, empirically ~5). Verified: `test dl,dl; je 0x1800093ae` (entry guard) @ `0x18000917b`; increment `add edi,1` @ `0x1800093a0`; `movzx eax,dl; cmp edi,eax; jb 0x180009183` @ `0x1800093a3`–`0x1800093a8`. **NOT 250.**
- Two induction-derived pointers per iteration:
  - `r11 = edi*0xfa4 + v30src` -> per-frame v30 SOURCE (`[rsp+0x58]`, model-fitter arg12).
  - `rbx = edi*0xb4 + r12` -> per-frame 180-byte DEST working record (`[rsp+0x28]`, model-fitter arg6).

```c
section_handle = 0;                 // [rsp+0x88]
esi = -1;                           // best-frame index (none)
[rsp+0xb4] = 0x7fff;                // threshold inout -> model-fitter arg5
gated_count = isref ? 0 : a3;       // -> [rsp+0x1b0] / [rsp+0x70]
[rsp+0x80] = sub_180005b90(ctx);    // get-0x68 dword  (0x180008f7d)
              sub_180005bc0(ctx);   // get-0x68 -> eax -> [rsp+0x80]; BYTE = LOOP B bound (0x180008f8c)
tag6b_ctr  = sub_180005d00(ctx);    // get-0x6b running counter -> [rsp+0x90]
r14 = N    = (eax of get-0x6b);     // KEYPOINT COUNT ~250  (0x180008f9b/0x180008fa8)

geomspan = sub_180003320(&[rsp+0x128], alloc9, N*20, &geombuf/*[rsp+0x98]*/);  // carve N*20 geom scratch (0x180008fc3)
copy48(&span_b8, geomspan);
section_handle = sub_180005d10(span_b8, ctx, &[rsp+0x88], N);                  // ALLOC keyed WS SECTION SLOT (0x180009019)
copy48(&srcspan_f8, &span_b8);                                                 // [rsp+0xf8] source span
sub_1800053e0(span_b8, [rsp+0x88], &span_b8, N);                               // type-2 geom sub-records into section (0x1800090a0)
ctxB = sub_180004d70(&[rsp+0x128], &[rsp+0xa8], &span_b8, geom->w*geom->h);    // build 250-cap kp-set + mapping ctx (0x1800090ce)
copy48(&span_b8, ctxB);

// ---- LOOP A ----
for (rbx=rec_base, i=N; i; --i, rbx+=0xb4) sub_180007980(rbx);   // 0x180009114
ebx = 0;
if (idxmap) for (k=0; k<geom[0x10][+8]; ++k) idxmap[k]=0;        // 0x180009150
sub_180007a80(geombuf, N);                                       // finalize geom buf (0x18000916d)

// ---- LOOP B  (bound = (BYTE)[rsp+0x80] ~5) ----
for (edi=0; edi < (BYTE)[rsp+0x80]; ++edi) {
    if (!isref && sub_18000b420(&geombuf[edi*5*4+4]) && esi!=-1) continue;  // dedup probe (0x18000919b)
    sub_180006470(edi, ctx, ctxB[+0x10]);                                  // codec/scratch (0x1800091ba)
    rec = rec_base + edi*0xb4;       // 180-byte DEST record
    v30 = v30src   + edi*0xfa4;      // per-frame v30 SOURCE
    sub_1800046e0(&[rsp+0xe8]/*out48*/, ctxB[+0x10], geom[0x10], &span_b8,
                  &[rsp+0xb4]=0x7fff, rec, geom->w8, geom->h8, 0,0,0,
                  v30, idxmap, &[rsp+0x84]/*errflag*/, gated_count);        // MODEL-FIT (0x18000925a)
    if ([rsp+0x84]) goto error_tail;                                        // (0x180009267)
    rec[0x90]=rec[0x68]; rec[0x94]=rec[0x88]; rec[0xa4]=rec[0x9c];          // pose self-copy (0x18000927b..)
    rec[0xa8]=rec[0x98]; rec[0xac]=rec[0xa0];
    if (mode7) { sub_180008e80(rec); continue; }                           // light path (0x1800092b6)
    rec[0x4c]=0;
    sub_1800082a0(rec, edi, ctx, &[rsp+0xe8],
                  section_handle, geombuf, 0, ctxB, geom, &span_b8, N);     // PER-FRAME emit (0x180009319)
    if (flag16>0 && flag8) sub_180008ec0(edi, section_handle, rec_base);    // merge (0x18000933f)
    sub_180008980(rec_base, p10, p15, &[rsp+0x208], &span_b8);              // per-frame finalize (0x180009385)
    if (!isref && rec[0x38] >= 0x699) esi = edi;                           // pick best frame (cmovae, 0x180009396)
}
error_tail:                                                                // 0x1800093ae
if (outerr) *outerr = [rsp+0x84];
sub_180008980(rec_base, p10, p15, &[rsp+0x208], &span_b8);                  // global finalize (0x180009409)
if (mode7 || [rsp+0x84]) return;
if (flag8) {
    if (esi != -1 && sub_180007ac0(geombuf, N)) {                          // validate (0x18000944c)
        status = sub_18000c6a0(ctx, geom, section_handle, geombuf, 0, geom,
                               &[rsp+0xa0], geom[0xc], rec_base, (BYTE)esi,
                               N, &[rsp+0xb0], &srcspan_f8, flag16);        // FINAL BUILDER (0x1800094c5)
        out->status = status;
        if (status) {
            if ([rsp+0xb0]==0) sub_180005b70((BYTE)[rsp+0x80]+1, ctx);      // set tag 0x03 (0x1800094f6)
            sub_1800051f0(section_handle, (BYTE)[handle+0x10], N, ctx, &srcspan_f8); // commit TABLE (0x18000951a)
            sub_180005ba0(++tag6b_ctr, ctx);                               // bump tag 0x6b (0x180009535)
        }
    } else if (flag16>0) {                                                 // fallback
        sub_1800051f0(section_handle, (BYTE)[handle+0x10], N, ctx, &srcspan_f8); // (0x180009565)
        out->status = 1;
    }
    out->[8] = [rsp+0xa0]; out->[4] = tag6b_ctr;
}
return; // RAX = status
```

---

## 3. Content-production mechanism (KEY)

**DEFINITIVE: the 4500-byte v30 record area (250 × `[u8 x][u8 y][16B descriptor]`) is NOT built by any loop inside `sub_180008f10`.** This function is purely an orchestrator. `put-N` (`sub_180006550`) is **never called here**, and there is no write into a TLV stream from this body. The "250" is the scalar `r14`, passed wholesale to callees.

The content is built in three handoffs:

**(a) Per-minutia geometry (NOT the descriptor bytes) — `sub_1800046e0` @ `0x18000925a`.**
Per accepted frame it reads the per-frame v30 SOURCE record at `r11 = arg12 + edi*0xfa4` and writes refined transform/coord scalars + neighbor-consensus stats into the 180-byte DEST slot (`rec = r12 + edi*0xb4`): `[rec+0x4/0x8/0xc/0x10]`, `[rec+0x5c]`=mean angle, `[rec+0x60]`=inlier count, `[rec+0x64]`=neighbor count, `[rec+0x68..]`=geometry block (via `sub_1800043d0`). It also fills a 48-byte out struct at `[rsp+0xe8]`.
**It does NOT emit `[x][y]`, the 16-byte oriented-BRIEF descriptor, or any TLV/record bytes** (re-confirmed against `/tmp/func_1800046e0.S`: no `put-N`, no `[rbx+0x138]` write). The 16-byte BRIEF source is its `arg3 = ctxB[+0x10]` (forwarded, not built). So the descriptor bytes originate in the **caller-supplied v30 buffer (`arg12`)** and the keypoint-set container that `sub_180004d70` set up (250×16B backing @ `0x180004e6a`, zeroed; 250×32B index array wiring x/y slots).

**(b) Per-frame record emit — `sub_1800082a0` @ `0x180009319`.**
Runs once per accepted frame (`rcx=rec`, `r9=&[rsp+0xe8]`, `[rsp+0x20]=section_handle`, `[rsp+0x28]=geombuf`, `[rsp+0x50]=r14`). Per its own decode it is a **geometry-transform / cross-frame match-consistency** stage that writes 16-byte int4 vectors and 5-int (20-byte) rows into *stack/ctx scratch*, gates `(x,y)` by range, and accumulates a running affine transform into the match-context. It **does NOT write `[x][y][16B]` into the persistent section buffer** and contains no `put-N`. It prepares/scores; it does not serialize the 4500-byte body.

**(c) Final section materialization — `sub_18000c6a0` @ `0x1800094c5`.**
This is the call that produces the consolidated record stream for the **single selected reference frame** (`(BYTE)esi`, the `cmovae` best frame with `[rec+0x38] >= 0x699`). It receives everything: `ctx`, `geom`, `section_handle` (`[rsp+0x88]`), `geombuf`, `rec_base` (`[rsp+0x40]`), `(BYTE)esi` (`[rsp+0x48]`), `N=r14` (`[rsp+0x50]`), `srcspan_f8` (`[rsp+0x60]`). Inside, on the match/emit branch it calls **`sub_1800057e0`** (`@ 0x18000c8b1`) which (per the c6a0 decode) appends to the TLV stream: an 8-byte field, a u8, then a **variable-count loop** (count `= *(src+8)`, source stride `0x20`) emitting `[16B descriptor (put-N 0x10)][x:u8 @ src+0x14][y:u8 @ src+0x18]` = 18 bytes/record, plus a `0x16`-byte trailer; `sub_180006a80` (`@ 0x18000c8c3`) backpatches the TLV record length. `sub_18000bdf0` (`@ 0x18000c8ee`) writes a 20-byte-stride geometry/match table and argsorts.

**Destination → WS TLV stream.** Content lands in (i) the persistent DEST record array (`arg1=r12`, the packer's `[rbx+0x138]`-class buffer, stride `0xb4`) and (ii) the keyed WS-container SECTION SLOT allocated by `sub_180005d10` (`[rsp+0x88]`). It reaches the WS TLV stream via `sub_1800051f0` (`@ 0x18000951a`, fallback `@ 0x180009565`), which commits the section TABLE/header using the handle + `srcspan_f8`; `sub_180005ba0` bumps tag `0x6b`. Per `sub_1800051f0`'s contract it does **not** emit the bulk 250-record content — therefore the bulk bytes are written by `sub_18000c6a0` / `sub_1800057e0` through the section handle, and `sub_1800051f0` only frames the surrounding table.

### NEEDS-HOOK — two links are not statically nailed down

1. **`sub_1800057e0` body was never independently disassembled** (`/tmp/func_1800057e0.S` does not exist). The 18-byte `[16B][x][y]` loop, the `*(src+8)` count, and the `0x14/0x18/0x20` offsets come from the **c6a0 decoder's read of c6a0's call into it** (c6a0 itself rated *medium* confidence). Whether the count is the live `*(src+8)` (=250 for enrollment) and whether the descriptor is copied **verbatim from the v30 source `arg12`** vs. the model-fitter's 48-byte out struct `[rsp+0xe8]` is **not proven**.
   - **HOOK:** `GDB_DUMP_PACKER_EMIT=1` (`dev/gdb_dump.py`, sites `0x2540..0x25d0` + `0x25d5`, 16-byte cursor at `[rsp+0x50]` of the packer `sub_180002240`). Diff consecutive stream snapshots across the c6a0 emit to confirm the 18-byte stride, the 250 count, and the byte deltas of each `put-N`.
   - **HOOK:** add a breakpoint at `0x18000c8b1` (call to `5780`) and `0x1800057e0` entry; dump `rsi` (stream obj) before/after and `*(src+8)`/`src+0x14`/`src+0x18` for the first few records. Also re-dump the function: `objdump`/IDA export `func_1800057e0.S` so the loop is read, not inferred.

2. **Which buffer the 4500 bytes physically live in before TLV commit** (section-slot `[rsp+0x88]` written directly by c6a0 through the handle, vs. DEST array `r12` then copied). The `sub_1800051f0`-does-not-emit-bulk contract strongly implies c6a0 writes through the handle, but this is inference.
   - **HOOK:** `RVA_46E0` (`DescEntryBP`, opt-in in `dev/gdb_dump.py`) to capture the per-frame descriptor inputs/outputs, **plus** a watchpoint on the section-slot data pointer (`*(([rsp+0x88])+0x18)` row buffers from `sub_180005d10`) across the `0x1800094c5` call to see who fills it.

---

## 4. Call map

Codec/TLV cluster (already decoded — used as call contracts, grouped first):

| Callee | Site | Role | Writes record bytes? | Conf |
|---|---|---|---|---|
| `sub_180005b90` | `0x180008f7d` | get tag `0x68` dword -> `[rsp+0x80]` | no | high |
| `sub_180005bc0` | `0x180008f8c` | get tag `0x68` -> `[rsp+0x80]`; **BYTE = LOOP B bound** (~5 frames) | no | high |
| `sub_180005d00` | `0x180008f9b` | get tag `0x6b` -> `r14` = **keypoint count ~250** + running counter `[rsp+0x90]` | no | high |
| `sub_180005b70` | `0x1800094f6` | set tag `0x03` = `(BYTE)[rsp+0x80]+1` | TLV scalar | high |
| `sub_180005ba0` | `0x180009535` | set tag `0x6b` = bumped counter | TLV scalar | high |
| `sub_1800051f0` | `0x18000951a` / `0x180009565` | commit section TABLE/header into WS TLV (lead bytes + NxN matrix). **Not** bulk content. | header/matrix only | high |
| `sub_180006470` | `0x1800091ba` | TLV conditional setter keyed by frame idx | no (ctx only) | high |

Allocators / span builders:

| Callee | Site | Role | Writes record bytes? | Conf |
|---|---|---|---|---|
| `sub_180003320` | `0x180008fc3` | carve `r14*20`-byte geometry scratch (20-byte records) -> `[rsp+0x98]` | no | high |
| `sub_180005d10` | `0x180009019` | allocate/zero keyed WS SECTION SLOT (header + roundup(N,4) + 4N + N×20N rows) -> `[rsp+0x88]` | no (zero-init) | high |
| `sub_180004d70` | `0x1800090ce` | build empty 250-cap keypoint+descriptor set (250×32B index -> 250×16B backing, count reset 0) + mapping ctx -> `[rsp+0xa8]` | no (pointers only) | high |

Per-frame processing:

| Callee | Site | Role | Writes record bytes? | Conf |
|---|---|---|---|---|
| `sub_180007980` | `0x180009117` | LOOP A: sentinel-init one 180-byte record (`0x7fff`/`0x10000`/`0xff`); called ~250× | yes (init/layout) | high |
| `sub_180007a80` | `0x18000916d` | finalize/zero-init the geom buffer (20-byte stride, via `sub_180007a70`) | yes (init) | high |
| `sub_18000b420` | `0x18000919b` | per-frame dedup probe: is 16-byte block != default `{0x10000,0,0,0}` | no (read) | high |
| `sub_1800046e0` | `0x18000925a` | **MODEL-FITTER**: reads v30 source, fills 180-byte slot geometry + 48B out struct. **No descriptor/TLV bytes.** | no (writes geom into 0xb4 slot) | high |
| `sub_180008e80` | `0x1800092b6` | light path: validate coord, conditional reset of 16B score block | conditional | high |
| `sub_1800082a0` | `0x180009319` | **PER-FRAME emit**: geometry-transform/match-consistency into scratch+ctx. **No `[x][y][16B]` into persistent buffer, no put-N.** | no | high |
| `sub_180008ec0` | `0x18000933f` | bump per-index validity counters in `obj[+8]` (4-byte slots) | yes (counts) | high |
| `sub_180008980` | `0x180009385` / `0x180009409` | per-frame & global finalize of DEST record stream | likely | medium |

Tail / final builder:

| Callee | Site | Role | Writes record bytes? | Conf |
|---|---|---|---|---|
| `sub_180007ac0` | `0x18000944c` | validate geom buffer (any coord in 31×50 grid) — gate for final build | no (read) | high |
| `sub_18000c6a0` | `0x1800094c5` | **FINAL SECTION BUILDER** for selected frame `(BYTE)esi`; via `sub_1800057e0` serializes `[16B][x][y]` (18B/rec) into TLV stream + 20-byte match table | **yes** (the serializer) | medium |

---

## 5. Connection to packer `[rbx+0x138]` and the 5-section consolidation

- `arg1 = r12` is the packer's per-frame **persistent working-record array** (`[rbx+0x138]`-class), 180-byte stride. `sub_180008f10` is invoked from the per-frame worker `sub_180001fe0` @ `0x18000215b`, which the packer `sub_180002240` drives. LOOP A seeds `r14`(~250) of these slots; LOOP B fits each accepted frame's keypoints into them via `sub_1800046e0`.
- The WS body target is **5 v30 sections**, each a 4500-byte record area. `sub_180008f10` builds **one section per call**: it allocates one keyed SECTION SLOT (`sub_180005d10` -> `[rsp+0x88]`), selects the single best reference frame (`esi`, `[rec+0x38] >= 0x699`), and lets `sub_18000c6a0` materialize that section's content. `sub_1800051f0` then commits the section TABLE into the shared WS TLV container (`ctx=r13`), and `sub_180005ba0` increments the tag-`0x6b` section/keypoint counter so the next section is keyed correctly. The 5 sections are therefore the result of **5 orchestrator invocations** accumulating into the same `ctx` TLV stream, not a 5× loop inside this function.
- Cross-frame merge: when `flag16>0 && flag8`, `sub_180008ec0` accumulates per-frame validity tallies (the `0x68`/`0x88` coord histograms) into the section accumulator before the single-frame final build — this is the empirical link to the **per-tile target counts** (`29,27,17,33,36,33,30,26,19`) recorded in MEMORY: the per-index counters decide which keypoints survive into the selected frame's section.

---

## 6. Contradictions / low-confidence items

1. **`sub_1800082a0` "PER-FRAME record emitter" label is misleading.** The orchestrator decode initially called it the per-frame *record emit*, but its own (high-conf) decode proves it writes **only scratch/ctx**, no `put-N`, no persistent-buffer write. Resolution: it is a **geometry/match-consistency** stage; the real serialization is `sub_18000c6a0`. The pseudocode label "PER-FRAME emit" should be read as "per-frame match-prep," not byte emission.
2. **The hint that `sub_1800046e0` is the E090/BRIEF descriptor builder is WRONG.** Disassembly shows it is the per-minutia geometric neighbor/consensus stage feeding the descriptor path. It forwards the 16-byte BRIEF (`arg3 = ctxB[+0x10]`); it does not build it.
3. **`sub_18000c6a0` is rated only `medium` confidence and `sub_1800057e0` was never dumped.** The entire "18-byte `[16B][x][y]` record, count `*(src+8)`, stride `0x20`" claim — i.e. the answer to the central question — rests on an un-re-verified read. This is the single most important thing to harden (see §3 NEEDS-HOOK, §7).
4. **`sub_18000c6a0` is described as the "matching/verification path," yet here it is on the enrollment WS-body build path.** Its decoder notes the routine is shared (match vs. enroll) and that the fixed 250/4500 comes from the *enrollment caller feeding the full keypoint set* — there is no hard-coded 250 inside it. Whether enrollment actually drives 250 records through it (vs. the live culled count ~29..36 per tile) is **unconfirmed** and directly relevant to whether the area is a fixed 4500 bytes or variable.
5. **`sub_180005b90` vs `sub_180005bc0`** are both labeled "get-0x68." Only `[rsp+0x80]` (overwritten by the second) is used as the LOOP B bound; the first's dword result appears unused for the bound. Their separate decodes should disambiguate (likely one returns a status byte, one a dword).
6. **`sub_180008980` finalize is medium-confidence** (not independently decoded for whether it writes record bytes).

---

## 7. Recommended next steps (ordered)

1. **Disassemble `sub_1800057e0` and decode it.** Export `/tmp/func_1800057e0.S` (it is the only undumped function in the critical content path). Confirm: the variable-count loop, `count = *(src+8)`, source stride `0x20`, the `[16B put-N][x:u8 src+0x14][y:u8 src+0x18]` layout, and **where the 16 descriptor bytes are read from** (v30 source `arg12` vs out-struct `[rsp+0xe8]`). This resolves contradiction #3 and the primary open question.
2. **Run `GDB_DUMP_PACKER_EMIT=1`** (`dev/gdb_dump.py`, RVA_2240 packer, 16-byte cursor at `[rsp+0x50]`, sites `0x2540..0x25d5`) during a native enrollment and diff consecutive stream snapshots across the `sub_18000c6a0` emit. Verify the per-record byte delta is 18 bytes and count the records (expect either 250 or the per-tile culled count). This empirically settles whether the section is a fixed 4500-byte area.
3. **Add a breakpoint at `0x18000c8b1` (call into `5780`) + `0x1800057e0` entry**, and a watchpoint on the `sub_180005d10` section-slot row-buffer pointer (`*(([rsp+0x88])+0x18)`), to prove the bytes land in the section slot (handle) vs. `r12`. Resolves NEEDS-HOOK #2.
4. **Decode `sub_18000c6a0` to high confidence** (currently medium). It is the function that holds the per-keypoint loop; with `5780` dumped this becomes the authoritative "4500-byte builder" decode.
5. **Run `RVA_46E0` (`DescEntryBP`)** to capture `sub_1800046e0` inputs/outputs and confirm the v30 source layout (`+0x14`/`+0x18`/`+0x10` of the `0x20`-stride source records line up with the serializer's x/y/descriptor offsets).
6. **Extend `dev/inspect_ws.py`** (the WS body byte-zone annotator) with an 18-byte-record `[16B][x][y]` zone parser for the v30 sections, parameterized by the per-section record count from step 2, so the captured emit deltas can be diffed against the chip's stored WS body. Also extend `dev/decode_variants.py` to test the "fixed 4500 vs per-tile-culled-count" hypothesis using the counts `29,27,17,33,36,33,30,26,19`.

---

*Scope note: every instruction address in §1–§3 was re-checked against `/tmp/func_180008f10.S`. The LOOP B bound (`movzx eax,dl` @ `0x1800093a3` over `(BYTE)[rsp+0x80]`) and the single-scalar `r14` keypoint count (`0x180008fa8`) are confirmed; there is no per-keypoint emit loop in this function. The §3(c) serializer chain is the only inferential link and is flagged NEEDS-HOOK.*

---

## 8. Addendum — `sub_1800057e0` read directly (the v30 record serializer)

The synthesis flagged `sub_1800057e0` as NEEDS-HOOK because it had not been disassembled. It has now been read directly (`/tmp/func_1800057e0.S`, 321 B, 87 instrs). It is the **per-keypoint v30 record serializer**, confirmed static. Signature: `sub_1800057e0(rcx = section object, rdx = TLV stream)`. With `S = *(H+0)`, `H = *(secobj+0x10)`, `N = *(u32*)(H+8)`, it emits into the stream (`rsi`):

1. `0x18000580d` — **8-byte header** from `&secobj[0x20]` via put-N (`sub_180006550`, n=8).
2. `0x18000581d` — **1 byte** `= BYTE[H+8]` (low byte of the record count `N`) via put-u8 (`sub_180006510`).
3. `0x180005830`–`0x18000587a` — **MAIN LOOP**, `ebp = 0..N` (`N = *(u32*)(H+8)`), source stride `0x20`, **18 bytes per record**:
   - `0x18000583f` — **16-byte descriptor** via put-N, source = `*(S + ebp*0x20 + 0)` (indirection: `S[i]+0` is a *pointer* to the 16B oriented-BRIEF descriptor);
   - `0x180005853` — **x** = `BYTE[S + ebp*0x20 + 0x14]` via put-u8;
   - `0x180005867` — **y** = `BYTE[S + ebp*0x20 + 0x18]` via put-u8.
4. `0x180005887`/`0x180005893` — 2 trailer bytes (`BYTE[H+0xc]`, `BYTE[secobj+0xc]`).
5. `0x1800058ba`/`0x1800058db` — two `sub_180005720` bucket-fills (`r8b=0`, then `r8b=0xb`) filling a local 22-byte buffer `[rsp+0x30]`.
6. `0x1800058f0`–`0x180005903` — **22-byte (`0x16`) trailer** from `[rsp+0x30]` via per-byte put-u8.

**On-wire v30 record = `[16B descriptor][x:u8][y:u8]` = 18 bytes, descriptor FIRST.** This **corrects** the old `NEXT-SESSION.md` assumption of `[u8 x][u8 y][16B desc]`. The record **count is the live `*(u32*)(H+8)`**, not a hardcoded 250 — so a section's record area is `N × 18` for the live `N` (candidate: the per-tile culled counts `29,27,17,33,36,33,30,26,19`), with `4500 = 250×18` the *maximum*.

**Still NEEDS-HOOK:** reconcile this `[16B][x][y]` order and the live `N` against a captured `ws_body` v30 section (`GDB_DUMP_PACKER_EMIT=1` settles both). The prior byte-exact descriptor work matched descriptor *bytes* but assumed intra-record field *order*. Also: `sub_18000c6a0` is the scorer/120×120-grid (`0x3840`) **match/verification** routine, so confirm the *enrollment* commit reaches `sub_1800057e0` via this same path vs. a separate enrollment-only serializer (the orchestrator→c6a0→57e0 chain says it does, but the grid scoring suggests c6a0 is dual-use enroll+identify).

---

## 9. `sub_180008980` — per-section reference-frame finalizer / quality scorer

Decoded directly (`/tmp/func_180008980.S`, 1275 B, 314 instrs). Called by the orchestrator inside LOOP B (`0x180009385`) and in the tail (`0x180009409`). 7-arg: `(rcx=rec_base, dl=n_frames, r8=out_ctx, r9, [+0x1e0]=posebuf int32[34] OUT, [+0x1e8]=fbuf double[32] OUT, [+0x1f0]=geom src)`. Does **not** write v30/WS-body bytes (no TLV put primitive). What it does:

1. **Build sort records** (LOOP1 `0x180008a30`): per frame a 12-byte `{rec[0x60], rec[0x68], i}`. A min-inlier gate (`rec[0x60] >= 4`); if no frame qualifies → degenerate path.
2. **qsort** (`0x180008aa2`, cmp `sub_180008950`) best-quality-first by `rec[0x68]` then `rec[0x60]`; write post-sort **rank → `[rec+0xb0]`** (LOOP2).
3. **Gather top-2 reference vector** (LOOP3, bound 2): 17 dword fields × best-2 frames = **34 values** into `posebuf`. Source offsets: `0x98,0x9c,0x74,0x78,0x7c,0x5c,0x60,0x8c,0x90,0x6c,0x80,0x84,0x94,0x68,0x88,0xa8,0xa4`.
4. **Clamp + quantize** (LOOP4, 34 elems): per-channel `(v - base)*1.6/denom`, clamp to a normalized band (`±1.6`, `1.1`, `±0.001` dead-zone), `*1024`, trunc → `posebuf[i]` (16.10 fixed point); `fbuf[i] = posebuf[i]/1024.0`. **9-channel `[base,denom]` table @`0x18011fb90`: `{22,22},{736.5,569.5},{3883.5,3883.5},{4344.5,4344.5},{4740.5,4740.5},{22.5,17.5},{12.5,12.5},{104.5,104.5},{45.5,29.5}`.** Saturate to `1.6` if raw `>= 0x7fff`.
5. **Quality score** (`0x180008d55`): `eax = sub_180002f80(...)` = clamp-to-[0, `0xbb8`=3000] scale mapper; **stamp `[rec+0x38] = eax` for every frame** (LOOP5). → This is the field the orchestrator compares to **`0x699`=1689** (`cmp [rbx+0x38],0x699; cmovae esi,edi` @`0x18000938f`) to pick the best frame. So 8980 *produces* the score; the orchestrator *selects*.
6. **Degenerate path** (no frame ≥4 inliers): fill `posebuf` with `(-2,-2)` sentinels (`0xFFFFFFFEFFFFFFFE`), `fbuf` with `-2.0` doubles, score 0.

**Why this matters for the WS body:** the 34-element quantized reference vector (`/1024` fixed-point, the `0x18011fb90` channel table) is a concrete, portable derivation — a strong candidate source for the per-section pre-v30 **geometry/pose** metadata (the `geometry_stats` VARIANT zone and pose records). It feeds `sub_18000c6a0` (the final builder) as the pose/feature spans. Confidence: high on structure/quantization; the semantic names of the 17 fields are medium.
