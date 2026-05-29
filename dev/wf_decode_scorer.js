export const meta = {
  name: 'decode-c6a0-scorer',
  description: 'Decode sub_18000c6a0 (120x120 voting-grid match scorer) + its grid helpers; recover the duplicate/identify match algorithm, score, and threshold',
  phases: [
    { title: 'Decode', detail: 'scorer + grid helpers, one agent each, parallel' },
    { title: 'Synthesize', detail: 'reconstruct the grid-voting match algorithm + decision' },
  ],
}

const ABI = `synaWudfBioUsb.dll, x86-64, Windows x64 ABI, objdump INTEL syntax (dest first). Args RCX,RDX,R8,R9 then [rsp+0x28]...; floats XMM0-3; 32-byte shadow space; return RAX/EAX (XMM0 float). "lea reg,[rip+0x..]" = .rdata const ref (note the "# 0x.." resolved addr). Pattern "mov rax,[obj+N]; call QWORD PTR [rip+...] # 0x18010a7f0" = CFG-guarded virtual call, real target in RAX. Disasm files: /tmp/func_<addr>.S. To read a .rdata constant/string, the DLL is /tmp/syna.dll (use dev/find_vtable.py's PE parser pattern or objdump -s -j .rdata).`

const KNOWN = `CONTEXT — sub_18000c6a0 is the SHARED scorer used by BOTH enrollment (section build via sub_180008f10) and identify/CheckForDuplicate (CeivMode::IdentifyUser, sub_180027540). It is a per-tile match/score routine built around a 0x78×0x78 = 120×120-cell spatial VOTING GRID (0x3840 bytes, 1 byte/cell, cells saturate ~0x64=100). From the prior (medium-confidence) pass:
- c6a0 inits best-index *(rbx)=0xffffffff and match-flag *(r13)=0; reads tile id/N = BYTE[r9+0x10].
- sub_180003320 copies a 0x3840 grid template into a local; sub_18000bfd0 FILLS the 120×120 grid; sub_18000c240 COUNTS non-zero cells; sub_18000c1a0 a further grid op; sub_18000c510 the SCORER (calls c270/c240/c4e0, returns a best index).
- A compare path (cmp esi,[rsp+0x160]) vs an EQUAL/emit branch that serializes records via sub_1800057e0 and builds a 20-byte geometry/match table via sub_18000bdf0 (which argsorts via sub_18000bd10, N=0x12c=300).
Already decoded (call contracts, don't re-derive): sub_1800057e0 = v30 RECORD SERIALIZER (8B hdr + u8 count + N×[16B desc][x:u8][y:u8] 18-byte records); sub_18000bd10 = ARGSORT (index permutation; constant primary key); sub_180003320 = generic span/struct copy; sub_1800066a0 = TLV open-record; sub_180006a80 = TLV close/backpatch; sub_180006550/510 = put-N / put-u8. Records are 18-byte [16B desc][x][y], source stride 0x20, x@+0x14 y@+0x18, count=*(src+8).`

const CENTRAL = `CENTRAL QUESTIONS: (1) What does each grid CELL accumulate — how does sub_18000bfd0 vote (per keypoint? per descriptor match? what maps a record's (x,y)/descriptor to a 120×120 cell, and what value is added)? (2) How is the MATCH SCORE computed from the filled grid (cell counts via sub_18000c240, peak/cluster via sub_18000c510/c270)? (3) What is the match DECISION / threshold that declares "same finger / duplicate" (the value compared, the constant, where the verdict lands — *(r13) match flag and *(rbx) best index)? (4) What does sub_18000bdf0's 20-byte geometry/match table + argsort represent? Trace constants (0x64/0x63 saturation, 0x12c=300, 0x333=819, any score thresholds).`

const MAIN_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['signature', 'overall_purpose', 'control_flow', 'pseudocode', 'grid_algorithm', 'match_decision', 'call_sites', 'constants', 'open_questions'],
  properties: {
    signature: { type: 'string', description: 'arg roles; identify the query records ptr, the candidate/enrolled ptr, the grid buffer, the OUT best-index (*rbx) and OUT match-flag (*r13)' },
    overall_purpose: { type: 'string' },
    control_flow: { type: 'string', description: 'loops + branches with addresses; the compare-only vs equal/emit split' },
    pseudocode: { type: 'string', description: 'full annotated C-like pseudocode' },
    grid_algorithm: { type: 'string', description: 'how the 120×120 grid is filled and what each cell accumulates (as far as visible from c6a0; bfd0 detail comes from its own agent)' },
    match_decision: { type: 'string', description: 'THE KEY ANSWER: how the match score is computed and the decision/threshold that sets the match flag *(r13) / best index *(rbx). Cite the compared value + constant + addresses.' },
    call_sites: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['site_addr', 'callee_addr', 'role'], properties: { site_addr: { type: 'string' }, callee_addr: { type: 'string' }, role: { type: 'string' } } } },
    constants: { type: 'array', items: { type: 'string' } },
    open_questions: { type: 'array', items: { type: 'string' } },
  },
}

const CALLEE_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['addr', 'one_line_role', 'detailed_behavior', 'signature_guess', 'grid_or_score_role', 'constants', 'calls', 'confidence', 'notes'],
  properties: {
    addr: { type: 'string' },
    one_line_role: { type: 'string' },
    detailed_behavior: { type: 'string', description: 'pseudocode-level, cite addresses' },
    signature_guess: { type: 'string' },
    grid_or_score_role: { type: 'string', description: 'exactly what it does to/with the 120×120 grid or the match score (votes? counts? peak? threshold?)' },
    constants: { type: 'array', items: { type: 'string' } },
    calls: { type: 'array', items: { type: 'string' } },
    confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    notes: { type: 'string' },
  },
}

const BATCH_SCHEMA = {
  type: 'object', additionalProperties: false, required: ['helpers'],
  properties: { helpers: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['addr', 'role', 'signature', 'grid_or_score_role', 'notes'], properties: { addr: { type: 'string' }, role: { type: 'string' }, signature: { type: 'string' }, grid_or_score_role: { type: 'string' }, notes: { type: 'string' } } } } },
}

const SUBSTANTIAL = [
  { addr: '18000bfd0', hint: '461B,136i -- FILLS the 120×120 voting grid (saturation ~0x64). KEY: what maps a record to a cell, and what value is voted.' },
  { addr: '18000c270', hint: '612B,181i -- LARGEST scorer sub-routine, called by sub_18000c510; the core score/peak computation.' },
  { addr: '18000c510', hint: '393B,99i -- the SCORER: loops calling c270/c240/c4e0, returns a best index. How is the score aggregated/compared?' },
  { addr: '18000c1a0', hint: '157B,57i -- a grid op between the two c240 counts (smoothing? thresholding? dilation of the vote grid?).' },
  { addr: '18000bdf0', hint: '445B,111i -- builds a 20-byte-stride (0x14) geometry/match table at *(r14+0x18) (4×u32 + x@+0,y@+1) then argsorts via sub_18000bd10. What does this table represent?' },
]

const BATCH = ['18000c240', '18000c4e0', '180005720']

phase('Decode')
const mainPrompt = `${ABI}

Read /tmp/func_18000c6a0.S (631B, 142 instrs) -- the SHARED match/score routine.

${KNOWN}

${CENTRAL}

Produce an exhaustive decode, filling match_decision with the DEFINITIVE answer to how a "same finger / duplicate" verdict is reached (the score, the compared constant, where the verdict lands). The grid helpers are decoded by other agents in parallel -- record each call's contract, don't open their files. Cite instruction addresses; trace induction variables.`

const calleePrompt = (c) => `${ABI}

Read /tmp/func_${c.addr}.S -- a grid/scoring helper under the matcher sub_18000c6a0. Hint: ${c.hint}

${KNOWN}

${CENTRAL}

Decode it. Set grid_or_score_role to exactly what it does to the 120×120 grid or the match score. Cite addresses. Set confidence honestly.`

const batchPrompt = `${ABI}

Decode this batch of small scorer helpers (read each /tmp/func_<addr>.S):
${BATCH.map(a => `  /tmp/func_${a}.S`).join('\n')}

${KNOWN}

For each: addr, role, signature, grid_or_score_role (what it does to the grid/score — e.g. sub_18000c240 counts non-zero cells; sub_18000c4e0 is a tiny inner helper; sub_180005720 is a bucket-fill also used by the serializer), notes. Cite addresses for non-obvious claims.`

const decodes = await parallel([
  () => agent(mainPrompt, { label: 'scorer:18000c6a0', phase: 'Decode', schema: MAIN_SCHEMA }),
  ...SUBSTANTIAL.map(c => () => agent(calleePrompt(c), { label: `callee:${c.addr}`, phase: 'Decode', schema: CALLEE_SCHEMA })),
  () => agent(batchPrompt, { label: 'callee:batch', phase: 'Decode', schema: BATCH_SCHEMA }),
])

const main = decodes[0]
const callees = decodes.slice(1, 1 + SUBSTANTIAL.length).filter(Boolean)
const batch = decodes[decodes.length - 1]
if (!main) return { error: 'main scorer decode failed', callees, batch }

phase('Synthesize')
const synthPrompt = `You are synthesizing a decode of sub_18000c6a0, the shared 120×120 voting-grid MATCH SCORER (used by both enrollment section-build and CeivMode::IdentifyUser / EnrollmentCheckForDuplicate) in the Synaptics fingerprint DLL.

${KNOWN}

${CENTRAL}

=== SCORER sub_18000c6a0 ===
${JSON.stringify(main, null, 1)}

=== GRID/SCORE HELPERS ===
${JSON.stringify(callees, null, 1)}

=== SMALL HELPERS ===
${JSON.stringify(batch, null, 1)}

Write a markdown report "sub_18000c6a0 (120×120 voting-grid match scorer) — decompilation" with:
1. Signature & role; the query vs candidate inputs, the grid buffer, the OUT best-index/match-flag.
2. **The grid-voting match ALGORITHM (KEY)** — step by step: how records map to the 120×120 grid, what each cell accumulates (sub_18000bfd0), the grid post-processing (sub_18000c1a0), the score/peak computation (sub_18000c510/c270/c240), and the final MATCH DECISION + threshold (the constant compared, where the verdict lands). State it concretely enough to reimplement.
3. Call map table (callee | role | grid/score function | conf).
4. The 20-byte geometry/match table (sub_18000bdf0) + argsort — what it represents and how it feeds the result.
5. How this serves duplicate detection (enrollment CheckForDuplicate) vs identify/verify — same code path, different inputs.
6. Contradictions / low-confidence items.
7. Recommended next steps + which gdb hook would confirm the score/threshold at runtime. Cite addresses. This report will be committed to dev/.`

const report = await agent(synthPrompt, { label: 'synthesize', phase: 'Synthesize' })
return { main, callees, batch, report }
