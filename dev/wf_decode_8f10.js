export const meta = {
  name: 'decode-8f10-content-builder',
  description: 'Decode sub_180008f10 (section/descriptor orchestrator) + new callees; find how the 4500-byte v30 content is built & emitted',
  phases: [
    { title: 'Decode', detail: 'orchestrator + 6 substantial callees + small batch, parallel' },
    { title: 'Synthesize', detail: 'how the v30 content + section is assembled; map to WS layout' },
  ],
}

const ABI = `synaWudfBioUsb.dll, x86-64, Windows x64 ABI, objdump INTEL syntax (dest first). Args RCX,RDX,R8,R9 then [rsp+0x28]...; floats XMM0-3; 32-byte shadow space (stores to [rsp+8..0x20] near entry spill args 1-4); return RAX/EAX (XMM0 float). "lea reg,[rip+..]" = .rdata const ref. Disasm files: /tmp/func_<addr>.S.`

const KNOWN = `ALREADY DECODED (do NOT re-derive — use as call contracts):
- sub_180002240 = WS-body packer (per-frame section appender; builds a TLV stream via a 16-byte cursor at [rsp+0x50]).
- sub_180001fe0 = per-frame WORKER; it calls sub_180008f10 (THIS subtree) at 0x18000215b.
- sub_1800051f0 = per-section TABLE emitter: lead bytes (put-N count=arg3 from *(obj+0)), u32 blob (*(obj+8)), 2 marker bytes, then N×N-minus-diagonal matrix (N=BYTE[obj+0x10]) of [x:u8][y:u8]+4×u32 rows; calls argsort sub_18000bd10. Does NOT emit the bulk 250-record content.
- sub_1800053e0 = type-2 TLV sub-record emitter (blobA(N)+blobB(4N)+counts+NxN 20-byte geometry-transformed records).
- sub_180003320 = generic struct/span copy (16/24/48-byte field copies).
- TLV format: record={u16 tag, u16 len, payload}; container byte-counter=u32 at container-hdr+4. Primitives: sub_1800064d0=put u32 (len+=4), sub_180006510=put u8 (len+=1), sub_180006550=put-N-from-source-ptr. Setter/getter dispatchers sub_180006b80/sub_180006930 (u32 scalars). Tags: 0x03/0x68/0x6a/0x6b u32 scalars; 0x6c=4×u32 container; 0x69=(h,w) container; 0x01=terminator.
- TLV thunks: sub_180005b70=set0x03, sub_180005b90=get0x03, sub_180005ba0=set0x68, sub_180005bc0=get0x68, sub_180005d00=get0x6b.`

const WS_CONTENT = `WS body target: 5 v30 sections, each with a 4500-byte v30 RECORD area = 250 × [u8 x][u8 y][16-byte oriented-BRIEF descriptor]. The CENTRAL QUESTION for this decode: how does sub_180008f10 produce that 4500-byte content? Specifically — is there a ~250-iteration loop emitting [x][y][16B] records? Where do x,y come from (the v30 feature/keypoint buffer)? Where does each 16-byte descriptor come from (sub_1800046e0)? Does it write into the persistent section buffer (the packer's [rbx+0x138]) or directly append to the TLV stream via put-N (sub_180006550)? Trace the buffer that ends up holding the 4500 bytes.`

const MAIN_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['signature', 'overall_purpose', 'control_flow', 'pseudocode', 'call_sites', 'memory_writes', 'content_mechanism', 'constants', 'open_questions'],
  properties: {
    signature: { type: 'string', description: 'derived signature; identify which arg is the dest section/record buffer and which is the v30 feature/keypoint source' },
    overall_purpose: { type: 'string' },
    control_flow: { type: 'string', description: 'loop structure with induction vars + addresses; is there a per-keypoint (~250) loop? what is its bound?' },
    pseudocode: { type: 'string', description: 'full annotated C-like pseudocode; annotate stores with target offset' },
    call_sites: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['site_addr', 'callee_addr', 'args_passed', 'role'], properties: { site_addr: { type: 'string' }, callee_addr: { type: 'string' }, args_passed: { type: 'string' }, role: { type: 'string' } } } },
    memory_writes: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['site_addr', 'dest', 'value_or_source'], properties: { site_addr: { type: 'string' }, dest: { type: 'string' }, value_or_source: { type: 'string' } } } },
    content_mechanism: { type: 'string', description: 'THE KEY ANSWER: exactly how the 4500-byte v30 content (250×[x][y][16B]) is built and where it lands. Cite the loop bound, the x/y source, the descriptor source, the destination buffer, and how it reaches the WS stream.' },
    constants: { type: 'array', items: { type: 'string' } },
    open_questions: { type: 'array', items: { type: 'string' } },
  },
}

const CALLEE_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['addr', 'one_line_role', 'detailed_behavior', 'signature_guess', 'writes_record_bytes', 'classification', 'constants', 'calls', 'confidence', 'notes'],
  properties: {
    addr: { type: 'string' },
    one_line_role: { type: 'string' },
    detailed_behavior: { type: 'string', description: 'pseudocode-level, cite addresses' },
    signature_guess: { type: 'string' },
    writes_record_bytes: { type: 'boolean', description: 'does it write [x][y]/descriptor/record bytes into a buffer (vs pure compute/read)?' },
    record_role: { type: 'string', description: 'if it touches records: what it writes (x/y coords? 16B descriptor? geometry transform? count?) and to which buffer' },
    classification: { type: 'string', enum: ['descriptor-builder', 'record-serializer', 'geometry-transform', 'tlv-codec', 'math-helper', 'allocator', 'copy', 'getter', 'other'] },
    constants: { type: 'array', items: { type: 'string' } },
    calls: { type: 'array', items: { type: 'string' } },
    confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    notes: { type: 'string' },
  },
}

const BATCH_SCHEMA = {
  type: 'object', additionalProperties: false, required: ['helpers'],
  properties: { helpers: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['addr', 'role', 'signature', 'classification', 'writes_record_bytes', 'notes'], properties: { addr: { type: 'string' }, role: { type: 'string' }, signature: { type: 'string' }, classification: { type: 'string' }, writes_record_bytes: { type: 'boolean' }, notes: { type: 'string' } } } } },
}

const SUBSTANTIAL = [
  { addr: '1800046e0', hint: '1322B,297i -- per-minutia DESCRIPTOR builder (E090/BRIEF path byte-exact in feature pipeline). DECODE ITS WRITE TARGET: does it fill the 16-byte descriptor into a record slot, and which?' },
  { addr: '1800082a0', hint: '1672B,321i -- LARGE unknown; prime candidate for the v30 record serializer or geometry transform' },
  { addr: '180008980', hint: '1275B,314i -- LARGE unknown, called 2x from 8f10; candidate record builder/transform' },
  { addr: '18000c6a0', hint: '631B,142i -- unknown' },
  { addr: '180005d10', hint: '554B,141i -- in the 0x18005xxx codec band (NOT a thunk); decode what it emits' },
  { addr: '180004d70', hint: '526B,130i -- unknown' },
]

const BATCH = ['180007980', '180007a70', '180007ac0', '180006470', '180008e80', '180008ec0', '18000b420']

phase('Decode')
const mainPrompt = `${ABI}

Read /tmp/func_180008f10.S (1696B, 352 instrs) -- the section/descriptor ORCHESTRATOR, called by the per-frame worker sub_180001fe0 at 0x18000215b.

${KNOWN}

${WS_CONTENT}

Produce an exhaustive decode. Fill content_mechanism with the DEFINITIVE answer to how the 4500-byte v30 content is produced (or, if it is NOT produced here, say so and name where). Trace the per-keypoint loop (bound? ~250? where the count comes from), the x/y coordinate source, the 16-byte descriptor source (sub_1800046e0?), and the destination buffer + how it reaches the WS TLV stream. Record every call site and notable memory write. Cite instruction addresses; trace induction variables; do not hand-wave loops. The 21 callees are decoded by other agents in parallel -- record each call's contract, don't open their files.`

const calleePrompt = (c) => `${ABI}

Read /tmp/func_${c.addr}.S -- a callee of the section orchestrator sub_180008f10. Hint: ${c.hint}

${KNOWN}

${WS_CONTENT}

Decode it. The central question: does it WRITE record bytes (x/y coords, the 16-byte descriptor, geometry-transformed values, counts) into a buffer, and which buffer/offsets? Set writes_record_bytes + record_role accordingly. Cite instruction addresses. Set confidence honestly.`

const batchPrompt = `${ABI}

Decode this batch of smaller callees of sub_180008f10. Read each file (skip any that is missing):
${BATCH.map(a => `  /tmp/func_${a}.S`).join('\n')}
(Note: func_180007a70.S also covers the call target 0x180007a80, which lands inside it.)

${KNOWN}

For each: addr, role (one line), signature, classification, writes_record_bytes (does it write [x][y]/descriptor/record/count bytes into a caller buffer?), notes. Keep concise but correct; flag anything that writes record content or touches the descriptor/coordinate data. Cite addresses for non-obvious claims.`

const decodes = await parallel([
  () => agent(mainPrompt, { label: 'main:180008f10', phase: 'Decode', schema: MAIN_SCHEMA }),
  ...SUBSTANTIAL.map(c => () => agent(calleePrompt(c), { label: `callee:${c.addr}`, phase: 'Decode', schema: CALLEE_SCHEMA })),
  () => agent(batchPrompt, { label: 'callee:batch', phase: 'Decode', schema: BATCH_SCHEMA }),
])

const main = decodes[0]
const callees = decodes.slice(1, 1 + SUBSTANTIAL.length).filter(Boolean)
const batch = decodes[decodes.length - 1]

if (!main) return { error: 'main decode failed', callees, batch }

phase('Synthesize')
const synthPrompt = `You are synthesizing a decode of sub_180008f10, the section/descriptor orchestrator in the Synaptics fingerprint DLL. Reconcile the parallel decodes into an authoritative report.

${KNOWN}

${WS_CONTENT}

=== ORCHESTRATOR sub_180008f10 ===
${JSON.stringify(main, null, 1)}

=== SUBSTANTIAL CALLEES ===
${JSON.stringify(callees, null, 1)}

=== SMALL CALLEES ===
${JSON.stringify(batch, null, 1)}

Write a markdown report "sub_180008f10 (section/descriptor orchestrator) — decompilation" with:
1. Signature & role; which arg is the dest buffer, which is the v30 feature source.
2. Control flow + compact pseudocode skeleton; the per-keypoint loop and its bound.
3. **Content-production mechanism (KEY)** — exactly how the 4500-byte v30 content (250×[x][y][16B]) is built: the loop bound, x/y source, descriptor source (sub_1800046e0), destination buffer, and how it reaches the WS TLV stream. If any link is not statically determinable, mark NEEDS-HOOK with the exact gdb hook (we already have GDB_DUMP_PACKER_EMIT for the [rsp+0x50] stream and the RVA_46E0 descriptor hook).
4. Call map table (callee | role | writes record bytes? | conf), grouping the already-known codec cluster.
5. How this connects to the packer's persistent [rbx+0x138] section buffer and the 5-section consolidation.
6. Contradictions / low-confidence items.
7. Recommended next steps (which function to decode next, which hook to run, which dev/*.py to extend), ordered.
Cite instruction addresses. This report will be committed to dev/.`

const report = await agent(synthPrompt, { label: 'synthesize', phase: 'Synthesize' })

return { main, callees, batch, report }
