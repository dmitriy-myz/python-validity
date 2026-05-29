export const meta = {
  name: 'decompile-ws-packer',
  description: 'Decompile sub_180002240 (WS-body packer) + its 25-callee tree from objdump, map WS-body bytes to writer functions',
  phases: [
    { title: 'Decode', detail: 'packer body + every callee, one agent each, in parallel' },
    { title: 'Synthesize', detail: 'merge into WS-body offset -> writer-function map' },
  ],
}

const WS_CONTEXT = `WS body layout (23056 bytes, 5 v30 sections). CONST = sensor-stable copyable; VARIANT = session-derived (the unknowns we must derive):
[0..4)     zeros                         CONST
[4..8)     size_u32 = 23036 = 0x59fc     CONST (sizeof payload)
[8..16)    06 02 05 00 02 00 08 01       CONST (config code)
[16..24)   04 03 02 01 00 00 00 00       CONST (sensor/algo identifier)
[24..40)   per_section_counts u32 x4     VARIANT (consolidated minutia counts, sections 0..3)
[40..44)   byte40=5th-section count + 3 flag bytes   PARTIAL
[44..64)   geometry_stats (20 B)         VARIANT 14/20
[64..309)  section0 pre-v30 (245 B)      VARIANT 132/245 (global section table + POSE)
[309..4809)   section0 v30 records (4500 B = 250 x [u8 x][u8 y][16B desc])   CONTENT
[4809..4905)  section1 pre-v30 (96 B)    VARIANT 24/96 (TLV skeleton)
[4905..9405)  section1 v30 records       CONTENT
[9405..9453)  section2 pre-v30 (48 B)    VARIANT 40/48
[9453..13953) section2 v30 records       CONTENT
[13953..13993) section3 pre-v30 (40 B)   VARIANT 35/40
[13993..18493) section3 v30 records      CONTENT
[18493..18533) section4 pre-v30 (40 B)   VARIANT 24/40
[18533..23033) section4 v30 records      CONTENT
[23033..23056) tail (23 B)               VARIANT 8/23
Each section's pre-v30 starts with 8 ASCENDING bytes (e.g. a4 a8 bf ce d9 db db e4) that vary per session+section -- the primary mystery ("POSE leads"). A common ~16-byte marker [id u32][TLV 00 b8 11 00][pad][cap 0xfa=250] frames each section.`

const ABI = `Target: synaWudfBioUsb.dll, x86-64, Windows x64 ABI. objdump INTEL syntax (dest first, e.g. "mov rax,rcx" = rax<-rcx). Integer args: RCX, RDX, R8, R9, then stack at [rsp+0x28], [rsp+0x30]... ; float args XMM0-3; 32-byte shadow space means stores to [rsp+0x8..0x20] near entry are spilling args 1-4 (RCX->[rsp+8], RDX->[rsp+0x10], R8->[rsp+0x18], R9->[rsp+0x20]). Return in RAX/EAX (or XMM0 for float). RIP-relative "lea reg,[rip+0x..]" usually points at a .rdata constant table -- note these as constant-table refs.`

const CALLEE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['addr', 'one_line_role', 'detailed_behavior', 'signature_guess',
             'reads_from', 'writes_to', 'writes_dest_buffer', 'classification',
             'constants', 'calls', 'confidence', 'notes'],
  properties: {
    addr: { type: 'string' },
    one_line_role: { type: 'string' },
    detailed_behavior: { type: 'string', description: 'pseudocode-level walkthrough, cite instruction addresses' },
    signature_guess: { type: 'string', description: 'e.g. "(rcx=ctx*, rdx=src*, r8d=count) -> rax=bytes_written"' },
    reads_from: { type: 'array', items: { type: 'string' } },
    writes_to: { type: 'array', items: { type: 'string' }, description: 'memory destinations; if it writes into a caller-supplied buffer, give offsets + what value (const/copied/computed)' },
    writes_dest_buffer: { type: 'boolean', description: 'true if it writes into a buffer/struct passed in by the caller (candidate WS-body writer)' },
    ws_body_relevant_offsets: { type: 'array', items: { type: 'string' }, description: 'WS-body offsets this could be writing, if inferable' },
    classification: { type: 'string', enum: ['tiny-getter', 'utility-copy', 'tlv-codec', 'record-builder', 'accumulator-candidate', 'finalize-candidate', 'math-helper', 'allocator', 'other'] },
    constants: { type: 'array', items: { type: 'string' } },
    calls: { type: 'array', items: { type: 'string' }, description: 'callee addresses this function calls' },
    confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    notes: { type: 'string' },
  },
}

const PACKER_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['signature', 'arg_count', 'args_desc', 'overall_purpose', 'control_flow',
             'pseudocode', 'call_sites', 'memory_writes', 'constants',
             'accumulator_evidence', 'open_questions'],
  properties: {
    signature: { type: 'string' },
    arg_count: { type: 'number' },
    args_desc: { type: 'array', items: { type: 'string' }, description: 'per-arg role; identify which arg is the destination WS body / session struct' },
    locals_desc: { type: 'string' },
    overall_purpose: { type: 'string' },
    control_flow: { type: 'string', description: 'loop structure: per-keypoint? per-section? nested? trace induction variables with addresses' },
    pseudocode: { type: 'string', description: 'full annotated C-like pseudocode of the WHOLE function; annotate stores with target struct offset' },
    call_sites: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['site_addr', 'callee_addr', 'args_passed', 'return_used_for', 'role_hypothesis'],
        properties: {
          site_addr: { type: 'string' },
          callee_addr: { type: 'string' },
          args_passed: { type: 'string' },
          return_used_for: { type: 'string' },
          role_hypothesis: { type: 'string' },
        },
      },
    },
    memory_writes: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['site_addr', 'dest', 'value_or_source'],
        properties: {
          site_addr: { type: 'string' },
          dest: { type: 'string', description: 'e.g. [rbx+0x18], [session+152+OFFSET]' },
          value_or_source: { type: 'string' },
          ws_body_offset_guess: { type: 'string' },
        },
      },
    },
    constants: { type: 'array', items: { type: 'string' } },
    accumulator_evidence: { type: 'string', description: 'evidence for/against cross-frame accumulation inside this fn: stores to persistent buffer, counters, frame-index checks' },
    open_questions: { type: 'array', items: { type: 'string' } },
  },
}

const TINY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['helpers'],
  properties: {
    helpers: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['addr', 'role', 'signature', 'classification', 'notes'],
        properties: {
          addr: { type: 'string' },
          role: { type: 'string' },
          signature: { type: 'string' },
          classification: { type: 'string' },
          writes_dest_buffer: { type: 'boolean' },
          notes: { type: 'string' },
        },
      },
    },
  },
}

const SUBSTANTIAL = [
  { addr: '1800053e0', hint: 'LARGEST callee (722B, 171 instrs) -- prime finalize/accumulator candidate' },
  { addr: '180001fe0', hint: '601B, 137 instrs -- per-keypoint 180-byte working-record builder (per prior RE); its own callee sub_180008F10 is the descriptor engine' },
  { addr: '1800051f0', hint: '484B, 122 instrs' },
  { addr: '180001df0', hint: '445B, 110 instrs' },
  { addr: '180001750', hint: '~375B leaf helper, called 3x from packer. NOTE: a "call 0x1730018a4" in this file is an objdump linear-sweep misparse near an embedded jump table -- ignore that bogus target' },
  { addr: '180003320', hint: '309B, 82 instrs -- prior RE flagged this as a GENERIC struct-copy utility (NOT the accumulator); confirm or refute its role here' },
  { addr: '180005fc0', hint: '177B, 44 instrs -- 0x18005xxx TLV-codec cluster' },
  { addr: '180006080', hint: '161B, 35 instrs -- 0x18006xxx TLV-codec cluster' },
  { addr: '180006130', hint: '142B, 34 instrs -- 0x18006xxx TLV-codec cluster' },
  { addr: '180005bd0', hint: '141B, 38 instrs -- 0x18005xxx TLV-codec cluster' },
  { addr: '180001d80', hint: '102B, 33 instrs' },
  { addr: '180006680', hint: '99B, 28 instrs -- 0x18006xxx TLV-codec cluster' },
  { addr: '1800056c0', hint: '90B, 25 instrs -- 0x18005xxx TLV-codec cluster' },
]

const TINY = [
  { addr: '180001000', hint: '3B identity (mov rax,rcx; ret)' },
  { addr: '1800013d0', hint: '7B' },
  { addr: '180001010', hint: '42B null-check validator' },
  { addr: '180001d30', hint: '64B' },
  { addr: '180005b70', hint: '14B' },
  { addr: '180005b90', hint: '5B' },
  { addr: '180005ba0', hint: '14B' },
  { addr: '180005cb0', hint: '14B' },
  { addr: '180005cd0', hint: '5B' },
  { addr: '180005ce0', hint: '14B' },
  { addr: '1800066f0', hint: '33B' },
  { addr: '1800068f0', hint: '49B' },
]

const packerPrompt = `${ABI}

Read the disassembly file /tmp/func_180002240.S with the Read tool -- it is the COMPLETE body of the function at virtual address 0x180002240, the "WS-body PACKER".

${WS_CONTEXT}

This packer is called ONCE PER enrollment frame by the per-frame processor sub_1800D89C0, which first runs the feature extractor (sub_180001A50, image -> 250 keypoints + 16-byte descriptors in a 'v30' buffer) and then calls this packer to fold those features into the WS-body template container. KEY OPEN QUESTION: does multi-frame accumulation (merging ~8 frames into 5 consolidated sections of ~95 minutiae each) happen INSIDE this function -- accumulating into a persistent buffer pointed to by one of its args (the prior RE note guesses session+152) -- or in the caller?

Produce an exhaustive decode (the 25 callees are decoded by OTHER agents in parallel -- do NOT open their files; just record each call's contract: callee addr, args passed + their provenance, how the return is used, your one-line role hypothesis).

Requirements:
1. Signature: arg count + role/type of each (RCX/RDX/R8/R9/stack). Identify which arg is the destination WS-body / session struct pointer; track it through the function (which register holds it).
2. Full annotated C-like pseudocode of the ENTIRE function. Preserve loop nesting; trace induction variables by register+address. Annotate every memory store with the struct offset it targets and (if inferable) the WS-body offset.
3. Every call site -> the call_sites array.
4. Every notable store -> the memory_writes array, especially writes into the dest buffer (size_u32=0x59fc, the 06 02 05.. config, 04 03 02 01 id, per_section_counts at +24, geometry_stats at +44, the 8-byte ascending section leads, TLV framing).
5. constants array (immediates: 0x59fc, 0xfa=250, 0x11b8 etc).
6. accumulator_evidence: stores to a buffer that persists across calls, counters that increment across frames, frame-index branches.
7. open_questions resolvable only by a runtime gdb hook.
Cite instruction addresses for every structural claim. Do not hand-wave.`

function calleePrompt(c) {
  return `${ABI}

Read /tmp/func_${c.addr}.S with the Read tool -- the COMPLETE body of the function at 0x${c.addr}, a callee of the WS-body packer sub_180002240. Hint: ${c.hint}

${WS_CONTEXT}

Decode this function. The CENTRAL question for every callee: does it write into a caller-supplied destination buffer (the WS body), and if so at which offsets and with what values (hardcoded constants? bytes copied from a source? computed values?)? We are tracing which function emits which WS-body bytes -- especially size_u32=0x59fc=23036, per_section_counts, the 20-byte geometry_stats, the 8-byte ascending "POSE" section leads, and TLV framing bytes ([id u32][00 b8 11 00][cap 0xfa]).

Fill every schema field. signature_guess = arg registers + roles + return. classification per the enum. List constants (immediates), and the addresses it calls. Cite instruction addresses for key claims. Set confidence honestly.`
}

const tinyPrompt = `${ABI}

You are decoding a batch of SMALL helper functions, each a callee of the WS-body packer sub_180002240. Read each of these files with the Read tool and decode it briefly:
${TINY.map(t => `  /tmp/func_${t.addr}.S  (${t.hint})`).join('\n')}

For each, return one entry in the helpers array: addr, role (one line), signature (arg regs + return), classification (tiny-getter/utility-copy/math-helper/allocator/other), writes_dest_buffer (does it write into a caller buffer?), and notes. These are mostly getters/setters/validators -- keep each concise but correct. Flag any that write into a caller-supplied buffer (potential WS-body writers) or touch constants like 0x59fc / 0xfa / TLV bytes.`

// ---- Phase 1: decode packer + all callees in parallel (barrier; synthesis needs all) ----
phase('Decode')
const decodes = await parallel([
  () => agent(packerPrompt, { label: 'packer:180002240', phase: 'Decode', schema: PACKER_SCHEMA }),
  ...SUBSTANTIAL.map(c => () => agent(calleePrompt(c), { label: `callee:${c.addr}`, phase: 'Decode', schema: CALLEE_SCHEMA })),
  () => agent(tinyPrompt, { label: 'callee:tiny-batch', phase: 'Decode', schema: TINY_SCHEMA }),
])

const packer = decodes[0]
const calleeResults = decodes.slice(1, 1 + SUBSTANTIAL.length).filter(Boolean)
const tinyResult = decodes[decodes.length - 1]

if (!packer) {
  return { error: 'packer decode failed/skipped', calleeResults, tinyResult }
}

// ---- Phase 2: synthesize into WS-body -> writer map ----
phase('Synthesize')
const synthPrompt = `${ABI}

You are the synthesis step of a decompilation of the WS-body PACKER (sub_180002240) in the Synaptics fingerprint DLL. Below are (a) the decoded packer, (b) decoded substantial callees, (c) decoded tiny helpers -- all produced by parallel agents reading the raw disassembly. Reconcile them into a single authoritative report.

${WS_CONTEXT}

=== DECODED PACKER (sub_180002240) ===
${JSON.stringify(packer, null, 1)}

=== DECODED SUBSTANTIAL CALLEES ===
${JSON.stringify(calleeResults, null, 1)}

=== DECODED TINY HELPERS ===
${JSON.stringify(tinyResult, null, 1)}

Write a thorough markdown report titled "sub_180002240 (WS-body packer) — decompilation". Sections required:

1. **Signature & role** — confirmed signature, which arg is the WS-body/session struct, one-paragraph purpose.
2. **Control flow** — the loop structure and what each loop iterates (keypoints? sections? frames?). Include a compact pseudocode skeleton.
3. **Call map** — a table: callee addr | role | classification | writes WS body? | confidence. Group the TLV-codec cluster.
4. **WS-body offset → writer map** — THE KEY DELIVERABLE. For EACH variant zone in the layout above (size_u32 @4, config @8, id @16, per_section_counts @24, byte40+flags @40, geometry_stats @44, each section's pre-v30 + the 8-byte ascending leads, the tail @23033), state: which function writes it (packer directly, or which callee), at which instruction if known, and the derivation (hardcoded constant / copied from source / computed-how). Mark UNKNOWN or NEEDS-HOOK where the static decode can't determine it, and say exactly which gdb hook would resolve it.
5. **Multi-frame accumulator verdict** — is the accumulator inside sub_180002240 or not? Cite the evidence (persistent-buffer stores, counters, frame-index branches). If not here, name the most likely location to decode next.
6. **The 8-byte ascending "POSE" leads** — best hypothesis for their source given the decode, and how to confirm.
7. **Contradictions / low-confidence items** — anything where the parallel agents disagreed or a claim needs a second look.
8. **Recommended next steps** — concrete, ordered: which function to decode next, which gdb hook to add (entry/exit dump of which buffer), which dev/*.py to extend.

Be concrete and cite instruction addresses. Prefer "NEEDS-HOOK: <exact hook>" over speculation. This report will be committed to dev/ and drives the next session.`

const report = await agent(synthPrompt, { label: 'synthesize', phase: 'Synthesize' })

return { packer, calleeResults, tinyResult, report }
