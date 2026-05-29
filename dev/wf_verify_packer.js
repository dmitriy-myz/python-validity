export const meta = {
  name: 'verify-ws-packer-claims',
  description: 'Adversarially verify the 3 interpretive claims from the packer decode + decode the TLV setter/getter dispatchers',
  phases: [
    { title: 'Verify', detail: 'refute-or-confirm each claim against raw disasm; decode dispatchers' },
    { title: 'Reconcile', detail: 'merge verdicts into a verification addendum' },
  ],
}

const ABI = `synaWudfBioUsb.dll, x86-64, Windows x64 ABI, objdump INTEL syntax (dest first). Args RCX,RDX,R8,R9 then [rsp+0x28]...; return RAX/EAX (XMM0 float). "lea reg,[rip+..]" = .rdata constant ref. Disasm files are /tmp/func_<addr>.S (one function each).`

const VERDICT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['claim_id', 'verdict', 'evidence', 'refutation_attempt', 'corrected_statement', 'confidence'],
  properties: {
    claim_id: { type: 'string' },
    verdict: { type: 'string', enum: ['CONFIRMED', 'PARTIAL', 'REFUTED', 'UNCERTAIN'] },
    evidence: { type: 'array', items: { type: 'string' }, description: 'instruction-address-cited evidence for/against' },
    refutation_attempt: { type: 'string', description: 'the strongest case AGAINST the claim you could build, and why it does/does not hold' },
    corrected_statement: { type: 'string', description: 'the precise, corrected version of the claim given what the disasm actually shows' },
    confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
  },
}

const DISPATCH_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['setter_180006b80', 'getter_180006930'],
  properties: {
    setter_180006b80: { type: 'string', description: 'full behavior: signature, what it does with (value, tag, ptr), which struct/stream field it writes, byte width, cite addresses' },
    getter_180006930: { type: 'string', description: 'full behavior: signature, what it reads by tag, return, cite addresses' },
    tag_map: { type: 'string', description: 'mapping of TLV tags 0x03/0x68/0x6a/0x6b/0x6c to the WS-body field each represents, as far as determinable' },
  },
}

phase('Verify')

const claimPose = `${ABI}

CLAIM TO REFUTE-OR-CONFIRM (claim_id="POSE_LEADS_ARE_SORTED_BYTES"):
"The 8-byte ascending 'POSE lead' bytes at the start of each WS section are produced by sub_1800051f0 calling sub_18000bd10 (at 0x18000522c), which permutes the byte array at *(obj+0) into ASCENDING order (using sort sub_1800095c0), and sub_1800051f0 then emits those now-sorted bytes as the first N bytes of the section via a put-N-bytes call (sub_180006550) at ~0x18000526b. N = BYTE[obj+0x10]."

Read and analyze:
- /tmp/func_1800051f0.S  (the v30 record / section emitter — find the call to 0x18000bd10 at 0x18000522c and the put-N at ~0x18000526b; what buffer/ptr is the source of the put-N, and is it the SAME *(obj+0) that bd10 permuted?)
- /tmp/func_18000bd10.S  (216B — does it actually permute bytes at *(obj+0) into ascending order? what is the sort KEY? is the output written back to *(obj+0) or elsewhere?)
- /tmp/func_1800095c0.S  (2443B sort — you only need to confirm it is a comparison sort and what it sorts; do NOT fully decode it, just establish it sorts the array bd10 hands it)
- /tmp/func_180006550.S  (put-N-bytes-from-source TLV primitive — confirm it copies N bytes from a source ptr into the stream)

Build the STRONGEST case you can that this claim is WRONG (e.g. bd10 sorts an INDEX array but does NOT reorder the actual bytes; or the put-N source is a different buffer than what bd10 touched; or the bytes emitted are coordinates not scores; or the ascending property is coincidental). Then state whether that refutation holds. Be precise about which pointer/offset flows where. Cite instruction addresses.`

const claimSize = `${ABI}

CLAIM TO REFUTE-OR-CONFIRM (claim_id="SIZE_FORMULA_IN_180001750_ID6"):
"sub_180001750 is a TLV-property getter indexed by a small id (0..0x13). For id==6 it computes the WS container size via the formula size(n) = (20*(n/2)+4544)*n + ((n+3)&~3) + 0x80, where n is a section count, so n=5 yields 23056 (=0x5a10) and the payload size_u32 at WS[4..8) is 23036 (=0x59fc = 23056-20)."

Read /tmp/func_180001750.S (the getter). Determine: (a) what selects the id/branch (a switch? jump table? the bogus 'call 0x1730018a4' near the embedded jump table is an objdump misparse — the real dispatch is a jump table); (b) for the id-6 case, what arithmetic is actually performed — match it against the claimed formula term by term (the 0x11c0=4544, the *20, the (n+3)&~3 alignment, the +0x80=128). Confirm or correct the formula and the constants. If the function is too thunked to see id-6 directly, say so and mark UNCERTAIN. Note: the arithmetic (20*(5//2)+4544)*5+((5+3)&~3)+0x80 = 23056 has ALREADY been verified numerically; your job is to confirm the DISASSEMBLY actually computes this, not the arithmetic. Cite addresses.`

const claimCounts = `${ABI}

CLAIM TO REFUTE-OR-CONFIRM (claim_id="PER_SECTION_COUNTS_VIA_180006080_TAG6C"):
"The per_section_counts (WS [24..40), 4×u32, VARIANT) are emitted by sub_180006080 as a TLV record under tag 0x6c, reading 4 session-derived u32 from the algo handle at offsets +0x130/+0x144/+0x150/+0x154 (these were earlier populated by the TLV-reader sub_180006130 from an input tag-0x6c field). The companion sub_180005ce0 writes a per-section count under tag 0x6b."

Read:
- /tmp/func_180006080.S  (the commit/flush emitter — does it read algo+0x130/0x144/0x150/0x154 and emit them as 4 u32 under tag 0x6c? Or different offsets/tag?)
- /tmp/func_180006a80.S  (the close/flush TLV primitive it likely calls — confirms framed record append)
Build the strongest refutation (e.g. the offsets are different; it's not 4 u32; tag isn't 0x6c; the record doesn't land at [24..40) but inside a section). Then judge. Note that whether tag-0x6c lands specifically at absolute [24..40) vs elsewhere in the stream is NOT statically determinable (TLV stream order) — so the honest verdict for the OFFSET part is likely PARTIAL/NEEDS-HOOK; focus your CONFIRMED/REFUTED on the mechanics (reads which offsets, emits how many u32, under which tag). Cite addresses.`

const dispatchPrompt = `${ABI}

Decode the two shared TLV dispatchers behind the packer's thunk family (the actual byte writers/readers). Read:
- /tmp/func_180006b80.S  (58B, 3-arg SETTER behind tags 0x03/0x68/0x6a/0x6b)
- /tmp/func_180006930.S  (62B, 2-arg GETTER behind tags 0x03/0x6a)

For the SETTER: signature (which reg is value, which is tag, which is the stream/struct ptr — note the thunks swap args), what it stores, byte width, and into which field/stream (cite addresses). For the GETTER: what it reads by tag and returns. Then give your best tag->WS-field map for 0x03, 0x68, 0x6a, 0x6b, 0x6c using all evidence. These settle whether per_section_counts/byte40/secondary-counter are u32 or smaller tagged fields.`

const verdicts = await parallel([
  () => agent(claimPose, { label: 'verify:pose-leads', phase: 'Verify', schema: VERDICT_SCHEMA }),
  () => agent(claimSize, { label: 'verify:size-formula', phase: 'Verify', schema: VERDICT_SCHEMA }),
  () => agent(claimCounts, { label: 'verify:per-section-counts', phase: 'Verify', schema: VERDICT_SCHEMA }),
  () => agent(dispatchPrompt, { label: 'decode:dispatchers', phase: 'Verify', schema: DISPATCH_SCHEMA }),
])

const claimVerdicts = verdicts.slice(0, 3).filter(Boolean)
const dispatchers = verdicts[3]

phase('Reconcile')
const reconcilePrompt = `You are reconciling adversarial verification of 3 claims from a reverse-engineering decode of the WS-body packer sub_180002240, plus a fresh decode of the TLV dispatchers.

=== CLAIM VERDICTS ===
${JSON.stringify(claimVerdicts, null, 1)}

=== DISPATCHER DECODE ===
${JSON.stringify(dispatchers, null, 1)}

Write a concise markdown "Verification addendum" with:
1. A verdict table: claim_id | verdict | confidence | one-line corrected statement.
2. For any REFUTED/PARTIAL/UNCERTAIN claim, the corrected understanding and what (if anything) still NEEDS-HOOK.
3. The TLV tag -> WS-field map from the dispatcher decode (0x03/0x68/0x6a/0x6b/0x6c).
4. A short "trust level" paragraph: which headline conclusions of the packer decode are now solid vs still hypotheses.
Be precise, cite addresses where given. This addendum will be appended to dev/PACKER-sub_180002240.md.`

const addendum = await agent(reconcilePrompt, { label: 'reconcile', phase: 'Reconcile' })

return { claimVerdicts, dispatchers, addendum }
