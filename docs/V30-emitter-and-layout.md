# v30 record emitter + layout (sub_1800057e0) — decode 2026-06-01

**KEY RESULT: the v30 on-wire record is `[16B descriptor][x:u8][y:u8]` (descriptor FIRST).**
This fixed every from-scratch no-match (see commit ad85c9e / memory native-pipeline-readiness).
Emit chain: packer sub_180002240 -> worker sub_180001fe0 -> orchestrator sub_180008f10 ->
section builder sub_18000c6a0 -> sub_1800057e0. Source kp record stride 0x20: desc-ptr@+0,
orient@+0xc, x@+0x14, y@+0x18. Records start at (find_v30_regions anchor - 16).

---

## Workflow synthesis (capture plan — now largely moot, kept for the emitter/record decode)

