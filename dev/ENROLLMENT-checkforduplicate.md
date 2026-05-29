# EnrollmentCheckForDuplicate — chain (MoH host enrollment)

The MoH host enrollment is the C++ class `CEohMohEIV` (Match-on-Chip parallel =
`CEocMocEIV`). Operation names are embedded as `.rdata` trace labels. The
enrollment state machine:

```
EnrollmentCreate            init context
EnrollmentUpdate × N frames BUILD the template (the packer sub_180002240 +
                            section orchestrator sub_180008f10 pipeline)
EnrollmentCheckForDuplicate IdentifyUser(prepared template vs stored set)  ← gate
EnrollmentCommit            PERSIST to storage (only if not a duplicate)
```

So the template is **assembled in memory during Update**, the duplicate check
runs on the **prepared-but-uncommitted** candidate, and Commit persists it.
(Commit itself is not yet decoded instruction-by-instruction — the build side
and the CheckForDuplicate dispatch are.)

## CheckForDuplicate dispatch chain

`CEohMohEIV` vtable base = **`0x18010db68`** (36 entries, preceded by a 16-byte
COM interface IID GUID). Resolve any slot with
`dev/find_vtable.py <dll> <func_vma> [slot_off]`.

```
sub_18001e5f0  CEohMohEIV::EnrollmentCheckForDuplicate   (vtable idx 8, off 0x40)
   │  RAII trace wrapper; calls (*this->vtable[0x78])(this, 0, &result, 0)
   │  (CFG-dispatched via guard stub 0x18010a7f0); on success marshals a
   │  ~0x4e-byte result struct into *out (out[0x4d]=valid flag); on failure traces.
   ▼
sub_18001f670  vtable[0x78] (idx 15) — MODE DISPATCHER on *(int*)(this+0x28):
   ├─ mode 2 → vtable[0xd8] = sub_180027540
   ├─ mode 1 → vtable[0xd0] = sub_180027ab0, then cleanup sub_18001e570
   └─ else   → 0x80070057 (E_INVALIDARG)
        ▼
   vtable[0xd0] = sub_180027ab0  CeivMode::IdentifyUserStorageOnHost (+RemoveEnrolledFinger)
   vtable[0xd8] = sub_180027540  CeivMode::IdentifyUser{StorageOnHost,StorageOnFlash}
                                  ← the big matcher (2279 B, 572 instrs); calls the
                                    template-store/DB helpers 0x1800e0ca0 / 0x1800e0a60 /
                                    0x1800e3d50 / 0x1800dba20. A match ⇒ duplicate.
```

The actual finger-vs-enrolled comparison/scoring is inside `IdentifyUser`
(`sub_180027540`), which shares the v30 record serializer `sub_1800057e0`
(`[16B desc][x][y]` 18-byte records) and the 120×120 spatial voting-grid scorer
`sub_18000c6a0` with the enrollment path — see `dev/decode_sub_180008f10.md`.

For native enrollment, CheckForDuplicate is **orthogonal to building/storing a
template** (it's a host-side identify gate). It matters only when implementing
matching ourselves, where `sub_18000c6a0` (the scorer) is the key.
