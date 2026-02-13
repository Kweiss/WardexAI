# ERC-4337 Compatibility Matrix (Phase 3)

This matrix tracks `WardexValidationModule.validateUserOp` behavior across account call-data patterns.

## Current Extractor Scope

- Supported today:
  - `execute(address,uint256,bytes)` selector `0xb61d27f6`
- Not parsed today (value extraction skipped):
  - Safe-style `execTransaction(...)` selector vectors (e.g. `0x6a761202`)
  - Kernel-style batched execute selector vectors (e.g. `0x1cff79cd`)

## Local Test Vector Status

| Pattern | Selector | Status | Contract Test |
|---|---|---|---|
| Generic `execute(address,uint256,bytes)` | `0xb61d27f6` | Enforced (spending limits applied) | `test_compatMatrix_genericExecutePattern_supportedAndEnforced` |
| Safe-style `execTransaction(...)` | `0x6a761202` | Skipped (no value extraction) | `test_compatMatrix_safeExecTransactionPattern_currentlyNotParsed` |
| Kernel-style execute vector | `0x1cff79cd` | Skipped (no value extraction) | `test_compatMatrix_kernelExecutePattern_currentlyNotParsed` |

## Real Account Validation Targets (Pending)

- [ ] Safe (4337 module path): validate UserOp end-to-end against deployed account implementation.
- [ ] Kernel path: validate UserOp end-to-end against deployed account implementation.
- [ ] Generic ERC-4337 account path: validate standard execute path.

## Execution Assets

- Config template: `packages/contracts/compatibility/erc4337-matrix.config.template.json`
- Execution runbook: `packages/contracts/compatibility/erc4337-matrix-runbook.md`
- Deployment manifest template: `packages/contracts/deployments/manifest.template.json`

## Notes

- Skipped extraction is intentional fail-safe behavior for now (off-chain Wardex SDK still enforces policy).
- Mainnet readiness requires replacing selector-only vectors with live-account integration tests and documenting any account-specific adapters required.
