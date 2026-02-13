# ERC-4337 Compatibility Matrix Runbook

This runbook executes the Phase 3 compatibility matrix against real account implementations.

## Inputs

- Matrix config: `packages/contracts/compatibility/erc4337-matrix.config.template.json`
- Deployment manifest: `packages/contracts/deployments/manifest.template.json`
- Target network RPC URL in env (`BASE_SEPOLIA_RPC`, etc.)
- Evaluator signer key in env (`EVALUATOR_PK`) for signed `userOpHash` vectors

## Goal

Validate `WardexValidationModule.validateUserOp` behavior for:

- Generic ERC-4337 account execute path (`0xb61d27f6`)
- Safe 4337 module path (`0x6a761202`)
- Kernel path (`0x1cff79cd`)

For each path, confirm:

1. Caller restriction (only account/entrypoint)
2. Signature validation behavior
3. Spending-limit enforcement behavior
4. Event emission and failure reason mapping

## Step 1: Prepare Config

1. Copy template and fill addresses:
   - `module.address`
   - `entryPoint.address`
   - each implementation `accountAddress`
   - evaluator address
2. Record deployment commit SHA.

## Step 2: Validate Deployed Module Presence

```bash
cast code <MODULE_ADDRESS> --rpc-url $BASE_SEPOLIA_RPC
```

Expected: non-empty bytecode.

## Step 3: Validate EntryPoint Wiring

For each account:

1. Ensure account initialized module with evaluator + limits.
2. Ensure account configured trusted entrypoint:
   - `setEntryPoint(entryPoint)`
3. Read back account config and limits (via public getters/mappings).

## Step 4: Run Matrix Vectors Per Implementation

For each `implementations[].id`:

- Build a representative `callData` using listed selector/signature.
- Vector A: below-limit value (`vectors.belowLimitValueWei`)
- Vector B: above-limit value (`vectors.aboveLimitValueWei`)

Assertions:

- Unauthorized caller -> returns invalid (`1`) and emits `TransactionBlocked(..., "Unauthorized validation caller")`
- Invalid evaluator signature -> returns invalid (`1`) and emits `TransactionBlocked(..., "Invalid Wardex approval")`
- Valid evaluator signature:
  - If `expectedValueExtraction == "supported"`:
    - below-limit vector returns valid (`0`)
    - above-limit vector returns invalid (`1`) with reason `"Spending limit exceeded"`
  - If `expectedValueExtraction == "currently_skipped"`:
    - vectors currently return valid (`0`) if other checks pass
    - no ETH spending increment should be recorded

## Step 5: Record Results

Add results to `packages/contracts/compatibility/erc4337-matrix.md`:

- chain/network/date
- implementation IDs tested
- pass/fail by assertion category
- tx hashes for reproducibility
- observed deviations from expected behavior

## Step 6: Mainnet Gate Decision

Gate to mainnet only if:

- Generic path fully green
- Safe/Kernel status explicitly accepted with documented mitigations OR extractor adapters implemented
- Event/reason observability green
- Deployment manifest and verification links complete

## Current Known Limitation

Current on-chain ETH value extraction is selector-specific to:

- `execute(address,uint256,bytes)` (`0xb61d27f6`)

Safe/Kernel selectors are currently tracked as compatibility vectors and do not enforce extracted-value limits on-chain yet.
