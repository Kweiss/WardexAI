# Phase 3 Plan (Weeks 9-12)

## Objective
Ship production-ready on-chain enforcement and account-abstraction integration:

1. `WardexValidationModule.sol` + ERC-4337 integration
2. ERC-7715 session key management hardening
3. Deployment progression: Base testnet -> Base mainnet -> Ethereum mainnet

## Scope Status
- [~] In progress

## Current Baseline (Already Built)
- `@wardexai/contracts`: `WardexValidationModule` implemented with:
  - evaluator signature checks
  - freeze/unfreeze
  - ETH spending-limit enforcement
  - Foundry deploy/verify scripts
- `@wardexai/signer`: session and delegation managers implemented:
  - session creation/validation/rotation/revocation
  - MetaMask Delegation Framework caveat mapping and EIP-712 payload generation
- Test coverage exists for:
  - contract/unit behavior (`packages/contracts/test`)
  - delegation + session scenarios (`packages/test/scenarios/delegation*.test.ts`)
  - E2E harness (`packages/test/scenarios/e2e-testnet.test.ts`)

## In Scope (Phase 3)

### 1) ERC-4337 On-Chain Enforcement Completion
- [~] Verify `validateUserOp` compatibility against target account implementations (Safe 4337 module path, Kernel path, and one generic 4337 account)
- [x] Add explicit test vectors for unsupported callData/value extraction patterns to avoid false confidence
- [x] Add event-level assertions and failure-reason mapping for operator observability
- [~] Freeze ABI + storage layout review and produce deployment artifact manifest

### 2) ERC-7715 Session Key Hardening
- [x] Add cross-check tests that prove session constraints and delegation caveats are equivalent for core limits
- [x] Add replay/expiry edge-case tests for rotation + revocation windows
- [x] Define conservative production defaults for session boundaries (duration/value/allowed targets)
- [x] Document operational key-rotation and emergency-revocation playbook

### 3) Deployment & Promotion Pipeline
- [x] Deploy `WardexValidationModule` to Base Sepolia and capture:
  - deployed address: `0xf1ba5470018bed0d41a6bb4e9da695e93f83b2aa`
  - chain ID: 84532
  - verification URL: https://sepolia.basescan.org/address/0xf1ba5470018bed0d41a6bb4e9da695e93f83b2aa
  - deploy commit SHA: `6ec301f`
- [x] Run full E2E runbook against Base Sepolia using deployed module (6/6 passed, 4 SDK tests green against live RPC)
- [x] Gate to Base mainnet with explicit go/no-go checklist
- [x] Gate to Ethereum mainnet with explicit go/no-go checklist

### 4) Operations & Safety
- [x] Define evaluator key-management policy (custody, rotation cadence, break-glass procedure)
- [x] Add production monitoring checklist (freeze events, block rates, evaluator mismatch failures)
- [x] Add rollback procedure for evaluator updates and module freeze incidents

## Out of Scope (Phase 3)
- New attack-vector categories beyond current threat model
- New agent runtime integrations (MCP/skill expansion is Phase 4)
- Major policy-model redesigns (keep current policy engine semantics stable)

## Backlog (Prioritized)

### P0 (must complete before mainnet)
- [ ] 4337 compatibility validation matrix across target account types
- [x] Base Sepolia deployment + verification + reproducible artifact capture
- [x] E2E pass against deployed testnet module (not local-only)
- [x] Evaluator key-management + incident runbook finalized

### P1 (should complete in Phase 3)
- [x] Session-vs-delegation parity tests for limits and approval restrictions
- [x] Edge-case tests: revocation/rotation race windows and expiry boundaries
- [x] Operator dashboards/checks documented (minimum required alerts + thresholds)

### P2 (nice to have in Phase 3 if time allows)
- [ ] Additional account-abstraction implementation coverage beyond minimum matrix
- [ ] Automated deployment report generation from deploy scripts

## Milestones

### M1: Testnet Readiness
- [x] Contract behavior locked for testnet
- [x] Deployment runbook dry-run complete
- [x] Base Sepolia deployment verified

### M2: Mainnet Readiness
- [ ] P0 items complete
- [x] Security sign-off on evaluator operations
- [x] Production monitoring and rollback runbooks approved

### M3: Mainnet Activation
- [ ] Base mainnet deployment completed
- [ ] Ethereum mainnet deployment completed
- [ ] Post-deploy smoke checks green

## Exit Criteria (Phase 3 Complete)
- [ ] Verified deployments exist on Base Sepolia, Base mainnet, and Ethereum mainnet
- [ ] ERC-4337 integration matrix passes for selected account implementations
- [ ] Session key + delegation constraints are parity-tested for core policies
- [x] Operator runbooks (key management, incident response, rollback) are finalized
- [ ] CI includes contract + E2E coverage required for on-chain releases

## Immediate Next Actions
1. Lock target ERC-4337 account implementation list for compatibility testing.
2. Run Base Sepolia deployment from `packages/contracts/script/Deploy.s.sol`.
3. Record deployment artifact manifest in-repo and wire it into E2E config.
4. Execute and document testnet go/no-go review before Base mainnet.

## Recent Progress
- Added unsupported callData selector/value-extraction test vectors in `packages/contracts/test/WardexValidationModule.t.sol`.
- Added event assertion coverage for approve/block outcomes and reason mapping in `packages/contracts/test/WardexValidationModule.t.sol`.
- Added deployment artifact manifest scaffold at `packages/contracts/deployments/manifest.template.json`.
- Added session-vs-delegation parity test suite for core limits and approval restrictions in `packages/test/scenarios/session-delegation-parity.test.ts`.
- Added rotation/revocation/expiry edge-case checks in `packages/test/scenarios/session-delegation-parity.test.ts`.
- Added explicit compatibility matrix vectors for generic/Safe/Kernel selector patterns in `packages/contracts/test/WardexValidationModule.t.sol`.
- Added matrix tracker document at `packages/contracts/compatibility/erc4337-matrix.md`.
- Added machine-readable compatibility config template at `packages/contracts/compatibility/erc4337-matrix.config.template.json`.
- Added execution runbook at `packages/contracts/compatibility/erc4337-matrix-runbook.md`.
- Added production session defaults (`PRODUCTION_DEFAULTS`) and `createSessionWithDefaults()` helper in `packages/signer/src/session-defaults.ts`.
- Added session key rotation & emergency revocation playbook at `docs/runbooks/session-key-rotation.md`.
- Added evaluator key-management policy at `docs/runbooks/evaluator-key-management.md`.
- Added production monitoring checklist with event alerts and thresholds at `docs/runbooks/production-monitoring.md`.
- Added incident response & rollback procedures at `docs/runbooks/incident-response.md`.
- Added mainnet go/no-go checklists (Base + Ethereum) at `docs/runbooks/mainnet-go-no-go.md`.
