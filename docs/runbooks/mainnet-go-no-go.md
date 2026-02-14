# Mainnet Go/No-Go Checklists

## Overview

These checklists gate deployment to Base mainnet and Ethereum mainnet. All items must be checked before proceeding with each deployment. A single unchecked item is a hard stop.

---

## Base Mainnet Gate

### Testing & Verification

- [ ] All 26 Solidity tests pass (`forge test` in `packages/contracts/`)
- [ ] Base Sepolia deployment verified and E2E green (6/6 scenarios)
- [ ] Session production defaults defined and tested (`PRODUCTION_DEFAULTS` in `@wardexai/signer`)

### Operations & Documentation

- [ ] Evaluator key-management runbook finalized and reviewed ([link](evaluator-key-management.md))
- [ ] Production monitoring configured — event alerts active for all critical events ([link](production-monitoring.md))
- [ ] Incident response playbook finalized ([link](incident-response.md))
- [ ] Session key rotation playbook finalized ([link](session-key-rotation.md))

### Deployment Readiness

- [ ] Deployer wallet funded on Base mainnet (sufficient ETH for deploy + verify transactions)
- [ ] Evaluator address generated and secured per key-management policy
- [ ] Deployment script tested with `--dry-run` on Base mainnet fork
- [ ] Contract constructor arguments reviewed and confirmed for mainnet context

### Sign-Off

- [ ] Security review of all P0 items complete
- [ ] Operator acknowledges production defaults and monitoring configuration
- [ ] Go/no-go decision recorded with date and approver

---

## Ethereum Mainnet Gate

### Prerequisites (All Base Mainnet Gate Items Apply)

- [ ] All Base mainnet gate items satisfied for Ethereum mainnet context
- [ ] Base mainnet deployment verified and stable (**minimum 7 days** of operation)
- [ ] No freeze incidents or unresolved blocked transactions on Base mainnet during stability period

### Ethereum-Specific Checks

- [ ] Gas costs validated on Ethereum mainnet (significantly higher than L2 — confirm budget)
- [ ] Spending limits reviewed for Ethereum mainnet gas costs (limits may need adjustment)
- [ ] Deployer wallet funded on Ethereum mainnet

### Sign-Off

- [ ] Security review complete for Ethereum mainnet deployment
- [ ] Operator acknowledges higher gas costs and adjusted operational parameters
- [ ] Go/no-go decision recorded with date and approver
