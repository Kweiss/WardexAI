# Incident Response & Rollback Procedures

## Overview

This playbook covers recovery procedures for evaluator updates, freeze incidents, and post-incident verification. All procedures assume the operator has access to the account owner key and `cast` CLI.

---

## Evaluator Rollback

If an evaluator was changed incorrectly (wrong address, unauthorized rotation):

1. **Call `setEvaluator(previousAddress)`** from the account owner.
   ```bash
   cast send <WARDEX_MODULE_ADDRESS> \
     "setEvaluator(address)" <PREVIOUS_EVALUATOR_ADDRESS> \
     --private-key <OWNER_PRIVATE_KEY> \
     --rpc-url <RPC_URL>
   ```
2. **Verify on-chain** — read the current evaluator address:
   ```bash
   cast call <WARDEX_MODULE_ADDRESS> \
     "getEvaluator(address)(address)" <ACCOUNT_ADDRESS> \
     --rpc-url <RPC_URL>
   ```
3. **Confirm** the returned address matches the intended evaluator.
4. **Update application config** to point the signing service back to the restored key.

---

## Freeze Incident Recovery

When an account is frozen (whether intentionally or by incident):

### 1. Diagnose Root Cause

- Was this an authorized freeze? Check with the operator who triggered it.
- Was this triggered by an attack? Review recent `TransactionBlocked` events and evaluator activity.
- Was this a false positive? Check if monitoring rules triggered an automated freeze.

### 2. Unfreeze (If Safe)

Only unfreeze after confirming the root cause is resolved.

```bash
cast send <WARDEX_MODULE_ADDRESS> \
  "unfreeze()" \
  --private-key <OWNER_PRIVATE_KEY> \
  --rpc-url <RPC_URL>
```

### 3. Verify Transactions Resume

- Submit a low-value test transaction through the approval pipeline.
- Confirm `TransactionApproved` event is emitted.
- Monitor for 15 minutes to ensure normal operation.

### 4. Post-Incident Review

Complete the post-incident checklist (see below).

---

## Transaction Replay Prevention

No special replay prevention is needed after freeze/unfreeze cycles:

- **Spending limits** have daily resets with on-chain epoch tracking (`dailyResetEpoch`). Unfreezing does not reset the daily counter.
- **Session nonces** are independent of freeze state.
- **Delegation nonces** are tracked separately and persist through freeze/unfreeze.

---

## State Verification After Rollback

After any rollback or recovery action, verify the full account configuration:

```bash
# Check evaluator address
cast call <WARDEX_MODULE_ADDRESS> \
  "getEvaluator(address)(address)" <ACCOUNT_ADDRESS> \
  --rpc-url <RPC_URL>

# Check frozen status
cast call <WARDEX_MODULE_ADDRESS> \
  "isFrozen(address)(bool)" <ACCOUNT_ADDRESS> \
  --rpc-url <RPC_URL>

# Check spending limits
cast call <WARDEX_MODULE_ADDRESS> \
  "getSpendingLimit(address,address)(uint256)" <ACCOUNT_ADDRESS> <TOKEN_ADDRESS> \
  --rpc-url <RPC_URL>
```

Confirm all values match the expected state before declaring the incident resolved.

---

## Post-Incident Checklist

After any incident (freeze, unauthorized evaluator change, anomalous transactions):

- [ ] **Root cause documented** — what happened and why
- [ ] **Timeline documented** — when the incident was detected, acknowledged, and resolved
- [ ] **Monitoring updated** — new alerts or threshold changes based on learnings
- [ ] **Spending limits reviewed** — are current limits appropriate given the incident?
- [ ] **Evaluator key rotated** — if compromise is suspected, rotate per [Evaluator Key Management](evaluator-key-management.md)
- [ ] **Session keys revoked and re-created** — if evaluator was compromised, all sessions should be refreshed
- [ ] **Stakeholders notified** — inform relevant parties of the incident and resolution
- [ ] **Runbooks updated** — incorporate any new procedures discovered during the incident
