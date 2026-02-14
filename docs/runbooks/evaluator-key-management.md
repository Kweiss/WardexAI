# Evaluator Key Management Policy

## Overview

The evaluator key signs approval payloads that authorize transactions through the `WardexValidationModule`. It is a critical security component — compromise of the evaluator key allows an attacker to approve arbitrary transactions (within spending limits). This document defines custody, rotation, and break-glass procedures.

---

## Key Custody

- **Hardware wallet or KMS required** — the evaluator private key must be held in a hardware wallet (Ledger, Trezor) or cloud KMS (AWS KMS, GCP Cloud HSM). It must **never** exist in plaintext on disk, in environment variables, or in source control.
- **Access control** — only authorized operators should have access to the KMS key or hardware wallet. Use IAM policies (for cloud KMS) or physical custody controls (for hardware wallets).
- **Audit logging** — all signing operations should be logged. Cloud KMS provides this natively; for hardware wallets, log usage at the application layer.

---

## Rotation Cadence

| Trigger | Timeline |
|---------|----------|
| Scheduled rotation | Quarterly (every 90 days) |
| Suspected compromise | Immediately |
| Personnel change (operator leaves) | Within 24 hours |
| Security audit finding | Per audit recommendation |

### Rotation Procedure

1. **Generate new evaluator key** in KMS or on a new hardware wallet.
2. **Call `setEvaluator(newAddress)`** from the smart account (requires account owner signature).
3. **Verify on-chain** — read `accounts[account].evaluator` via `cast call` to confirm the new address.
4. **Update application config** — point the approval signing service to the new key.
5. **Decommission old key** — disable the old KMS key version or securely wipe the old hardware wallet.
6. **Log the rotation** — record old address, new address, timestamp, and reason.

---

## Break-Glass Procedure

Use when the evaluator key is lost or compromised.

1. **Freeze the account immediately** — call `freeze()` from the account owner to halt all transactions.
2. **Rotate the evaluator** — call `setEvaluator(newAddress)` from the account owner with a freshly generated key.
3. **Verify the new evaluator** — read on-chain state to confirm the evaluator address is updated.
4. **Unfreeze the account** — call `unfreeze()` from the account owner after verifying the new evaluator is correct.
5. **Audit** — review recent transactions for unauthorized approvals signed by the compromised key.
6. **Revoke all active sessions** — compromised evaluator may have approved session keys; revoke and re-create them.

---

## Separation of Concerns

| Role | Purpose | Holds Funds? |
|------|---------|-------------|
| Account Owner | Full control — freeze, unfreeze, set evaluator, deploy | Yes |
| Evaluator | Signs approval payloads for transactions | **No** |
| Session Key | Executes transactions within boundaries | **No** |

The evaluator key must **never** be the same key as the account owner. This separation ensures that evaluator compromise does not grant full account control.

---

## Backup

- **Encrypted seed backup** — keep an encrypted backup of the evaluator key seed phrase in cold storage (e.g., encrypted USB in a safe). This backup must be stored **separately** from the account owner backup.
- **Recovery test** — verify the backup can restore the evaluator key at least once per quarter (during scheduled rotation).
- **Access control** — the backup should require multi-party access (e.g., two-of-three custody).
