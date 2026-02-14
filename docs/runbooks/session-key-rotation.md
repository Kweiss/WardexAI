# Session Key Rotation & Emergency Revocation Playbook

## Overview

Session keys are short-lived signing keys that allow AI agents to transact within strict boundaries. This runbook covers proactive rotation, emergency revocation, and delegation rotation procedures.

---

## Proactive Rotation

Rotate session keys **before** they expire to avoid transaction interruptions.

1. **Detect expiring sessions** — call `getExpiringSessionsSoon(600)` to find sessions expiring within the next 10 minutes.
2. **Rotate each expiring session** — call `rotateSession(id)` which atomically:
   - Revokes the old session (zeros private key buffer)
   - Creates a new session with the same config but a fresh key and expiration
3. **Verify** — confirm the new session appears in `getActiveSessions()` and the old session is marked `revoked: true`.

**Recommended schedule:** Run the expiration check every 5 minutes via a cron job or background timer.

---

## Emergency Revocation

Use when immediate invalidation is required — do not wait for natural expiry.

1. **Revoke the session** — call `revokeSession(id)`.
   - The session is immediately marked `revoked: true`.
   - The private key buffer is zeroed in-place (`Buffer.fill(0)`) and deleted from memory.
2. **Verify** — call `getSession(id)` and confirm `revoked === true`.
3. **Audit** — log the revocation event with timestamp, session ID, and reason.

---

## Delegation Rotation

For MetaMask Delegation Framework delegations:

1. **Revoke the old delegation** — call `rotateDelegation(id)` which:
   - Revokes the existing delegation
   - Creates a new unsigned delegation with the same caveat config
   - The new delegation requires the account owner to re-sign
2. **Obtain owner signature** — the new delegation is unsigned and must be signed by the account owner before it becomes active.
3. **Verify** — confirm the old delegation is revoked and the new delegation has a valid owner signature.

---

## Bulk Emergency Shutdown

When a broad compromise is suspected, revoke everything:

1. **Revoke all active sessions** — iterate `getActiveSessions()` and call `revokeSession(id)` for each.
2. **Revoke all active delegations** — iterate `getActiveDelegations()` and call `revokeDelegation(id)` for each.
3. **Scrub key material** — call `cleanup()` to remove all expired/revoked sessions from memory and zero remaining key buffers.
4. **Verify** — confirm `getActiveSessions()` and `getActiveDelegations()` both return empty arrays.

---

## When to Rotate

| Trigger | Action |
|---------|--------|
| Scheduled (before expiry) | Proactive rotation via `getExpiringSessionsSoon()` |
| Suspicious activity detected | Emergency revocation of affected session(s) |
| Policy change (new limits needed) | Revoke old session, create new with updated config |
| Evaluator address changed | Revoke all sessions, re-create under new evaluator |

## When to Emergency-Revoke

| Trigger | Action |
|---------|--------|
| Key compromise suspected | Immediate revocation + bulk shutdown if scope unclear |
| Anomalous transaction patterns | Revoke affected session, investigate before re-creating |
| Evaluator mismatch detected | Revoke all sessions, investigate evaluator state |
| On-chain freeze event observed | Revoke all sessions (they can't transact anyway) |
