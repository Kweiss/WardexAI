# Production Monitoring Checklist

## Overview

This checklist defines the on-chain events to monitor, alert thresholds, and escalation procedures for Wardex smart account operations. Configure alerts via BaseScan/Etherscan alerts, a custom indexer, or an event-monitoring service (e.g., OpenZeppelin Defender, Tenderly).

---

## Events to Monitor

### Critical (Page On-Call Immediately)

| Event | Signature | Action |
|-------|-----------|--------|
| Account Frozen | `AccountFrozen(address)` | Page on-call immediately. Investigate cause — was this an authorized freeze or a potential attack? |
| Evaluator Updated | `EvaluatorUpdated(address, address)` | Page on-call immediately. Verify the rotation was planned and authorized. Require operator confirmation within 15 minutes. |
| Entry Point Updated | `EntryPointUpdated(address, address)` | Page on-call immediately. Verify the update was expected and the new entry point is a known-good address. |

### Warning (Alert + Investigate)

| Event | Signature | Action |
|-------|-----------|--------|
| Account Unfrozen | `AccountUnfrozen(address)` | Verify the unfreeze was authorized by the account owner. Log for audit trail. |
| Spending Limit Updated | `SpendingLimitUpdated(address, address, uint256, uint256)` | Verify the change was planned. Alert if the new limit is significantly higher than the previous one. |

### Informational (Log for Audit)

| Event | Signature | Action |
|-------|-----------|--------|
| Transaction Approved | `TransactionApproved(uint256, address)` | Normal operation. Log for audit trail and volume tracking. |
| Transaction Blocked | `TransactionBlocked(uint256, address, string)` | Track block rate (see thresholds below). Log block reason for analysis. |

---

## Alert Thresholds

| Condition | Severity | Action |
|-----------|----------|--------|
| Transaction block rate > 10/hour | **Critical** | Page on-call. Possible attack or misconfiguration causing repeated rejections. |
| Any `AccountFrozen` event | **Critical** | Page on-call. Immediate investigation required. |
| Any `EvaluatorUpdated` event | **Critical** | Page on-call. Require operator confirmation within 15 minutes. |
| Daily volume > 80% of spending limit | **Advisory** | Notify operator. May need limit increase or investigation into unexpected volume. |
| Daily volume > 95% of spending limit | **Warning** | Alert operator. Transactions will start being blocked soon. |
| No `TransactionApproved` events in 24 hours | **Advisory** | Investigate if expected (account may be idle) or unexpected (possible freeze/misconfiguration). |

---

## Escalation Procedure

1. **Advisory** — logged and sent to operator notification channel (Slack, email). No immediate action required.
2. **Warning** — sent to operator + team lead. Investigate within 1 hour.
3. **Critical** — page on-call engineer. Acknowledge within 5 minutes. Begin investigation immediately.

### Critical Incident Steps

1. Acknowledge the alert.
2. Check on-chain state: is the account frozen? Is the evaluator address correct?
3. If compromised: follow the [Incident Response Playbook](incident-response.md).
4. If false positive: document and update alert rules if needed.
5. Post-incident review within 24 hours.

---

## Dashboard Metrics

Track these metrics for operational visibility:

- **Transaction approval rate** — approved / (approved + blocked) per hour
- **Daily volume** — cumulative ETH value of approved transactions
- **Block reasons breakdown** — categorize blocked transactions by reason string
- **Session key count** — number of active session keys
- **Time since last evaluator rotation** — alert if > 90 days
