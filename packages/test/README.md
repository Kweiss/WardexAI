# @wardexai/test

Integration and scenario test suite for Wardex.

## Scope

Covers end-to-end and scenario-level behavior across core security paths,
including prompt-injection detection, signer controls, delegation flows,
and policy/risk behavior.

Current suite coverage includes:
- Delegation EIP-712 signature validation and redemption encoding checks
- MCP and policy guardrail regressions
- Full scenario matrix for Phase 1/2 behaviors

## Run Tests

```bash
npm test --workspace @wardexai/test
```

## Notes

- This workspace is private and not intended for npm publishing.
