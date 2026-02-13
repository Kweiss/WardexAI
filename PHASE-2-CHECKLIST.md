# Phase 2 Checklist (Weeks 5-8)

## Objective
Ship intelligence, context integrity, output filtering, and risk/policy hardening to production-ready quality.

## Status Legend
- [x] Complete
- [~] In progress
- [ ] Pending

## Workstreams

### 1) Intelligence
- [x] Address and contract analysis pipeline implemented
- [x] Proxy and honeypot bytecode pattern detection implemented
- [x] Address ageDays population from explorer tx history implemented (`@wardexai/intelligence`)
- [ ] Add additional timeout/fallback tests for explorer and RPC degradation
- [ ] Add fixture coverage for high-risk bytecode variants and false-positive guards

### 2) Context Analyzer
- [x] Rule-based prompt injection detection implemented
- [x] Coherence and trust-source checks implemented
- [ ] Tune escalation heuristics with deterministic threshold tests
- [ ] Add calibration notes for source trust scoring in docs

### 3) Output Filter
- [x] Private key / mnemonic / keystore filtering implemented
- [x] Default BIP-39 wordlist loading enabled
- [ ] Add adversarial corpus tests (obfuscated separators, mixed encodings, multiline variants)

### 4) Risk + Policy
- [x] Composite risk aggregation and tiered policy engine implemented
- [x] Tier override guardrails implemented
- [ ] Add tier calibration matrix tests for boundary values and trigger precedence

## Exit Criteria
- [ ] All scenario + unit tests for Phase 2 surfaces pass in CI
- [ ] No open High/Critical findings on Phase 2 components
- [ ] Documentation updated for final Phase 2 behavior and operator defaults

## Kickoff Completed (Today)
- Implemented address age derivation in intelligence provider using explorer tx history.
- Added unit tests for age population and explorer fallback behavior.
