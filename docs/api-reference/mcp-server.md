# @wardexai/mcp-server API Reference

The MCP server exposes Wardex wallet security tools to Claude Code and any MCP-compatible AI agent framework via the Model Context Protocol.

> **Integration guide**: For setup instructions and usage examples, see [MCP Server Integration](../guides/mcp-server.md).

---

## Server Info

| Field | Value |
|---|---|
| Name | `wardex` |
| Version | `0.1.0` |
| Protocol | MCP (Model Context Protocol) |
| Transports | `stdio` (default), `http` (Streamable HTTP / SSE) |

---

## Tools

The server exposes four tools. Each tool accepts JSON input and returns plain-text output.

### wardex_evaluate_transaction

Runs the full 9-stage security pipeline against a transaction and returns a security verdict.

**Input Schema**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `to` | `string` | Yes | Target address (0x-prefixed, 42 characters) |
| `value` | `string` | No | Value in wei (as decimal string). Defaults to `"0"`. |
| `data` | `string` | No | Encoded calldata (0x-prefixed hex) |
| `chainId` | `number` | No | Chain ID. Defaults to `1` (Ethereum mainnet). |
| `gasLimit` | `string` | No | Gas limit (decimal string) |
| `maxFeePerGas` | `string` | No | Max fee per gas in wei (decimal string) |

**Output Fields**

| Field | Description |
|---|---|
| `Status` | Human-readable status: `SAFE`, `WARNING`, `BLOCKED`, or `FROZEN` |
| `Decision` | Machine-readable: `approve`, `advise`, `block`, or `freeze` |
| `Tier` | Security tier that was applied: `audit`, `copilot`, `guardian`, `fortress` |
| `Risk Scores` | Four scores (0-100): Context, Transaction, Behavioral, Composite |
| `Findings` | Array of `[SEVERITY] CODE: message` lines (only present if findings exist) |
| `Suggestions` | Actionable remediation steps (only present if suggestions exist) |
| `Required Action` | `block`, `freeze`, or omitted for non-blocking verdicts |
| `Evaluation ID` | UUID v4 for audit trail correlation |

---

### wardex_check_address

Evaluates an address against denylists, reputation data, and risk factors. Lighter weight than a full transaction evaluation.

**Input Schema**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `address` | `string` | Yes | Ethereum address to check (0x-prefixed) |
| `chainId` | `number` | No | Chain ID. Defaults to `1`. |

**Output Fields**

| Field | Description |
|---|---|
| `Address` | The address that was checked |
| `Transaction Risk Score` | Score (0-100) from address-specific analysis |
| `Safe` | `Yes` if score < 30, `No` otherwise |
| `Findings` | Address-specific findings (only present if issues found) |

**Implementation Note**: Internally, this tool creates a zero-value transaction to the target address and runs it through the evaluation pipeline, then filters the verdict for address-specific reasons.

---

### wardex_get_status

Returns the current state of the Wardex security system. Takes no input parameters.

**Output Fields**

| Field | Description |
|---|---|
| `Mode` | Current security mode: `adaptive`, `guardian`, or `copilot` |
| `Frozen` | `No` or `YES - EMERGENCY` |
| `Evaluations` | Total number of evaluations since startup |
| `Blocked` | Number of blocked transactions |
| `Advisories` | Number of advisory verdicts issued |
| `Daily Volume` | Cumulative daily transaction volume in wei |
| `Signer Healthy` | Whether the isolated signer process is responsive |
| `Intelligence Updated` | ISO 8601 timestamp of last intelligence provider update (if configured) |

---

### wardex_filter_output

Scans text for private keys, seed phrases, mnemonic sequences, and keystore data. Returns sanitized text with sensitive content replaced.

**Input Schema**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `text` | `string` | Yes | Text to scan and filter |

**Output Fields**

| Field | Description |
|---|---|
| (filtered text) | The input text with sensitive items replaced by `[REDACTED BY WARDEX]` |
| `[Wardex] N sensitive item(s) redacted` | Summary of redactions with types (only present if redactions occurred) |
| `[Wardex] Output BLOCKED` | Shown when the entire output is blocked due to excessive sensitive data |

**Detection Patterns**

| Pattern | Description |
|---|---|
| Hex private keys | 64 hex characters with or without `0x` prefix |
| BIP-39 mnemonics | 12/15/18/21/24 word sequences with uncommon-word heuristic (40%+ non-common English) |
| JSON keystore | `"crypto": {"cipher":` structure |

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `WARDEX_MODE` | `adaptive` | Security mode: `adaptive`, `guardian`, or `copilot` |
| `WARDEX_SIGNER_SOCKET` | `/tmp/wardex-signer.sock` | Unix socket path for the isolated signer |
| `WARDEX_TRANSPORT` | `stdio` | Transport: `stdio` or `http` |
| `WARDEX_PORT` | `3100` | HTTP port (only used with `http` transport) |

---

## CLI Arguments

```bash
npx @wardexai/mcp-server [--transport stdio|http] [--port 3100]
```

| Argument | Default | Description |
|---|---|---|
| `--transport` | `stdio` | Transport protocol |
| `--port` | `3100` | HTTP port (ignored for stdio) |

CLI arguments take precedence over environment variables.

---

## HTTP Transport

When running with `--transport http`, the server exposes three HTTP endpoints:

| Endpoint | Method | Description |
|---|---|---|
| `/mcp` | POST | MCP protocol endpoint (Streamable HTTP / SSE) |
| `/` | POST | Alias for `/mcp` |
| `/health` | GET | Returns JSON status object |

### Health Check Response

```json
{
  "status": "ok",
  "mode": "adaptive",
  "frozen": false,
  "evaluationCount": 0,
  "blockCount": 0,
  "advisoryCount": 0,
  "dailyVolumeWei": "0",
  "signerHealthy": true
}
```

---

## Internal Architecture

```
MCP Client (Claude Code, Cursor, etc.)
    |
    | MCP protocol (stdio or HTTP)
    v
@wardexai/mcp-server
    |
    | initShield() → createWardex()
    v
@wardexai/core WardexShield
    |
    | 9-stage middleware pipeline
    v
SecurityVerdict → formatVerdict() → plain text response
```

The server creates a single `WardexShield` instance at startup and shares it across all tool calls. The shield instance maintains the evaluation counter, audit log, behavioral profile, and freeze state for the lifetime of the process.

---

## What's Next?

- **[MCP Server Guide](../guides/mcp-server.md)** -- Step-by-step setup and configuration
- **[Claude Code Skill](../guides/claude-skill.md)** -- Auto-interception with PreToolUse hooks
- **[@wardexai/core API](./core.md)** -- Full API reference for the evaluation engine
- **[Types Reference](./types.md)** -- All TypeScript types
