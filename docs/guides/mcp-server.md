# MCP Server Integration

Wardex ships an MCP (Model Context Protocol) server that exposes wallet security tools to Claude Code and any MCP-compatible AI agent framework. One command adds always-on transaction evaluation, address reputation checks, output filtering, and status monitoring to your agent -- no SDK wiring required.

> **What is MCP?** Model Context Protocol is an open standard that lets AI models call external tools over stdio or HTTP. Claude Code, Cursor, and other agent runtimes use it to extend what an LLM can do.

---

## Step 1: Install

Register the Wardex MCP server with Claude Code:

```bash
claude mcp add wardex npx @wardexai/mcp-server
```

That single command tells Claude Code to launch `@wardexai/mcp-server` as a child process and expose its tools in every conversation. No config files to edit.

To verify it registered:

```bash
claude mcp list
```

Expected output:

```
wardex: npx @wardexai/mcp-server (stdio)
```

---

## Step 2: Available Tools

The server exposes four tools. Claude (or any MCP client) can call them by name.

| Tool | Purpose |
|------|---------|
| `wardex_evaluate_transaction` | Evaluate a transaction for security threats before signing |
| `wardex_check_address` | Check the reputation and safety of an Ethereum address |
| `wardex_get_status` | Get the current Wardex security status |
| `wardex_filter_output` | Filter text for private keys, seed phrases, and sensitive data |

### wardex_evaluate_transaction

Runs the full 9-stage security pipeline: context analysis, transaction decoding, value assessment, address checking, contract checking, behavioral comparison, risk aggregation, and policy enforcement.

**Input schema:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `to` | `string` | Yes | Target address (0x-prefixed) |
| `value` | `string` | No | Value in wei (as string) |
| `data` | `string` | No | Encoded calldata (0x-prefixed hex) |
| `chainId` | `number` | No | Chain ID (1 = Ethereum, 8453 = Base) |
| `gasLimit` | `string` | No | Gas limit |
| `maxFeePerGas` | `string` | No | Max fee per gas (wei) |

**Example call and response:**

```
Tool: wardex_evaluate_transaction
Input: {
  "to": "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",
  "value": "100000000000000000",
  "chainId": 1
}
```

```
Status: SAFE
Decision: approve
Tier: copilot
Risk Scores:
  Context: 0/100
  Transaction: 5/100
  Behavioral: 0/100
  Composite: 3/100
Evaluation ID: a1b2c3d4-5678-90ab-cdef-1234567890ab
```

When threats are detected, the response includes findings and suggestions:

```
Status: BLOCKED
Decision: block
Tier: guardian
Risk Scores:
  Context: 85/100
  Transaction: 40/100
  Behavioral: 0/100
  Composite: 72/100
Findings:
  [CRITICAL] PROMPT_INJECTION: Detected prompt injection pattern in context
  [HIGH] INFINITE_APPROVAL: Token approval for unlimited amount
Suggestions:
  - Review conversation history for manipulation attempts
  - Use a bounded approval amount instead of type(uint256).max
Required Action: block
Evaluation ID: f9e8d7c6-5432-10ba-fedc-ba0987654321
```

### wardex_check_address

Evaluates an address against denylists and reputation signals. Lighter weight than a full transaction evaluation -- useful for pre-screening counterparties.

**Input schema:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | `string` | Yes | Ethereum address to check (0x-prefixed) |
| `chainId` | `number` | No | Chain ID |

**Example call and response:**

```
Tool: wardex_check_address
Input: {
  "address": "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",
  "chainId": 1
}
```

```
Address: 0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45
Transaction Risk Score: 5/100
Safe: Yes
No address-specific findings.
```

When the address is on a denylist:

```
Address: 0xdead000000000000000000000000000000000001
Transaction Risk Score: 90/100
Safe: No
Findings:
  [CRITICAL] DENYLISTED_ADDRESS: Address is on the known-malicious denylist
```

### wardex_get_status

Returns the current state of the Wardex security system. No inputs required.

**Example response:**

```
Wardex Security Status
Mode: adaptive
Frozen: No
Evaluations: 42
Blocked: 3
Advisories: 7
Daily Volume: 250000000000000000 wei
Signer Healthy: Yes
Intelligence Updated: 2025-01-15T10:30:00Z
```

If the system is frozen (emergency halt):

```
Wardex Security Status
Mode: adaptive
Frozen: YES - EMERGENCY
Evaluations: 43
Blocked: 4
...
```

### wardex_filter_output

Scans text for private keys, seed phrases, mnemonic words, and keystore data. Returns the text with sensitive content replaced by `[REDACTED BY WARDEX]`.

**Input schema:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `text` | `string` | Yes | Text to filter for sensitive data |

**Example call and response:**

```
Tool: wardex_filter_output
Input: {
  "text": "Your new wallet address is 0xabc123... with private key 0x4c0883a69102937d6231471b5dbb6204fe512961..."
}
```

```
Your new wallet address is 0xabc123... with private key [REDACTED BY WARDEX]

[Wardex] 1 sensitive item(s) redacted:
  - private_key
```

---

## Step 3: Configuration

The MCP server reads configuration from environment variables. Set them before launching, or pass them through Claude Code's MCP configuration.

| Variable | Default | Description |
|----------|---------|-------------|
| `WARDEX_MODE` | `adaptive` | Security mode: `guardian`, `copilot`, or `adaptive` |
| `WARDEX_SIGNER_SOCKET` | `/tmp/wardex-signer.sock` | Unix socket path for the isolated signer process |
| `WARDEX_TRANSPORT` | `stdio` | Transport protocol: `stdio` or `http` |
| `WARDEX_PORT` | `3100` | HTTP port (only used when transport is `http`) |

**Modes explained:**

| Mode | Behavior |
|------|----------|
| `adaptive` | Security tier scales with transaction value (Audit / Co-pilot / Guardian / Fortress) |
| `guardian` | All transactions evaluated at Guardian level (blocks at composite score > 70) |
| `copilot` | Advisory-only mode -- warns but never blocks (except critical threats) |

To pass environment variables through Claude Code:

```bash
claude mcp add wardex -e WARDEX_MODE=guardian npx @wardexai/mcp-server
```

---

## Step 4: HTTP Transport for Remote Agents

By default the MCP server uses stdio (standard input/output), which works when the server runs as a child process of Claude Code. For remote agents, multi-client setups, or non-Claude runtimes, switch to HTTP transport.

### Start the HTTP server

```bash
npx @wardexai/mcp-server --transport http --port 3100
```

Expected output:

```
[wardex] MCP server ready (HTTP transport on port 3100)
[wardex] MCP endpoint: http://localhost:3100/mcp
[wardex] Health check: http://localhost:3100/health
```

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/mcp` | POST | MCP protocol endpoint (Streamable HTTP / SSE) |
| `/` | POST | Alias for `/mcp` |
| `/health` | GET | Health check -- returns JSON status |

### Health check

```bash
curl http://localhost:3100/health
```

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

### Connect a remote MCP client

Any MCP-compatible client can connect to the HTTP endpoint. For Claude Code connecting to a remote Wardex server:

```bash
claude mcp add wardex --transport http http://your-server:3100/mcp
```

### Environment variable alternative

You can also configure HTTP transport via environment variables instead of CLI flags:

```bash
export WARDEX_TRANSPORT=http
export WARDEX_PORT=3100
npx @wardexai/mcp-server
```

---

## Architecture

```
Claude Code (or any MCP client)
    |
    |  MCP protocol (stdio or HTTP)
    v
@wardexai/mcp-server
    |
    |  createWardex()
    v
@wardexai/core  ──>  9-stage middleware pipeline
    |                  contextAnalyzer
    |                  transactionDecoder
    |                  valueAssessor
    |                  addressChecker
    |                  contractChecker
    |                  behavioralComparator
    |                  [custom middleware]
    |                  riskAggregator
    v                  policyEngine
SecurityVerdict { decision, riskScore, reasons, suggestions }
```

---

## What's Next?

- **Auto-interception**: Add the [Claude Code Skill](./claude-skill.md) so every wallet tool call is evaluated automatically via PreToolUse hooks, without Claude needing to call Wardex tools explicitly.
- **On-chain enforcement**: Use the [Delegation Framework](./delegation-framework.md) to add blockchain-level backstops that hold even if the SDK is bypassed.
- **Direct SDK usage**: See the [Operator Quickstart](../operator-quickstart.md) to wire Wardex into your own TypeScript code with `createWardex()`.
