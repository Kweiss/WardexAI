# Claude Code Skill

The Wardex Claude Code skill adds automatic security evaluation to every wallet-related tool call. When installed, a PreToolUse hook intercepts MCP tool calls that involve signing, sending, or approving crypto transactions, runs them through the Wardex security pipeline, and decides whether to allow, deny, or prompt the user -- all before the tool executes.

No changes to your agent code. No explicit `wardex_evaluate_transaction` calls. The skill sits between Claude and your wallet MCP server and acts as a transparent security layer.

---

## Step 1: Install the Skill

Install the package and copy the skill and hook configuration into your project:

```bash
npm install @wardexai/claude-skill
```

Then set up the skill directory and hooks:

```bash
# Copy the skill definition (SKILL.md, commands, hooks)
cp -r node_modules/@wardexai/claude-skill/.claude/skills/wardex .claude/skills/

# Copy the hook configuration
cp node_modules/@wardexai/claude-skill/hooks/pre-transaction.json .claude/hooks/
```

Alternatively, merge the hook configuration directly into your existing `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "mcp__wallet__.*|mcp__crypto__.*|mcp__defi__.*|mcp__eth__send.*|mcp__eth__sign.*|mcp__eth__approve.*|mcp__ethers__.*|mcp__viem__.*",
        "hooks": [
          {
            "type": "command",
            "command": "node node_modules/@wardexai/claude-skill/hooks/evaluate-transaction.mjs",
            "timeout": 15,
            "statusMessage": "Wardex: Evaluating transaction security..."
          }
        ]
      }
    ]
  }
}
```

---

## Step 2: How PreToolUse Hooks Work

Claude Code's hook system lets you run custom scripts before or after specific tool calls. Wardex uses `PreToolUse` hooks -- scripts that execute *before* a tool call happens and can allow, deny, or escalate it.

### The interception flow

```
Claude decides to call mcp__wallet__send_transaction
    |
    v
PreToolUse hook fires (matcher matches tool name)
    |
    v
evaluate-transaction.mjs runs
    |
    |  1. Reads tool_name + tool_input from stdin
    |  2. Extracts transaction parameters (to, value, data, chainId)
    |  3. Creates a Wardex instance and runs evaluate()
    |  4. Maps the verdict to a hook decision
    |
    v
Hook decision returned to Claude Code
    |
    +-- allow  -->  Tool call proceeds normally
    +-- deny   -->  Tool call is blocked, Claude sees the reason
    +-- ask    -->  User is prompted to review risks before proceeding
```

### Supported tool patterns

The hook matcher uses a regex pattern to intercept wallet-related MCP tool calls. These patterns cover the most common wallet MCP server naming conventions:

| Pattern | Matches |
|---------|---------|
| `mcp__wallet__*` | Generic wallet servers (send, sign, balance, etc.) |
| `mcp__crypto__*` | Crypto-focused MCP tools |
| `mcp__defi__*` | DeFi protocol interaction tools |
| `mcp__eth__send*` | Ethereum send operations |
| `mcp__eth__sign*` | Ethereum signing operations |
| `mcp__eth__approve*` | Token approval operations |
| `mcp__ethers__*` | ethers.js-based MCP servers |
| `mcp__viem__*` | viem-based MCP servers |

The full matcher regex:

```
mcp__wallet__.*|mcp__crypto__.*|mcp__defi__.*|mcp__eth__send.*|mcp__eth__sign.*|mcp__eth__approve.*|mcp__ethers__.*|mcp__viem__.*
```

If your wallet MCP server uses a different naming convention, edit the `matcher` field in your hook configuration.

### Transaction extraction

The hook script extracts transaction parameters from various tool input formats. It handles:

- **Direct fields**: `{ to, value, data, chainId }`
- **Nested transaction**: `{ transaction: { to, value, ... } }`
- **Approve calls**: `{ spender, contract, ... }` or `{ operator, token, ... }`
- **Transfer calls**: `{ recipient, value, ... }` or `{ destination, amount, ... }`

If the script cannot extract transaction parameters, it returns an `ask` decision so the user can manually review the call.

---

## Step 3: Slash Commands

The skill registers four slash commands that you can invoke directly in a Claude Code conversation:

### /wardex-evaluate

Evaluate a transaction for security threats. Claude will ask you for:

- Target address (`to`)
- Value in ETH (converted to wei internally)
- Calldata (optional, for contract interactions)
- Chain ID (defaults to 1)

Then it calls `wardex_evaluate_transaction` and presents the verdict with risk scores, findings, and suggestions.

```
> /wardex-evaluate

Target address: 0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45
Value in ETH: 0.5
Chain ID: 1

[Wardex] SAFE
Decision: approve
Risk: context=0/100, tx=5/100, behavioral=0/100, composite=3/100
```

### /wardex-check

Check whether an Ethereum address is safe to interact with. Returns the address risk score, denylist status, and a clear recommendation.

```
> /wardex-check

Address: 0xdead000000000000000000000000000000000001

[Wardex] Address: 0xdead000000000000000000000000000000000001
Transaction Risk Score: 90/100
Safe: No
Findings:
  [CRITICAL] DENYLISTED_ADDRESS: Address is on the known-malicious denylist
Recommendation: Avoid interacting with this address.
```

### /wardex-status

Display the current Wardex security system status: enforcement mode, freeze state, evaluation and block counts, daily volume, signer health.

```
> /wardex-status

Wardex Security Status
Mode: adaptive
Frozen: No
Evaluations: 42
Blocked: 3
Advisories: 7
Daily Volume: 250000000000000000 wei
Signer Healthy: Yes
```

### /wardex-freeze

Emergency freeze all wallet operations. Claude will explain what a freeze does, ask for confirmation, and display the current freeze status. To unfreeze, the operator must call `wardex.unfreeze()` through the SDK or restart the service.

```
> /wardex-freeze

This will halt ALL wallet operations until manually unfrozen.
Are you sure you want to freeze all wallet operations? (yes/no)
```

---

## How the Hook Makes Decisions

The hook maps Wardex security verdicts to Claude Code hook decisions:

| Wardex Verdict | Hook Decision | What Happens |
|----------------|---------------|--------------|
| `approve` | `allow` | Tool call proceeds automatically. Claude sees the safety confirmation. |
| `advise` | `ask` | Claude pauses and shows the user all risk findings and scores. The user must explicitly confirm to proceed. |
| `block` | `deny` | Tool call is rejected. Claude sees the block reason and suggestions. The transaction never executes. |
| `freeze` | `deny` | Tool call is rejected. All subsequent wallet operations are also denied until the operator unfreezes. |

**Failure mode**: If the Wardex evaluation itself throws an error (missing dependency, socket timeout, etc.), the hook returns `ask` with the error message. It never silently blocks or silently allows on evaluation failure.

---

## When to Use Each Integration

Wardex offers three integration paths. Choose based on your setup:

| Integration | Best For | How It Works |
|-------------|----------|--------------|
| **Claude Code Skill** (this guide) | Claude Code users who want zero-config protection | PreToolUse hooks intercept wallet tool calls automatically |
| **MCP Server** | Any MCP-compatible agent runtime, or when you want on-demand tool access | Claude (or another agent) explicitly calls `wardex_evaluate_transaction` |
| **Direct SDK** | Custom TypeScript agents, server-side applications | Import `@wardexai/core` and call `wardex.evaluate()` in your own code |

You can combine them. A common pattern is to use both the skill (automatic interception) and the MCP server (explicit evaluation when Claude needs it):

```bash
# Add the MCP server for explicit tool access
claude mcp add wardex npx @wardexai/mcp-server

# Install the skill for automatic interception
npm install @wardexai/claude-skill
cp -r node_modules/@wardexai/claude-skill/.claude/skills/wardex .claude/skills/
```

With both installed, every wallet tool call is automatically screened by the hook, and Claude can also call Wardex tools directly for pre-screening addresses or filtering output.

---

## Configuration

The hook script reads the same environment variables as the MCP server:

| Variable | Default | Description |
|----------|---------|-------------|
| `WARDEX_MODE` | `adaptive` | Security mode: `guardian`, `copilot`, or `adaptive` |
| `WARDEX_SIGNER_SOCKET` | `/tmp/wardex-signer.sock` | Unix socket path for the isolated signer process |

The hook has a 15-second timeout. If evaluation takes longer than 15 seconds, Claude Code skips the hook and lets the tool call proceed.

---

## What's Next?

- **MCP Server**: Set up the [MCP Server](./mcp-server.md) to give Claude explicit access to Wardex tools alongside the automatic hook interception.
- **On-chain enforcement**: Use the [Delegation Framework](./delegation-framework.md) to add blockchain-level backstops.
- **Customize policies**: See the [Operator Quickstart](../operator-quickstart.md) to adjust security tiers, denylists, and transaction limits.
