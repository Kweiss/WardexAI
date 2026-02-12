#!/usr/bin/env node
/**
 * Wardex PreToolUse Hook Script
 *
 * This script is invoked by Claude Code's PreToolUse hook system whenever
 * a wallet-related MCP tool is called. It:
 *
 * 1. Reads the hook input from stdin (tool_name, tool_input, etc.)
 * 2. Extracts transaction parameters from the tool input
 * 3. Evaluates the transaction using Wardex core
 * 4. Returns a hook decision: allow, deny, or ask
 *
 * Configuration:
 *   WARDEX_MODE=guardian|copilot|adaptive (default: adaptive)
 *   WARDEX_SIGNER_SOCKET=/tmp/wardex-signer.sock (default)
 *
 * Exit codes:
 *   0 = success (stdout JSON is processed)
 *   2 = block (stderr message fed back to Claude)
 */

import { createReadStream } from 'node:fs';

// Read all stdin into a string
async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * Extracts transaction parameters from various tool input formats.
 * Different MCP servers may structure their tool inputs differently.
 */
function extractTransaction(toolName, toolInput) {
  // Direct transaction fields
  if (toolInput.to) {
    return {
      to: toolInput.to,
      value: toolInput.value ?? toolInput.amount ?? '0',
      data: toolInput.data ?? toolInput.calldata ?? undefined,
      chainId: toolInput.chainId ?? toolInput.chain_id ?? 1,
      gasLimit: toolInput.gasLimit ?? toolInput.gas_limit ?? undefined,
      maxFeePerGas: toolInput.maxFeePerGas ?? toolInput.max_fee_per_gas ?? undefined,
    };
  }

  // Nested under a transaction field
  if (toolInput.transaction) {
    return extractTransaction(toolName, toolInput.transaction);
  }

  // For approve-type calls
  if (toolInput.spender || toolInput.operator) {
    return {
      to: toolInput.contract ?? toolInput.token ?? toolInput.address,
      value: '0',
      data: undefined, // Will be reconstructed by Wardex if needed
      chainId: toolInput.chainId ?? 1,
    };
  }

  // For send/transfer calls
  if (toolInput.recipient || toolInput.destination) {
    return {
      to: toolInput.recipient ?? toolInput.destination,
      value: toolInput.value ?? toolInput.amount ?? '0',
      chainId: toolInput.chainId ?? 1,
    };
  }

  return null;
}

/**
 * Formats a Wardex verdict into a human-readable string for Claude.
 */
function formatVerdictMessage(verdict) {
  const lines = [];

  const status =
    verdict.decision === 'approve' ? '✅ SAFE' :
    verdict.decision === 'advise' ? '⚠️ WARNING' :
    verdict.decision === 'block' ? '🛑 BLOCKED' :
    '🔒 FROZEN';

  lines.push(`[Wardex] ${status}`);

  if (verdict.riskScore) {
    lines.push(`Risk: context=${verdict.riskScore.context}/100, tx=${verdict.riskScore.transaction}/100, behavioral=${verdict.riskScore.behavioral}/100 → composite=${verdict.riskScore.composite}/100`);
  }

  if (verdict.reasons?.length > 0) {
    lines.push('Findings:');
    for (const r of verdict.reasons) {
      lines.push(`  [${r.severity.toUpperCase()}] ${r.code}: ${r.message}`);
    }
  }

  if (verdict.suggestions?.length > 0) {
    lines.push('Suggestions:');
    for (const s of verdict.suggestions) {
      lines.push(`  - ${s}`);
    }
  }

  return lines.join('\n');
}

async function main() {
  let input;
  try {
    const raw = await readStdin();
    input = JSON.parse(raw);
  } catch (err) {
    // M-06 FIX: Default to 'ask' instead of silent allow on parse errors.
    // A broken hook should prompt the user, not silently approve transactions.
    process.stderr.write(`[Wardex] Hook input parse error: ${err?.message ?? 'unknown'}\n`);
    const output = {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'ask',
        permissionDecisionReason: '[Wardex] Security hook could not parse input. Manual review required before proceeding.',
      },
    };
    process.stdout.write(JSON.stringify(output));
    process.exit(0);
  }

  const { tool_name, tool_input } = input;

  // Extract transaction parameters
  const tx = extractTransaction(tool_name, tool_input ?? {});

  if (!tx) {
    // Can't extract transaction info - allow and let the tool handle it
    // Add context so Claude knows Wardex couldn't evaluate
    const output = {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'ask',
        permissionDecisionReason: '[Wardex] Could not extract transaction parameters for security evaluation. Proceed with caution.',
        additionalContext: 'Wardex could not parse this tool call as a transaction. Manual review recommended.',
      },
    };
    process.stdout.write(JSON.stringify(output));
    process.exit(0);
  }

  // Evaluate using Wardex core (inline, no IPC needed for evaluation)
  try {
    // Dynamic import of @wardex/core
    const { createWardex, defaultPolicy } = await import('@wardex/core');

    const wardex = createWardex({
      policy: defaultPolicy(),
      signer: {
        type: 'isolated-process',
        endpoint: process.env.WARDEX_SIGNER_SOCKET ?? '/tmp/wardex-signer.sock',
      },
      mode: process.env.WARDEX_MODE ?? 'adaptive',
    });

    const verdict = await wardex.evaluate(tx);
    const message = formatVerdictMessage(verdict);

    if (verdict.decision === 'block' || verdict.decision === 'freeze') {
      // BLOCK: Deny the tool call
      const output = {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason: message,
        },
      };
      process.stdout.write(JSON.stringify(output));
      process.exit(0);
    }

    if (verdict.decision === 'advise') {
      // ADVISORY: Ask the user for confirmation with context
      const output = {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'ask',
          permissionDecisionReason: message,
          additionalContext: `Wardex detected potential risks. Risk scores: context=${verdict.riskScore.context}, transaction=${verdict.riskScore.transaction}, behavioral=${verdict.riskScore.behavioral}, composite=${verdict.riskScore.composite}. User should review before proceeding.`,
        },
      };
      process.stdout.write(JSON.stringify(output));
      process.exit(0);
    }

    // APPROVED: Allow the tool call
    const output = {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'allow',
        permissionDecisionReason: message,
      },
    };
    process.stdout.write(JSON.stringify(output));
    process.exit(0);
  } catch (err) {
    // If Wardex evaluation fails, don't block the tool call
    // but add context that evaluation was not performed
    process.stderr.write(`[Wardex] Evaluation error: ${err.message}\n`);
    const output = {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'ask',
        permissionDecisionReason: `[Wardex] Security evaluation failed: ${err.message}. Manual review required.`,
      },
    };
    process.stdout.write(JSON.stringify(output));
    process.exit(0);
  }
}

main();
