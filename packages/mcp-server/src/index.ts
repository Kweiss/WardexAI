#!/usr/bin/env node
/**
 * @wardexai/mcp-server
 *
 * MCP server that exposes Wardex wallet security tools to
 * Claude Code and other MCP-compatible AI agent frameworks.
 *
 * Usage (stdio - default, for Claude Code):
 *   claude mcp add wardex npx @wardexai/mcp-server
 *
 * Usage (HTTP - for remote agents / multi-client):
 *   npx @wardexai/mcp-server --transport http --port 3100
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { createServer as createHttpServer } from 'node:http';
import { createWardex, defaultPolicy } from '@wardexai/core';
import type {
  WardexShield,
  TransactionRequest,
  SecurityVerdict,
} from '@wardexai/core';

// ---------------------------------------------------------------------------
// Shield initialization
// ---------------------------------------------------------------------------

function initShield(): WardexShield {
  return createWardex({
    policy: defaultPolicy(),
    signer: {
      type: 'isolated-process',
      endpoint: process.env.WARDEX_SIGNER_SOCKET ?? '/tmp/wardex-signer.sock',
    },
    mode: (process.env.WARDEX_MODE as 'guardian' | 'copilot' | 'adaptive') ?? 'adaptive',
  });
}

// ---------------------------------------------------------------------------
// Tool definitions (JSON Schema format for MCP)
// ---------------------------------------------------------------------------

const TOOLS = [
  {
    name: 'wardex_evaluate_transaction',
    description:
      'Evaluate a transaction for security threats before signing. ' +
      'Checks for prompt injection, malicious contracts, infinite approvals, ' +
      'denylisted addresses, and behavioral anomalies. Returns a security verdict ' +
      'with risk scores and a decision (approve/advise/block/freeze).',
    inputSchema: {
      type: 'object' as const,
      properties: {
        to: { type: 'string', description: 'Target address (0x-prefixed)' },
        value: { type: 'string', description: 'Value in wei (as string)' },
        data: { type: 'string', description: 'Encoded calldata (0x-prefixed hex)' },
        chainId: { type: 'number', description: 'Chain ID (1=Ethereum, 8453=Base)' },
        gasLimit: { type: 'string', description: 'Gas limit' },
        maxFeePerGas: { type: 'string', description: 'Max fee per gas (wei)' },
      },
      required: ['to'],
    },
  },
  {
    name: 'wardex_check_address',
    description:
      'Check the reputation and safety of an Ethereum address. ' +
      'Returns whether the address is on known denylists, its reputation score, ' +
      'and any risk factors.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        address: { type: 'string', description: 'Ethereum address to check (0x-prefixed)' },
        chainId: { type: 'number', description: 'Chain ID' },
      },
      required: ['address'],
    },
  },
  {
    name: 'wardex_get_status',
    description:
      'Get the current Wardex security status including ' +
      'evaluation count, block count, daily volume, and freeze status.',
    inputSchema: {
      type: 'object' as const,
      properties: {},
    },
  },
  {
    name: 'wardex_filter_output',
    description:
      'Filter text to remove any private keys, seed phrases, or ' +
      'other sensitive wallet data that should never be exposed.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        text: { type: 'string', description: 'Text to filter for sensitive data' },
      },
      required: ['text'],
    },
  },
];

// ---------------------------------------------------------------------------
// Verdict formatting
// ---------------------------------------------------------------------------

function formatVerdict(verdict: SecurityVerdict): string {
  const status =
    verdict.decision === 'approve' ? 'SAFE' :
    verdict.decision === 'advise' ? 'WARNING' :
    verdict.decision === 'block' ? 'BLOCKED' :
    'FROZEN';

  const lines: string[] = [
    `Status: ${status}`,
    `Decision: ${verdict.decision}`,
    `Tier: ${verdict.tierId}`,
    `Risk Scores:`,
    `  Context: ${verdict.riskScore.context}/100`,
    `  Transaction: ${verdict.riskScore.transaction}/100`,
    `  Behavioral: ${verdict.riskScore.behavioral}/100`,
    `  Composite: ${verdict.riskScore.composite}/100`,
  ];

  if (verdict.reasons.length > 0) {
    lines.push('Findings:');
    for (const r of verdict.reasons) {
      lines.push(`  [${r.severity.toUpperCase()}] ${r.code}: ${r.message}`);
    }
  }

  if (verdict.suggestions.length > 0) {
    lines.push('Suggestions:');
    for (const s of verdict.suggestions) {
      lines.push(`  - ${s}`);
    }
  }

  if (verdict.requiredAction && verdict.requiredAction !== 'none') {
    lines.push(`Required Action: ${verdict.requiredAction}`);
  }

  lines.push(`Evaluation ID: ${verdict.evaluationId}`);
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Tool handler dispatch
// ---------------------------------------------------------------------------

async function handleToolCall(
  shield: WardexShield,
  toolName: string,
  args: Record<string, unknown>,
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  switch (toolName) {
    case 'wardex_evaluate_transaction': {
      const tx: TransactionRequest = {
        to: args.to as string,
        value: (args.value as string) ?? '0',
        data: args.data as string | undefined,
        chainId: (args.chainId as number) ?? 1,
        gasLimit: args.gasLimit as string | undefined,
        maxFeePerGas: args.maxFeePerGas as string | undefined,
      };
      const verdict = await shield.evaluate(tx);
      return { content: [{ type: 'text', text: formatVerdict(verdict) }] };
    }

    case 'wardex_check_address': {
      const tx: TransactionRequest = {
        to: args.address as string,
        value: '0',
        chainId: (args.chainId as number) ?? 1,
      };
      const verdict = await shield.evaluate(tx);
      const addressReasons = verdict.reasons.filter((r) => r.source === 'address');

      const lines: string[] = [
        `Address: ${args.address}`,
        `Transaction Risk Score: ${verdict.riskScore.transaction}/100`,
        `Safe: ${verdict.riskScore.transaction < 30 ? 'Yes' : 'No'}`,
      ];
      if (addressReasons.length > 0) {
        lines.push('Findings:');
        for (const r of addressReasons) {
          lines.push(`  [${r.severity.toUpperCase()}] ${r.code}: ${r.message}`);
        }
      } else {
        lines.push('No address-specific findings.');
      }
      return { content: [{ type: 'text', text: lines.join('\n') }] };
    }

    case 'wardex_get_status': {
      const status = shield.getStatus();
      const lines: string[] = [
        `Wardex Security Status`,
        `Mode: ${status.mode}`,
        `Frozen: ${status.frozen ? 'YES - EMERGENCY' : 'No'}`,
        `Evaluations: ${status.evaluationCount}`,
        `Blocked: ${status.blockCount}`,
        `Advisories: ${status.advisoryCount}`,
        `Daily Volume: ${status.dailyVolumeWei} wei`,
        `Signer Healthy: ${status.signerHealthy ? 'Yes' : 'No'}`,
      ];
      if (status.intelligenceLastUpdated) {
        lines.push(`Intelligence Updated: ${status.intelligenceLastUpdated}`);
      }
      return { content: [{ type: 'text', text: lines.join('\n') }] };
    }

    case 'wardex_filter_output': {
      const result = shield.outputFilter.filterText(args.text as string);
      const lines: string[] = [result.filtered];
      if (result.redactions.length > 0) {
        lines.push('');
        lines.push(`[Wardex] ${result.redactions.length} sensitive item(s) redacted:`);
        for (const r of result.redactions) {
          lines.push(`  - ${r.type}`);
        }
      }
      if (result.blocked) {
        lines.push('[Wardex] Output BLOCKED - too much sensitive data detected');
      }
      return { content: [{ type: 'text', text: lines.join('\n') }] };
    }

    default:
      throw new Error(`Unknown tool: ${toolName}`);
  }
}

// ---------------------------------------------------------------------------
// Server factory (shared between transports)
// ---------------------------------------------------------------------------

function createMCPServer(shield: WardexShield): Server {
  const server = new Server(
    { name: 'wardex', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    return handleToolCall(shield, name, args ?? {});
  });

  return server;
}

// ---------------------------------------------------------------------------
// Transport: stdio
// ---------------------------------------------------------------------------

async function startStdio(shield: WardexShield): Promise<void> {
  const server = createMCPServer(shield);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('[wardex] MCP server ready (stdio transport)');
}

// ---------------------------------------------------------------------------
// Transport: HTTP (Streamable HTTP / SSE)
// ---------------------------------------------------------------------------

async function startHttp(shield: WardexShield, port: number): Promise<void> {
  const server = createMCPServer(shield);

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => crypto.randomUUID(),
  });

  await server.connect(transport);

  const httpServer = createHttpServer(async (req, res) => {
    // Health check endpoint
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', ...shield.getStatus() }));
      return;
    }

    // MCP endpoint
    if (req.url === '/mcp' || req.url === '/') {
      await transport.handleRequest(req, res);
      return;
    }

    res.writeHead(404);
    res.end('Not Found');
  });

  httpServer.listen(port, () => {
    console.error(`[wardex] MCP server ready (HTTP transport on port ${port})`);
    console.error(`[wardex] MCP endpoint: http://localhost:${port}/mcp`);
    console.error(`[wardex] Health check: http://localhost:${port}/health`);
  });
}

// ---------------------------------------------------------------------------
// CLI argument parsing & main
// ---------------------------------------------------------------------------

function parseArgs(): { transport: 'stdio' | 'http'; port: number } {
  const args = process.argv.slice(2);
  let transport: 'stdio' | 'http' = 'stdio';
  let port = 3100;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--transport' && args[i + 1]) {
      const value = args[i + 1];
      if (value === 'http' || value === 'stdio') {
        transport = value;
      }
      i++;
    } else if (args[i] === '--port' && args[i + 1]) {
      port = parseInt(args[i + 1], 10);
      i++;
    }
  }

  // Also respect environment variables
  if (process.env.WARDEX_TRANSPORT === 'http') transport = 'http';
  if (process.env.WARDEX_PORT) port = parseInt(process.env.WARDEX_PORT, 10);

  return { transport, port };
}

async function main(): Promise<void> {
  const shield = initShield();
  const { transport, port } = parseArgs();

  if (transport === 'http') {
    await startHttp(shield, port);
  } else {
    await startStdio(shield);
  }
}

main().catch((err) => {
  console.error('[wardex] Fatal error:', err);
  process.exit(1);
});
