import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { createIntelligenceProvider } from './provider.js';

const ADDRESS = '0x1234567890abcdef1234567890abcdef12345678';
const RPC_URL = 'https://rpc.example';
const API_URL = 'https://api.etherscan.io/api';

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('createIntelligenceProvider - address age', () => {
  const realFetch = globalThis.fetch;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-02-13T00:00:00.000Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
    globalThis.fetch = realFetch;
  });

  it('should populate ageDays from explorer txlist when configured', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === RPC_URL && init?.method === 'POST') {
        const payload = JSON.parse(String(init.body)) as { method: string };
        if (payload.method === 'eth_getTransactionCount') {
          return jsonResponse({ jsonrpc: '2.0', id: 1, result: '0x2a' });
        }
        if (payload.method === 'eth_getCode') {
          return jsonResponse({ jsonrpc: '2.0', id: 1, result: '0x' });
        }
        if (payload.method === 'eth_getBalance') {
          return jsonResponse({ jsonrpc: '2.0', id: 1, result: '0x0' });
        }
      }

      if (url.includes('module=account') && url.includes('action=txlist')) {
        // First tx at 2026-02-02T00:00:00Z -> age = 11 days
        return jsonResponse({
          status: '1',
          result: [{ timeStamp: '1769980800' }],
        });
      }

      throw new Error(`Unexpected fetch: ${url}`);
    });

    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const intel = createIntelligenceProvider({
      rpcUrl: RPC_URL,
      chainId: 1,
      explorerApiKey: 'test-key',
      explorerApiUrl: API_URL,
    });

    const reputation = await intel.getAddressReputation(ADDRESS);

    expect(reputation.ageDays).toBe(11);
    expect(reputation.transactionCount).toBe(42);
  });

  it('should keep ageDays at 0 when explorer does not return txlist data', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === RPC_URL && init?.method === 'POST') {
        const payload = JSON.parse(String(init.body)) as { method: string };
        if (payload.method === 'eth_getTransactionCount') {
          return jsonResponse({ jsonrpc: '2.0', id: 1, result: '0x1' });
        }
        if (payload.method === 'eth_getCode') {
          return jsonResponse({ jsonrpc: '2.0', id: 1, result: '0x' });
        }
        if (payload.method === 'eth_getBalance') {
          return jsonResponse({ jsonrpc: '2.0', id: 1, result: '0x0' });
        }
      }

      if (url.includes('module=account') && url.includes('action=txlist')) {
        return jsonResponse({ status: '0', result: 'No transactions found' });
      }

      throw new Error(`Unexpected fetch: ${url}`);
    });

    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const intel = createIntelligenceProvider({
      rpcUrl: RPC_URL,
      chainId: 1,
      explorerApiKey: 'test-key',
      explorerApiUrl: API_URL,
    });

    const reputation = await intel.getAddressReputation(ADDRESS);

    expect(reputation.ageDays).toBe(0);
  });
});
