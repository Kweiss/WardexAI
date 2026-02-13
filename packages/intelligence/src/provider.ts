/**
 * Intelligence Provider
 *
 * Provides threat intelligence to the Wardex evaluation pipeline.
 * Fetches address reputation via JSON-RPC, analyzes contract bytecode,
 * and manages the local denylist.
 */

import type { AddressReputation, ContractAnalysis, ContractPattern } from './types.js';
import { loadDenylist, type DenylistEntry } from './denylist.js';
import { analyzeContractBytecode } from './contract-analyzer.js';

export interface IntelligenceProviderConfig {
  /** RPC endpoint for on-chain queries */
  rpcUrl: string;
  /** Chain ID */
  chainId: number;
  /** Path to local denylist file */
  denylistPath?: string;
  /** Block explorer API key (e.g., Etherscan) */
  explorerApiKey?: string;
  /** Block explorer API base URL */
  explorerApiUrl?: string;
  /** Timeout for RPC/explorer requests in milliseconds (default: 5000) */
  requestTimeoutMs?: number;
}

export interface IntelligenceProvider {
  /** Get reputation data for an address */
  getAddressReputation(address: string): Promise<AddressReputation>;
  /** Get contract analysis for a contract address */
  getContractAnalysis(address: string): Promise<ContractAnalysis>;
  /** Check if an address is on the denylist */
  isDenylisted(address: string): boolean;
  /** Refresh intelligence data */
  refresh(): Promise<void>;
}

const DEFAULT_REQUEST_TIMEOUT_MS = 5000;

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number
): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Makes a JSON-RPC call to an Ethereum node.
 */
async function rpcCall(
  rpcUrl: string,
  method: string,
  params: unknown[],
  timeoutMs: number
): Promise<unknown> {
  const response = await fetchWithTimeout(rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method,
      params,
    }),
  }, timeoutMs);

  if (!response.ok) {
    throw new Error(`RPC request failed: ${response.status}`);
  }

  const data = await response.json() as { result?: unknown; error?: { message: string } };
  if (data.error) {
    throw new Error(`RPC error: ${data.error.message}`);
  }

  return data.result;
}

/**
 * Queries the Etherscan-compatible API for contract verification status.
 */
async function checkContractVerification(
  address: string,
  apiUrl: string,
  apiKey: string,
  timeoutMs: number
): Promise<{ isVerified: boolean; contractName?: string }> {
  try {
    const url = `${apiUrl}?module=contract&action=getabi&address=${address}&apikey=${apiKey}`;
    const response = await fetchWithTimeout(url, { method: 'GET' }, timeoutMs);
    const data = await response.json() as { status: string; result: string };

    if (data.status === '1' && data.result !== 'Contract source code not verified') {
      return { isVerified: true };
    }
    return { isVerified: false };
  } catch {
    return { isVerified: false };
  }
}

/**
 * Queries an Etherscan-compatible txlist endpoint and estimates address age in days.
 * Returns undefined if unavailable.
 */
async function getAddressAgeDays(
  address: string,
  apiUrl: string,
  apiKey: string,
  timeoutMs: number,
  nowMs?: number
): Promise<number | undefined> {
  try {
    const url =
      `${apiUrl}?module=account&action=txlist&address=${address}` +
      `&startblock=0&endblock=99999999&page=1&offset=1&sort=asc&apikey=${apiKey}`;
    const response = await fetchWithTimeout(url, { method: 'GET' }, timeoutMs);
    const data = await response.json() as {
      status?: string;
      result?: Array<{ timeStamp?: string }> | string;
    };

    if (data.status !== '1' || !Array.isArray(data.result) || data.result.length === 0) {
      return undefined;
    }

    const tsRaw = data.result[0]?.timeStamp;
    if (!tsRaw) return undefined;
    const firstSeenSec = Number(tsRaw);
    if (!Number.isFinite(firstSeenSec) || firstSeenSec <= 0) return undefined;

    const now = nowMs ?? Date.now();
    const deltaSec = Math.max(0, Math.floor(now / 1000) - firstSeenSec);
    return Math.floor(deltaSec / 86400);
  } catch {
    return undefined;
  }
}

export function createIntelligenceProvider(
  config: IntelligenceProviderConfig
): IntelligenceProvider {
  let denylist: Map<string, DenylistEntry> = new Map();

  // Caches to avoid repeated RPC calls
  const reputationCache = new Map<string, { data: AddressReputation; expiry: number }>();
  const contractCache = new Map<string, { data: ContractAnalysis; expiry: number }>();
  const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
  const MAX_CACHE_ENTRIES = 5000;
  const requestTimeoutMs = config.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;

  function pruneCache<T>(cache: Map<string, { data: T; expiry: number }>): void {
    const now = Date.now();

    // First remove expired entries.
    for (const [key, entry] of cache.entries()) {
      if (entry.expiry <= now) {
        cache.delete(key);
      }
    }

    // If still too large, drop oldest inserted entries.
    while (cache.size > MAX_CACHE_ENTRIES) {
      const oldestKey = cache.keys().next().value as string | undefined;
      if (!oldestKey) break;
      cache.delete(oldestKey);
    }
  }

  // Load initial denylist
  if (config.denylistPath) {
    const entries = loadDenylist(config.denylistPath);
    for (const entry of entries) {
      denylist.set(entry.address.toLowerCase(), entry);
    }
  }

  return {
    async getAddressReputation(address: string): Promise<AddressReputation> {
      const normalized = address.toLowerCase();

      // Check cache
      const cached = reputationCache.get(normalized);
      if (cached && cached.expiry > Date.now()) {
        return cached.data;
      }

      const denyEntry = denylist.get(normalized);

      const reputation: AddressReputation = {
        address: normalized,
        score: denyEntry ? 0 : 50,
        isDenylisted: !!denyEntry,
        isAllowlisted: false,
        ageDays: 0,
        transactionCount: 0,
        labels: [],
        riskFactors: denyEntry ? [denyEntry.reason] : [],
      };

      // Fetch on-chain data via RPC
      try {
        // Get transaction count (nonce) - indicates how active the address is
        const txCountHex = await rpcCall(
          config.rpcUrl,
          'eth_getTransactionCount',
          [normalized, 'latest'],
          requestTimeoutMs
        ) as string;
        reputation.transactionCount = parseInt(txCountHex, 16);

        // Get code at address to determine if it's a contract
        const code = await rpcCall(
          config.rpcUrl,
          'eth_getCode',
          [normalized, 'latest'],
          requestTimeoutMs
        ) as string;
        const isContract = code !== '0x' && code !== '0x0';

        // Get balance
        const balanceHex = await rpcCall(
          config.rpcUrl,
          'eth_getBalance',
          [normalized, 'latest'],
          requestTimeoutMs
        ) as string;
        const balanceWei = BigInt(balanceHex);
        void balanceWei;

        if (config.explorerApiKey && config.explorerApiUrl) {
          const ageDays = await getAddressAgeDays(
            normalized,
            config.explorerApiUrl,
            config.explorerApiKey,
            requestTimeoutMs
          );
          if (typeof ageDays === 'number') {
            reputation.ageDays = ageDays;
          }
        }

        // Adjust reputation score based on on-chain data
        if (reputation.transactionCount > 100) {
          reputation.score += 15; // Well-established address
        } else if (reputation.transactionCount > 10) {
          reputation.score += 5;
        } else if (reputation.transactionCount === 0) {
          reputation.riskFactors.push('Address has zero transaction history');
          reputation.score -= 20;
        }

        if (reputation.ageDays > 365) {
          reputation.score += 10;
        } else if (reputation.ageDays > 0 && reputation.ageDays < 7) {
          reputation.riskFactors.push(`Address is only ${reputation.ageDays} day(s) old`);
          reputation.score -= 10;
        }

        if (isContract) {
          reputation.labels.push('contract');
          // Check verification status if we have an explorer API key
          if (config.explorerApiKey && config.explorerApiUrl) {
            const verification = await checkContractVerification(
              normalized,
              config.explorerApiUrl,
              config.explorerApiKey,
              requestTimeoutMs
            );
            reputation.isVerified = verification.isVerified;
            if (verification.isVerified) {
              reputation.score += 10;
              reputation.labels.push('verified');
            } else {
              reputation.riskFactors.push('Contract code is not verified on block explorer');
              reputation.score -= 10;
            }
          }
        }

        // Clamp score to 0-100
        reputation.score = Math.max(0, Math.min(100, reputation.score));
      } catch {
        // RPC unavailable - note but use denylist data
        reputation.riskFactors.push('Could not fetch on-chain data - RPC unavailable');
      }

      // Cache the result
      reputationCache.set(normalized, {
        data: reputation,
        expiry: Date.now() + CACHE_TTL_MS,
      });
      pruneCache(reputationCache);

      return reputation;
    },

    async getContractAnalysis(address: string): Promise<ContractAnalysis> {
      const normalized = address.toLowerCase();

      // Check cache
      const cached = contractCache.get(normalized);
      if (cached && cached.expiry > Date.now()) {
        return cached.data;
      }

      const analysis: ContractAnalysis = {
        address: normalized,
        isVerified: false,
        isProxy: false,
        dangerousPatterns: [],
        allowsInfiniteApproval: false,
        hasSelfDestruct: false,
        hasUnsafeDelegatecall: false,
        risk: 'medium',
      };

      try {
        // Fetch bytecode
        const code = await rpcCall(
          config.rpcUrl,
          'eth_getCode',
          [normalized, 'latest'],
          requestTimeoutMs
        ) as string;

        if (code === '0x' || code === '0x0') {
          // Not a contract (EOA)
          analysis.risk = 'safe';
          return analysis;
        }

        // Analyze bytecode for dangerous patterns
        const bytecodeAnalysis = analyzeContractBytecode(code);
        analysis.hasSelfDestruct = bytecodeAnalysis.hasSelfDestruct;
        analysis.hasUnsafeDelegatecall = bytecodeAnalysis.hasDelegatecall;
        analysis.isProxy = bytecodeAnalysis.isProxy;
        analysis.implementationAddress = bytecodeAnalysis.implementationAddress;
        analysis.dangerousPatterns = bytecodeAnalysis.patterns;

        // Check for approve function with unlimited amount capability
        // (presence of approve selector + no amount cap in bytecode)
        analysis.allowsInfiniteApproval = bytecodeAnalysis.hasApproveFunction;

        // Check verification status
        if (config.explorerApiKey && config.explorerApiUrl) {
          const verification = await checkContractVerification(
            normalized,
            config.explorerApiUrl,
            config.explorerApiKey,
            requestTimeoutMs
          );
          analysis.isVerified = verification.isVerified;
        }

        // Determine overall risk
        if (analysis.hasSelfDestruct) {
          analysis.risk = 'critical';
        } else if (analysis.hasUnsafeDelegatecall && !analysis.isVerified) {
          analysis.risk = 'high';
        } else if (analysis.isProxy && !analysis.isVerified) {
          analysis.risk = 'high';
        } else if (!analysis.isVerified) {
          analysis.risk = 'medium';
        } else if (analysis.dangerousPatterns.length > 0) {
          analysis.risk = 'medium';
        } else {
          analysis.risk = 'low';
        }
      } catch {
        analysis.risk = 'medium'; // Can't analyze - default to medium
      }

      // Cache the result
      contractCache.set(normalized, {
        data: analysis,
        expiry: Date.now() + CACHE_TTL_MS,
      });
      pruneCache(contractCache);

      return analysis;
    },

    isDenylisted(address: string): boolean {
      return denylist.has(address.toLowerCase());
    },

    async refresh(): Promise<void> {
      if (config.denylistPath) {
        const entries = loadDenylist(config.denylistPath);
        const newDenylist = new Map<string, DenylistEntry>();
        for (const entry of entries) {
          newDenylist.set(entry.address.toLowerCase(), entry);
        }
        denylist = newDenylist;
      }

      // Clear caches on refresh
      reputationCache.clear();
      contractCache.clear();
    },
  };
}
