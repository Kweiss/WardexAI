/**
 * ethers.js v6 Provider Wrapper
 *
 * Wraps an ethers.js v6 Provider/Signer so all transactions pass through
 * the Wardex evaluation pipeline before reaching the network.
 *
 * Usage:
 *   import { createWardex, wrapEthersProvider } from '@wardexai/core';
 *   const wardex = createWardex({ ... });
 *   const protectedSigner = wrapEthersProvider(signer, wardex);
 *   await protectedSigner.sendTransaction({ to, value }); // evaluated by Wardex
 */

import type { WardexShield, TransactionRequest, SecurityVerdict } from '../types.js';

/**
 * Minimal ethers.js v6 Signer interface.
 * We use a structural type rather than importing ethers directly,
 * so this module works whether or not ethers is installed.
 */
interface EthersSigner {
  getAddress(): Promise<string>;
  sendTransaction(tx: EthersTransactionRequest): Promise<EthersTransactionResponse>;
  provider?: EthersProvider | null;
}

interface EthersProvider {
  getNetwork(): Promise<{ chainId: bigint }>;
}

interface EthersTransactionRequest {
  to?: string | null;
  value?: bigint | string | number;
  data?: string;
  gasLimit?: bigint | string | number;
  maxFeePerGas?: bigint | string | number;
  maxPriorityFeePerGas?: bigint | string | number;
  nonce?: number;
  chainId?: bigint | number;
}

interface EthersTransactionResponse {
  hash: string;
  wait(confirmations?: number): Promise<unknown>;
}

export class WardexBlockedError extends Error {
  public readonly verdict: SecurityVerdict;
  constructor(verdict: SecurityVerdict) {
    const reasons = verdict.reasons.map((r) => `[${r.severity}] ${r.code}: ${r.message}`).join('; ');
    super(`Wardex blocked transaction: ${reasons}`);
    this.name = 'WardexBlockedError';
    this.verdict = verdict;
  }
}

/**
 * Wraps an ethers.js v6 Signer so that all sendTransaction calls
 * are evaluated by Wardex before execution.
 *
 * - If verdict is 'approve': transaction proceeds normally
 * - If verdict is 'advise': transaction proceeds, advisory is logged
 * - If verdict is 'block' or 'freeze': throws WardexBlockedError
 *
 * @param signer - An ethers.js v6 AbstractSigner
 * @param shield - A WardexShield instance
 * @returns A proxied signer with Wardex protection
 */
export function wrapEthersSigner<T extends EthersSigner>(
  signer: T,
  shield: WardexShield,
): T {
  return new Proxy(signer, {
    get(target, prop, receiver) {
      if (prop === 'sendTransaction') {
        return async (tx: EthersTransactionRequest): Promise<EthersTransactionResponse> => {
          // Convert ethers tx format to Wardex format
          let chainId = 1;
          if (tx.chainId) {
            chainId = typeof tx.chainId === 'bigint' ? Number(tx.chainId) : tx.chainId;
          } else if (target.provider) {
            try {
              const network = await target.provider.getNetwork();
              chainId = Number(network.chainId);
            } catch {
              // Default to 1 if we can't get the chain ID
            }
          }

          const wardexTx: TransactionRequest = {
            to: tx.to ?? '',
            value: tx.value !== undefined ? BigInt(tx.value).toString() : '0',
            data: tx.data,
            chainId,
            gasLimit: tx.gasLimit !== undefined ? BigInt(tx.gasLimit).toString() : undefined,
            maxFeePerGas: tx.maxFeePerGas !== undefined ? BigInt(tx.maxFeePerGas).toString() : undefined,
            maxPriorityFeePerGas: tx.maxPriorityFeePerGas !== undefined ? BigInt(tx.maxPriorityFeePerGas).toString() : undefined,
            nonce: tx.nonce,
          };

          // Evaluate
          const verdict = await shield.evaluate(wardexTx);

          if (verdict.decision === 'block' || verdict.decision === 'freeze') {
            throw new WardexBlockedError(verdict);
          }

          // Proceed with original send
          return target.sendTransaction(tx);
        };
      }

      return Reflect.get(target, prop, receiver);
    },
  });
}
