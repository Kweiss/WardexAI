/**
 * viem Wallet Client Wrapper
 *
 * Wraps a viem WalletClient so all transactions pass through
 * the Wardex evaluation pipeline before reaching the network.
 *
 * Usage:
 *   import { createWardex, wrapViemWalletClient } from '@wardexai/core';
 *   const wardex = createWardex({ ... });
 *   const protectedClient = wrapViemWalletClient(walletClient, wardex);
 *   await protectedClient.sendTransaction({ to, value }); // evaluated by Wardex
 */

import type { WardexShield, TransactionRequest, SecurityVerdict } from '../types.js';
import { WardexBlockedError } from './ethers.js';

/**
 * Minimal viem WalletClient interface.
 * Structural typing avoids hard dependency on viem.
 */
interface ViemWalletClient {
  sendTransaction(args: ViemSendTransactionParameters): Promise<string>;
  chain?: { id: number } | undefined;
  account?: { address: string } | undefined;
}

interface ViemSendTransactionParameters {
  to?: string;
  value?: bigint;
  data?: string;
  gas?: bigint;
  maxFeePerGas?: bigint;
  maxPriorityFeePerGas?: bigint;
  nonce?: number;
  chain?: { id: number } | null;
}

/**
 * Wraps a viem WalletClient so that all sendTransaction calls
 * are evaluated by Wardex before execution.
 *
 * - If verdict is 'approve': transaction proceeds normally
 * - If verdict is 'advise': transaction proceeds, advisory is logged
 * - If verdict is 'block' or 'freeze': throws WardexBlockedError
 *
 * @param client - A viem WalletClient
 * @param shield - A WardexShield instance
 * @returns A proxied wallet client with Wardex protection
 */
export function wrapViemWalletClient<T extends ViemWalletClient>(
  client: T,
  shield: WardexShield,
): T {
  return new Proxy(client, {
    get(target, prop, receiver) {
      if (prop === 'sendTransaction') {
        return async (args: ViemSendTransactionParameters): Promise<string> => {
          const chainId = args.chain?.id ?? target.chain?.id ?? 1;

          const wardexTx: TransactionRequest = {
            to: args.to ?? '',
            value: args.value !== undefined ? args.value.toString() : '0',
            data: args.data,
            chainId,
            gasLimit: args.gas !== undefined ? args.gas.toString() : undefined,
            maxFeePerGas: args.maxFeePerGas !== undefined ? args.maxFeePerGas.toString() : undefined,
            maxPriorityFeePerGas: args.maxPriorityFeePerGas !== undefined ? args.maxPriorityFeePerGas.toString() : undefined,
            nonce: args.nonce,
          };

          const verdict = await shield.evaluate(wardexTx);

          if (verdict.decision === 'block' || verdict.decision === 'freeze') {
            throw new WardexBlockedError(verdict);
          }

          return target.sendTransaction(args);
        };
      }

      return Reflect.get(target, prop, receiver);
    },
  });
}
