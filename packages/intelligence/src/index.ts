/**
 * @wardexai/intelligence
 *
 * Threat intelligence for Wardex.
 * On-chain monitoring, address reputation, contract analysis.
 *
 * v1: Local denylist, on-chain address age/activity, contract verification,
 *     bytecode analysis (selfdestruct, delegatecall, proxy, honeypot)
 * v2: Community threat feeds, privacy-preserving sharing
 */

export { createIntelligenceProvider, type IntelligenceProvider, type IntelligenceProviderConfig } from './provider.js';
export { loadDenylist, saveDenylist, createDenylistEntry, type DenylistEntry } from './denylist.js';
export { analyzeContractBytecode, type BytecodeAnalysis } from './contract-analyzer.js';
export type { AddressReputation, ContractAnalysis, ContractPattern } from './types.js';
