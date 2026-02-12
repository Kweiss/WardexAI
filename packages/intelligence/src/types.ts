/**
 * Re-export types used by the intelligence package.
 * These mirror the types from @wardexai/core to avoid a circular dependency.
 */

export interface AddressReputation {
  address: string;
  score: number;
  isDenylisted: boolean;
  isAllowlisted: boolean;
  ageDays: number;
  transactionCount: number;
  labels: string[];
  isVerified?: boolean;
  riskFactors: string[];
}

export interface ContractAnalysis {
  address: string;
  isVerified: boolean;
  isProxy: boolean;
  implementationAddress?: string;
  dangerousPatterns: ContractPattern[];
  allowsInfiniteApproval: boolean;
  hasSelfDestruct: boolean;
  hasUnsafeDelegatecall: boolean;
  risk: 'safe' | 'low' | 'medium' | 'high' | 'critical';
}

export interface ContractPattern {
  name: string;
  pattern: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
}
