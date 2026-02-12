/**
 * Test Scenario: Contract Bytecode Analysis
 *
 * Verifies that the intelligence layer correctly identifies dangerous
 * patterns in EVM bytecode without requiring source code.
 */

import { describe, it, expect } from 'vitest';
import { analyzeContractBytecode } from '@wardexai/intelligence';

describe('Contract Bytecode Analysis', () => {
  it('should detect SELFDESTRUCT opcode', () => {
    // Bytecode containing the FF (SELFDESTRUCT) opcode
    const bytecodeWithSelfDestruct = '0x6080604052ff';
    const analysis = analyzeContractBytecode(bytecodeWithSelfDestruct);

    expect(analysis.hasSelfDestruct).toBe(true);
    expect(analysis.patterns.some((p) => p.name === 'SELFDESTRUCT')).toBe(true);
    expect(analysis.patterns.find((p) => p.name === 'SELFDESTRUCT')?.severity).toBe('critical');
  });

  it('should detect DELEGATECALL opcode (non-proxy)', () => {
    // Bytecode with DELEGATECALL (F4) but not matching standard proxy patterns
    const bytecodeWithDelegatecall = '0x60806040526004f4';
    const analysis = analyzeContractBytecode(bytecodeWithDelegatecall);

    expect(analysis.hasDelegatecall).toBe(true);
    expect(analysis.patterns.some((p) => p.name === 'DELEGATECALL')).toBe(true);
  });

  it('should detect deprecated CALLCODE opcode', () => {
    // Bytecode with CALLCODE (F2)
    const bytecodeWithCallcode = '0x6080604052f2';
    const analysis = analyzeContractBytecode(bytecodeWithCallcode);

    expect(analysis.hasCallcode).toBe(true);
    expect(analysis.patterns.some((p) => p.name === 'CALLCODE')).toBe(true);
  });

  it('should detect EIP-1167 minimal proxy', () => {
    // EIP-1167 minimal proxy for implementation at 0xbebebebebebebebebebebebebebebebebebebebe
    const minimalProxy =
      '0x363d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebebe5af43d82803e903d91602b57fd5bf3';
    const analysis = analyzeContractBytecode(minimalProxy);

    expect(analysis.isProxy).toBe(true);
    expect(analysis.implementationAddress).toBe('0xbebebebebebebebebebebebebebebebebebebebe');
  });

  it('should detect EIP-1967 proxy pattern', () => {
    // Bytecode containing the EIP-1967 implementation storage slot
    const eip1967Proxy =
      '0x6080604052360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc54';
    const analysis = analyzeContractBytecode(eip1967Proxy);

    expect(analysis.isProxy).toBe(true);
    expect(analysis.patterns.some((p) => p.name === 'EIP_1967_PROXY')).toBe(true);
  });

  it('should detect approve function selector', () => {
    // Bytecode containing the approve(address,uint256) selector
    const tokenBytecode =
      '0x6080604052600436106100095763095ea7b314610021576100095b';
    const analysis = analyzeContractBytecode(tokenBytecode);

    expect(analysis.hasApproveFunction).toBe(true);
  });

  it('should flag suspiciously small token contracts', () => {
    // Very small bytecode that has both transfer and approve selectors
    // This is suspicious - real token contracts are much larger
    const suspiciousToken = '0x095ea7b3a9059cbb';
    const analysis = analyzeContractBytecode(suspiciousToken);

    expect(analysis.patterns.some((p) => p.name === 'SUSPICIOUS_TOKEN_SIZE')).toBe(true);
  });

  it('should handle empty or minimal bytecode', () => {
    expect(analyzeContractBytecode('0x').hasSelfDestruct).toBe(false);
    expect(analyzeContractBytecode('').hasSelfDestruct).toBe(false);
    expect(analyzeContractBytecode('0x00').hasSelfDestruct).toBe(false);
  });

  it('should detect factory capability (CREATE/CREATE2)', () => {
    // Bytecode with CREATE2 (F5)
    const factoryBytecode = '0x60806040526004f5';
    const analysis = analyzeContractBytecode(factoryBytecode);

    expect(analysis.hasFactoryCapability).toBe(true);
  });

  it('should not flag standard proxy DELEGATECALL', () => {
    // EIP-1967 proxy with DELEGATECALL - the DELEGATECALL is expected
    const standardProxy =
      '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbcf4';
    const analysis = analyzeContractBytecode(standardProxy);

    expect(analysis.hasDelegatecall).toBe(true);
    expect(analysis.isProxy).toBe(true);
    // DELEGATECALL should NOT be flagged as dangerous in a standard proxy
    expect(analysis.patterns.some((p) => p.name === 'DELEGATECALL')).toBe(false);
  });
});
