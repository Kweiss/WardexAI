/**
 * Wardex Session Keys + DeFi Example
 *
 * Demonstrates setting up a scoped DeFi trading session where:
 * 1. Agent gets a session key limited to specific protocols
 * 2. Every transaction is validated by BOTH Wardex and session limits
 * 3. Session auto-rotates before expiry
 * 4. Attacks are caught by both layers (defense in depth)
 */

import { createWardex, defaultPolicy } from '@wardexai/core';
import { SessionManager } from '@wardexai/signer';

const UNISWAP_ROUTER = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
const AAVE_POOL = '0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2';
const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';

async function main() {
  // 1. Create Wardex shield with DeFi-tuned policy
  const policy = defaultPolicy();
  policy.allowlists.contracts.push(UNISWAP_ROUTER, AAVE_POOL, USDC);
  policy.behavioral.enabled = true;
  policy.behavioral.sensitivityLevel = 'high';

  const wardex = createWardex({
    policy,
    signer: { type: 'isolated-process', endpoint: '/tmp/defi-agent.sock' },
    mode: 'adaptive',
    onBlock: (e) => console.log(`[BLOCKED] ${e.verdict.reasons[0]?.message}`),
    onFreeze: (e) => console.log(`[FREEZE] ${e.reason}`),
  });

  // 2. Create a scoped trading session
  const sessions = new SessionManager();
  const session = sessions.createSession({
    allowedContracts: [UNISWAP_ROUTER, AAVE_POOL, USDC],
    maxValuePerTx: '2000000000000000000',    // 2 ETH per trade
    maxDailyVolume: '20000000000000000000',   // 20 ETH daily cap
    durationSeconds: 3600,                     // 1-hour session
    forbidInfiniteApprovals: true,
  });
  console.log(`Session created: ${session.id}`);
  console.log(`  Allowed: ${session.config.allowedContracts.join(', ')}`);
  console.log(`  Expires: ${session.expiresAt}`);

  // 3. Execute a swap — double-validated
  const swapTx = {
    to: UNISWAP_ROUTER,
    value: '500000000000000000', // 0.5 ETH
    data: '0x5ae401dc', // multicall selector
    chainId: 1,
  };

  // Layer 1: Wardex risk evaluation
  const verdict = await wardex.evaluate(swapTx);
  console.log(`\nWardex verdict: ${verdict.decision} (score: ${verdict.riskScore.composite})`);

  // Layer 2: Session key validation
  const sessionCheck = sessions.validateTransaction(
    session.id,
    swapTx.to,
    swapTx.value!,
    swapTx.data,
  );
  console.log(`Session check: ${sessionCheck.valid ? 'PASS' : 'FAIL'}`);

  if (verdict.decision === 'approve' && sessionCheck.valid) {
    // Both layers approve — safe to sign
    sessions.recordTransaction(session.id, swapTx.value!, swapTx.to);
    console.log('Transaction would be signed and sent.');
  }

  // 4. Session state tracking
  const state = sessions.getSessionState(session.id);
  console.log(`\nSession state:`);
  console.log(`  Transactions: ${state!.transactionCount}`);
  console.log(`  Daily volume: ${state!.dailyVolumeWei} wei`);

  // 5. Detect near-expiry sessions and rotate
  const expiring = sessions.getExpiringSessionsSoon(3600);
  if (expiring.length > 0) {
    for (const s of expiring) {
      const rotated = sessions.rotateSession(s.id);
      console.log(`\nRotated session ${s.id} → ${rotated!.id}`);
    }
  }

  // 6. Attack simulation — both layers catch it
  console.log('\n--- Attack Simulation ---');
  const attackTx = {
    to: '0xdead000000000000000000000000000000000001',
    value: '5000000000000000000',
    chainId: 1,
  };

  const attackVerdict = await wardex.evaluate(attackTx);
  const attackSession = sessions.validateTransaction(
    session.id,
    attackTx.to,
    attackTx.value!,
  );

  console.log(`Wardex: ${attackVerdict.decision}`);
  console.log(`Session: ${attackSession.valid ? 'PASS' : `FAIL (${attackSession.reason})`}`);

  // 7. System status
  const status = wardex.getStatus();
  console.log(`\nStatus: ${status.evaluationCount} evals, ${status.blockCount} blocks`);
}

main().catch(console.error);
