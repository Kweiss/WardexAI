# Deploy the WardexValidationModule

The `WardexValidationModule` is a Solidity smart contract that provides on-chain defense-in-depth for AI agent wallets. It enforces spending limits, evaluator signature verification, and emergency freeze at the blockchain level -- even if the entire off-chain SDK is bypassed.

This guide walks through deploying the module to any EVM chain, initializing it, and configuring spending limits.

> **Why on-chain enforcement?** The TypeScript SDK catches attacks before transactions reach the chain. But if an attacker bypasses the SDK entirely, the on-chain module is the last line of defense. It cannot be circumvented without control of the smart account itself.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| [Foundry](https://book.getfoundry.sh/) | `forge` CLI for Solidity compilation and deployment |
| Deployer private key | An account with ETH for gas on your target chain |
| RPC endpoint | For your target chain (e.g., Base Sepolia, Ethereum mainnet) |
| Etherscan API key | Optional, for contract verification |

---

## Step 1: Install Foundry (if needed)

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

---

## Step 2: Build the Contract

```bash
cd packages/contracts
forge build
```

Expected output:

```
[...] Compiling...
[...] Compiler run successful!
```

---

## Step 3: Deploy

### Testnet (Base Sepolia)

```bash
forge script script/Deploy.s.sol \
  --rpc-url $BASE_SEPOLIA_RPC \
  --private-key $DEPLOYER_PK \
  --broadcast \
  --verify \
  --etherscan-api-key $ETHERSCAN_KEY
```

### Dry Run (simulation, no broadcast)

```bash
forge script script/Deploy.s.sol --rpc-url $RPC_URL
```

### Mainnet

```bash
forge script script/Deploy.s.sol \
  --rpc-url $ETH_RPC \
  --private-key $DEPLOYER_PK \
  --broadcast \
  --verify \
  --etherscan-api-key $ETHERSCAN_KEY \
  --slow
```

> **Tip**: Use `--slow` on mainnet to avoid nonce issues with multiple deployments.

### Expected Output

```
========================================
WardexValidationModule deployed at: 0x1234...abcd
Chain ID: 84532
========================================

Next steps:
  1. From your smart account, call:
     module.initialize(evaluatorAddress, ethMaxPerTx, ethMaxPerDay)
  2. Set token-specific limits with:
     module.setSpendingLimit(tokenAddress, maxPerTx, maxPerDay)
  3. Install the module on your ERC-4337 account
```

---

## Step 4: Initialize

After deployment, the module must be initialized from your smart account. This sets the evaluator address and ETH spending limits.

```typescript
// Using ethers.js
const module = new ethers.Contract(moduleAddress, WardexValidationModuleABI, signer);

await module.initialize(
  evaluatorAddress,        // Wardex evaluator (signs approval tokens)
  ethers.parseEther('1'),  // Max 1 ETH per transaction
  ethers.parseEther('10'), // Max 10 ETH per day
);
```

| Parameter | Type | Description |
|---|---|---|
| `evaluator` | `address` | Address authorized to sign Wardex approval tokens |
| `ethMaxPerTx` | `uint256` | Maximum ETH per single transaction (wei) |
| `ethMaxPerDay` | `uint256` | Maximum cumulative ETH per day (wei) |

> **Important**: `initialize()` can only be called once per account. The evaluator can be updated later with `setEvaluator()`.

---

## Step 5: Set Token Spending Limits

Add per-token limits for ERC-20 tokens your agent will interact with:

```typescript
// USDC limits: 1,000 per tx, 10,000 per day
const usdc = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
await module.setSpendingLimit(usdc, 1000e6, 10000e6);

// WETH limits: 2 per tx, 20 per day
const weth = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2';
await module.setSpendingLimit(weth, ethers.parseEther('2'), ethers.parseEther('20'));
```

| Parameter | Type | Description |
|---|---|---|
| `token` | `address` | Token contract address (`address(0)` for ETH) |
| `maxPerTx` | `uint256` | Maximum per transaction (in token's smallest unit) |
| `maxPerDay` | `uint256` | Maximum per day (in token's smallest unit) |

Daily limits reset automatically at midnight (based on `block.timestamp / 1 days`).

---

## Step 6: Verify Deployment

Run the verification script to exercise all module functions:

```bash
MODULE_ADDRESS=0x1234...abcd \
EVALUATOR=0xYourEvaluatorAddress \
forge script script/Verify.s.sol \
  --rpc-url $BASE_SEPOLIA_RPC \
  --private-key $DEPLOYER_PK \
  --broadcast \
  -vvvv
```

The verification script tests:

1. Initialization with evaluator and limits
2. Spending limit enforcement (within and exceeding limits)
3. Token-specific limit configuration
4. Freeze and unfreeze cycle
5. Evaluator address update

Expected output:

```
--- Step 1: Initialize ---
  Initialized with evaluator: 0x1111...1111
--- Step 2: Spending Limits ---
  0.5 ETH within limits: true
  2 ETH exceeds per-tx: true
--- Step 3: Token Limits ---
  USDC limits set and verified
--- Step 4: Freeze/Unfreeze ---
  Frozen: true
  Unfrozen: true
--- Step 5: Evaluator Update ---
  Evaluator updated to: 0x2222...2222

========================================
All verification checks PASSED
========================================
```

---

## Contract API Reference

### Core Functions

| Function | Access | Description |
|---|---|---|
| `initialize(evaluator, ethMaxPerTx, ethMaxPerDay)` | Anyone (once) | Set up Wardex protection for the calling account |
| `validateUserOp(userOp, userOpHash, missingFunds)` | EntryPoint | ERC-4337 validation hook |
| `setSpendingLimit(token, maxPerTx, maxPerDay)` | Account only | Set per-token spending limits |
| `checkSpendingLimit(account, token, amount)` | View | Check if amount is within limits |

### Emergency Controls

| Function | Access | Description |
|---|---|---|
| `freeze()` | Account only | Freeze the account -- blocks ALL transactions |
| `unfreeze()` | Account only | Resume normal operation |
| `setEvaluator(newEvaluator)` | Account only | Update the evaluator address |

### View Functions

| Function | Returns | Description |
|---|---|---|
| `isInitialized(account)` | `bool` | Whether the account has Wardex protection |
| `isFrozen(account)` | `bool` | Whether the account is emergency-frozen |
| `getEvaluator(account)` | `address` | The evaluator address for the account |

### Events

| Event | Emitted When |
|---|---|
| `EvaluatorUpdated(account, evaluator)` | Evaluator is set or updated |
| `SpendingLimitSet(account, token, maxPerTx, maxPerDay)` | Spending limits are configured |
| `AccountFrozen(account)` | Account is frozen |
| `AccountUnfrozen(account)` | Account is unfrozen |
| `TransactionApproved(account, userOpHash)` | UserOp passes validation |
| `TransactionBlocked(account, userOpHash, reason)` | UserOp is rejected |

---

## How Validation Works

When an ERC-4337 EntryPoint calls `validateUserOp`:

1. **Freeze check**: If the account is frozen, the transaction is rejected immediately
2. **Signature verification**: The module extracts the ECDSA signature from the UserOp and verifies it was signed by the account's evaluator address (EIP-191 prefixed hash)
3. **Spending limits**: The transaction value is checked against per-transaction and daily limits

If all checks pass, the module returns `0` (valid). Otherwise it returns `1` (invalid) and emits a `TransactionBlocked` event.

```
ERC-4337 EntryPoint
    |
    | validateUserOp()
    v
WardexValidationModule
    |
    +-- Is account frozen? → Reject
    |
    +-- Is evaluator signature valid? → Reject if not
    |
    +-- Within spending limits? → Reject if exceeded
    |
    v
Return 0 (approved)
```

---

## Compatible Smart Accounts

The `WardexValidationModule` follows the ERC-4337 module pattern and is compatible with:

| Account | Compatibility |
|---|---|
| Safe (w/ 4337 module) | Install as a validation module |
| Kernel | Add as a validator |
| Biconomy | Register as a module |
| Any ERC-4337 account | Standard `validateUserOp` interface |

---

## Phase 3 Compatibility Matrix

For production readiness, execute the ERC-4337 compatibility matrix across real account implementations:

- Matrix tracker: `packages/contracts/compatibility/erc4337-matrix.md`
- Config template: `packages/contracts/compatibility/erc4337-matrix.config.template.json`
- Execution runbook: `packages/contracts/compatibility/erc4337-matrix-runbook.md`

This matrix verifies `validateUserOp` behavior for:
- Generic `execute(address,uint256,bytes)` paths
- Safe 4337 module paths
- Kernel account paths

and records caller/auth/value-extraction outcomes for go/no-go decisions.

---

## What's Next?

- **[Delegation Framework](./delegation-framework.md)** -- Add MetaMask delegation for fine-grained on-chain enforcement
- **[Session Keys](./session-keys.md)** -- Scoped off-chain permissions with ERC-7715
- **[Security Tiers](../security/security-tiers.md)** -- How the SDK decides enforcement level
- **[Threat Model](../security/threat-model.md)** -- What the module defends against
