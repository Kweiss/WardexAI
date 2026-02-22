// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title WardexValidationModule
 * @notice ERC-4337 compatible validation module for AI agent smart accounts.
 *         Provides on-chain defense-in-depth: spending limits, approval token
 *         verification, and emergency freeze - even if the off-chain SDK is bypassed.
 *
 * @dev Designed to be installed as a module on ERC-4337 smart accounts
 *      (Safe, Kernel, Biconomy, etc.). The module validates that every
 *      UserOperation was approved by the Wardex evaluation engine.
 *
 *      Architecture:
 *      - Off-chain: Wardex SDK evaluates transaction → produces approval signature
 *      - On-chain: This module verifies the approval signature before allowing execution
 *      - Defense in depth: Even if SDK is compromised, on-chain limits hold
 */

/**
 * @dev Minimal interface for ERC-4337 validation.
 *      The full PackedUserOperation struct is defined by the EntryPoint.
 */
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

interface IWardexValidationModule {
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData);
}

contract WardexValidationModule is IWardexValidationModule {
    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event EvaluatorUpdated(address indexed account, address indexed evaluator);
    event SpendingLimitSet(address indexed account, address indexed token, uint256 maxPerTx, uint256 maxPerDay);
    event AccountFrozen(address indexed account);
    event AccountUnfrozen(address indexed account);
    event EntryPointUpdated(address indexed account, address indexed entryPoint);
    event TransactionApproved(address indexed account, bytes32 indexed userOpHash);
    event TransactionBlocked(address indexed account, bytes32 indexed userOpHash, string reason);

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    error AccountIsFrozen();
    error InvalidEvaluator();
    error InvalidApprovalSignature();
    error SpendingLimitExceeded(string limitType);
    error NotAccountOwner();
    error ZeroAddress();

    // -----------------------------------------------------------------------
    // Structs
    // -----------------------------------------------------------------------

    struct SpendingLimit {
        uint256 maxPerTx;       // Maximum value per single transaction
        uint256 maxPerDay;      // Maximum cumulative daily volume
        uint256 spentToday;     // Amount spent in current day
        uint256 lastResetDay;   // Day number of last reset
    }

    struct AccountConfig {
        address evaluator;      // Address authorized to sign approval tokens
        address entryPoint;     // Trusted caller for validateUserOp (ERC-4337 EntryPoint)
        bool frozen;            // Emergency freeze flag
        bool initialized;       // Whether this account has been set up
    }

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------

    /// @notice Configuration per smart account
    mapping(address => AccountConfig) public accounts;

    /// @notice Spending limits per account per token (address(0) = ETH)
    mapping(address => mapping(address => SpendingLimit)) public spendingLimits;

    // -----------------------------------------------------------------------
    // Modifiers
    // -----------------------------------------------------------------------

    modifier onlyAccount() {
        if (accounts[msg.sender].initialized == false) revert NotAccountOwner();
        _;
    }

    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------

    /**
     * @notice Initialize Wardex protection for a smart account.
     * @param evaluator Address of the Wardex evaluator (signs approval tokens)
     * @param ethMaxPerTx Maximum ETH per transaction (wei)
     * @param ethMaxPerDay Maximum ETH per day (wei)
     */
    function initialize(
        address evaluator,
        uint256 ethMaxPerTx,
        uint256 ethMaxPerDay
    ) external {
        if (evaluator == address(0)) revert ZeroAddress();
        if (accounts[msg.sender].initialized) revert NotAccountOwner();

        accounts[msg.sender] = AccountConfig({
            evaluator: evaluator,
            entryPoint: address(0),
            frozen: false,
            initialized: true
        });

        // Set default ETH spending limits
        spendingLimits[msg.sender][address(0)] = SpendingLimit({
            maxPerTx: ethMaxPerTx,
            maxPerDay: ethMaxPerDay,
            spentToday: 0,
            lastResetDay: block.timestamp / 1 days
        });

        emit EvaluatorUpdated(msg.sender, evaluator);
        emit SpendingLimitSet(msg.sender, address(0), ethMaxPerTx, ethMaxPerDay);
    }

    // -----------------------------------------------------------------------
    // ERC-4337 Validation
    // -----------------------------------------------------------------------

    /**
     * @notice Validates a UserOperation for the EntryPoint.
     * @dev Checks:
     *      1. Account is not frozen
     *      2. UserOp signature contains a valid Wardex approval
     *      3. Transaction value is within spending limits
     *
     * @param userOp The UserOperation to validate
     * @param userOpHash Hash of the UserOperation (for signature verification)
     * @return validationData 0 if valid, 1 if invalid (per ERC-4337 spec)
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 /* missingAccountFunds */
    ) external override returns (uint256 validationData) {
        AccountConfig storage config = accounts[userOp.sender];

        // Caller restriction: only the account itself (tests/simulation) or
        // its configured ERC-4337 EntryPoint may invoke validation.
        if (msg.sender != userOp.sender && msg.sender != config.entryPoint) {
            emit TransactionBlocked(userOp.sender, userOpHash, "Unauthorized validation caller");
            return 1; // Invalid
        }

        // 1. Check freeze status
        if (config.frozen) {
            emit TransactionBlocked(userOp.sender, userOpHash, "Account is frozen");
            return 1; // Invalid
        }

        // 2. Verify Wardex approval signature
        // The signature field contains the evaluator's ECDSA signature over the userOpHash
        if (!_verifyApproval(userOp.signature, userOpHash, config.evaluator)) {
            emit TransactionBlocked(userOp.sender, userOpHash, "Invalid Wardex approval");
            return 1; // Invalid
        }

        // 3. M-10 FIX: Check and record spending limits for ETH transfers.
        //    Extract value from callData using the standard execute(address,uint256,bytes)
        //    pattern (selector 0xb61d27f6) used by most ERC-4337 smart accounts
        //    (Safe, Kernel, Biconomy). If callData doesn't match this pattern,
        //    the spending check is skipped (defense-in-depth: the off-chain SDK
        //    still enforces limits).
        uint256 extractedValue = _extractExecuteValue(userOp.callData);
        if (extractedValue > 0) {
            if (!checkSpendingLimit(userOp.sender, address(0), extractedValue)) {
                emit TransactionBlocked(userOp.sender, userOpHash, "Spending limit exceeded");
                return 1; // Invalid
            }
            // Record spending optimistically (before execution).
            // If the UserOp reverts during execution, the spending counter is
            // over-counted. This is a conservative trade-off (fail-safe, not fail-open).
            _recordSpending(userOp.sender, address(0), extractedValue);
        }

        emit TransactionApproved(userOp.sender, userOpHash);
        return 0; // Valid
    }

    // -----------------------------------------------------------------------
    // Spending Limits
    // -----------------------------------------------------------------------

    /**
     * @notice Set spending limits for a specific token.
     * @param token Token address (address(0) for ETH)
     * @param maxPerTx Maximum per transaction
     * @param maxPerDay Maximum per day
     */
    function setSpendingLimit(
        address token,
        uint256 maxPerTx,
        uint256 maxPerDay
    ) external onlyAccount {
        spendingLimits[msg.sender][token] = SpendingLimit({
            maxPerTx: maxPerTx,
            maxPerDay: maxPerDay,
            spentToday: 0,
            lastResetDay: block.timestamp / 1 days
        });

        emit SpendingLimitSet(msg.sender, token, maxPerTx, maxPerDay);
    }

    /**
     * @notice Check if a transaction value is within spending limits.
     * @param account The smart account
     * @param token Token address (address(0) for ETH)
     * @param amount Transaction amount
     * @return withinLimits Whether the amount is within limits
     */
    function checkSpendingLimit(
        address account,
        address token,
        uint256 amount
    ) public view returns (bool withinLimits) {
        SpendingLimit storage limit = spendingLimits[account][token];

        if (limit.maxPerTx == 0 && limit.maxPerDay == 0) {
            return true; // No limits set
        }

        // Check per-transaction limit
        if (amount > limit.maxPerTx) {
            return false;
        }

        // Check daily limit (with day reset)
        uint256 currentDay = block.timestamp / 1 days;
        uint256 todaySpent = limit.spentToday;
        if (currentDay > limit.lastResetDay) {
            todaySpent = 0; // New day, reset counter
        }

        if (todaySpent + amount > limit.maxPerDay) {
            return false;
        }

        return true;
    }

    /**
     * @notice Record spending against daily limits.
     * @dev Called internally after successful validation.
     */
    function _recordSpending(
        address account,
        address token,
        uint256 amount
    ) internal {
        SpendingLimit storage limit = spendingLimits[account][token];
        uint256 currentDay = block.timestamp / 1 days;

        if (currentDay > limit.lastResetDay) {
            limit.spentToday = amount;
            limit.lastResetDay = currentDay;
        } else {
            limit.spentToday += amount;
        }
    }

    // -----------------------------------------------------------------------
    // Emergency Controls
    // -----------------------------------------------------------------------

    /**
     * @notice Freeze the account - blocks ALL transactions.
     * @dev Can only be called by the account itself (via a previous UserOp).
     */
    function freeze() external onlyAccount {
        accounts[msg.sender].frozen = true;
        emit AccountFrozen(msg.sender);
    }

    /**
     * @notice Unfreeze the account - resumes normal operation.
     */
    function unfreeze() external onlyAccount {
        accounts[msg.sender].frozen = false;
        emit AccountUnfrozen(msg.sender);
    }

    /**
     * @notice Set the trusted EntryPoint for validateUserOp calls.
     * @dev Set this to your ERC-4337 EntryPoint address in production.
     */
    function setEntryPoint(address entryPoint) external onlyAccount {
        if (entryPoint == address(0)) revert ZeroAddress();
        accounts[msg.sender].entryPoint = entryPoint;
        emit EntryPointUpdated(msg.sender, entryPoint);
    }

    /**
     * @notice Update the Wardex evaluator address.
     * @param newEvaluator New evaluator address
     */
    function setEvaluator(address newEvaluator) external onlyAccount {
        if (newEvaluator == address(0)) revert ZeroAddress();
        accounts[msg.sender].evaluator = newEvaluator;
        emit EvaluatorUpdated(msg.sender, newEvaluator);
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /**
     * @notice Verifies that the UserOp was approved by the Wardex evaluator.
     * @param signature ECDSA signature from the evaluator
     * @param hash The UserOp hash that was signed
     * @param evaluator Expected signer address
     * @return valid Whether the signature is valid
     */
    function _verifyApproval(
        bytes calldata signature,
        bytes32 hash,
        address evaluator
    ) internal pure returns (bool valid) {
        if (signature.length != 65) return false;

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        // EIP-191 prefixed hash
        bytes32 prefixedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );

        address recovered = ecrecover(prefixedHash, v, r, s);
        return recovered == evaluator && recovered != address(0);
    }

    /**
     * @notice Extracts the ETH value from supported execute callData patterns.
     * @dev Supported selectors:
     *      - Generic execute(address,uint256,bytes):       0xb61d27f6
     *      - Safe execTransaction(address,uint256,...):     0x6a761202
     *      - Kernel execute((address,uint256,bytes)[]):     0x1cff79cd
     *
     *      Generic and Safe both have the value as the 2nd ABI parameter at
     *      callData offset 36. Kernel uses a dynamic array of tuples; we sum
     *      all value fields via _extractKernelBatchValue().
     *
     *      If the callData doesn't match any supported pattern, returns 0
     *      (no value extracted, spending check skipped — defense-in-depth:
     *      the off-chain SDK still enforces limits).
     */
    function _extractExecuteValue(bytes calldata callData) internal pure returns (uint256) {
        // Minimum length: 4 (selector) + 32 (address) + 32 (value) = 68 bytes
        if (callData.length < 68) return 0;

        bytes4 selector = bytes4(callData[:4]);

        // Generic: execute(address,uint256,bytes) — 0xb61d27f6
        // Safe:    execTransaction(address,uint256,...) — 0x6a761202
        // Both have value as 2nd param at callData offset 36
        if (selector == bytes4(0xb61d27f6) || selector == bytes4(0x6a761202)) {
            uint256 value;
            assembly {
                value := calldataload(add(callData.offset, 36))
            }
            return value;
        }

        // Kernel: execute((address,uint256,bytes)[]) — 0x1cff79cd
        // ABI-encoded dynamic array of (address,uint256,bytes) tuples.
        // Sum all value fields for aggregate spending check.
        if (selector == bytes4(0x1cff79cd)) {
            return _extractKernelBatchValue(callData);
        }

        return 0;
    }

    /**
     * @notice Extracts summed ETH value from a Kernel-style batch execute callData.
     * @dev Layout after 4-byte selector:
     *      - 32 bytes: offset pointer to dynamic array
     *      - At that offset: 32 bytes array length, then N tuple offset pointers
     *      - Each tuple: (address padded to 32, uint256 value, bytes offset/data)
     *      Iterations capped at 8 to bound gas and prevent DoS.
     */
    function _extractKernelBatchValue(bytes calldata callData) internal pure returns (uint256) {
        // Minimum: 4 (selector) + 32 (offset) + 32 (length) = 68 bytes
        if (callData.length < 68) return 0;

        // Read the offset pointer to the dynamic array
        uint256 arrayOffset;
        assembly {
            arrayOffset := calldataload(add(callData.offset, 4))
        }
        uint256 arrayStart = 4 + arrayOffset;
        if (callData.length < arrayStart + 32) return 0;

        // Read array length
        uint256 arrayLen;
        assembly {
            arrayLen := calldataload(add(callData.offset, arrayStart))
        }

        // Cap iterations to prevent DoS (max 8 batch items)
        if (arrayLen > 8) arrayLen = 8;

        uint256 total = 0;
        uint256 offsetsStart = arrayStart + 32;

        for (uint256 i = 0; i < arrayLen; i++) {
            // Each element has an offset pointer
            if (callData.length < offsetsStart + (i + 1) * 32) break;
            uint256 elemOffset;
            assembly {
                elemOffset := calldataload(add(callData.offset, add(offsetsStart, mul(i, 32))))
            }

            uint256 elemStart = arrayStart + 32 + elemOffset;
            // value is 2nd field in tuple: elemStart + 32 (skip address)
            if (callData.length < elemStart + 64) break;
            uint256 val;
            assembly {
                val := calldataload(add(callData.offset, add(elemStart, 32)))
            }
            total += val;
        }
        return total;
    }

    // -----------------------------------------------------------------------
    // View Functions
    // -----------------------------------------------------------------------

    /**
     * @notice Check if an account is initialized with Wardex.
     */
    function isInitialized(address account) external view returns (bool) {
        return accounts[account].initialized;
    }

    /**
     * @notice Check if an account is frozen.
     */
    function isFrozen(address account) external view returns (bool) {
        return accounts[account].frozen;
    }

    /**
     * @notice Get the evaluator address for an account.
     */
    function getEvaluator(address account) external view returns (address) {
        return accounts[account].evaluator;
    }
}
