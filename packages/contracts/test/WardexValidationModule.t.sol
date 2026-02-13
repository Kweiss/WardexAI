// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/WardexValidationModule.sol";

/**
 * @title WardexValidationModule Tests
 * @notice Tests the on-chain defense-in-depth layer: spending limits,
 *         approval signature verification, freeze/unfreeze, and daily resets.
 */
contract WardexValidationModuleTest is Test {
    WardexValidationModule module;

    address evaluator;
    uint256 evaluatorPk;

    address account;
    address entryPoint;

    event TransactionApproved(address indexed account, bytes32 indexed userOpHash);
    event TransactionBlocked(address indexed account, bytes32 indexed userOpHash, string reason);

    function setUp() public {
        module = new WardexValidationModule();

        // Create an evaluator keypair
        evaluatorPk = 0xA11CE;
        evaluator = vm.addr(evaluatorPk);

        // "account" is the smart account that calls into the module
        account = address(0xBEEF);
        entryPoint = address(0x4337);
    }

    function _signUserOp(bytes32 userOpHash, uint256 signingKey) internal returns (bytes memory) {
        bytes32 prefixedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signingKey, prefixedHash);
        return abi.encodePacked(r, s, v);
    }

    function _buildUserOp(bytes memory signature, bytes memory callData) internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: account,
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: signature
        });
    }

    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------

    function test_initialize() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        assertTrue(module.isInitialized(account));
        assertEq(module.getEvaluator(account), evaluator);
        assertFalse(module.isFrozen(account));
    }

    function test_initialize_rejectsZeroAddress() public {
        vm.prank(account);
        vm.expectRevert(WardexValidationModule.ZeroAddress.selector);
        module.initialize(address(0), 1 ether, 10 ether);
    }

    function test_initialize_rejectsDoubleInit() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        vm.prank(account);
        vm.expectRevert(WardexValidationModule.NotAccountOwner.selector);
        module.initialize(evaluator, 1 ether, 10 ether);
    }

    // -----------------------------------------------------------------------
    // Freeze / Unfreeze
    // -----------------------------------------------------------------------

    function test_freeze() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        vm.prank(account);
        module.freeze();

        assertTrue(module.isFrozen(account));
    }

    function test_unfreeze() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        vm.prank(account);
        module.freeze();
        assertTrue(module.isFrozen(account));

        vm.prank(account);
        module.unfreeze();
        assertFalse(module.isFrozen(account));
    }

    function test_freeze_onlyAccount() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        vm.prank(address(0xDEAD));
        vm.expectRevert(WardexValidationModule.NotAccountOwner.selector);
        module.freeze();
    }

    // -----------------------------------------------------------------------
    // Spending Limits
    // -----------------------------------------------------------------------

    function test_setSpendingLimit() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        address usdc = address(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
        vm.prank(account);
        module.setSpendingLimit(usdc, 1000e6, 10000e6);

        assertTrue(module.checkSpendingLimit(account, usdc, 500e6));
        assertFalse(module.checkSpendingLimit(account, usdc, 2000e6));
    }

    function test_checkSpendingLimit_withinPerTx() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        // 0.5 ETH < 1 ETH per-tx limit
        assertTrue(module.checkSpendingLimit(account, address(0), 0.5 ether));
    }

    function test_checkSpendingLimit_exceedsPerTx() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        // 2 ETH > 1 ETH per-tx limit
        assertFalse(module.checkSpendingLimit(account, address(0), 2 ether));
    }

    function test_checkSpendingLimit_noLimitsSet() public {
        // For a token with no limits set, should return true
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        address randomToken = address(0x1234);
        assertTrue(module.checkSpendingLimit(account, randomToken, 1000 ether));
    }

    // -----------------------------------------------------------------------
    // Evaluator Management
    // -----------------------------------------------------------------------

    function test_setEvaluator() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        address newEvaluator = address(0xCAFE);
        vm.prank(account);
        module.setEvaluator(newEvaluator);

        assertEq(module.getEvaluator(account), newEvaluator);
    }

    function test_setEvaluator_rejectsZeroAddress() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        vm.prank(account);
        vm.expectRevert(WardexValidationModule.ZeroAddress.selector);
        module.setEvaluator(address(0));
    }

    // -----------------------------------------------------------------------
    // UserOp Validation
    // -----------------------------------------------------------------------

    function test_validateUserOp_validSignature() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        bytes32 userOpHash = keccak256("test-user-op");

        // Sign the userOpHash with the evaluator key (EIP-191 prefixed)
        bytes32 prefixedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(evaluatorPk, prefixedHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: account,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: signature
        });

        // Call as the EntryPoint would
        vm.prank(account);
        uint256 result = module.validateUserOp(userOp, userOpHash, 0);

        assertEq(result, 0, "Valid signature should return 0");
    }

    function test_validateUserOp_invalidSignature() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        bytes32 userOpHash = keccak256("test-user-op");

        // Sign with a DIFFERENT key (not the evaluator)
        uint256 wrongKey = 0xBAD;
        bytes32 prefixedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, prefixedHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: account,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: signature
        });

        vm.prank(account);
        uint256 result = module.validateUserOp(userOp, userOpHash, 0);

        assertEq(result, 1, "Invalid signature should return 1");
    }

    function test_validateUserOp_frozenAccount() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        vm.prank(account);
        module.freeze();

        bytes32 userOpHash = keccak256("test-user-op");

        // Even with a valid signature, frozen account should reject
        bytes32 prefixedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(evaluatorPk, prefixedHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: account,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: signature
        });

        vm.prank(account);
        uint256 result = module.validateUserOp(userOp, userOpHash, 0);

        assertEq(result, 1, "Frozen account should return 1");
    }

    function test_validateUserOp_malformedSignature() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        bytes32 userOpHash = keccak256("test-user-op");

        // Signature too short
        bytes memory badSignature = hex"deadbeef";

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: account,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: badSignature
        });

        vm.prank(account);
        uint256 result = module.validateUserOp(userOp, userOpHash, 0);

        assertEq(result, 1, "Malformed signature should return 1");
    }

    function test_validateUserOp_rejectsUnauthorizedCaller() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        bytes32 userOpHash = keccak256("test-user-op");
        bytes32 prefixedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(evaluatorPk, prefixedHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: account,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: signature
        });

        vm.prank(address(0xCAFE));
        uint256 result = module.validateUserOp(userOp, userOpHash, 0);
        assertEq(result, 1, "Unauthorized caller should return 1");
    }

    function test_validateUserOp_allowsConfiguredEntryPoint() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        vm.prank(account);
        module.setEntryPoint(entryPoint);

        bytes32 userOpHash = keccak256("test-user-op");
        bytes32 prefixedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(evaluatorPk, prefixedHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: account,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: signature
        });

        vm.prank(entryPoint);
        uint256 result = module.validateUserOp(userOp, userOpHash, 0);
        assertEq(result, 0, "Configured EntryPoint should be allowed");
    }

    function test_validateUserOp_emitsBlockedEventForUnauthorizedCaller() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        bytes32 userOpHash = keccak256("blocked-unauthorized");
        bytes memory signature = _signUserOp(userOpHash, evaluatorPk);
        PackedUserOperation memory userOp = _buildUserOp(signature, "");

        vm.expectEmit(true, true, false, true, address(module));
        emit TransactionBlocked(account, userOpHash, "Unauthorized validation caller");

        vm.prank(address(0xCAFE));
        uint256 result = module.validateUserOp(userOp, userOpHash, 0);
        assertEq(result, 1);
    }

    function test_validateUserOp_emitsBlockedEventForInvalidApproval() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        bytes32 userOpHash = keccak256("blocked-invalid-approval");
        bytes memory wrongSignature = _signUserOp(userOpHash, 0xBAD);
        PackedUserOperation memory userOp = _buildUserOp(wrongSignature, "");

        vm.expectEmit(true, true, false, true, address(module));
        emit TransactionBlocked(account, userOpHash, "Invalid Wardex approval");

        vm.prank(account);
        uint256 result = module.validateUserOp(userOp, userOpHash, 0);
        assertEq(result, 1);
    }

    function test_validateUserOp_emitsApprovedEvent() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        bytes32 userOpHash = keccak256("approved-userop");
        bytes memory signature = _signUserOp(userOpHash, evaluatorPk);
        PackedUserOperation memory userOp = _buildUserOp(signature, "");

        vm.expectEmit(true, true, false, false, address(module));
        emit TransactionApproved(account, userOpHash);

        vm.prank(account);
        uint256 result = module.validateUserOp(userOp, userOpHash, 0);
        assertEq(result, 0);
    }

    function test_validateUserOp_blocksExecuteValueAboveLimit() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        bytes memory executeCallData = abi.encodeWithSelector(
            bytes4(0xb61d27f6), // execute(address,uint256,bytes)
            address(0x1111),
            2 ether, // exceeds 1 ether maxPerTx
            bytes("")
        );

        bytes32 userOpHash = keccak256("execute-value-over-limit");
        bytes memory signature = _signUserOp(userOpHash, evaluatorPk);
        PackedUserOperation memory userOp = _buildUserOp(signature, executeCallData);

        vm.expectEmit(true, true, false, true, address(module));
        emit TransactionBlocked(account, userOpHash, "Spending limit exceeded");

        vm.prank(account);
        uint256 result = module.validateUserOp(userOp, userOpHash, 0);
        assertEq(result, 1, "execute(...) value above limit should be blocked");
    }

    function test_validateUserOp_unsupportedSelectorSkipsValueExtraction() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        // Unsupported selector: same argument shape but not execute(address,uint256,bytes).
        bytes memory unsupportedCallData = abi.encodeWithSelector(
            bytes4(0xdeadbeef),
            address(0x1111),
            20 ether, // would exceed limits if extracted
            bytes("")
        );

        bytes32 userOpHash = keccak256("unsupported-selector");
        bytes memory signature = _signUserOp(userOpHash, evaluatorPk);
        PackedUserOperation memory userOp = _buildUserOp(signature, unsupportedCallData);

        vm.prank(account);
        uint256 result = module.validateUserOp(userOp, userOpHash, 0);
        assertEq(result, 0, "unsupported selector should skip value extraction and pass");

        (, , uint256 spentToday, ) = module.spendingLimits(account, address(0));
        assertEq(spentToday, 0, "no spending should be recorded when value extraction is skipped");
    }

    function test_compatMatrix_genericExecutePattern_supportedAndEnforced() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        bytes memory genericExecuteCallData = abi.encodeWithSelector(
            bytes4(0xb61d27f6), // execute(address,uint256,bytes)
            address(0x1111),
            2 ether, // above per-tx limit
            bytes("")
        );

        bytes32 userOpHash = keccak256("compat-generic-execute");
        bytes memory signature = _signUserOp(userOpHash, evaluatorPk);
        PackedUserOperation memory userOp = _buildUserOp(signature, genericExecuteCallData);

        vm.prank(account);
        uint256 result = module.validateUserOp(userOp, userOpHash, 0);
        assertEq(result, 1, "generic execute selector should be parsed and limit-enforced");
    }

    function test_compatMatrix_safeExecTransactionPattern_currentlyNotParsed() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        // Safe-style selector (execTransaction(...)); payload includes a large value,
        // but module's current extractor only handles execute(address,uint256,bytes).
        bytes memory safeExecCallData = abi.encodeWithSelector(
            bytes4(0x6a761202), // execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)
            address(0x2222),
            5 ether,
            bytes(""),
            uint8(0),
            uint256(0),
            uint256(0),
            uint256(0),
            address(0),
            address(0),
            bytes("")
        );

        bytes32 userOpHash = keccak256("compat-safe-exectx");
        bytes memory signature = _signUserOp(userOpHash, evaluatorPk);
        PackedUserOperation memory userOp = _buildUserOp(signature, safeExecCallData);

        vm.prank(account);
        uint256 result = module.validateUserOp(userOp, userOpHash, 0);
        assertEq(result, 0, "safe execTransaction pattern is currently skipped by extractor");

        (, , uint256 spentToday, ) = module.spendingLimits(account, address(0));
        assertEq(spentToday, 0, "no spending recorded for unsupported safe selector");
    }

    function test_compatMatrix_kernelExecutePattern_currentlyNotParsed() public {
        vm.prank(account);
        module.initialize(evaluator, 1 ether, 10 ether);

        // Kernel-like execute selector vector (placeholder ABI shape for compatibility gating).
        bytes memory kernelExecuteCallData = abi.encodeWithSelector(
            bytes4(0x1cff79cd), // execute((address,uint256,bytes)[])
            abi.encode(address(0x3333), uint256(4 ether), bytes(""))
        );

        bytes32 userOpHash = keccak256("compat-kernel-execute");
        bytes memory signature = _signUserOp(userOpHash, evaluatorPk);
        PackedUserOperation memory userOp = _buildUserOp(signature, kernelExecuteCallData);

        vm.prank(account);
        uint256 result = module.validateUserOp(userOp, userOpHash, 0);
        assertEq(result, 0, "kernel-style execute vector is currently skipped by extractor");

        (, , uint256 spentToday, ) = module.spendingLimits(account, address(0));
        assertEq(spentToday, 0, "no spending recorded for unsupported kernel selector");
    }
}
