// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "./ProofParser.t.sol";

import "../src/SunflowerSafePlugin.sol";
import "../src/OptimismBlockCache.sol";

contract OptimismBlockCacheMock is OptimismBlockCache {
    function setTimestamp(bytes32 blockHash, uint64 timestamp) public {
        getTimestamp[blockHash] = timestamp;
    }
}

contract SafeMock is ISafe {
    function execTransactionFromModule(
        address payable,
        uint256,
        bytes calldata,
        uint8
    ) external returns (bool success) {
        assembly {
            sstore(0, 0)
        }
        return true;
    }

    function execTransactionFromModuleReturnData(
        address,
        uint256,
        bytes memory,
        uint8
    ) external returns (bool success, bytes memory returnData) {
        assembly {
            sstore(0, 0)
        }
        return (true, hex"");
    }
}

contract SunflowerSafePluginTest is Test {
    OptimismBlockCacheMock blockCache;
    address verifier;
    SafeMock safe;

    SunflowerSafePlugin plugin;

    function setUp() public {
        bytes memory vb = verifierBytecode;
        assembly {
            sstore(verifier.slot, create(0, vb, mload(vb)))
        }
        blockCache = new OptimismBlockCacheMock();
        safe = new SafeMock();
        plugin = new SunflowerSafePlugin(blockCache, verifier);
    }

    function testExecTransaction() public {
        bytes[] memory zkProof = new bytes[](1);
        zkProof[0] = proof_1;

        blockCache.setTimestamp(
            0xfe2f6fd8f0d09b9e979ffc7afbf9147af588af2cef5395ebc92e22baf76e9e5c,
            uint64(block.timestamp)
        );

        plugin.executeTransaction({
            manager: ISafeProtocolManager(address(0)),
            safe: safe,
            action: SafeProtocolAction({
                to: payable(0x1111111111111111111111111111111111111111),
                value: 0,
                data: hex""
            }),
            operation: 0,
            zkProof: zkProof,
            l1OwnerSignatures: hex"a87648a5ebb4e55877b320a87d9d2d1cb9ad2890fbfc0aae20757b3513b61b1d71ba49ac3482b29df2e83a33c84e6944cafb8b398e2d1d5ab16737b66c4150851c6d686719f9d57222998fb23cfe4bc8ff945526aa0a58244b8a04e7e26c33ee343b406577e9bc06dba2f7665781092ad2139b6538ef6be764bd7a8163d38dede11b"
        });
    }
}
