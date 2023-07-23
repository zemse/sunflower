// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import {ISafe} from "@safe-global/safe-core-protocol/contracts/interfaces/Accounts.sol";
import {ISafeProtocolManager} from "@safe-global/safe-core-protocol/contracts/interfaces/Manager.sol";
import {ISafeProtocolPlugin} from "@safe-global/safe-core-protocol/contracts/interfaces/Integrations.sol";
import {SafeProtocolAction, SafeTransaction, SafeRootAccess} from "@safe-global/safe-core-protocol/contracts/DataTypes.sol";

import {BasePluginWithEventMetadata, PluginMetadata} from "@5afe/safe-core-protocol-demo/contracts/Base.sol";

import {CheckSignatures} from "./utils/CheckSignatures.sol";
import {ProofParser} from "./utils/ProofParser.sol";
import {OptimismBlockCache} from "./OptimismBlockCache.sol";

/// @title The Sunflower plugin for Gnosis Safe
/// @notice This plugin is to be used for safes on L2 to use owners on L1 using zk proofs.
contract SunflowerSafePlugin is
    ISafeProtocolPlugin,
    BasePluginWithEventMetadata,
    CheckSignatures,
    ProofParser
{
    // Cache is used to prevent using zk proofs to prove the list of owners for every action.
    // After a long time, zk proof will be used to read owners from L1, however to reduce costs
    // some expiry like 6 hours can be used so that the Safe users can perform back to back
    // actions without using zk proofs every time.
    struct L1SafeOwnersCache {
        uint128 ttl;
        uint128 l1BlockTimestamp;
        address[] owners;
    }
    mapping(ISafe => L1SafeOwnersCache) public ownersCache;

    // Contains valid block data
    OptimismBlockCache blockCache;

    uint public pluginNonce;

    constructor(
        OptimismBlockCache blockCache_,
        address plonkVerifier
    )
        BasePluginWithEventMetadata(
            PluginMetadata({
                name: "Sunflower Plugin",
                version: "0.0.1",
                requiresRootAccess: true,
                iconUrl: "",
                appUrl: "https://5afe.github.io/safe-core-protocol-demo/#/relay/${plugin}"
            })
        )
        ProofParser(plonkVerifier)
    {
        blockCache = blockCache_;
    }

    // inputs transaction & claimed owners & prooof & owner signatures
    function executeTransaction(
        ISafeProtocolManager manager,
        ISafe safe,
        SafeProtocolAction calldata action,
        uint8 operation,
        bytes[] calldata zkProof,
        bytes calldata l1OwnerSignatures
    ) external {
        address[] memory owners;
        uint threshold;

        if (zkProof.length != 0) {
            bytes32 blockHash;
            address account;

            // verifies zk proof and parses the instances
            (blockHash, , account, , threshold, owners) = parse(zkProof);

            // check block hash
            uint64 l1BlockTimestamp = blockCache.getTimestamp(blockHash);
            require(l1BlockTimestamp != 0, "block not cached");
            require(
                l1BlockTimestamp + 2 hours > block.timestamp,
                "too old block"
            );

            // save to cache
            require(
                ownersCache[safe].l1BlockTimestamp == 0 ||
                    l1BlockTimestamp > ownersCache[safe].l1BlockTimestamp,
                "more recent block already in cache"
            );
        } else {
            require(
                _l2CurrentTimestamp() <
                    ownersCache[safe].l1BlockTimestamp + ownersCache[safe].ttl
            );
            owners = ownersCache[safe].owners;
        }

        {
            uint currentNonce = pluginNonce++;

            bytes memory encodedTx = encodeTx({
                to: action.to,
                value: action.value,
                data: action.data,
                operation: 0,
                chainId: getChainId(),
                nonce: currentNonce
            });

            bytes32 dataHash = keccak256(encodedTx);

            // check if the signatures are from the L1 owners
            checkSignatures(
                threshold,
                dataHash,
                encodedTx,
                l1OwnerSignatures,
                owners
            );
        }

        // execute transaction
        if (address(manager) != address(0)) {
            // go through the manager as a mediator plugin.
            // requires this plugin to be whitelisted in the manager plugin.
            uint256 safeNonce = uint256(
                keccak256(abi.encode(this, manager, safe, action))
            );
            if (operation == 0) {
                SafeProtocolAction[] memory actions = new SafeProtocolAction[](
                    1
                );
                actions[0] = action;
                manager.executeTransaction(
                    safe,
                    SafeTransaction(actions, safeNonce, bytes32(0))
                );
            } else if (operation == 1) {
                manager.executeRootAccess(
                    safe,
                    SafeRootAccess(action, safeNonce, bytes32(0))
                );
            } else {
                revert("invalid opr");
            }
        } else {
            // directly approach the gnosis safe.
            // requires this plugin to be whitelisted in the gnosis safe.
            safe.execTransactionFromModule(
                action.to,
                action.value,
                action.data,
                operation
            );
        }
    }

    // keccak256("SunflowerSafePluginEthParis")
    bytes32 constant domainSeparator =
        0x6c426e77058bfdeef67364197b83db6647aa1e9fad867312eae40d220d014ba4;

    function encodeTx(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 chainId,
        uint256 nonce
    ) public pure returns (bytes memory) {
        bytes32 safeTxHash = keccak256(
            abi.encode(to, value, keccak256(data), operation, nonce)
        );
        return
            abi.encodePacked(
                bytes1(0x19),
                bytes1(0x01),
                domainSeparator,
                chainId,
                safeTxHash
            );
    }

    /// @notice Allows overriding this function to use different L2s requirements.
    function _l2CurrentTimestamp() public view virtual returns (uint) {
        return block.timestamp;
    }

    function getChainId() public view returns (uint id) {
        assembly {
            id := chainid()
        }
    }
}
