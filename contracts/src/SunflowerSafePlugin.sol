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
        uint128 blockTimestamp;
        address[] owners;
    }
    mapping(ISafe => L1SafeOwnersCache) public cache;

    // Contains valid block data
    OptimismBlockCache blockCache;

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
    function executeTransactionThroughManager(
        ISafeProtocolManager manager,
        ISafe safe,
        SafeProtocolAction calldata action,
        uint8 operation,
        bytes[] calldata zkProof,
        bytes calldata l1OwnerSignatures
    ) external {
        address[] memory owners;

        if (zkProof.length != 0) {
            // TODO
            // check if proof corresponds to correct owners and recent block
            (
                uint blockHash,
                ,
                address account,
                uint ownersCount,
                uint threshold,
                address[] memory owners
            ) = parse(zkProof);

            // blockCache.getTimestamp(blockHash);

            // save to cxache
        } else {
            require(
                _l2CurrentTimestamp() <
                    cache[safe].blockTimestamp + cache[safe].ttl
            );
            owners = cache[safe].owners;
        }

        // TODO review this code
        checkSignatures({
            threshold: 0, // TODO take from zk proof
            dataHash: bytes32(0), // TODO do someting
            data: action.data,
            signatures: l1OwnerSignatures,
            owners: owners
        });

        // execute transaction
        if (address(manager) != address(0)) {
            // go through the manager as a mediator plugin.
            // requires this plugin to be whitelisted in the manager plugin.
            uint256 nonce = uint256(
                keccak256(abi.encode(this, manager, safe, action))
            );
            if (operation == 0) {
                SafeProtocolAction[] memory actions = new SafeProtocolAction[](
                    1
                );
                actions[0] = action;
                manager.executeTransaction(
                    safe,
                    SafeTransaction(actions, nonce, bytes32(0))
                );
            } else if (operation == 1) {
                manager.executeRootAccess(
                    safe,
                    SafeRootAccess(action, nonce, bytes32(0))
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

    /// @notice Allows overriding this function to use different L2s requirements.
    function _l2CurrentTimestamp() public view virtual returns (uint) {
        return block.timestamp;
    }
}
