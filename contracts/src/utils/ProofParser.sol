// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

uint constant SLOTS_PER_PROOF = 10;

uint constant SENTINEL_OWNERS = 0x1;
uint constant PLACEHOLDER_SLOT = 0;
uint constant OWNERS_MAPPING_SLOT = 2;
uint constant OWNERS_COUNT_SLOT = 3;
uint constant THRESHOLD_SLOT = 4;

import "forge-std/console.sol";

contract ProofParser {
    address public immutable verifier;

    constructor(address _verifier) {
        verifier = _verifier;
    }

    function parse(
        bytes[] calldata proofs
    )
        public
        view
        returns (
            uint blockHash,
            uint blockNumber,
            address account,
            uint ownersCount,
            uint threshold,
            address[] memory owners
        )
    {
        uint[] memory slots;
        uint[] memory values;
        (blockHash, blockNumber, account, slots, values) = parseMultipleProofs(
            proofs
        );
        (ownersCount, threshold, owners) = parseState(slots, values);
    }

    function parseSingleProof(
        bytes calldata proof,
        uint[] memory slots,
        uint[] memory values,
        uint startLocation
    ) public view returns (uint blockHash, uint blockNumber, address account) {
        (bool success, ) = verifier.staticcall(proof);
        require(success, "Proof verification failed");

        blockHash =
            (uint256(bytes32(proof[384:384 + 32])) << 128) |
            uint128(bytes16(proof[384 + 48:384 + 64]));
        blockNumber = uint256(bytes32(proof[384 + 64:384 + 96]));
        account = address(bytes20(proof[384 + 108:384 + 128]));

        for (uint16 i = 0; i < SLOTS_PER_PROOF; i++) {
            uint256 slot = (uint256(
                bytes32(proof[384 + 128 + 128 * i:384 + 160 + 128 * i])
            ) << 128) |
                uint128(
                    bytes16(proof[384 + 176 + 128 * i:384 + 192 + 128 * i])
                );
            uint256 value = (uint256(
                bytes32(proof[384 + 192 + 128 * i:384 + 224 + 128 * i])
            ) << 128) |
                uint128(
                    bytes16(proof[384 + 240 + 128 * i:384 + 256 + 128 * i])
                );

            slots[startLocation + i] = slot;
            values[startLocation + i] = value;
        }
    }

    function parseMultipleProofs(
        bytes[] calldata proofs
    )
        public
        view
        returns (
            uint blockHash,
            uint blockNumber,
            address account,
            uint[] memory slots,
            uint[] memory values
        )
    {
        uint totalSlots = proofs.length * SLOTS_PER_PROOF;

        slots = new uint[](totalSlots);
        values = new uint[](totalSlots);

        (blockHash, blockNumber, account) = parseSingleProof(
            proofs[0],
            slots,
            values,
            0
        );

        for (uint i = 1; i < proofs.length; i++) {
            (
                uint _blockHash,
                uint _blockNumber,
                address _account
            ) = parseSingleProof(proofs[i], slots, values, i * SLOTS_PER_PROOF);
            require(blockHash == _blockHash);
            require(blockNumber == _blockNumber);
            require(account == _account);
        }
    }

    function parseState(
        uint[] memory slots,
        uint[] memory values
    )
        public
        pure
        returns (uint ownersCount, uint threshold, address[] memory owners)
    {
        require(slots.length == values.length, "same length");
        require(slots.length >= 3, "atleast 3");

        // ensure correct owners count
        require(slots[0] == OWNERS_COUNT_SLOT, "owners count slot");
        require(values[0] >= 1, "owners count value");
        ownersCount = values[0];

        // ensure correct threshold
        require(slots[1] == THRESHOLD_SLOT, "threshold slot");
        require(values[1] <= values[0], "threshold value");
        threshold = values[1];

        // creating a owners array to convert the linked list owners into mapping
        owners = new address[](ownersCount);

        // ensure that the correct mapping reads and parse results into
        uint key = SENTINEL_OWNERS;
        uint value;
        for (uint i = 0; i < ownersCount; i++) {
            uint expectedSlot = hashTwo(key, OWNERS_MAPPING_SLOT);
            require(slots[i + 2] == expectedSlot, "slot mismatch");

            // assuming value is correct, it should be a owner
            value = values[i + 2];
            require(value < (1 << 160), "value is out of range");

            owners[i] = address(uint160(value));

            // next owner present in mapping at key as current owner
            // https://github.com/safe-global/safe-contracts/blob/fca63a0fe0395a885032deacbdf02f26e7ff06a0/contracts/base/OwnerManager.sol#L44
            key = value;
        }

        require(
            values[ownersCount + 2] == SENTINEL_OWNERS,
            "last value should be 1"
        );
    }

    function hashTwo(uint a, uint b) private pure returns (uint c) {
        assembly {
            mstore(0, a)
            mstore(0x20, b)
            c := keccak256(0, 0x40)
        }
    }
}
