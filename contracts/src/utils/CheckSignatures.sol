// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import {ISignatureValidator, ISignatureValidatorConstants} from "@safe-global/safe-contracts/interfaces/ISignatureValidator.sol";
import {SignatureDecoder} from "@safe-global/safe-contracts/common/SignatureDecoder.sol";
import {SafeMath} from "@safe-global/safe-contracts/external/SafeMath.sol";

contract CheckSignatures is SignatureDecoder, ISignatureValidatorConstants {
    using SafeMath for uint256;

    address internal constant SENTINEL_OWNERS = address(0x1);

    /**
     * @notice Checks whether the signature provided is valid for the provided data and hash. Reverts otherwise.
     * @param threshold The threshold value of signatures
     * @param dataHash Hash of the data (could be either a message hash or transaction hash)
     * @param data That should be signed (this is passed to an external validator contract)
     * @param signatures Signature data that should be verified.
     *                   Can be packed ECDSA signature ({bytes32 r}{bytes32 s}{uint8 v}), contract signature (EIP-1271) or approved hash.
     * @param owners List of the owners
     */
    function checkSignatures(
        uint256 threshold,
        bytes32 dataHash,
        bytes memory data,
        bytes memory signatures,
        address[] memory owners
    ) public view {
        // Check that a threshold is set
        require(threshold > 0, "GS001");
        checkNSignatures(dataHash, data, signatures, owners, threshold);
    }

    /**
     * @notice Checks whether the signature provided is valid for the provided data and hash. Reverts otherwise.
     * @dev Since the EIP-1271 does an external call, be mindful of reentrancy attacks.
     * @param dataHash Hash of the data (could be either a message hash or transaction hash)
     * @param data That should be signed (this is passed to an external validator contract)
     * @param signatures Signature data that should be verified.
     *                   Can be packed ECDSA signature ({bytes32 r}{bytes32 s}{uint8 v}), contract signature (EIP-1271) or approved hash.
     * @param owners List of the owners
     * @param requiredSignatures Amount of required valid signatures.
     */
    function checkNSignatures(
        bytes32 dataHash,
        bytes memory data,
        bytes memory signatures,
        address[] memory owners,
        uint256 requiredSignatures
    ) public view {
        // Check that the provided signature data is not too short
        require(signatures.length >= requiredSignatures.mul(65), "GS020");
        // There cannot be an owner with address 0.
        address lastOwner = address(0);
        address currentOwner;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 i;
        uint256 o;
        for (i = 0; i < requiredSignatures; i++) {
            (v, r, s) = signatureSplit(signatures, i);
            if (v == 0) {
                require(keccak256(data) == dataHash, "GS027");
                // If v is 0 then it is a contract signature
                // When handling contract signatures the address of the contract is encoded into r
                currentOwner = address(uint160(uint256(r)));

                // Check that signature data pointer (s) is not pointing inside the static part of the signatures bytes
                // This check is not completely accurate, since it is possible that more signatures than the threshold are send.
                // Here we only check that the pointer is not pointing inside the part that is being processed
                require(uint256(s) >= requiredSignatures.mul(65), "GS021");

                // Check that signature data pointer (s) is in bounds (points to the length of data -> 32 bytes)
                require(uint256(s).add(32) <= signatures.length, "GS022");

                // Check if the contract signature is in bounds: start of data is s + 32 and end is start + signature length
                uint256 contractSignatureLen;
                // solhint-disable-next-line no-inline-assembly
                assembly {
                    contractSignatureLen := mload(add(add(signatures, s), 0x20))
                }
                require(
                    uint256(s).add(32).add(contractSignatureLen) <=
                        signatures.length,
                    "GS023"
                );

                // Check signature
                bytes memory contractSignature;
                // solhint-disable-next-line no-inline-assembly
                assembly {
                    // The signature data for contract signatures is appended to the concatenated signatures and the offset is stored in s
                    contractSignature := add(add(signatures, s), 0x20)
                }
                require(
                    ISignatureValidator(currentOwner).isValidSignature(
                        data,
                        contractSignature
                    ) == EIP1271_MAGIC_VALUE,
                    "GS024"
                );
            } else if (v == 1) {
                revert("approved hash not supported currently");
                // // If v is 1 then it is an approved hash
                // // When handling approved hashes the address of the approver is encoded into r
                // currentOwner = address(uint160(uint256(r)));
                // // Hashes are automatically approved by the sender of the message or when they have been pre-approved via a separate transaction
                // require(
                //     msg.sender == currentOwner ||
                //         approvedHashes[currentOwner][dataHash] != 0,
                //     "GS025"
                // );
            } else if (v > 30) {
                // If v > 30 then default va (27,28) has been adjusted for eth_sign flow
                // To support eth_sign and similar we adjust v and hash the messageHash with the Ethereum message prefix before applying ecrecover
                currentOwner = ecrecover(
                    keccak256(
                        abi.encodePacked(
                            "\x19Ethereum Signed Message:\n32",
                            dataHash
                        )
                    ),
                    v - 4,
                    r,
                    s
                );
            } else {
                // Default is the ecrecover flow with the provided data hash
                // Use ecrecover with the messageHash for EOA signatures
                currentOwner = ecrecover(dataHash, v, r, s);
            }

            while (owners[o] != currentOwner) {
                o++;
            }

            require(
                currentOwner > lastOwner &&
                    owners[o] == currentOwner &&
                    currentOwner != SENTINEL_OWNERS,
                "GS026"
            );
            lastOwner = currentOwner;
        }
    }
}
