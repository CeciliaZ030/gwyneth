// SPDX-License-Identifier: MIT
//  _____     _ _         _         _
// |_   _|_ _(_) |_____  | |   __ _| |__ ___
//   | |/ _` | | / / _ \ | |__/ _` | '_ (_-<
//   |_|\__,_|_|_\_\___/ |____\__,_|_.__/__/

pragma solidity ^0.8.20;

import "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import "../common/AddressResolver.sol";
import "../common/EssentialContract.sol";
import "../libs/LibAddress.sol";
import "./TaikoL1.sol";
import "./TaikoData.sol";
import "./VerifierRegistry.sol";
import "./verifiers/IVerifier.sol";

/// @title BasedOperator
/// @notice A based operator for Taiko.
contract BasedOperator is EssentialContract {
    using LibAddress for address;

    struct Block {
        address assignedProver;
        uint96 bond;
    }

    /// @dev Struct representing transition to be proven.
    struct BlockProof {
        address prover;
    }

    /// @dev Struct representing transition to be proven.
    struct ProofData {
        IVerifier verifier;
        bytes proof;
    }

    /// @dev Struct representing transition to be proven.
    struct ProofBatch {
        TaikoData.BlockMetadata _block;
        TaikoData.Transition transition;
        ProofData[] proofs;
        address prover;
    }

    uint public constant PROVER_BOND = 1 ether / 10;
    uint public constant MAX_GAS_PROVER_PAYMENT = 50_000;
    uint public constant MAX_BLOCKS_TO_VERIFY = 5;
    uint public constant PROVING_WINDOW = 1 hours;

    TaikoL1 public taiko;
    VerifierRegistry public verifierRegistry;
    address public treasury;

    mapping(uint => Block) public blocks;

    /// @dev Proposes a Taiko L2 block.
    function proposeBlock(
        bytes calldata params,
        bytes calldata txList,
        address prover
    )
        external
        payable
        nonReentrant
        whenNotPaused
        returns (TaikoData.BlockMetadata memory _block)
    {
        require(msg.value == PROVER_BOND, "Prover bond not expected");

        _block = taiko.proposeBlock(params, txList);

        // Check if we have whitelisted proposers
        require(_isProposerPermitted(_block), "proposer not allowed");

        // Store who paid for proving the block
        blocks[_block.id] = Block({
            assignedProver: prover,
            bond: uint96(PROVER_BOND)
        });

        // Verify some blocks
        _verifyBlocks(MAX_BLOCKS_TO_VERIFY);
    }

    /// @dev Proposes a Taiko L2 block.
    function proveBlock(bytes calldata data)
        external
        nonReentrant
        whenNotPaused
    {
        // Decode the block data
        ProofBatch memory proofBatch = abi.decode(data, (ProofBatch));

        // Check who can prove the block
        TaikoData.Block memory taikoBlock = taiko.getBlock(proofBatch._block.id);
        if (block.timestamp < taikoBlock.proposedAt + PROVING_WINDOW) {
            require(proofBatch.prover == blocks[proofBatch._block.id].assignedProver, "assigned prover not the prover");
        }

        // Verify the proofs
        uint160 prevVerifier = uint160(0);
        for (uint i = 0; i < proofBatch.proofs.length; i++) {
            IVerifier verifier = proofBatch.proofs[i].verifier;
            // Make sure each verifier is unique
            require(prevVerifier >= uint160(address(verifier)), "duplicated verifier");
            // Make sure it's a valid verifier
            require(verifierRegistry.isVerifier(address(verifier)), "invalid verifier");
            // Verify the proof
            verifier.verifyProof(proofBatch._block, proofBatch.transition, proofBatch.prover, proofBatch.proofs[i].proof);
            prevVerifier = uint160(address(verifier));
        }

        // Make sure the supplied proofs are sufficient.
        // Can use some custom logic here. but let's keep it simple
        require(proofBatch.proofs.length >= 3, "insufficient number of proofs");

        // Only allow an already proven block to be overwritten when the verifiers used are now invalid
        // Get the currently stored transition
        TaikoData.TransitionState memory storedTransition = taiko.getTransition(proofBatch._block.id, proofBatch.transition.parentHash);
        if (storedTransition.blockHash != proofBatch.transition.blockHash) {
            // TODO(Brecht): Check that one of the verifiers is now poissoned
        } else {
            revert("block already proven");
        }

        // Prove the block
        taiko.proveBlock(proofBatch._block, proofBatch.transition, proofBatch.prover);

        // Verify some blocks
        _verifyBlocks(MAX_BLOCKS_TO_VERIFY);
    }

    function verifyBlocks(uint maxBlocksToVerify) external nonReentrant whenNotPaused {
        _verifyBlocks(maxBlocksToVerify);
    }

    function _verifyBlocks(uint maxBlocksToVerify) internal {
        uint lastVerifiedBlockIdBefore = taiko.getLastVerifiedBlockId();
        // Verify the blocks
        taiko.verifyBlocks(maxBlocksToVerify);
        uint lastVerifiedBlockIdAfter = taiko.getLastVerifiedBlockId();

        // So some additional checks on top of the standard checks done in the rollup contract
        for (uint blockId = lastVerifiedBlockIdBefore + 1; blockId <= lastVerifiedBlockIdAfter; blockId++) {
            Block storage blk = blocks[blockId];

            // TODO(Brecht): Verify that all the verifers used to prove the block are still valid

            // Find out who the prover is
            TaikoData.Block memory previousBlock = taiko.getBlock(uint64(blockId) - 1);
            address prover = taiko.getTransition(uint64(blockId), previousBlock.blockHash).prover;

            // Return the bond or reward the other prover half the bond
            uint256 bondToReturn = blk.bond;
            if (prover != blk.assignedProver) {
                bondToReturn >>= 1;
                treasury.sendEther(bondToReturn, MAX_GAS_PROVER_PAYMENT);
            }
            prover.sendEther(bondToReturn, MAX_GAS_PROVER_PAYMENT);
        }
    }

    // Additinal proposer rules
    function _isProposerPermitted(
        TaikoData.BlockMetadata memory _block
    )
        private
        view
        returns (bool)
    {
        if (_block.id == 1) {
            // Only proposer_one can propose the first block after genesis
            address proposerOne = resolve("proposer_one", true);
            if (proposerOne != address(0) && msg.sender != proposerOne) {
                return false;
            }
        }

        address proposer = resolve("proposer", true);
        return proposer == address(0) || msg.sender == proposer;
    }
}
