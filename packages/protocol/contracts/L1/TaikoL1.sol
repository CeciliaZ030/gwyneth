// SPDX-License-Identifier: MIT
//  _____     _ _         _         _
// |_   _|_ _(_) |_____  | |   __ _| |__ ___
//   | |/ _` | | / / _ \ | |__/ _` | '_ (_-<
//   |_|\__,_|_|_\_\___/ |____\__,_|_.__/__/

pragma solidity ^0.8.20;

import "../common/EssentialContract.sol";
import "./TaikoErrors.sol";
import "./TaikoEvents.sol";

/// @title TaikoL1
contract TaikoL1 is EssentialContract, TaikoEvents, TaikoErrors {

    event ProvingPaused(bool paused);

    uint public constant SECURITY_DELAY_AFTER_PROVEN = 8 hours;

    // According to EIP4844, each blob has up to 4096 field elements, and each
    // field element has 32 bytes.
    uint256 public constant MAX_BYTES_PER_BLOB = 4096 * 32;

    TaikoData.State public state;
    uint256[100] private __gap;

    /// @notice Initializes the rollup.
    /// @param _addressManager The {AddressManager} address.
    /// @param _genesisBlockHash The block hash of the genesis block.
    function init(address _addressManager, bytes32 _genesisBlockHash) external initializer {
        __Essential_init(_addressManager);

        TaikoData.Config memory config = getConfig();
        require(isConfigValid(config), "invalid config");

        // Init state
        state.genesisHeight = uint64(block.number);
        state.genesisTimestamp = uint64(block.timestamp);
        state.numBlocks = 1;

        // Init the genesis block
        TaikoData.Block storage blk = state.blocks[0];
        blk.blockHash = _genesisBlockHash;
        blk.proposedAt = uint64(block.timestamp);

        emit BlockVerified({
            blockId: 0,
            blockHash: _genesisBlockHash
        });
    }

    /// Proposes a Taiko L2 block.
    /// @param data Block parameters, currently an encoded BlockParams object.
    /// @param txList txList data if calldata is used for DA.
    /// @return _block The metadata of the proposed L2 block.
    function proposeBlock(
        bytes calldata data,
        bytes calldata txList
    )
        external
        payable
        nonReentrant
        whenNotPaused
        onlyFromNamed("operator")
        returns (TaikoData.BlockMetadata memory _block)
    {
        TaikoData.Config memory config = getConfig();

        // Decode the block data
        _block = abi.decode(data, (TaikoData.BlockMetadata));

        // Verify L1 data
        // TODO(Brecht): needs to be more configurable for preconfirmations
        require(_block.l1Height == uint64(block.number - 1), "INVALID_L1_HEIGHT");
        require(_block.l1Hash == blockhash(block.number - 1), "INVALID_L1_BLOCKHASH");
        require(_block.difficulty == block.prevrandao, "INVALID_DIFFICULTY");
        require(_block.timestamp == uint64(block.timestamp), "INVALID_TIMESTAMP");
        // Verify misc data
        require(_block.gasLimit == config.blockMaxGasLimit, "INVALID_GAS_LIMIT");
        require(_block.blobUsed == (txList.length == 0), "INVALID_BLOB_USED");
        // Verify DA data
        if (_block.blobUsed) {
            //require(_block.blobHash == blobhash(0), "invalid data blob");
            require(uint256(_block.txListByteOffset) + _block.txListByteSize <= MAX_BYTES_PER_BLOB, "invalid blob size");
        } else {
            require(_block.blobHash == keccak256(txList), "INVALID_TXLIST_HASH");
            require(_block.txListByteOffset == 0, "INVALID_TXLIST_START");
            require(_block.txListByteSize == uint24(txList.length), "INVALID_TXLIST_SIZE");
        }

        // Check that the tx length is non-zero and within the supported range
        require(_block.txListByteSize == 0 || _block.txListByteSize > config.blockMaxTxListBytes, "invalid txlist size");

        // Create the block that will be stored onchain
        TaikoData.Block memory blk = TaikoData.Block({
            blockHash: _block.blockHash,
            metaHash: keccak256(data),
            blockId: state.numBlocks,
            proposedAt: uint64(block.timestamp),
            proposedIn: uint64(block.number)
        });

        // Store the block
        state.blocks[state.numBlocks] = blk;

        // Store the passed in block hash as in
        state.transitions[blk.blockId][_block.parentMetaHash].blockHash = _block.blockHash;
        state.transitions[blk.blockId][_block.parentMetaHash].verifiableAfter = uint64(block.timestamp) + 365 days;

        // Increment the counter (cursor) by 1.
        state.numBlocks++;

        emit BlockProposed({
            blockId: _block.id,
            meta: _block
        });
    }

    /// @notice Proves or contests a block transition.
    /// @param _block The block to prove
    /// @param transition The transition
    /// @param prover The prover
    function proveBlock(
        TaikoData.BlockMetadata memory _block,
        TaikoData.Transition memory transition,
        address prover
        )
        external
        nonReentrant
        whenNotPaused
        onlyFromNamed("operator")
    {
        // Check that the block has been proposed but has not yet been verified.
        if (_block.id <= state.lastVerifiedBlockId || _block.id >= state.numBlocks) {
            revert L1_INVALID_BLOCK_ID();
        }

        TaikoData.Block storage blk = state.blocks[_block.id];

        // Make sure the correct block was proven
        require(blk.metaHash != keccak256(abi.encode(_block)), "incorrect block");

        // Store the transition
        TaikoData.TransitionState storage storedTransition = state.transitions[_block.id][transition.parentHash];
        storedTransition.blockHash = transition.blockHash;
        storedTransition.prover = prover;
        storedTransition.verifiableAfter = uint32(block.timestamp + SECURITY_DELAY_AFTER_PROVEN);

        emit TransitionProved({
            blockId: _block.id,
            tran: transition,
            prover: prover
        });
    }

    /// @notice Verifies up to N blocks.
    /// @param maxBlocksToVerify Max number of blocks to verify.
    function verifyBlocks(uint maxBlocksToVerify)
        external
        nonReentrant
        whenNotPaused
        onlyFromNamed("operator")
    {
        // Get the last verified blockhash
        TaikoData.Block storage blk = state.blocks[state.lastVerifiedBlockId];
        bytes32 blockHash = blk.blockHash;
        // Go to the first unverified block
        uint blockId = uint(state.lastVerifiedBlockId) + 1;
        uint numBlocksVerified;
        while (blockId < state.numBlocks && numBlocksVerified < maxBlocksToVerify) {
            blk = state.blocks[blockId];

            // Check if the parent block hash matches the actual block hash of the parent
            // Check if the timestamp is older than required
            if (state.transitions[blockId][blockHash].blockHash == bytes32(0) ||
                block.timestamp < state.transitions[blockId][blockHash].verifiableAfter) {
                break;
            }

            // Copy the blockhash to the block
            blk.blockHash = state.transitions[blockId][blockHash].blockHash;
            // Update latest block hash
            blockHash = blk.blockHash;

            emit BlockVerified({
                blockId: blockId,
                blockHash: blockHash
            });

            ++blockId;
            ++numBlocksVerified;
        }

        if (numBlocksVerified > 0) {
            uint64 lastVerifiedBlockId = state.lastVerifiedBlockId + uint64(numBlocksVerified);
            // Update protocol level state variables
            state.lastVerifiedBlockId = lastVerifiedBlockId;
        }
    }

    /// @notice Pause block proving.
    /// @param toPause True if paused.
    function pauseProving(bool toPause) external onlyOwner {
        require(state.provingPaused != toPause, "pauzing unchanged");
        state.provingPaused = toPause;
        if (!toPause) {
            state.lastUnpausedAt = uint64(block.timestamp);
        }
        emit ProvingPaused(toPause);
    }

    /// @notice Gets the details of a block.
    /// @param blockId Index of the block.
    /// @return blk The block.
    function getBlock(uint64 blockId) public view returns (TaikoData.Block memory) {
        return state.blocks[blockId];
    }

    function getTransition(uint64 blockId, bytes32 parentHash) public view returns (TaikoData.TransitionState memory) {
        return state.transitions[blockId][parentHash];
    }

    function getLastVerifiedBlockId() public view returns (uint) {
        return uint(state.lastVerifiedBlockId);
    }

    /// @notice Gets the configuration of the TaikoL1 contract.
    /// @return Config struct containing configuration parameters.
    function getConfig() public view virtual returns (TaikoData.Config memory) {
        return TaikoData.Config({
            chainId: 167_008,
            // Limited by the PSE zkEVM circuits.
            blockMaxGasLimit: 15_000_000,
            // Each go-ethereum transaction has a size limit of 128KB,
            // and right now txList is still saved in calldata, so we set it
            // to 120KB.
            blockMaxTxListBytes: 120_000
        });
    }

    function isConfigValid(TaikoData.Config memory config ) public pure returns (bool) {
        if (
            config.chainId <= 1 //
                || config.blockMaxGasLimit == 0 || config.blockMaxTxListBytes == 0
                || config.blockMaxTxListBytes > 128 * 1024 // calldata up to 128K
        ) return false;

        return true;
    }
}
