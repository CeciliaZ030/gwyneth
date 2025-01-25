use std::{collections::HashMap, marker::PhantomData, sync::{Arc, RwLock}, time::Duration};

use alloy_eips::BlockNumHash;
use alloy_rlp::Decodable;
use alloy_sol_types::{sol, SolEventInterface};
use futures::StreamExt;
use reth_chainspec::Head;
use reth_primitives::{SealedBlockWithSenders, SealedHeader};
use reth_rpc_builder::auth::AuthServerHandle;
use tokio::time::sleep;

use crate::{
    GwynethEngineTypes, GwynethNode, GwynethPayloadAttributes,
    GwynethPayloadBuilderAttributes,
};
use reth_consensus::Consensus;
use reth_db::{test_utils::TempDatabase, DatabaseEnv};
use reth_ethereum_engine_primitives::EthPayloadAttributes;
use reth_evm_ethereum::EthEvmConfig;
use reth_execution_types::Chain;
use reth_exex::{ExExContext, ExExEvent};
use reth_node_api::{
    BuiltPayload, FullNodeComponents, FullNodeTypes, FullNodeTypesAdapter, NodeAddOns, PayloadBuilder, PayloadBuilderAttributes
};
use reth_node_builder::{components::Components, FullNode, NodeAdapter, NodeComponents};
use reth_node_ethereum::{node::EthereumAddOns, EthExecutorProvider};
use reth_payload_builder::{EthBuiltPayload, PayloadBuilderHandle};
use reth_provider::{
    providers::{BlockchainProvider, BlockchainProvider2},
    CanonStateSubscriptions, DatabaseProviderFactory, StateProviderFactory,
};
use reth_transaction_pool::{
    blobstore::DiskFileBlobStore, CoinbaseTipOrdering, EthPooledTransaction,
    EthTransactionValidator, Pool, TransactionValidationTaskExecutor,
};
use alloy_consensus::Transaction;
use reth_chainspec::EthChainSpec;
// use RollupContract::{BlockProposed, RollupContractEvents};

#[derive(Debug)]
pub struct L1ParentState {
    pub block_number: u64,
    // None at launch
    pub header: Option<SealedHeader>,
}

#[derive(Clone, Debug, Default)]
pub struct L1ParentStates(Arc<HashMap<u64, RwLock<L1ParentState>>>);

impl L1ParentStates {
    // pub fn new(nodes: &Vec<GwynethFullNode>) -> Self {
    //     let states = nodes.iter().map(|node| {
    //         let chain_id = node.chain_id();
    //         let state = RwLock::new(L1ParentState {block_number: 0, header: None});
    //         (chain_id, state)
    //     }).collect::<HashMap<_, _>>();
    //     L1ParentStates(Arc::new(states))
    // }

    pub fn get(&self, chain_id: u64) -> (u64, Option<SealedHeader>) {
        let state = self.0
            .get(&chain_id)
            .expect("L1ParentStates: chain_id not found")
            .read()
            .expect("L1ParentStates lock poisoned");
        (state.block_number, state.header.clone())
    }

    pub async fn update (&self, block: &SealedBlockWithSenders, chain_id: u64) -> eyre::Result<()> {
        let mut state = self.0
            .get(&chain_id)
            .expect("L1ParentStates: chain_id not found")
            .write()
            .expect("L1ParentStates lock poisoned");
        state.block_number = block.number;
        state.header = Some(block.header.clone());
        Ok(())
    }
}