use std::{collections::HashMap, marker::PhantomData, sync::{Arc, RwLock}, time::Duration};

use alloy_eips::BlockNumHash;
use alloy_rlp::Decodable;
use alloy_sol_types::{sol, SolEventInterface};
use futures::StreamExt;
use reth::{network::NetworkHandle, rpc::eth::EthApi};
use reth_chainspec::Head;
use reth_primitives::{SealedBlockWithSenders, SealedHeader};
use reth_rpc_builder::auth::AuthServerHandle;
use tokio::time::sleep;

use crate::{
    GwynethEngineTypes, GwynethEngineValidatorBuilder, GwynethNode, GwynethPayloadAttributes, GwynethPayloadBuilderAttributes
};
use reth_consensus::Consensus;
use reth_db::{test_utils::TempDatabase, DatabaseEnv};
use reth_ethereum_engine_primitives::EthPayloadAttributes;
use reth_evm_ethereum::EthEvmConfig;
use reth_execution_types::Chain;
use reth_exex::{ExExContext, ExExEvent};
use reth_node_api::{
    BuiltPayload, FullNodeComponents, FullNodeTypes, FullNodeTypesAdapter, NodeAddOns, NodeTypesWithDBAdapter, PayloadBuilder, PayloadBuilderAttributes
};
use reth_node_builder::{components::Components, rpc::RpcAddOns, FullNode, NodeAdapter, NodeComponents};
use reth_node_ethereum::{node::EthereumAddOns, BasicBlockExecutorProvider, EthExecutionStrategyFactory, EthExecutorProvider};
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



type GwynethProvider1 = BlockchainProvider<NodeTypesWithDBAdapter<GwynethNode, Arc< DatabaseEnv>>>;
type GwynethProvider2 = BlockchainProvider2<NodeTypesWithDBAdapter<GwynethNode, Arc< DatabaseEnv>>>;

type NodeDapter1 = NodeAdapter<
    FullNodeTypesAdapter<
        NodeTypesWithDBAdapter<GwynethNode, Arc<DatabaseEnv>>,
        GwynethProvider1
    >,
    Components<
        FullNodeTypesAdapter<
            NodeTypesWithDBAdapter<GwynethNode, Arc<DatabaseEnv>>,
            GwynethProvider1
        >,
        Pool<
            TransactionValidationTaskExecutor<
                EthTransactionValidator<GwynethProvider1, EthPooledTransaction>
            >,
            CoinbaseTipOrdering<EthPooledTransaction>,
            DiskFileBlobStore
        >,
        EthEvmConfig,
        BasicBlockExecutorProvider<EthExecutionStrategyFactory>,
        Arc<dyn Consensus>
    >
>;

pub type GwynethFullNode1 = FullNode<
    NodeDapter1,
    RpcAddOns<
        NodeDapter1,
        EthApi<
            GwynethProvider1,
            Pool<
                TransactionValidationTaskExecutor<
                    EthTransactionValidator<GwynethProvider1, EthPooledTransaction>
                >,
                CoinbaseTipOrdering<EthPooledTransaction>,
                DiskFileBlobStore
            >,
            NetworkHandle,
            EthEvmConfig
        >,
        GwynethEngineValidatorBuilder
    >
>;

type NodeDapter2 = NodeAdapter<
    FullNodeTypesAdapter<
        NodeTypesWithDBAdapter<GwynethNode, Arc<DatabaseEnv>>,
        GwynethProvider2
    >,
    Components<
        FullNodeTypesAdapter<
            NodeTypesWithDBAdapter<GwynethNode, Arc<DatabaseEnv>>,
            GwynethProvider2
        >,
        Pool<
            TransactionValidationTaskExecutor<
                EthTransactionValidator<GwynethProvider2, EthPooledTransaction>
            >,
            CoinbaseTipOrdering<EthPooledTransaction>,
            DiskFileBlobStore
        >,
        EthEvmConfig,
        BasicBlockExecutorProvider<EthExecutionStrategyFactory>,
        Arc<dyn Consensus>
    >
>;

pub type GwynethFullNode2 = FullNode<
    NodeDapter2,
    RpcAddOns<
        NodeDapter2,
        EthApi<
            GwynethProvider2,
            Pool<
                TransactionValidationTaskExecutor<
                    EthTransactionValidator<GwynethProvider2, EthPooledTransaction>
                >,
                CoinbaseTipOrdering<EthPooledTransaction>,
                DiskFileBlobStore
            >,
            NetworkHandle,
            EthEvmConfig
        >,
        GwynethEngineValidatorBuilder
    >
>;

pub enum GwynethFullNode {
    Provider1(GwynethFullNode1),
    Provider2(GwynethFullNode2),
}

impl GwynethFullNode {
    pub fn chain_id(&self) -> u64{
        match self {
            GwynethFullNode::Provider1(node) => (node.chain_spec().chain().id()),
            GwynethFullNode::Provider2(node) => (node.chain_spec().chain().id()),
        }
    }

    pub fn payload_builder(&self) -> &PayloadBuilderHandle<GwynethEngineTypes> {
        match self {
            GwynethFullNode::Provider1(node) => &node.payload_builder,
            GwynethFullNode::Provider2(node) => &node.payload_builder,
        }
    }
}




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
