use std::{collections::HashMap, marker::PhantomData, sync::{Arc, RwLock}, time::Duration};

use alloy_rlp::Decodable;
use alloy_sol_types::{sol, SolEventInterface};
use reth_chainspec::Head;
use reth_rpc_builder::auth::AuthServerHandle;
use tokio::time::sleep;

use crate::{
    engine_api::EngineApiContext, GwynethEngineTypes, GwynethNode, GwynethPayloadAttributes,
    GwynethPayloadBuilderAttributes,
};
use reth_consensus::Consensus;
use reth_db::{test_utils::TempDatabase, DatabaseEnv};
use reth_ethereum_engine_primitives::EthPayloadAttributes;
use reth_evm_ethereum::EthEvmConfig;
use reth_execution_types::Chain;
use reth_exex::{ExExContext, ExExEvent};
use reth_node_api::{
    FullNodeComponents, FullNodeTypes, FullNodeTypesAdapter, NodeAddOns, PayloadBuilderAttributes,
};
use reth_node_builder::{components::Components, FullNode, NodeAdapter, NodeComponents};
use reth_node_ethereum::{node::EthereumAddOns, EthExecutorProvider};
use reth_payload_builder::{EthBuiltPayload, PayloadBuilderHandle};
use reth_primitives::{
    address, Address, Header, SealedBlock, SealedBlockWithSenders, SealedHeader, TransactionSigned, B256, U256
};
use reth_provider::{
    providers::{BlockchainProvider, BlockchainProvider2},
    CanonStateSubscriptions, DatabaseProviderFactory,
};
use reth_rpc_types::engine::PayloadStatusEnum;
use reth_transaction_pool::{
    blobstore::DiskFileBlobStore, CoinbaseTipOrdering, EthPooledTransaction,
    EthTransactionValidator, Pool, TransactionValidationTaskExecutor,
};
use RollupContract::{BlockProposed, RollupContractEvents};

const ROLLUP_CONTRACT_ADDRESS: Address = address!("9fCF7D13d10dEdF17d0f24C62f0cf4ED462f65b7");
pub const BASE_CHAIN_ID: u64 = 167010;
const INITIAL_TIMESTAMP: u64 = 1710338135;

type GwynethFullNode1 = FullNode<
    NodeAdapter<
        FullNodeTypesAdapter<GwynethNode, Arc<DatabaseEnv>, BlockchainProvider<Arc<DatabaseEnv>>>,
        Components<
            FullNodeTypesAdapter<
                GwynethNode,
                Arc<DatabaseEnv>,
                BlockchainProvider<Arc<DatabaseEnv>>,
            >,
            Pool<
                TransactionValidationTaskExecutor<
                    EthTransactionValidator<
                        BlockchainProvider<Arc<DatabaseEnv>>,
                        EthPooledTransaction,
                    >,
                >,
                CoinbaseTipOrdering<EthPooledTransaction>,
                DiskFileBlobStore,
            >,
            EthEvmConfig,
            EthExecutorProvider,
            Arc<dyn Consensus>,
        >,
    >,
    EthereumAddOns,
>;

type GwynethFullNode2 = FullNode<
    NodeAdapter<
        FullNodeTypesAdapter<GwynethNode, Arc<DatabaseEnv>, BlockchainProvider2<Arc<DatabaseEnv>>>,
        Components<
            FullNodeTypesAdapter<
                GwynethNode,
                Arc<DatabaseEnv>,
                BlockchainProvider2<Arc<DatabaseEnv>>,
            >,
            Pool<
                TransactionValidationTaskExecutor<
                    EthTransactionValidator<
                        BlockchainProvider2<Arc<DatabaseEnv>>,
                        EthPooledTransaction,
                    >,
                >,
                CoinbaseTipOrdering<EthPooledTransaction>,
                DiskFileBlobStore,
            >,
            EthEvmConfig,
            EthExecutorProvider,
            Arc<dyn Consensus>,
        >,
    >,
    EthereumAddOns,
>;

sol!(RollupContract, "TaikoL1.json");

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
    pub fn new(nodes: &Vec<GwynethFullNode>) -> Self {
        let states = nodes.iter().map(|node| {
            let chain_id = node.chain_id();
            let state = RwLock::new(L1ParentState {block_number: 0, header: None});
            (chain_id, state)
        }).collect::<HashMap<_, _>>();
        L1ParentStates(Arc::new(states))
    }

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

pub struct Rollup<Node: reth_node_api::FullNodeComponents> {
    ctx: ExExContext<Node>,
    nodes: Vec<GwynethFullNode>,
    engine_apis: Vec<EngineApiContext<GwynethEngineTypes>>,
    pub l1_parents: L1ParentStates,
}

impl<Node: reth_node_api::FullNodeComponents> Rollup<Node> {
    pub async fn new(ctx: ExExContext<Node>, nodes: Vec<GwynethFullNode>, l1_parents: L1ParentStates) -> eyre::Result<Self> {
        let mut engine_apis = Vec::new();
        for node in &nodes {
            match node {
                GwynethFullNode::Provider1(node) => {
                    let engine_api = EngineApiContext {
                        engine_api_client: node.auth_server_handle().http_client(),
                        canonical_stream: node.provider.canonical_state_stream(),
                        _marker: PhantomData::<GwynethEngineTypes>,
                    };
                    engine_apis.push(engine_api);
                }
                GwynethFullNode::Provider2(node) => {
                    let engine_api = EngineApiContext {
                        engine_api_client: node.auth_server_handle().http_client(),
                        canonical_stream: node.provider.canonical_state_stream(),
                        _marker: PhantomData::<GwynethEngineTypes>,
                    };
                    engine_apis.push(engine_api);
                }
            }
        }
        Ok(Self { ctx, nodes, engine_apis, l1_parents })
    }

    pub async fn start(mut self) -> eyre::Result<()> {
        while let Some(notification) = self.ctx.notifications.recv().await {
            if let Some(reverted_chain) = notification.reverted_chain() {
                self.revert(&reverted_chain)?;
            }

            if let Some(committed_chain) = notification.committed_chain() {
                println!("[reth] Exex Gwyneth: synced_l1_header 🎃 {:?}, synced_l1_number: {:?}", committed_chain.tip().hash(), committed_chain.tip().number);
                for (i, node) in self.nodes.iter().enumerate() {
                    self.commit(&committed_chain, i).await?;
                    self.l1_parents.update(committed_chain.tip(), node.chain_id()).await?;
                }
                self.ctx.events.send(ExExEvent::FinishedHeight(committed_chain.tip().number))?;
            }

            if let Some(commited_block) = notification.commited_block() {
                // self.l1_parents.0
                //     .iter()
                //     .for_each(|(_, state)| {
                //         let mut state = state.write().unwrap();
                //         state.block_number = commited_block.header().number;
                //         state.header = Some(commited_block.clone());
                //     });
            }
        }

        Ok(())
    }

    pub async fn commit(&self, chain: &Chain, node_idx: usize) -> eyre::Result<()> {
        let node = &self.nodes[node_idx];
        let events = decode_chain_into_rollup_events(chain);
        for (block, _, event) in events {
            if let RollupContractEvents::BlockProposed(BlockProposed {
                blockId: block_number,
                meta,
            }) = event
            {
                println!("[reth] l2 {} block_number: {:?}", node.chain_id(), block_number);
                let transactions: Vec<TransactionSigned> = decode_transactions(&meta.txList);
                println!("tx_list: {:?}", transactions);

                let filtered_transactions: Vec<TransactionSigned> = transactions
                    .into_iter()
                    .filter(|tx| tx.chain_id() == Some(node.chain_id()))
                    .collect();

                if filtered_transactions.len() == 0 {
                    self.l1_parents.update(block, node.chain_id()).await?;
                    println!("no transactions for chain: {}", node.chain_id());
                    continue;
                }

                let attrs = GwynethPayloadAttributes {
                    inner: EthPayloadAttributes {
                        timestamp: block.timestamp,
                        prev_randao: B256::ZERO,
                        suggested_fee_recipient: Address::ZERO,
                        withdrawals: Some(vec![]),
                        parent_beacon_block_root: Some(B256::ZERO),
                    },
                    transactions: Some(filtered_transactions.clone()),
                    gas_limit: None,
                };

                let l1_state_provider = self
                    .ctx
                    .provider()
                    .database_provider_ro()
                    .unwrap()
                    .state_provider_by_block_number(block.number)
                    .unwrap();

                let mut builder_attrs =
                    GwynethPayloadBuilderAttributes::try_new(B256::ZERO, attrs).unwrap();
                builder_attrs.l1_provider =
                    Some((self.ctx.config.chain.chain().id(), Arc::new(l1_state_provider)));

                let payload_id = builder_attrs.inner.payload_id();
                let parrent_beacon_block_root =
                    builder_attrs.inner.parent_beacon_block_root.unwrap();

                println!("👛 Exex: sending payload_id: {:?}\n {:?}", payload_id, builder_attrs);

                // trigger new payload building draining the pool
                node.payload_builder().new_payload(builder_attrs).await.unwrap();

                // wait for the payload builder to have finished building
                let mut payload =
                    EthBuiltPayload::new(payload_id, SealedBlock::default(), U256::ZERO);
                loop {
                    let result = node.payload_builder().best_payload(payload_id).await;

                    if let Some(result) = result {
                        if let Ok(new_payload) = result {
                            payload = new_payload;
                            if payload.block().body.is_empty() {
                                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                                continue;
                            }
                        } else {
                            println!("Gwyneth: No payload?");
                            continue;
                        }
                    } else {
                        println!("Gwyneth: No block?");
                        continue;
                    }
                    break;
                }

                // trigger resolve payload via engine api
                self.engine_apis[node_idx].get_payload_v3_value(payload_id).await?;

                // submit payload to engine api
                let block_hash = self.engine_apis[node_idx]
                    .submit_payload(
                        payload.clone(),
                        parrent_beacon_block_root,
                        PayloadStatusEnum::Valid,
                        vec![],
                    )
                    .await?;

                // trigger forkchoice update via engine api to commit the block to the blockchain
                self.engine_apis[node_idx].update_forkchoice(block_hash, block_hash).await?;
            }
            self.l1_parents.update(block, node.chain_id()).await?;
        }
        Ok(())
    }

    fn revert(&mut self, chain: &Chain) -> eyre::Result<()> {
        unimplemented!()
    }
}

/// Decode chain of blocks into a flattened list of receipt logs, filter only transactions to the
/// Rollup contract [`ROLLUP_CONTRACT_ADDRESS`] and extract [`RollupContractEvents`].
fn decode_chain_into_rollup_events(
    chain: &Chain,
) -> Vec<(&SealedBlockWithSenders, &TransactionSigned, RollupContractEvents)> {
    chain
        // Get all blocks and receipts
        .blocks_and_receipts()
        // Get all receipts
        .flat_map(|(block, receipts)| {
            block
                .body
                .iter()
                .zip(receipts.iter().flatten())
                .map(move |(tx, receipt)| (block, tx, receipt))
        })
        // Get all logs from rollup contract
        .flat_map(|(block, tx, receipt)| {
            receipt
                .logs
                .iter()
                .filter(|log| log.address == ROLLUP_CONTRACT_ADDRESS)
                .map(move |log| (block, tx, log))
        })
        // Decode and filter rollup events
        .filter_map(|(block, tx, log)| {
            RollupContractEvents::decode_raw_log(log.topics(), &log.data.data, true)
                .ok()
                .map(|event| (block, tx, event))
        })
        .collect()
}

fn decode_transactions(tx_list: &[u8]) -> Vec<TransactionSigned> {
    #[allow(clippy::useless_asref)]
    Vec::<TransactionSigned>::decode(&mut tx_list.as_ref()).unwrap_or_else(|e| {
        // If decoding fails we need to make an empty block
        println!("decode_transactions not successful: {e:?}, use empty tx_list");
        vec![]
    })
}
