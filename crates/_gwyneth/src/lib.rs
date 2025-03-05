//! Ethereum Node types config.
use std::{fmt::Debug, path::PathBuf, sync::Arc};

use alloy_consensus::Header;
use alloy_rpc_types_engine::PayloadAttributes;
use builder::default_gwyneth_payload_builder;
use reth_consensus::Consensus;
use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
use reth_evm_ethereum::EthEvmConfig;
use reth_primitives::{BlockHash, ChainId, EthPrimitives};
use reth_tasks::TaskManager;
use revm::primitives::CfgEnvWithHandlerCfg;
use thiserror::Error;

use reth_basic_payload_builder::{
    BasicPayloadJobGenerator, BasicPayloadJobGeneratorConfig, BuildArguments, BuildOutcome,
    PayloadBuilder, PayloadConfig,
};
use reth_chainspec::{Chain, ChainSpec};
use reth_ethereum_engine_primitives::{
    EthBuiltPayload, EthPayloadAttributes, EthPayloadBuilderAttributes, ExecutionPayloadEnvelopeV2,
    ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4,
};
use reth_node_api::{
    payload::{EngineApiMessageVersion, EngineObjectValidationError, PayloadOrAttributes}, validate_version_specific_fields, EngineTypes, NodeTypesWithEngine, PayloadAttributes, PayloadBuilderAttributes, PayloadBuilderError
};
use reth_node_builder::{
    components::{ComponentsBuilder, PayloadServiceBuilder, PoolBuilder}, node::{FullNodeTypes, NodeTypes}, BuilderContext, Node, NodeBuilder, NodeComponentsBuilder, NodeConfig, PayloadBuilderConfig, PayloadTypes
};
use reth_node_core::{
    args::RpcServerArgs,
    primitives::{
        revm_primitives::{BlockEnv, CfgEnvWithHandlerCfg},
        transaction::WithEncoded,
        Address, Genesis, Header, TransactionSigned, Withdrawals, B256,
    },
};
use reth_node_ethereum::node::{
    EthereumAddOns, EthereumConsensusBuilder, EthereumExecutorBuilder, EthereumNetworkBuilder,
    EthereumPoolBuilder,
};
use reth_payload_builder::{
    error::PayloadBuilderError, PayloadBuilderHandle, PayloadBuilderService, PayloadId,
};
use reth_provider::{
    providers::BlockchainProvider, CanonStateSubscriptions, ChainSpecProvider, StateProviderBox, StateProviderFactory
};
use reth_rpc_types::{ExecutionPayloadV1, Withdrawal};
use reth_tracing::{RethTracer, Tracer};
use reth_transaction_pool::{
    blobstore, test_utils::TestPoolBuilder, CoinbaseTipOrdering, EthPooledTransaction, EthTransactionValidator, Pool, TransactionPool, TransactionValidationTaskExecutor
};
use serde::{Deserialize, Serialize};

pub mod builder;
pub mod cli;
pub mod engine_api;
pub mod exex;

/// Gwyneth error type used in payload attributes validation
#[derive(Debug, Error)]
pub enum GwynetError {
    #[error("Gwyneth field is not zero")]
    RlpError(alloy_rlp::Error),
}

/// Gwyneth Payload Attributes
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GwynethPayloadAttributes {
    /// The payload attributes
    #[serde(flatten)]
    pub inner: EthPayloadAttributes,
    /// Transactions is a field for rollups: the transactions list is forced into the block
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transactions: Option<Vec<TransactionSigned>>,
    /// If set, this sets the exact gas limit the block produced with.
    #[serde(skip_serializing_if = "Option::is_none", with = "alloy_serde::quantity::opt")]
    pub gas_limit: Option<u64>,
}

impl PayloadAttributes for GwynethPayloadAttributes {
    fn timestamp(&self) -> u64 {
        self.inner.timestamp
    }

    fn withdrawals(&self) -> Option<&Vec<Withdrawal>> {
        self.inner.withdrawals.as_ref()
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.inner.parent_beacon_block_root
    }
}

/// Gwyneth Payload Builder Attributes
#[derive(Clone, Debug)]
pub struct GwynethPayloadBuilderAttributes<SyncProvider> {
    /// Inner ethereum payload builder attributes
    pub inner: EthPayloadBuilderAttributes,
    /// Decoded transactions and the original EIP-2718 encoded bytes as received in the payload
    /// attributes.
    pub transactions: Vec<WithEncoded<TransactionSigned>>,
    /// The gas limit for the generated payload
    pub gas_limit: Option<u64>,
    /// Cross-chain provider for L1
    /// TODO: make this HashMap<ChainId, SyncProvider> for multiple chains
    pub l1_provider: Option<(ChainId, SyncProvider)>,
}

impl<SyncProvider: Debug + Sync + Send> PayloadBuilderAttributes
    for GwynethPayloadBuilderAttributes<SyncProvider>
{
    type RpcPayloadAttributes = GwynethPayloadAttributes;
    type Error = alloy_rlp::Error;

    fn try_new(
        parent: B256,
        // TODO: make this EthAttributea
        attributes: GwynethPayloadAttributes,
        _version: u8,
    ) -> Result<Self, alloy_rlp::Error> {
        let transactions = attributes
            .transactions
            .unwrap_or_default()
            .into_iter()
            .map(|tx| WithEncoded::new(tx.envelope_encoded(), tx))
            .collect();

        Ok(Self {
            inner: EthPayloadBuilderAttributes::new(parent, attributes.inner),
            transactions,
            gas_limit: attributes.gas_limit,
            l1_provider: None,
        })
    }

    fn payload_id(&self) -> PayloadId {
        self.inner.id
    }

    fn parent(&self) -> B256 {
        self.inner.parent
    }

    fn timestamp(&self) -> u64 {
        self.inner.timestamp
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.inner.parent_beacon_block_root
    }

    fn suggested_fee_recipient(&self) -> Address {
        self.inner.suggested_fee_recipient
    }

    fn prev_randao(&self) -> B256 {
        self.inner.prev_randao
    }

    fn withdrawals(&self) -> &Withdrawals {
        &self.inner.withdrawals
    }
}

/// Gwyneth engine types - uses a Gwyneth payload attributes RPC type, but uses the default
/// payload builder attributes type.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[non_exhaustive]
pub struct GwynethEngineTypes;

impl PayloadTypes for GwynethEngineTypes {
    type BuiltPayload = EthBuiltPayload;
    type PayloadAttributes = GwynethPayloadAttributes;
    type PayloadBuilderAttributes = GwynethPayloadBuilderAttributes<Self::SyncProvider>;
    type SyncProvider = Arc<StateProviderBox>;
}

impl EngineTypes for GwynethEngineTypes {
    type ExecutionPayloadEnvelopeV1 = ExecutionPayloadV1;
    type ExecutionPayloadEnvelopeV2 = ExecutionPayloadEnvelopeV2;
    type ExecutionPayloadEnvelopeV3 = ExecutionPayloadEnvelopeV3;
    type ExecutionPayloadEnvelopeV4 = ExecutionPayloadEnvelopeV4;
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct GwynethNode;

/// Configure the node types
impl NodeTypes for GwynethNode {
    type Primitives = ();
    // use ethereum chain spec
    type ChainSpec = ChainSpec;
    // use the Gwyneth engine types
    type StateCommitment = MerklePatriciaTrie;
}

impl GwynethNode {
    /// Returns a [`ComponentsBuilder`] configured for a regular Ethereum node.
    pub fn components<Node>() -> ComponentsBuilder<
        Node,
        EthereumPoolBuilder,
        GwynethPayloadBuilder,
        EthereumNetworkBuilder,
        EthereumExecutorBuilder,
        EthereumConsensusBuilder,
    >
    where
        Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec>>,
        <Node::Types as NodeTypesWithEngine>::Engine: PayloadTypes<
            BuiltPayload = EthBuiltPayload,
            PayloadAttributes = GwynethPayloadAttributes,
            PayloadBuilderAttributes = GwynethPayloadBuilderAttributes,
        >,
    {
        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(EthereumPoolBuilder::default())
            .payload(GwynethPayloadBuilder::default())
            .network(EthereumNetworkBuilder::default())
            .executor(EthereumExecutorBuilder::default())
            .consensus(EthereumConsensusBuilder::default())
    }
}

/// Implement the Node trait for the Gwyneth node
///
/// This provides a preset configuration for the node
impl<N> Node<N> for GwynethNode
where
    N: FullNodeTypes<Types: NodeTypesWithEngine<Engine = GwynethEngineTypes, ChainSpec = ChainSpec>>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        TestPoolBuilder,
        GwynethPayloadBuilder,
        EthereumNetworkBuilder,
        EthereumExecutorBuilder,
        EthereumConsensusBuilder,
    >;
    type AddOns = EthereumAddOns<
        NodeAdapter<N, <Self::ComponentsBuilder as NodeComponentsBuilder<N>>::Components>,
    >;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        Self::components()
    }

    fn add_ons(&self) -> Self::AddOns {
        EthereumAddOns::default()
    }
}

impl NodeTypesWithEngine for GwynethNode {
    type Engine = GwynethEngineTypes;
}

/// The type responsible for building Gwyneth payloads
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct GwynethPayloadBuilder<EvmConfig = EthEvmConfig> {
    /// The type responsible for creating the evm.
    evm_config: EvmConfig,
}

impl<EvmConfig> GwynethPayloadBuilder<EvmConfig> {
    /// `EthereumPayloadBuilder` constructor.
    pub const fn new(evm_config: EvmConfig) -> Self {
        Self { evm_config }
    }
}

impl<EvmConfig> GwynethPayloadBuilder<EvmConfig>
where
    EvmConfig: ConfigureEvm<Header = Header>,
{
    /// Returns the configured [`CfgEnvWithHandlerCfg`] and [`BlockEnv`] for the targeted payload
    /// (that has the `parent` as its parent).
    fn cfg_and_block_env(
        &self,
        config: &PayloadConfig<GwynethPayloadBuilderAttributes>,
        parent: &Header,
    ) -> Result<(CfgEnvWithHandlerCfg, BlockEnv), EvmConfig::Error> {
        let next_attributes = NextBlockEnvAttributes {
            timestamp: config.attributes.timestamp(),
            suggested_fee_recipient: config.attributes.suggested_fee_recipient(),
            prev_randao: config.attributes.prev_randao(),
        };
        self.evm_config.next_cfg_and_block_env(parent, next_attributes)
    }
}

impl<EvmConfig, Pool, Client> PayloadBuilder<Pool, Client> for GwynethPayloadBuilder<EvmConfig>
where
    EvmConfig: ConfigureEvm<Header = Header>,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec = ChainSpec>,
    Pool: TransactionPool,
{
    type Attributes = GwynethPayloadBuilderAttributes<Arc<StateProviderBox>>;
    type BuiltPayload = EthBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<Pool, Client, GwynethPayloadBuilderAttributes, EthBuiltPayload>,
    ) -> Result<BuildOutcome<Self::BuiltPayload>, PayloadBuilderError> {
        let (cfg_env, block_env) = self
            .cfg_and_block_env(&args.config, &args.config.parent_header)
            .map_err(PayloadBuilderError::other)?;

        let pool = args.pool.clone();
        default_gwyneth_payload(self.evm_config.clone(), args, cfg_env, block_env, |attributes| {
            pool.best_transactions_with_attributes(attributes)
        })
    }

    fn build_empty_payload(
        &self,
        client: &Client,
        config: PayloadConfig<Self::Attributes>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        let PayloadConfig {
            parent_header,
            extra_data,
            attributes,
        } = config;
        let payload_builder = GwynethPayloadBuilder::new(EthEvmConfig::new(chain_spec.clone()));
        payload_builder.build_empty_payload(client, config)
    }
}

pub struct GwynethPayloadServiceBuilder;

impl GwynethPayloadServiceBuilder {
    /// A helper method initializing [`PayloadBuilderService`] with the given EVM config.
    pub fn spawn<Types, Node, Evm, Pool>(
        self,
        evm_config: Evm,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<PayloadBuilderHandle<Types::Engine>>
    where
        Types: NodeTypesWithEngine<ChainSpec = ChainSpec>,
        Node: FullNodeTypes<Types = Types>,
        Evm: ConfigureEvm<Header = Header>,
        Pool: TransactionPool + Unpin + 'static,
        Types::Engine: PayloadTypes<
            BuiltPayload = EthBuiltPayload,
            PayloadAttributes = GwynethPayloadAttributes,
            PayloadBuilderAttributes = EthPayloadBuilderAttributes,
        >,
    {
        let conf = ctx.payload_builder_config();
        let payload_builder = GwynethPayloadBuilder::new(evm_config);

        let payload_job_config = BasicPayloadJobGeneratorConfig::default()
            .interval(conf.interval())
            .deadline(conf.deadline())
            .max_payload_tasks(conf.max_payload_tasks());

        let payload_generator = BasicPayloadJobGenerator::with_builder(
            ctx.provider().clone(),
            pool,
            ctx.task_executor().clone(),
            payload_job_config,
            payload_builder,
        );
        let (payload_service, payload_builder) =
            PayloadBuilderService::new(payload_generator, ctx.provider().canonical_state_stream());

        ctx.task_executor().spawn_critical("payload builder service", Box::pin(payload_service));

        Ok(payload_builder)
    }
}



impl<Types, Node, Pool> PayloadServiceBuilder<Node, Pool> for GwynethPayloadBuilder
where
    Types: NodeTypesWithEngine<ChainSpec = ChainSpec>,
    Node: FullNodeTypes<Types = Types>,
    Pool: TransactionPool + Unpin + 'static,
    Types::Engine: PayloadTypes<
        BuiltPayload = EthBuiltPayload,
        PayloadAttributes = GwynethPayloadAttributes,
        PayloadBuilderAttributes = EthPayloadBuilderAttributes,
    >,
{
    async fn spawn_payload_service(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<PayloadBuilderHandle<Types::Engine>> {
        self.spawn(EthEvmConfig::new(ctx.chain_spec()), ctx, pool)
    }
}


#[tokio::test]
async fn test() -> eyre::Result<()> {
    let _guard = RethTracer::new().init()?;

    let tasks = TaskManager::current();

    // create gwyneth genesis with canyon at block 2
    let spec = ChainSpec::builder()
        .chain(Chain::mainnet())
        .genesis(Genesis::default())
        .london_activated()
        .paris_activated()
        .shanghai_activated()
        .build();

    // create node config
    let node_config =
        NodeConfig::default().with_rpc(RpcServerArgs::default().with_http()).with_chain(spec);

    let handle = NodeBuilder::new(node_config)
        .with_gwyneth_launch_context(tasks.executor(), PathBuf::from("/tmp/gwyneth"))
        .node(GwynethNode::default())
        .launch()
        .await?;

    handle.node_exit_future.await
}
