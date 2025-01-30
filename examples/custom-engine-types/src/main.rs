use std::{convert::Infallible, path::PathBuf, sync::Arc};

use alloy_consensus::Header;
use node::{GwynethFullNode1, GwynethFullNode2};
use reth_db::DatabaseEnv;
use reth_node_builder::{DefaultNodeLauncher, EngineNodeLauncher, LaunchNode};
use reth_primitives::EthPrimitives;
use reth_provider::providers::{BlockchainProvider2, ProviderNodeTypes};
use reth_tasks::TaskExecutor;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use alloy_eips::eip4895::Withdrawals;
use alloy_genesis::Genesis;
use alloy_primitives::{map::HashMap, Address, ChainId, B256};
use alloy_rpc_types::{
    engine::{
        ExecutionPayloadEnvelopeV2, ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4,
        ExecutionPayloadV1, PayloadAttributes as EthPayloadAttributes, PayloadId,
    }, Withdrawal
};
use reth::{
    api::PayloadTypes, builder::{
        components::{ComponentsBuilder, PayloadServiceBuilder},
        node::{NodeTypes, NodeTypesWithEngine},
        rpc::{EngineValidatorBuilder, RpcAddOns},
        BuilderContext, FullNodeTypes, Node, NodeAdapter, NodeBuilder, NodeComponentsBuilder,
        PayloadBuilderConfig,
    }, network::NetworkHandle, primitives::{transaction::WithEncoded, TransactionSigned}, providers::{CanonStateSubscriptions, StateProviderBox, StateProviderFactory}, revm::primitives::{BlockEnv, CfgEnvWithHandlerCfg}, rpc::eth::EthApi, tasks::TaskManager, transaction_pool::TransactionPool
};
use reth_basic_payload_builder::{
    BasicPayloadJobGenerator, BasicPayloadJobGeneratorConfig, BuildArguments, BuildOutcome,
    PayloadBuilder, PayloadConfig,
};
use reth_chainspec::{Chain, ChainSpec, ChainSpecProvider};
use reth_node_api::{
    payload::{EngineApiMessageVersion, EngineObjectValidationError, PayloadOrAttributes}, validate_version_specific_fields, AddOnsContext, ConfigureEvm, ConfigureEvmEnv, EngineTypes, EngineValidator, FullNodeComponents, NextBlockEnvAttributes, NodeTypesWithDB, NodeTypesWithDBAdapter, PayloadAttributes, PayloadBuilderAttributes
};
use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
use reth_node_ethereum::{
    node::{
        EthereumAddOns, EthereumConsensusBuilder, EthereumExecutorBuilder, EthereumNetworkBuilder, EthereumPoolBuilder
    },
    EthEvmConfig, EthereumNode,
};
use reth_payload_builder::{
    EthBuiltPayload, EthPayloadBuilderAttributes, PayloadBuilderError, PayloadBuilderHandle,
    PayloadBuilderService,
};
use reth_tracing::{RethTracer, Tracer};
use reth_trie_db::MerklePatriciaTrie;
use builder::default_gwyneth_payload;

pub mod builder;
pub mod cli;
pub mod node;

/// A custom payload attributes type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GwynethPayloadAttributes {
    /// An inner payload type
    #[serde(flatten)]
    pub inner: EthPayloadAttributes,
    /// A custom field
    pub custom: u64,
    /// Transactions is a field for rollups: the transactions list is forced into the block
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transactions: Option<Vec<TransactionSigned>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,
}

/// Custom error type used in payload attributes validation
#[derive(Debug, Error)]
pub enum CustomError {
    #[error("Custom field is not zero")]
    CustomFieldIsNotZero,
}

impl PayloadAttributes for GwynethPayloadAttributes {
    fn timestamp(&self) -> u64 {
        self.inner.timestamp()
    }

    fn withdrawals(&self) -> Option<&Vec<Withdrawal>> {
        self.inner.withdrawals()
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.inner.parent_beacon_block_root()
    }
}

/// New type around the payload builder attributes type
#[derive(Clone, Debug)]
pub struct GwynethPayloadBuilderAttributes {
    /// Inner ethereum payload builder attributes
    pub inner: EthPayloadBuilderAttributes,
    /// Decoded transactions and the original EIP-2718 encoded bytes as received in the payload
    /// attributes.
    pub transactions: Vec<WithEncoded<TransactionSigned>>,
    /// The gas limit for the generated payload
    pub gas_limit: Option<u64>,
    /// Cross-chain provider for L1
    pub sync_provider: Option<HashMap<ChainId, Arc<StateProviderBox>>>,
}

impl PartialEq for GwynethPayloadBuilderAttributes {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
            && self.transactions == other.transactions
            && self.gas_limit == other.gas_limit
            // && self.sync_provider == other.sync_provider
    }
}

impl Eq for GwynethPayloadBuilderAttributes {}


impl PayloadBuilderAttributes for GwynethPayloadBuilderAttributes {
    type RpcPayloadAttributes = GwynethPayloadAttributes;
    type Error = Infallible;

    fn try_new(
        parent: B256,
        attributes: GwynethPayloadAttributes,
        _version: u8,
    ) -> Result<Self, Infallible> {
        let transactions = attributes
            .transactions
            .unwrap_or_default()
            .into_iter()
            .map(|tx| {
                let mut buf = Vec::with_capacity(128 + tx.transaction.input().len());
                tx.eip2718_encode(tx.signature(), &mut buf);
                WithEncoded::new(buf.into(), tx)
            })
            .collect();

        Ok(Self {
            inner: EthPayloadBuilderAttributes::new(parent, attributes.inner),
            transactions,
            gas_limit: attributes.gas_limit,
            sync_provider: None,
        })    }

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

/// Custom engine types - uses a custom payload attributes RPC type, but uses the default
/// payload builder attributes type.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[non_exhaustive]
pub struct GwynethEngineTypes;

impl PayloadTypes for GwynethEngineTypes {
    type BuiltPayload = EthBuiltPayload;
    type PayloadAttributes = GwynethPayloadAttributes;
    type PayloadBuilderAttributes = GwynethPayloadBuilderAttributes;
}

impl EngineTypes for GwynethEngineTypes {
    type ExecutionPayloadEnvelopeV1 = ExecutionPayloadV1;
    type ExecutionPayloadEnvelopeV2 = ExecutionPayloadEnvelopeV2;
    type ExecutionPayloadEnvelopeV3 = ExecutionPayloadEnvelopeV3;
    type ExecutionPayloadEnvelopeV4 = ExecutionPayloadEnvelopeV4;
}

/// Custom engine validator
#[derive(Debug, Clone)]
pub struct CustomEngineValidator {
    chain_spec: Arc<ChainSpec>,
}

impl<T> EngineValidator<T> for CustomEngineValidator
where
    T: EngineTypes<PayloadAttributes = GwynethPayloadAttributes>,
{
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, T::PayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        validate_version_specific_fields(&self.chain_spec, version, payload_or_attrs)
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &T::PayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        validate_version_specific_fields(&self.chain_spec, version, attributes.into())?;

        // custom validation logic - ensure that the custom field is not zero
        if attributes.custom == 0 {
            return Err(EngineObjectValidationError::invalid_params(
                CustomError::CustomFieldIsNotZero,
            ))
        }

        Ok(())
    }
}

/// Custom engine validator builder
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct GwynethEngineValidatorBuilder;

impl<N> EngineValidatorBuilder<N> for GwynethEngineValidatorBuilder
where
    N: FullNodeComponents<
        Types: NodeTypesWithEngine<Engine = GwynethEngineTypes, ChainSpec = ChainSpec>,
    >,
{
    type Validator = CustomEngineValidator;

    async fn build(self, ctx: &AddOnsContext<'_, N>) -> eyre::Result<Self::Validator> {
        Ok(CustomEngineValidator { chain_spec: ctx.config.chain.clone() })
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
struct GwynethNode;

impl NodeTypes for GwynethNode {
    type Primitives = EthPrimitives;
    type ChainSpec = ChainSpec;
    type StateCommitment = MerklePatriciaTrie;
}

impl NodeTypesWithEngine for GwynethNode {
    type Engine = GwynethEngineTypes;
}

impl NodeTypesWithDB for GwynethNode {
    type DB = Arc<DatabaseEnv>;
}

pub type GwynethAddOns<N> = RpcAddOns<
    N,
    EthApi<
        <N as FullNodeTypes>::Provider,
        <N as FullNodeComponents>::Pool,
        NetworkHandle,
        <N as FullNodeComponents>::Evm,
    >,
    GwynethEngineValidatorBuilder,
>;


impl<N> Node<N> for GwynethNode
where
    N: FullNodeTypes<Types: NodeTypesWithEngine<Engine = GwynethEngineTypes, ChainSpec = ChainSpec>>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        EthereumPoolBuilder,
        GwynethPayloadServiceBuilder,
        EthereumNetworkBuilder,
        EthereumExecutorBuilder,
        EthereumConsensusBuilder,
    >;
    type AddOns = GwynethAddOns<
        NodeAdapter<N, <Self::ComponentsBuilder as NodeComponentsBuilder<N>>::Components>,
    >;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        ComponentsBuilder::default()
            .node_types::<N>()
            .pool(EthereumPoolBuilder::default())
            .payload(GwynethPayloadServiceBuilder::default())
            .network(EthereumNetworkBuilder::default())
            .executor(EthereumExecutorBuilder::default())
            .consensus(EthereumConsensusBuilder::default())
    }

    fn add_ons(&self) -> Self::AddOns {
        GwynethAddOns::default()
    }
}

/// A custom payload service builder that supports the custom engine types
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct GwynethPayloadServiceBuilder;

impl<Node, Pool> PayloadServiceBuilder<Node, Pool> for GwynethPayloadServiceBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypesWithEngine<Engine = GwynethEngineTypes, ChainSpec = ChainSpec>,
    >,
    Pool: TransactionPool + Unpin + 'static,
{
    async fn spawn_payload_service(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<PayloadBuilderHandle<<Node::Types as NodeTypesWithEngine>::Engine>> {
        let payload_builder = CustomPayloadBuilder::default();
        let conf = ctx.payload_builder_config();

        let payload_job_config = BasicPayloadJobGeneratorConfig::default()
            .interval(conf.interval())
            .deadline(conf.deadline())
            .max_payload_tasks(conf.max_payload_tasks())
            .extradata(conf.extradata_bytes());

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

/// The type responsible for building custom payloads
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct CustomPayloadBuilder;

impl<Pool, Client> PayloadBuilder<Pool, Client> for CustomPayloadBuilder
where
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec = ChainSpec>,
    Pool: TransactionPool,
{
    type Attributes = GwynethPayloadBuilderAttributes;
    type BuiltPayload = EthBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<Pool, Client, Self::Attributes, Self::BuiltPayload>,
    ) -> Result<BuildOutcome<Self::BuiltPayload>, PayloadBuilderError> {
        let BuildArguments { client, pool, cached_reads, config, cancel, best_payload } = &args;
        let next_attributes = NextBlockEnvAttributes {
            timestamp: config.attributes.timestamp(),
            suggested_fee_recipient: config.attributes.suggested_fee_recipient(),
            prev_randao: config.attributes.prev_randao(),
        };
        let PayloadConfig { parent_header, extra_data, attributes } = config;

        let chain_spec = client.chain_spec();
        let evm_config = EthEvmConfig::new(chain_spec.clone());
        let (cfg_env, block_env) = evm_config.next_cfg_and_block_env(parent_header.header(), next_attributes).unwrap();

        default_gwyneth_payload(evm_config, args, cfg_env, block_env)
    }

    fn build_empty_payload(
        &self,
        client: &Client,
        config: PayloadConfig<Self::Attributes>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        let PayloadConfig { parent_header, extra_data, attributes } = config;
        let chain_spec = client.chain_spec();
        <reth_ethereum_payload_builder::EthereumPayloadBuilder as PayloadBuilder<Pool, Client>>::build_empty_payload(&reth_ethereum_payload_builder::EthereumPayloadBuilder::new(EthEvmConfig::new(chain_spec.clone())),client,
                                                                                                                     PayloadConfig { parent_header, extra_data, attributes: attributes.inner})
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _guard = RethTracer::new().init()?;

    let tasks = TaskManager::current();

    // create optimism genesis with canyon at block 2
    let spec = ChainSpec::builder()
        .chain(Chain::mainnet())
        .genesis(Genesis::default())
        .london_activated()
        .paris_activated()
        .shanghai_activated()
        .build();

    // create node config
    let node_config =
        NodeConfig::test().with_rpc(RpcServerArgs::default().with_http()).with_chain(spec);

    let handle = NodeBuilder::new(node_config)
        .with_gwyneth_launch_context(TaskManager::current().executor(), PathBuf::new())
        .launch_node(GwynethNode::default())
        .await
        .unwrap();
    let a: GwynethFullNode1 = handle.node.clone();

    println!("Node started");

    handle.node_exit_future.await
}


async fn main__() -> eyre::Result<()> {
    let _guard = RethTracer::new().init()?;

    let tasks = TaskManager::current();

    // create optimism genesis with canyon at block 2
    let spec = ChainSpec::builder()
        .chain(Chain::mainnet())
        .genesis(Genesis::default())
        .london_activated()
        .paris_activated()
        .shanghai_activated()
        .build();

    // create node config
    let node_config =
        NodeConfig::test().with_rpc(RpcServerArgs::default().with_http()).with_chain(spec);

    
    let handle = NodeBuilder::new(node_config)
        .with_gwyneth_launch_context(TaskManager::current().executor(), PathBuf::new())
        .with_types_and_provider::<GwynethNode, BlockchainProvider2<NodeTypesWithDBAdapter<GwynethNode, Arc<DatabaseEnv>>>>()
        .with_components({
            GwynethNode::components_builder(&GwynethNode::default())
        })
        .with_add_ons(GwynethAddOns::default())
        .launch_with_fn(|launch_ctx| { 
            let launcher = EngineNodeLauncher::new(
                launch_ctx.task_executor.clone(),
                launch_ctx.builder.config.datadir(),
                Default::default(),
            );
            launch_ctx.launch_with(launcher)
        }).await?;

    // let a: GwynethFullNode2 = handle.node.clone();

    println!("Node started");

    handle.node_exit_future.await
}