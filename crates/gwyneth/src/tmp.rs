//! This example shows how to implement a custom [EngineTypes].
//!
//! The [EngineTypes] trait can be implemented to configure the engine to work with custom types,
//! as long as those types implement certain traits.
//!
//! Custom payload attributes can be supported by implementing two main traits:
//!
//! [PayloadAttributes] can be implemented for payload attributes types that are used as
//! arguments to the `engine_forkchoiceUpdated` method. This type should be used to define and
//! _spawn_ payload jobs.
//!
//! [PayloadBuilderAttributes] can be implemented for payload attributes types that _describe_
//! running payload jobs.
//!
//! Once traits are implemented and custom types are defined, the [EngineTypes] trait can be
//! implemented:

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use std::{convert::Infallible, sync::Arc};

use alloy_consensus::Header;
use reth_node_builder::components::ComponentsBuilder;
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
    payload::{EngineApiMessageVersion, EngineObjectValidationError, PayloadOrAttributes}, validate_version_specific_fields, AddOnsContext, ConfigureEvm, ConfigureEvmEnv, EngineTypes, EngineValidator, FullNodeComponents, NextBlockEnvAttributes, PayloadAttributes, PayloadBuilderAttributes
};
use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
use reth_node_ethereum::{
    node::{
        EthereumConsensusBuilder, EthereumExecutorBuilder, EthereumNetworkBuilder,
        EthereumPoolBuilder,
    },
    EthEvmConfig,
};
use reth_payload_builder::{
    EthBuiltPayload, EthPayloadBuilderAttributes, PayloadBuilderError, PayloadBuilderHandle,
    PayloadBuilderService,
};
use reth_tracing::{RethTracer, Tracer};
use reth_trie_db::MerklePatriciaTrie;

// pub mod builder;
pub fn default_gwyneth_payload<EvmConfig, Pool, Client>(
    evm_config: EvmConfig,
    args: BuildArguments<Pool, Client, CustomPayloadBuilderAttributes, EthBuiltPayload>,
    initialized_cfg: CfgEnvWithHandlerCfg,
    initialized_block_env: BlockEnv,
) -> Result<BuildOutcome<EthBuiltPayload>, PayloadBuilderError>
where
    EvmConfig: ConfigureEvm<Header = Header>,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec = ChainSpec>,
    // SP: StateProviderFactory + ChainSpecProvider,
    Pool: TransactionPool,
{
    todo!()
}
/// A custom payload attributes type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomPayloadAttributes {
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

impl PayloadAttributes for CustomPayloadAttributes {
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
pub struct CustomPayloadBuilderAttributes {
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

impl PartialEq for CustomPayloadBuilderAttributes {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
            && self.transactions == other.transactions
            && self.gas_limit == other.gas_limit
            // && self.sync_provider == other.sync_provider
    }
}

impl Eq for CustomPayloadBuilderAttributes {}


impl PayloadBuilderAttributes for CustomPayloadBuilderAttributes {
    type RpcPayloadAttributes = CustomPayloadAttributes;
    type Error = Infallible;

    fn try_new(
        parent: B256,
        attributes: CustomPayloadAttributes,
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
pub struct CustomEngineTypes;

impl PayloadTypes for CustomEngineTypes {
    type BuiltPayload = EthBuiltPayload;
    type PayloadAttributes = CustomPayloadAttributes;
    type PayloadBuilderAttributes = CustomPayloadBuilderAttributes;
}

impl EngineTypes for CustomEngineTypes {
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
    T: EngineTypes<PayloadAttributes = CustomPayloadAttributes>,
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
pub struct CustomEngineValidatorBuilder;

impl<N> EngineValidatorBuilder<N> for CustomEngineValidatorBuilder
where
    N: FullNodeComponents<
        Types: NodeTypesWithEngine<Engine = CustomEngineTypes, ChainSpec = ChainSpec>,
    >,
{
    type Validator = CustomEngineValidator;

    async fn build(self, ctx: &AddOnsContext<'_, N>) -> eyre::Result<Self::Validator> {
        Ok(CustomEngineValidator { chain_spec: ctx.config.chain.clone() })
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
struct MyCustomNode;

/// Configure the node types
impl NodeTypes for MyCustomNode {
    type Primitives = ();
    type ChainSpec = ChainSpec;
    type StateCommitment = MerklePatriciaTrie;
}

/// Configure the node types with the custom engine types
impl NodeTypesWithEngine for MyCustomNode {
    type Engine = CustomEngineTypes;
}

/// Custom addons configuring RPC types
pub type MyNodeAddOns<N> = RpcAddOns<
    N,
    EthApi<
        <N as FullNodeTypes>::Provider,
        <N as FullNodeComponents>::Pool,
        NetworkHandle,
        <N as FullNodeComponents>::Evm,
    >,
    CustomEngineValidatorBuilder,
>;

/// Implement the Node trait for the custom node
///
/// This provides a preset configuration for the node
impl<N> Node<N> for MyCustomNode
where
    N: FullNodeTypes<Types: NodeTypesWithEngine<Engine = CustomEngineTypes, ChainSpec = ChainSpec>>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        EthereumPoolBuilder,
        CustomPayloadServiceBuilder,
        EthereumNetworkBuilder,
        EthereumExecutorBuilder,
        EthereumConsensusBuilder,
    >;
    type AddOns = MyNodeAddOns<
        NodeAdapter<N, <Self::ComponentsBuilder as NodeComponentsBuilder<N>>::Components>,
    >;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        ComponentsBuilder::default()
            .node_types::<N>()
            .pool(EthereumPoolBuilder::default())
            .payload(CustomPayloadServiceBuilder::default())
            .network(EthereumNetworkBuilder::default())
            .executor(EthereumExecutorBuilder::default())
            .consensus(EthereumConsensusBuilder::default())
    }

    fn add_ons(&self) -> Self::AddOns {
        MyNodeAddOns::default()
    }
}

/// A custom payload service builder that supports the custom engine types
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct CustomPayloadServiceBuilder;

impl<Node, Pool> PayloadServiceBuilder<Node, Pool> for CustomPayloadServiceBuilder
where
    Node: FullNodeTypes<
        Types: NodeTypesWithEngine<Engine = CustomEngineTypes, ChainSpec = ChainSpec>,
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
    type Attributes = CustomPayloadBuilderAttributes;
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

#[tokio::test]
async fn test() -> eyre::Result<()> {
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
        .testing_node(tasks.executor())
        .launch_node(MyCustomNode::default())
        .await
        .unwrap();

    println!("Node started");

    handle.node_exit_future.await
}
