use alloy_eips::eip4895::{Withdrawal, Withdrawals};
use builder::default_gwyneth_payload;
use eyre::Chain;
use reth_basic_payload_builder::{BasicPayloadJobGenerator, BuildArguments, BuildOutcome, PayloadBuilder, PayloadConfig};
use reth_chainspec::ChainSpec;
use reth_ethereum_engine_primitives::{
    EthPayloadAttributes, EthereumEngineValidator, ExecutionPayloadEnvelopeV2, ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4, ExecutionPayloadV1
};
use reth_ethereum_payload_builder::EthereumPayloadBuilder;
use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
use reth_evm_ethereum::EthEvmConfig;
use reth_network::NetworkHandle;
use reth_node_api::{
    validate_version_specific_fields, AddOnsContext, EngineApiMessageVersion, EngineObjectValidationError, EngineTypes, EngineValidator, FullNodeComponents, FullNodeTypes, NodeAddOns, NodeTypes, NodeTypesWithDB, NodeTypesWithEngine, PayloadAttributes, PayloadBuilderAttributes, PayloadBuilderError, PayloadOrAttributes, PayloadTypes
};
use reth_node_builder::{components::{ComponentsBuilder, PayloadServiceBuilder}, rpc::{EngineValidatorBuilder, RethRpcAddOns, RpcAddOns, RpcHandle}, BuilderContext, Node, NodeAdapter, NodeComponentsBuilder};
use reth_node_ethereum::{node::{EthereumAddOns, EthereumConsensusBuilder, EthereumEngineValidatorBuilder, EthereumExecutorBuilder, EthereumNetworkBuilder, EthereumPoolBuilder}, BasicBlockExecutorProvider, EthExecutionStrategyFactory};
use reth_payload_builder::{EthBuiltPayload, EthPayloadBuilderAttributes, PayloadBuilderHandle, PayloadBuilderService, PayloadId};
use reth_primitives::{transaction::WithEncoded, TransactionSigned};
use reth_provider::{ChainSpecProvider, StateProviderBox, StateProviderFactory};
use reth_rpc::{eth::EthereumEthApiTypes, EthApi};
use reth_transaction_pool::{blobstore::DiskFileBlobStore, noop::NoopTransactionPool, CoinbaseTipOrdering, EthPooledTransaction, EthTransactionValidator, TransactionPool, TransactionValidationTaskExecutor};
use reth_trie_db::MerklePatriciaTrie;
use reth_chain_state::CanonStateSubscriptions;
use reth_node_builder::PayloadBuilderConfig;
use reth_basic_payload_builder::BasicPayloadJobGeneratorConfig;
use alloy_consensus::{Header, EMPTY_OMMER_ROOT_HASH};

use revm::primitives::{alloy_primitives::ChainId, Address, BlockEnv, CfgEnvWithHandlerCfg, B256};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Debug, sync::Arc};

pub mod builder;
pub mod exex;
pub mod cli;
// pub mod rpc;
pub mod tmp;

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

impl PayloadBuilderAttributes for GwynethPayloadBuilderAttributes
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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[non_exhaustive]
pub struct GwynethEngineTypes;

impl PayloadTypes for GwynethEngineTypes {
    type BuiltPayload = EthBuiltPayload;
    type PayloadAttributes = GwynethPayloadAttributes;
    type PayloadBuilderAttributes = GwynethPayloadBuilderAttributes;
    // type SyncProvider = Arc<StateProviderBox>;
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

impl GwynethNode {
    /// Returns a [`ComponentsBuilder`] configured for a regular Ethereum node.
    pub fn components<Node>() -> ComponentsBuilder<
        Node,
        EthereumPoolBuilder,
        GwynethPayloadService,
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
            .payload(GwynethPayloadService::default())
            .network(EthereumNetworkBuilder::default())
            .executor(EthereumExecutorBuilder::default())
            .consensus(EthereumConsensusBuilder::default())
    }
}


// pub struct GwynethAddOns<N>(RpcAddOns<
//     N,
//     EthApi<
//         <N as FullNodeTypes>::Provider,
//         <N as FullNodeComponents>::Pool,
//         NetworkHandle,
//         <N as FullNodeComponents>::Evm,
//     >,
//     GwynethEngineValidatorBuilder,
// >);

// impl<N> NodeAddOns<N> for GwynethAddOns<N>
// where
//     N: FullNodeComponents<
//         Types: NodeTypes<ChainSpec = OpChainSpec>,
//         PayloadBuilder: PayloadBuilder<PayloadType = <N::Types as NodeTypesWithEngine>::Engine>,
//     >,
//     EthereumEngineValidator: EngineValidator<<N::Types as NodeTypesWithEngine>::Engine>,
// {
//     type Handle = RpcHandle<N, EthApi<N>>;

//     async fn launch_add_ons(
//         self,
//         ctx: reth_node_api::AddOnsContext<'_, N>,
//     ) -> eyre::Result<Self::Handle> {
//         // install additional OP specific rpc methods
//         self.0.launch_add_ons_with(ctx, |_| Ok(())).await

//     }
// }

impl<N> Node<N> for GwynethNode
where
    N: FullNodeTypes<Types: NodeTypesWithEngine<Engine = GwynethEngineTypes, ChainSpec = ChainSpec>>,
    // GwynethEngineValidatorBuilder: EngineValidatorBuilder<NodeAdapter<N, reth_node_builder::components::Components<N, reth_transaction_pool::Pool<TransactionValidationTaskExecutor<EthTransactionValidator<<N as FullNodeTypes>::Provider, EthPooledTransaction>>, CoinbaseTipOrdering<EthPooledTransaction>, DiskFileBlobStore>, EthEvmConfig, BasicBlockExecutorProvider<EthExecutionStrategyFactory>, Arc<(dyn reth_consensus::Consensus + 'static)>>>>
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        EthereumPoolBuilder,
        GwynethPayloadService,
        EthereumNetworkBuilder,
        EthereumExecutorBuilder,
        EthereumConsensusBuilder,
    >;
    type AddOns = ();

    fn components_builder(&self) -> Self::ComponentsBuilder {
        ComponentsBuilder::default()
            .node_types::<N>()
            .pool(EthereumPoolBuilder::default())
            .payload(GwynethPayloadService::default())
            .network(EthereumNetworkBuilder::default())
            .executor(EthereumExecutorBuilder::default())
            .consensus(EthereumConsensusBuilder::default())
    }

    fn add_ons(&self) -> Self::AddOns {
        ()
    }
}

impl NodeTypes for GwynethNode {
    type Primitives = ();
    // use ethereum chain spec
    type ChainSpec = ChainSpec;
    // use the Gwyneth engine types
    type StateCommitment = MerklePatriciaTrie;
}

impl NodeTypesWithEngine for GwynethNode {
    type Engine = GwynethEngineTypes;
}


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
    type Attributes = GwynethPayloadBuilderAttributes;
    type BuiltPayload = EthBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<Pool, Client, Self::Attributes, EthBuiltPayload>,
    ) -> Result<BuildOutcome<Self::BuiltPayload>, PayloadBuilderError> {
        let (cfg_env, block_env) = self
            .cfg_and_block_env(&args.config, (*args.config.parent_header).clone().header())
            .map_err(PayloadBuilderError::other)?;

        let pool = args.pool.clone();
        default_gwyneth_payload(self.evm_config.clone(), args, cfg_env, block_env)
    }

    fn build_empty_payload(
        &self,
        client: &Client,
        // depends on config.attributes.transactions is empty
        config: PayloadConfig<Self::Attributes>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        let args = BuildArguments::new(
            client,
            // we use defaults here because for the empty payload we don't need to execute anything
            NoopTransactionPool::default(),
            Default::default(),
            config,
            Default::default(),
            None,
        );
        assert!(args.config.attributes.transactions.is_empty(), "Transactions must be empty for empty payload");

        let (cfg_env, block_env) = self
            .cfg_and_block_env(&args.config, &args.config.parent_header)
            .map_err(PayloadBuilderError::other)?;

        default_gwyneth_payload(self.evm_config.clone(), args, cfg_env, block_env)?
        .into_payload()
        .ok_or_else(|| PayloadBuilderError::MissingPayload)
    }
}


#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct GwynethPayloadService;

impl GwynethPayloadService {
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
            PayloadBuilderAttributes = GwynethPayloadBuilderAttributes,
        >,
    {
        let payload_builder = GwynethPayloadBuilder::new(evm_config);
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

impl<Types, Node, Pool> PayloadServiceBuilder<Node, Pool> for GwynethPayloadService
where
    Types: NodeTypesWithEngine<ChainSpec = ChainSpec>,
    Node: FullNodeTypes<Types = Types>,
    Pool: TransactionPool + Unpin + 'static,
    Types::Engine: PayloadTypes<
        BuiltPayload = EthBuiltPayload,
        PayloadAttributes = GwynethPayloadAttributes,
        PayloadBuilderAttributes = GwynethPayloadBuilderAttributes,
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


// /// Add-ons w.r.t. optimism.
// #[derive(Debug)]
// pub struct GwynethAddOns<N: FullNodeComponents>(pub RpcAddOns<N, EthereumEthApiTypes, EthereumEngineValidatorBuilder>);

// impl<N: FullNodeComponents> Default for GwynethAddOns<N> {
//     fn default() -> Self {
//         Self::new()
//     }
// }

// impl<N: FullNodeComponents> GwynethAddOns<N> {
//     /// Create a new instance with the given `sequencer_http` URL.
//     pub fn new() -> Self {
//         Self(RpcAddOns::new(
//             move |ctx| EthereumEthApiTypes::default(), 
//             EthereumEngineValidatorBuilder::default()
//         ))
//     }
// }

// impl<N> NodeAddOns<N> for GwynethAddOns<N>
// where
//     N: FullNodeComponents<
//         Types: NodeTypes<ChainSpec = ChainSpec>,
//         PayloadBuilder: reth_payload_builder_primitives::traits::PayloadBuilder<PayloadType = <N::Types as NodeTypesWithEngine>::Engine>,
//     >,
//     EthereumEngineValidator: EngineValidator<<N::Types as NodeTypesWithEngine>::Engine>,
// {
//     type Handle = RpcHandle<N, EthereumEthApiTypes>;

//     async fn launch_add_ons(
//         self,
//         ctx: reth_node_api::AddOnsContext<'_, N>,
//     ) -> eyre::Result<Self::Handle> {
//         self.0.launch_add_ons(ctx)
//     }
// }


// impl<N, EthApi, EV> NodeAddOns<N> for RpcAddOns<N, EthApi, EV>
// where
//     N: FullNodeComponents<
//         Types: ProviderNodeTypes,
//         PayloadBuilder: reth_payload_builder_primitives::traits::PayloadBuilder<PayloadType = <N::Types as NodeTypesWithEngine>::Engine>,
//     >,
//     EthApi: EthApiTypes + FullEthApiServer + AddDevSigners + Unpin + 'static,
//     EV: EngineValidatorBuilder<N>,
// {
//     type Handle = RpcHandle<N, EthApi>;

//     async fn launch_add_ons(self, ctx: AddOnsContext<'_, N>) -> eyre::Result<Self::Handle> {
//         self.launch_add_ons_with(ctx, |_| Ok(())).await
//     }
// }


// impl<N> RethRpcAddOns<N> for GwynethAddOns<N>
// where
//     N: FullNodeComponents<
//         Types: NodeTypes<ChainSpec = OpChainSpec>,
//         PayloadBuilder: PayloadBuilder<PayloadType = <N::Types as NodeTypesWithEngine>::Engine>,
//     >,
//     EthereumEngineValidator: EngineValidator<<N::Types as NodeTypesWithEngine>::Engine>,
// {
//     type EthApi = EthereumEthApiTypes;

//     fn hooks_mut(&mut self) -> &mut reth_node_builder::rpc::RpcHooks<N, Self::EthApi> {
//         self.0.hooks_mut()
//     }
// }

#[test]
fn test() {
    println!("Hello, world!");
}
