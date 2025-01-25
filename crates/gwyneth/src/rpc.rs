// pub use receipt::{OpReceiptBuilder, OpReceiptFieldsBuilder};

use std::{fmt, sync::Arc};
use alloy_eips::BlockId;
use alloy_network::{Ethereum, Network};
use alloy_rpc_types_eth::{TransactionInfo, TransactionReceipt};
use derive_more::Deref;
use alloy_consensus::{Header, Transaction};
// use op_alloy_network::Optimism;
use reth_chainspec::{ChainSpec, EthChainSpec, EthereumHardforks};
use reth_evm::ConfigureEvm;
use reth_network::NetworkInfo;
use reth_node_api::{validate_version_specific_fields, EngineApiMessageVersion, EngineObjectValidationError, EngineTypes, EngineValidator, FullNodeComponents, NodeAddOns, NodeTypes, NodeTypesWithEngine, PayloadBuilder, PayloadOrAttributes};
use reth_node_builder::{rpc::{EngineValidatorBuilder, RethRpcAddOns, RpcAddOns, RpcHandle}, EthApiBuilderCtx};
use reth_primitives::TransactionMeta;
use reth_provider::{
    BlockNumReader, BlockReaderIdExt, CanonStateSubscriptions, ChainSpecProvider, EvmEnvProvider, HeaderProvider, StageCheckpointReader, StateProviderFactory, TransactionsProvider
};
use reth_rpc_eth_api::{helpers::{estimate::EstimateCall, Call, EthBlocks, EthCall, EthTransactions, LoadTransaction}, FromEthApiError, FullEthApiTypes, RpcReceipt, TransactionCompat};
use reth_rpc::eth::{core::EthApiInner, DevSigner, EthTxBuilder};
use reth_rpc_eth_api::{
    helpers::{
        AddDevSigners, EthApiSpec, EthFees, EthSigner, EthState, LoadBlock, LoadFee, LoadPendingBlock, LoadReceipt, LoadState, SpawnBlocking, Trace
    },
    EthApiTypes, RpcNodeCore, RpcNodeCoreExt,
};
use reth_rpc_eth_types::{EthApiError, EthReceiptBuilder, EthStateCache, FeeHistoryCache, GasPriceOracle};
use reth_tasks::{
    pool::{BlockingTaskGuard, BlockingTaskPool},
    TaskSpawner,
};
use reth_transaction_pool::TransactionPool;
use revm::primitives::U256;

use crate::{GwynethEngineTypes, GwynethPayloadAttributes, GwynethPayloadBuilder};

/// Adapter for [`EthApiInner`], which holds all the data required to serve core `eth_` API.
pub type EthApiNodeBackend<N> = EthApiInner<
    <N as RpcNodeCore>::Provider,
    <N as RpcNodeCore>::Pool,
    <N as RpcNodeCore>::Network,
    <N as RpcNodeCore>::Evm,
>;

/// OP-Reth `Eth` API implementation.
///
/// This type provides the functionality for handling `eth_` related requests.
///
/// This wraps a default `Eth` implementation, and provides additional functionality where the
/// optimism spec deviates from the default (ethereum) spec, e.g. transaction forwarding to the
/// sequencer, receipts, additional RPC fields for transaction receipts.
///
/// This type implements the [`FullEthApi`](reth_rpc_eth_api::helpers::FullEthApi) by implemented
/// all the `Eth` helper traits and prerequisite traits.
#[derive(Deref, Clone)]
pub struct GwynethEthApi<N: RpcNodeCore> {
    inner: Arc<EthApiNodeBackend<N>>,
}

impl<N> GwynethEthApi<N>
where
    N: RpcNodeCore<
        Provider: BlockReaderIdExt + ChainSpecProvider + CanonStateSubscriptions + Clone + 'static,
    >,
{
    /// Creates a new instance for given context.
    pub fn new(ctx: &EthApiBuilderCtx<N>) -> Self {
        let blocking_task_pool =
            BlockingTaskPool::build().expect("failed to build blocking task pool");

        let inner = EthApiInner::new(
            ctx.provider.clone(),
            ctx.pool.clone(),
            ctx.network.clone(),
            ctx.cache.clone(),
            ctx.new_gas_price_oracle(),
            ctx.config.rpc_gas_cap,
            ctx.config.rpc_max_simulate_blocks,
            ctx.config.eth_proof_window,
            blocking_task_pool,
            ctx.new_fee_history_cache(),
            ctx.evm_config.clone(),
            ctx.executor.clone(),
            ctx.config.proof_permits,
        );

        Self { inner: Arc::new(inner) }
    }
}

impl<N> EthApiTypes for GwynethEthApi<N>
where
    Self: Send + Sync,
    N: RpcNodeCore,
{
    type Error = EthApiError;
    type NetworkTypes = alloy_network::Ethereum;
    type TransactionCompat = Self;

    fn tx_resp_builder(&self) -> &Self::TransactionCompat {
        self
    }
}

impl<N> RpcNodeCore for GwynethEthApi<N>
where
    N: RpcNodeCore,
{
    type Provider = N::Provider;
    type Pool = N::Pool;
    type Evm = <N as RpcNodeCore>::Evm;
    type Network = <N as RpcNodeCore>::Network;
    type PayloadBuilder = ();

    #[inline]
    fn pool(&self) -> &Self::Pool {
        self.inner.pool()
    }

    #[inline]
    fn evm_config(&self) -> &Self::Evm {
        self.inner.evm_config()
    }

    #[inline]
    fn network(&self) -> &Self::Network {
        self.inner.network()
    }

    #[inline]
    fn payload_builder(&self) -> &Self::PayloadBuilder {
        &()
    }

    #[inline]
    fn provider(&self) -> &Self::Provider {
        self.inner.provider()
    }
}

impl<N> RpcNodeCoreExt for GwynethEthApi<N>
where
    N: RpcNodeCore,
{
    #[inline]
    fn cache(&self) -> &EthStateCache {
        self.inner.cache()
    }
}

impl<N> EthApiSpec for GwynethEthApi<N>
where
    N: RpcNodeCore<
        Provider: ChainSpecProvider<ChainSpec: EthereumHardforks>
                      + BlockNumReader
                      + StageCheckpointReader,
        Network: NetworkInfo,
    >,
{
    #[inline]
    fn starting_block(&self) -> U256 {
        self.inner.starting_block()
    }

    #[inline]
    fn signers(&self) -> &parking_lot::RwLock<Vec<Box<dyn EthSigner>>> {
        self.inner.signers()
    }
}

impl<N> SpawnBlocking for GwynethEthApi<N>
where
    Self: Send + Sync + Clone + 'static,
    N: RpcNodeCore,
{
    #[inline]
    fn io_task_spawner(&self) -> impl TaskSpawner {
        self.inner.task_spawner()
    }

    #[inline]
    fn tracing_task_pool(&self) -> &BlockingTaskPool {
        self.inner.blocking_task_pool()
    }

    #[inline]
    fn tracing_task_guard(&self) -> &BlockingTaskGuard {
        self.inner.blocking_task_guard()
    }
}

impl<N> LoadFee for GwynethEthApi<N>
where
    Self: LoadBlock<Provider = N::Provider>,
    N: RpcNodeCore<
        Provider: BlockReaderIdExt
                      + EvmEnvProvider
                      + ChainSpecProvider<ChainSpec: EthChainSpec + EthereumHardforks>
                      + StateProviderFactory,
    >,
{
    #[inline]
    fn gas_oracle(&self) -> &GasPriceOracle<Self::Provider> {
        self.inner.gas_oracle()
    }

    #[inline]
    fn fee_history_cache(&self) -> &FeeHistoryCache {
        self.inner.fee_history_cache()
    }
}

impl<N> LoadState for GwynethEthApi<N> where
    N: RpcNodeCore<
        Provider: StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks>,
        Pool: TransactionPool,
    >
{
}

impl<N> EthState for GwynethEthApi<N>
where
    Self: LoadState + SpawnBlocking,
    N: RpcNodeCore,
{
    #[inline]
    fn max_proof_window(&self) -> u64 {
        self.inner.eth_proof_window()
    }
}

impl<N> EthFees for GwynethEthApi<N>
where
    Self: LoadFee,
    N: RpcNodeCore,
{
}

impl<N> Trace for GwynethEthApi<N>
where
    Self: LoadState<Evm: ConfigureEvm<Header = Header>>,
    N: RpcNodeCore,
{
}

impl<N> AddDevSigners for GwynethEthApi<N>
where
    N: RpcNodeCore,
{
    fn with_dev_accounts(&self) {
        *self.inner.signers().write() = DevSigner::random_signers(20)
    }
}

impl<N: RpcNodeCore> fmt::Debug for GwynethEthApi<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GwynethEthApi").finish_non_exhaustive()
    }
}

impl<N> LoadPendingBlock for GwynethEthApi<N>
where
    Self: SpawnBlocking,
    N: RpcNodeCore<
        Provider: BlockReaderIdExt
                      + EvmEnvProvider
                      + ChainSpecProvider<ChainSpec: EthChainSpec + EthereumHardforks>
                      + StateProviderFactory,
        Pool: TransactionPool,
        Evm: ConfigureEvm<Header = Header>,
    >,
{
    fn pending_block(&self) -> &tokio::sync::Mutex<Option<reth_rpc_eth_types::PendingBlock>> {
        self.inner.pending_block()
    }
}

impl<N> LoadReceipt for GwynethEthApi<N>
where
    Self: Send + Sync,
    N: FullNodeComponents<Types: NodeTypes<ChainSpec = ChainSpec>>,
{
    async fn build_transaction_receipt(
        &self,
        tx: reth_primitives::TransactionSigned,
        meta: reth_primitives::TransactionMeta,
        receipt: reth_primitives::Receipt,
    ) -> Result<RpcReceipt<Self::NetworkTypes>, Self::Error> {
        let hash = meta.block_hash;
        // get all receipts for the block
        let all_receipts = self
            .cache()
            .get_receipts(hash)
            .await
            .map_err(Self::Error::from_eth_err)?
            .ok_or(EthApiError::HeaderNotFound(hash.into()))?;

        Ok(EthReceiptBuilder::new(&tx, meta, &receipt, &all_receipts)?.build())
    }
}

impl<N> LoadTransaction for GwynethEthApi<N>
where
    Self: SpawnBlocking + FullEthApiTypes,
    N: RpcNodeCore<Provider: TransactionsProvider, Pool: TransactionPool>,
{
}

impl<N> TransactionCompat for GwynethEthApi<N>
where
    N: FullNodeComponents,
{
    type Transaction = <Ethereum as Network>::TransactionResponse;
    type Error = EthApiError;
    
    fn fill(
        &self,
        tx: reth_primitives::TransactionSignedEcRecovered,
        tx_inf: TransactionInfo,
    ) -> Result<Self::Transaction, Self::Error> {
        let tx_builder = EthTxBuilder::default();
        tx_builder.fill(tx, tx_inf)
    }
    
    fn otterscan_api_truncate_input(tx: &mut Self::Transaction) {
        <EthTxBuilder as TransactionCompat>::otterscan_api_truncate_input(tx)
    }
}

impl<N> EthTransactions for GwynethEthApi<N>
where
    Self: LoadTransaction<Provider: BlockReaderIdExt>,
    N: RpcNodeCore,
{
    fn signers(&self) -> &parking_lot::RwLock<Vec<Box<dyn EthSigner>>> {
       self.inner.signers()
    }
}

impl<N> LoadBlock for GwynethEthApi<N>
where
    Self: LoadPendingBlock + SpawnBlocking,
    N: RpcNodeCore,
{
}

impl<N> EthCall for GwynethEthApi<N>
where
    Self: EstimateCall + LoadPendingBlock,
    N: RpcNodeCore,
{
}

impl<N> EthBlocks for GwynethEthApi<N>
where
    Self: LoadBlock<
        Error = EthApiError,
        NetworkTypes: Network<ReceiptResponse = TransactionReceipt>,
    >,
    N: RpcNodeCore<Provider: ChainSpecProvider<ChainSpec = ChainSpec> + HeaderProvider>,
{
    async fn block_receipts(
        &self,
        block_id: BlockId,
    ) -> Result<Option<Vec<RpcReceipt<Self::NetworkTypes>>>, Self::Error>
    where
        Self: LoadReceipt,
    {
        if let Some((block, receipts)) = self.load_block_and_receipts(block_id).await? {
            let block_number = block.number;
            let base_fee = block.base_fee_per_gas;
            let block_hash = block.hash();
            let excess_blob_gas = block.excess_blob_gas;
            let timestamp = block.timestamp;
            let block = block.unseal();

            return block
                .body
                .transactions
                .into_iter()
                .zip(receipts.iter())
                .enumerate()
                .map(|(idx, (tx, receipt))| {
                    let meta = TransactionMeta {
                        tx_hash: tx.hash,
                        index: idx as u64,
                        block_hash,
                        block_number,
                        base_fee,
                        excess_blob_gas,
                        timestamp,
                    };
                    EthReceiptBuilder::new(&tx, meta, receipt, &receipts)
                        .map(|builder| builder.build())
                })
                .collect::<Result<Vec<_>, Self::Error>>()
                .map(Some)
        }

        Ok(None)
    }
}

impl<N> Call for GwynethEthApi<N>
where
    Self: LoadState<Evm: ConfigureEvm<Header = Header>> + SpawnBlocking,
    Self::Error: From<EthApiError>,
    N: RpcNodeCore,
{
    #[inline]
    fn call_gas_limit(&self) -> u64 {
        self.inner.gas_cap()
    }

    #[inline]
    fn max_simulate_blocks(&self) -> u64 {
        self.inner.max_simulate_blocks()
    }
}

impl<N> EstimateCall for GwynethEthApi<N>
where
    Self: Call,
    Self::Error: From<EthApiError>,
    N: RpcNodeCore,
{
}

#[derive(Debug)]
pub struct GwynethAddOns<N: FullNodeComponents>(pub RpcAddOns<N, GwynethEthApi<N>, GwynethEngineValidatorBuilder>);

impl<N: FullNodeComponents> Default for GwynethAddOns<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<N> RethRpcAddOns<N> for GwynethAddOns<N>
where
    N: FullNodeComponents<
        Types: NodeTypes<ChainSpec = ChainSpec>,
        PayloadBuilder: PayloadBuilder<PayloadType = <N::Types as NodeTypesWithEngine>::Engine>,
    >,
    GwynethEngineValidator: EngineValidator<<N::Types as NodeTypesWithEngine>::Engine>,
{
    type EthApi = GwynethEthApi<N>;

    fn hooks_mut(&mut self) -> &mut reth_node_builder::rpc::RpcHooks<N, Self::EthApi> {
        self.0.hooks_mut()
    }
}

impl<N: FullNodeComponents> GwynethAddOns<N> {
    /// Create a new instance with the given `sequencer_http` URL.
    pub fn new() -> Self {
        Self(RpcAddOns::new(move |ctx| GwynethEthApi::new(ctx), Default::default()))
    }
}

impl<N> NodeAddOns<N> for GwynethAddOns<N>
where
    N: FullNodeComponents<
        Types: NodeTypes<ChainSpec = ChainSpec>,
        PayloadBuilder: PayloadBuilder<PayloadType = <N::Types as NodeTypesWithEngine>::Engine>,
    >,
    GwynethEngineValidator: EngineValidator<<N::Types as NodeTypesWithEngine>::Engine>,
{
    type Handle = RpcHandle<N, GwynethEthApi<N>>;

    async fn launch_add_ons(
        self,
        ctx: reth_node_api::AddOnsContext<'_, N>,
    ) -> eyre::Result<Self::Handle> {

        self.0.launch_add_ons_with(ctx, |_| Ok(())).await
    }
}

#[derive(Debug, Clone)]
pub struct GwynethEngineValidator {
    pub chain_spec: Arc<ChainSpec>,
}

impl GwynethEngineValidator {
    /// Instantiates a new validator.
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { chain_spec }
    }
}

impl<Types> EngineValidator<Types> for GwynethEngineValidator
where
    Types: EngineTypes<PayloadAttributes = GwynethPayloadAttributes>,
{
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, GwynethPayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        validate_version_specific_fields(&self.chain_spec, version, payload_or_attrs)
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &GwynethPayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        validate_version_specific_fields(&self.chain_spec, version, attributes.into())
    }
}

#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct GwynethEngineValidatorBuilder;

impl<Node, Types> EngineValidatorBuilder<Node> for GwynethEngineValidatorBuilder
where
    Types: NodeTypesWithEngine<ChainSpec = ChainSpec>,
    Node: FullNodeComponents<Types = Types>,
    GwynethEngineValidator: EngineValidator<Types::Engine>,
{
    type Validator = GwynethEngineValidator;

    async fn build(self, ctx: &AddOnsContext<'_, Node>) -> eyre::Result<GwynethEngineValidator> {
        Ok(GwynethEngineValidator::new(ctx.config.chain.clone()))
    }
}





