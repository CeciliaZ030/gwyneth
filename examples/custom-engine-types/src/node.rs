use reth::{consensus::Consensus, network::NetworkHandle, rpc::eth::EthApi};
use reth_db::{DatabaseEnv, test_utils::TempDatabase};  
use reth_evm_ethereum::EthEvmConfig;
use reth_node_api::{FullNodeTypesAdapter, NodeTypesWithDBAdapter};  
use reth_node_builder::{components::Components, rpc::RpcAddOns, FullNode, NodeAdapter};  
use reth_node_ethereum::{BasicBlockExecutorProvider, EthExecutionStrategyFactory};
use reth_provider::providers::{BlockchainProvider, BlockchainProvider2};  
use reth_transaction_pool::{  
    Pool, TransactionValidationTaskExecutor, EthTransactionValidator,  
    EthPooledTransaction, CoinbaseTipOrdering, blobstore::DiskFileBlobStore,  
};  
use std::sync::Arc;

use crate::{GwynethEngineValidatorBuilder, GwynethNode};  

type NodeTypes = NodeTypesWithDBAdapter<GwynethNode, Arc<DatabaseEnv>>;  
type Provider1 = BlockchainProvider<NodeTypes>;  
type Provider2 = BlockchainProvider2<NodeTypes>;  

type FullTypes1 = FullNodeTypesAdapter<NodeTypes, Provider1>;  
type FullTypes2 = FullNodeTypesAdapter<NodeTypes, Provider2>;  

type TxPool1 = Pool<  
    TransactionValidationTaskExecutor<  
        EthTransactionValidator<Provider1, EthPooledTransaction>  
    >,  
    CoinbaseTipOrdering<EthPooledTransaction>,  
    DiskFileBlobStore  
>;  
type TxPool2 = Pool<  
    TransactionValidationTaskExecutor<  
        EthTransactionValidator<Provider2, EthPooledTransaction>  
    >,  
    CoinbaseTipOrdering<EthPooledTransaction>,  
    DiskFileBlobStore  
>;  
type NodeComponents1 = Components<  
    FullTypes1,  
    TxPool1,  
    EthEvmConfig,  
    BasicBlockExecutorProvider<EthExecutionStrategyFactory>,  
    Arc<dyn Consensus>  
>;  
type NodeComponents2 = Components<  
    FullTypes2,  
    TxPool2,  
    EthEvmConfig,  
    BasicBlockExecutorProvider<EthExecutionStrategyFactory>,  
    Arc<dyn Consensus>  
>;  


type EthApiType1 = EthApi<  
    Provider1,  
    TxPool1,  
    NetworkHandle,  
    EthEvmConfig  
>;  
type EthApiType2 = EthApi<  
    Provider2,  
    TxPool2,  
    NetworkHandle,  
    EthEvmConfig
>;

type NodeType1 = NodeAdapter<FullTypes1, NodeComponents1>;  
type NodeType2 = NodeAdapter<FullTypes2, NodeComponents2>;  

pub type GwynethFullNode1 = FullNode<  
    NodeType1,  
    RpcAddOns<NodeType1, EthApiType1, GwynethEngineValidatorBuilder>  
>;
pub type GwynethFullNode2 = FullNode<  
    NodeType2,  
    RpcAddOns<NodeType2, EthApiType2, GwynethEngineValidatorBuilder>  
>;