#![allow(missing_docs)]
// We use jemalloc for performance reasons.
#[cfg(all(feature = "jemalloc", unix))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::str::FromStr;

use alloy_network::{Ethereum, EthereumWallet, TransactionBuilder};
use alloy_signer_local::PrivateKeySigner;
use jsonrpsee::{core::client::ClientT, rpc_params};
use gwyneth::cli::{create_gwyneth_nodes, GwynethArgs};
use reth_node_ethereum::EthereumNode;
use reth_primitives::{Address, B256, U256};
use reth_rpc_types::{TransactionInput, TransactionRequest};
use alloy_network::eip2718::Encodable2718;

fn main() -> eyre::Result<()> {
    println!("WTF");
    reth::cli::Cli::<GwynethArgs>::parse_args_l2().run(|builder, arg| async move {
        let gwyneth_nodes = create_gwyneth_nodes(
            &arg, 
            builder.task_executor().clone(),
            builder.config()
        ).await;
        
        let handle = builder
            .node(EthereumNode::default())
            .install_exex("Rollup", move |ctx| async {
                Ok(gwyneth::exex::Rollup::new(ctx, gwyneth_nodes).await?.start())
            })
            .launch()
            .await?;

        
        
        let client = handle.node.rpc_server_handles.rpc.http_client().unwrap();
        println!("Cecilia ==> on_rpc_started  {:?}", client);

        let pk = "5d2344259f42259f82d2c140aa66102ba89b57b4883ee441a8b312622bd42491";
        let signer = PrivateKeySigner::from_str(&pk)?;
        let wallet = EthereumWallet::from(signer.clone());

        let contract_address = "0x9fCF7D13d10dEdF17d0f24C62f0cf4ED462f65b7";
        let mut tx = TransactionRequest::default()
            .with_to(Address::from_str(&contract_address).unwrap())
            .input(TransactionInput {
                input: Some(vec![1,2,3,4,5,6,7].into()),
                data: None,
            })
            .with_value(U256::from(0))
            .with_gas_limit(5_000_000)
            .with_max_priority_fee_per_gas(1_000_000)
            .with_max_fee_per_gas(10_000_000);

        let nonce = client.request::<U256, _>(
                "eth_getTransactionCount", 
                rpc_params![signer.address().to_string()]
            ).await?;       
        let chain_id = client.request::<Option<reth_primitives::U64>, _>("eth_chainId", rpc_params![]).await?.unwrap();
        println!("BlockProposer tx_envelope done - nonce {:?} on {:?}", 1, chain_id);
        tx.nonce = Some(nonce.try_into().unwrap());
        // Build the transaction with the provided wallet. Flashbots Protect requires the transaction to
        // be signed locally and send using `eth_sendRawTransaction`.
        let tx_encoded = <TransactionRequest as TransactionBuilder<Ethereum>>::build(tx, &wallet)
            .await?
            .encoded_2718();
        let params = format!("0x{}", reth_primitives::hex::encode(tx_encoded));
        let tx_hash = client.request::<B256, _>("eth_sendRawTransaction", rpc_params!(params)).await?.to_string();
        println!("BlockProposer eth_sendRawTransaction");

        handle.wait_for_node_exit().await?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use clap::{Args, Parser};
    
    /// A helper type to parse Args more easily
    #[derive(Parser)]
    struct CommandParser<T: Args> {
        #[command(flatten)]
        args: T,
    }
}
