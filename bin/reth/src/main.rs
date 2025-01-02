#![allow(missing_docs)]
// We use jemalloc for performance reasons.
#[cfg(all(feature = "jemalloc", unix))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::str::FromStr;

use alloy_network::{Ethereum, EthereumWallet, TransactionBuilder};
use alloy_signer_local::PrivateKeySigner;
use jsonrpsee::{core::client::ClientT, rpc_params};
use gwyneth::{cli::{create_gwyneth_nodes, GwynethArgs}, exex::L1ParentStates};
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
        let l1_parents = L1ParentStates::new(gwyneth_nodes.len());
        
        let handle = builder
            .node(EthereumNode::default())
            .install_exex("Rollup", move |ctx| async {
                Ok(gwyneth::exex::Rollup::new(ctx, gwyneth_nodes, l1_parents).await?.start())
            })
            .launch()
            .await?;

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
