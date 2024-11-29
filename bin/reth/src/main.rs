#![allow(missing_docs)]
// We use jemalloc for performance reasons.
#[cfg(all(feature = "jemalloc", unix))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::sync::Arc;

use gwyneth::{
    cli::{create_gwyneth_nodes, GwynethArgs},
    engine_api::RpcServerArgsExEx,
    exex::GwynethFullNode,
    GwynethNode,
};
use reth_chainspec::ChainSpecBuilder;
use reth_db::init_db;
use reth_node_builder::{
    EngineNodeLauncher, LaunchNode, Node, NodeBuilder, NodeConfig, NodeHandle, WithLaunchContext,
};
use reth_node_ethereum::{node::EthereumAddOns, EthereumNode};
use reth_provider::{
    providers::{BlockchainProvider, BlockchainProvider2},
    StateProviderFactory,
};
use reth_tasks::TaskManager;

fn main() -> eyre::Result<()> {
    println!("WTF");
    reth::cli::Cli::<GwynethArgs>::parse_args_l2().run(|builder, arg| async move {
        println!("Starting reth node with custom exex \n {:?}", arg);
        let gwyneth_nodes = create_gwyneth_nodes(arg).await;
        let handle = builder
            .node(EthereumNode::default())
            .install_exex("Rollup", move |ctx| async {
                Ok(gwyneth::exex::Rollup::new(ctx, gwyneth_nodes).await?.start())
            })
            .launch()
            .await?;

        handle.wait_for_node_exit().await?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;
    use clap::{Args, Parser};
    use tokio::runtime::{Handle, Runtime};

    /// A helper type to parse Args more easily
    #[derive(Parser)]
    struct CommandParser<T: Args> {
        #[command(flatten)]
        args: T,
    }
}
