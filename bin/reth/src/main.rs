#![allow(missing_docs)]
// We use jemalloc for performance reasons.
#[cfg(all(feature = "jemalloc", unix))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;


use gwyneth::cli::{create_gwyneth_nodes, GwynethArgs};
use reth_node_ethereum::EthereumNode;

fn main() -> eyre::Result<()> {
    println!("WTF");
    reth::cli::Cli::<GwynethArgs>::parse_args_l2().run(|builder, arg| async move {
        let gwyneth_nodes = create_gwyneth_nodes(&arg, builder.config()).await;
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
    use clap::{Args, Parser};
    
    /// A helper type to parse Args more easily
    #[derive(Parser)]
    struct CommandParser<T: Args> {
        #[command(flatten)]
        args: T,
    }
}
