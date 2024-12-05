use crate::{exex::GwynethFullNode, GwynethNode};
use clap::{builder::Str, value_parser, Args, Parser};
use reth_chainspec::{Chain, ChainSpec, ChainSpecBuilder};
use reth_db::{
    init_db,
    mdbx::{DatabaseArguments, MaxReadTransactionDuration},
    models::ClientVersion,
    DatabaseEnv,
};
use reth_node_builder::{EngineNodeLauncher, Node, NodeBuilder, WithLaunchContext};
use reth_node_core::{
    args::{
        utils::{chain_help, chain_value_parser, SUPPORTED_CHAINS},
        DatabaseArgs, DatadirArgs, DebugArgs, DevArgs, DiscoveryArgs, NetworkArgs,
        PayloadBuilderArgs, PruningArgs, RpcServerArgs, TxPoolArgs,
    },
    dirs::{DataDirPath, MaybePlatformPath},
    node_config::{self, NodeConfig},
    version,
};
use reth_node_ethereum::node::EthereumAddOns;
use reth_provider::providers::{BlockchainProvider, BlockchainProvider2};
use reth_tasks::TaskManager;
use std::{ffi::OsString, fmt, future::Future, net::SocketAddr, path::PathBuf, sync::Arc};

#[derive(Debug, Clone, Default, Args, PartialEq, Eq)]
pub struct GwynethArgs {
    #[arg(long = "l2.chain_ids", required = true, num_args = 1..,)]
    pub chain_ids: Vec<u64>,

    /// Path to the IPC socket shared btw reth and rbuilder
    #[arg(long = "l2.ipcs", required = true, num_args = 1..,)]
    pub ipc_paths: Vec<PathBuf>,

    /// DB path initialized by reth, passed to rbuilder
    #[arg(long = "l2.datadirs", required = true, num_args = 1..,)]
    pub datadirs: Vec<PathBuf>,

    /// RPC ports for reth nodes
    #[arg(long = "l2.ports", num_args = 1..,)]
    pub ports: Vec<u16>,

    /// Path of the rbuilder config to use
    #[arg(long = "rbuilder.config")]
    pub rbuilder_config: PathBuf,

    /// Enable the engine2 experimental features on reth binary
    #[arg(long = "engine.experimental", default_value = "false")]
    pub experimental: bool,
}

impl GwynethArgs {
    pub fn build_node_configs(&self) -> Vec<NodeConfig> {
        assert_eq!(self.chain_ids.len(), self.datadirs.len());

        let network_config = NetworkArgs {
            discovery: DiscoveryArgs { disable_discovery: true, ..DiscoveryArgs::default() },
            ..NetworkArgs::default()
        };

        let chain_spec_builder = ChainSpecBuilder::default()
            .genesis(
                serde_json::from_str(include_str!("../../ethereum/node/tests/assets/genesis.json"))
                    .unwrap(),
            )
            .cancun_activated();

        self.chain_ids
            .iter()
            .zip(self.ipc_paths.iter())
            .zip(self.datadirs.iter())
            .zip(self.ports.iter())
            .map(|(((chain_id, ipc), _), port)| {
                let chain_spec =
                    chain_spec_builder.clone().chain(Chain::from_id(chain_id.clone())).build();

                NodeConfig::default()
                    .with_chain(chain_spec.clone())
                    .with_network(network_config.clone())
                    .with_rpc(
                        RpcServerArgs::default()
                            .with_unused_ports()
                            .set_ipc_path(String::from(ipc.to_str().unwrap()))
                            .set_http_port(port.clone()),
                    )
            })
            .collect::<Vec<_>>()
    }

    pub async fn configure<F, N, Fut>(&self, f: F) -> Vec<N>
    where
        F: Fn(WithLaunchContext<NodeBuilder<Arc<DatabaseEnv>>>) -> Fut,
        Fut: Future<Output = eyre::Result<N>>,
    {
        let node_configs = self.build_node_configs();
        let mut gwyneth_nodes = Vec::new();

        for (datadir, mut node_config) in self.datadirs.iter().zip(node_configs.into_iter()) {
            let path = MaybePlatformPath::<DataDirPath>::from(datadir.clone());
            node_config = node_config.with_datadir_args(reth_node_core::args::DatadirArgs {
                datadir: path.clone(),
                ..Default::default()
            });

            let data_dir =
                path.unwrap_or_chain_default(node_config.chain.chain, node_config.datadir.clone());

            println!("data_dir: {:?}", data_dir);

            let db = init_db(
                data_dir,
                DatabaseArguments::new(ClientVersion::default())
                    .with_max_read_transaction_duration(Some(
                        MaxReadTransactionDuration::Unbounded,
                    )),
            )
            .unwrap();

            let builder = NodeBuilder::new(node_config.clone()).with_database(Arc::new(db));
            let ctx =
                WithLaunchContext { builder, task_executor: TaskManager::current().executor() };
            let node = f(ctx).await.unwrap();
            gwyneth_nodes.push(node);
        }

        gwyneth_nodes
    }
}

pub async fn create_gwyneth_nodes(arg: &GwynethArgs) -> Vec<GwynethFullNode> {
    if arg.experimental {
        arg.configure(|ctx| {
            ctx.with_types_and_provider::<GwynethNode, BlockchainProvider2<_>>()
                .with_components(GwynethNode::default().components_builder())
                .with_add_ons::<EthereumAddOns>()
                .launch_with_fn(|builder| {
                    let launcher = EngineNodeLauncher::new(
                        builder.task_executor().clone(),
                        builder.config().datadir(),
                    );
                    builder.launch_with(launcher)
                })
        })
        .await
        .iter()
        .map(|handle| GwynethFullNode::Provider2(handle.node.clone()))
        .collect::<Vec<_>>()
    } else {
        // BlockchainProvider
        arg.configure(|ctx| ctx.node(GwynethNode::default()).launch())
            .await
            .iter()
            .map(|handle| GwynethFullNode::Provider1(handle.node.clone()))
            .collect::<Vec<_>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_cli_commands::node::NodeCommand;

    #[test]
    fn parse_common_node_command_l2_args() {
        let args = NodeCommand::<GwynethArgs>::parse_from([
            "reth",
            "--l2.chain_ids",
            "160010",
            "160011",
            "--l2.datadirs",
            "path/one",
            "path/two",
            "--l2.ports",
            "1234",
            "2345",
            "--l2.ipcs",
            "/tmp/ipc",
            "--rbuilder.config",
            "path/to/rbuilder.toml",
            "--engine.experimental",
        ]);
        assert_eq!(
            args.ext,
            GwynethArgs {
                chain_ids: vec![160010, 160011],
                datadirs: vec!["path/one".into(), "path/two".into()],
                ports: vec![1234, 2345],
                ipc_paths: vec!["/tmp/ipc".into()],
                rbuilder_config: "path/to/rbuilder.toml".into(),
                experimental: true,
            }
        )
    }

    #[test]
    #[should_panic]
    fn parse_l2_args() {
        let args = NodeCommand::<GwynethArgs>::try_parse_from(["reth"]).unwrap();
    }
}
