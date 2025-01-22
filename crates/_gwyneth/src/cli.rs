use crate::{exex::GwynethFullNode, GwynethNode};
use clap::Args;
use reth_chainspec::{Chain, ChainSpec, ChainSpecBuilder};
use reth_db::{
    init_db,
    mdbx::{DatabaseArguments, MaxReadTransactionDuration},
    models::ClientVersion,
    DatabaseEnv,
};
use reth_node_builder::{
    EngineNodeLauncher, Node, NodeBuilder, WithLaunchContext,
};
use reth_node_core::{
    args::{
        DatadirArgs, DiscoveryArgs, NetworkArgs, RpcServerArgs
    },
    dirs::{DataDirPath, MaybePlatformPath},
    node_config::NodeConfig,
};
use reth_node_ethereum::node::EthereumAddOns;
use reth_provider::providers::BlockchainProvider2;
use reth_tasks::{TaskExecutor, TaskManager};
use std::{future::Future, path::PathBuf, sync::Arc};

/// Gwyneth node command line arguments
#[derive(Debug, Clone, Default, Args, PartialEq, Eq)]
pub struct GwynethArgs {

    /// Chain IDs for Gwyneth nodes
    #[arg(long = "l2.chain_ids", required = true, num_args = 0..,)]
    pub chain_ids: Vec<u64>,

    /// DB path initialized by reth, passed to rbuilder
    #[arg(long = "l2.datadirs", required = true, num_args = 0..,)]
    pub datadirs: Vec<PathBuf>,

    /// RPC ports for reth nodes
    #[arg(long = "l2.ports", num_args = 0..,)]
    pub ports: Option<Vec<u16>>,

    /// Engine API ports for reth nodes
    #[arg(long = "l2.auth_ports", num_args = 0..,)]
    pub auth_ports: Option<Vec<u16>>,

    /// Path to the IPC socket shared btw reth and rbuilder
    #[arg(long = "l2.ipcs", num_args = 0..,)]
    pub ipc_paths: Option<Vec<PathBuf>>,

    /// Path of the rbuilder config to use
    #[arg(long = "rbuilder.config")]
    pub rbuilder_config: Option<PathBuf>,

    /// Enable the engine2 experimental features on reth binary
    #[arg(long = "engine.experimental", default_value = "false")]
    pub experimental: bool,
}

impl GwynethArgs {
    /// Build node configs for Gwyneth nodes
    pub fn build_node_configs(&self, l1_node_config: &NodeConfig<ChainSpec>) -> Vec<NodeConfig<ChainSpec>> {
        assert_eq!(self.chain_ids.len(), self.datadirs.len());
        let mut network_config = NetworkArgs {
            // No p2p btw gwyneth nodes for now, otherwise we have one p2p instance per chain
            // and need to configure ports in the containers
            discovery: DiscoveryArgs {
                disable_discovery: true,
                disable_discv4_discovery: true,
                disable_dns_discovery: true,
                ..DiscoveryArgs::default()
            },
            ..NetworkArgs::default()
        };

        let chain_spec_builder = ChainSpecBuilder::default()
            .genesis(
                serde_json::from_str(include_str!("../genesis.json"))
                    .unwrap(),
            )
            .cancun_activated();

        let node_configs = self
            .chain_ids
            .iter()
            .enumerate()
            .map(|(idx, chain_id)| {
                let chain_spec =
                    chain_spec_builder.clone().chain(Chain::from_id(chain_id.clone())).build();
                let mut rpc = RpcServerArgs::default().with_http();
                rpc.http_api = Some(reth_rpc_builder::RpcModuleSelection::Standard);
                rpc.adjust_instance_ports((idx + 2) as u16);
                rpc.http_addr = l1_node_config.rpc.http_addr.clone();
                rpc.auth_addr = l1_node_config.rpc.auth_addr.clone();

                if let Some(ports) = self.ports.clone() {
                    rpc = rpc.set_http_port(ports[idx]);
                }
                if let Some(auth_ports) = self.auth_ports.clone() {
                    rpc = rpc.set_auth_port(auth_ports[idx]);
                }
                if let Some(ipcs) = self.ipc_paths.clone() {
                    rpc = rpc.set_ipc_path(ipcs[idx].to_str().unwrap().to_string());
                }

                // TODO(Cecilia): Should use the same network component across nodes
                network_config.port = (30303 + idx + 1) as u16;
                NodeConfig::default()
                    .with_chain(chain_spec.clone())
                    .with_network(network_config.clone())
                    .with_rpc(rpc)
                    .with_datadir_args(DatadirArgs {
                        datadir: MaybePlatformPath::from(self.datadirs[idx].clone()),
                        ..Default::default()
                    })
            })
            .collect::<Vec<_>>();
        node_configs
    }

    async fn can_run_dev_node() -> eyre::Result<()> {
        reth_tracing::init_test_tracing();
        let tasks = TaskManager::current();
        let exec = tasks.executor();
    
        let node_config = NodeConfig::test()
            .with_chain(custom_chain())
            .with_dev(DevArgs { dev: true, ..Default::default() });
        let NodeHandle { node, .. } = NodeBuilder::new(node_config.clone())
            .testing_node(exec.clone())
            .with_types_and_provider::<GwynethNode, BlockchainProvider2<_>>()
            .with_components(::components())
            .with_add_ons(EthereumAddOns::default())
            .launch_with_fn(|builder| {
                let b = builder.clone();
                let launcher = EngineNodeLauncher::new(
                    builder.task_executor().clone(),
                    builder.config().datadir(),
                    Default::default(),
                );
                builder.launch_with(launcher)
            })
            .await?;
    
        assert_chain_advances(node).await;
    
        Ok(())
    }


    /// Configure Gwyneth nodes with the given args and l1 node config
    pub async fn configure<F, Fut, N>(
        &self,
        l1_node_config: &NodeConfig,
        exec: TaskExecutor,
        f: F,
    ) -> Vec<N>
    where
        F: FnOnce(WithLaunchContext<NodeBuilder<Arc<DatabaseEnv>, ChainSpec>>) -> Fut,
        Fut: Future<Output = eyre::Result<N>>,
    {
        let node_configs = self.build_node_configs(l1_node_config);
        let mut gwyneth_nodes = Vec::new();

        for config in node_configs {
            let data_dir = config.datadir();
            let db_path = data_dir.db();
    
            tracing::info!(target: "reth::cli", path = ?db_path, "Opening database");
            let db = init_db(
                data_dir,
                DatabaseArguments::new(ClientVersion::default())
                    .with_max_read_transaction_duration(Some(
                        MaxReadTransactionDuration::Unbounded,
                    )),
            )?;
            let ctx = NodeBuilder::new(node_config)
                .with_database(database)
                .with_launch_context(exec.clone());
            let node = f(ctx).await?;
            gwyneth_nodes.push(node);
        }

        gwyneth_nodes
    }
}

/// Create Gwyneth nodes with the given args and l1 node config
pub async fn create_gwyneth_nodes(
    arg: &GwynethArgs,
    exec: TaskExecutor,
    l1_node_config: &NodeConfig,
) -> Vec<GwynethFullNode> {
    if arg.experimental {
        // BlockchainProvider2
        arg.configure(l1_node_config, exec, |ctx| {
            let n: WithLaunchContext<reth_node_builder::NodeBuilderWithTypes<reth_node_api::FullNodeTypesAdapter<reth_node_api::NodeTypesWithDBAdapter<GwynethNode, Arc<DatabaseEnv>>, BlockchainProvider2<_>>>> = ctx.with_types_and_provider::<GwynethNode, BlockchainProvider2<_>>();
            let c = n.with_components(GwynethNode::components::<reth_node_builder::NodeBuilderWithTypes<reth_node_api::FullNodeTypesAdapter<reth_node_api::NodeTypesWithDBAdapter<GwynethNode, Arc<DatabaseEnv>>>>>());
            
            ctx.with_types_and_provider::<GwynethNode, BlockchainProvider2<_>>()
                .with_components(GwynethNode::components())
                .with_add_ons::<EthereumAddOns>()
                .launch_with_fn(|launch_ctx| { 
                    let launcher = EngineNodeLauncher::new(
                        launch_ctx.task_executor.clone(),
                        launch_ctx.builder.config.datadir(),
                        Default::default(),
                    );
                    launch_ctx.launch_with(launcher)
                })
        })
        .await
        .iter()
        .map(|handle| GwynethFullNode::Provider2(handle.node.clone()))
        .collect::<Vec<_>>()
    } else {
        // BlockchainProvider
        arg.configure(l1_node_config, exec, |ctx| ctx.node(GwynethNode::default()).launch())
            .await
            .iter()
            .map(|handle| GwynethFullNode::Provider1(handle.node.clone()))
            .collect::<Vec<_>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
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
            "--l2.auth_ports",
            "6666",
            "7777",
            "--l2.ipcs",
            "/tmp/ipc-1",
            "/tmp/ipc-2",
            "--rbuilder.config",
            "path/to/rbuilder.toml",
            "--engine.experimental",
        ]);
        assert_eq!(
            args.ext,
            GwynethArgs {
                chain_ids: vec![160010, 160011],
                datadirs: vec!["path/one".into(), "path/two".into()],
                ports: Some(vec![1234, 2345]),
                auth_ports: Some(vec![6666, 7777]),
                ipc_paths: Some(vec!["/tmp/ipc-1".into(), "/tmp/ipc-2".into()]),
                rbuilder_config: Some("path/to/rbuilder.toml".into()),
                experimental: true,
            }
        )
    }

    #[test]
    #[should_panic]
    fn parse_l2_args() {
        let _ = NodeCommand::<GwynethArgs>::try_parse_from(["reth"]).unwrap();
    }

    #[tokio::test]
    async fn test_creating_nodes() {
        let args = GwynethArgs {
            chain_ids: vec![160010, 160011],
            datadirs: vec!["path/one".into(), "path/two".into()],
            ..Default::default()
        };
        let l1_node_config = NodeConfig::default();
        let exec = TaskManager::current().executor();

        let gwyneth_nodes = create_gwyneth_nodes(&args, exec, &l1_node_config).await;
        assert_eq!(gwyneth_nodes.len(), 2);
    }
}
