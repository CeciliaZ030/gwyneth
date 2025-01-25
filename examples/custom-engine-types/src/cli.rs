use clap::Args;
use reth_chainspec::{Chain, ChainSpec, ChainSpecBuilder};
use reth_db::{
    init_db,
    mdbx::{DatabaseArguments, MaxReadTransactionDuration},
    models::ClientVersion,
    DatabaseEnv,
};
use reth_node_builder::{
    engine_tree_config::TreeConfig, DefaultNodeLauncher, EngineNodeLauncher, Node, NodeBuilder, WithLaunchContext
};
use reth_node_core::{
    args::{
        DatadirArgs, DiscoveryArgs, NetworkArgs, RpcServerArgs
    },
    dirs::{DataDirPath, MaybePlatformPath},
    node_config::NodeConfig,
};
use reth_provider::providers::BlockchainProvider2;
use reth_tasks::{TaskExecutor, TaskManager};
use reth::rpc::server_types::RpcModuleSelection;

use std::{future::Future, path::PathBuf, sync::Arc};

use crate::{GwynethAddOns, GwynethNode};


pub const DEFAULT_DISCOVERY_PORT: u16 = 30303;

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
                network_config.port = DEFAULT_DISCOVERY_PORT + (idx as u16) + 1;
                NodeConfig::default()
                    .with_chain(chain_spec.clone())
                    .with_network(network_config.clone())
                    .with_rpc(rpc)
            })
            .collect::<Vec<_>>();
        node_configs
    }

    /// Configure Gwyneth nodes with the given args and l1 node config
    pub async fn configure<F, Fut, N>(
        &self,
        l1_node_config: &NodeConfig<ChainSpec>,
        exec: TaskExecutor,
        f: F,
    ) -> Vec<N>
    where
        F: Fn(WithLaunchContext<NodeBuilder<Arc<DatabaseEnv>, ChainSpec>>) -> Fut,
        Fut: Future<Output = eyre::Result<N>>,
    {
        let node_configs = self.build_node_configs(l1_node_config);
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
            let ctx = WithLaunchContext { builder, task_executor: exec.clone() };
            println!(
                "Gwyneth node {:?} launch with config: {:?}",
                node_config.chain.chain.id(),
                node_config.network
            );
            let node = f(ctx).await.unwrap();
            gwyneth_nodes.push(node);
        }

        gwyneth_nodes
    }
}


// /// Create Gwyneth nodes with the given args and l1 node config
// pub async fn create_gwyneth_nodes(
//     arg: &GwynethArgs,
//     exec: TaskExecutor,
//     l1_node_config: &NodeConfig<ChainSpec>,
// ) -> Vec<GwynethFullNode> {
//     if arg.experimental {
//         // BlockchainProvider2
//         arg.configure(l1_node_config, exec, |ctx| {
//             let n: WithLaunchContext<reth_node_builder::NodeBuilderWithTypes<reth_node_api::FullNodeTypesAdapter<reth_node_api::NodeTypesWithDBAdapter<GwynethNode, Arc<DatabaseEnv>>, BlockchainProvider2<_>>>> = ctx.with_types_and_provider::<GwynethNode, BlockchainProvider2<_>>();
//             let c = n.with_components(GwynethNode::components::<reth_node_builder::NodeBuilderWithTypes<reth_node_api::FullNodeTypesAdapter<reth_node_api::NodeTypesWithDBAdapter<GwynethNode, Arc<DatabaseEnv>>>>>());
            
//             ctx.with_types_and_provider::<GwynethNode, BlockchainProvider2<_>>()
//                 .with_components(GwynethNode::components())
//                 .with_add_ons(GwynethAddOns::default())
//                 .launch_with_fn(|launch_ctx| { 
//                     let launcher = EngineNodeLauncher::new(
//                         launch_ctx.task_executor.clone(),
//                         launch_ctx.builder.config.datadir(),
//                         Default::default(),
//                     );
//                     launch_ctx.launch_with(launcher)
//                 })
//         })
//         .await
//         .iter()
//         .map(|handle| {
//             let a = handle.node.clone();
//             GwynethFullNode::Provider2(handle.node.clone())
//         })
//         .collect::<Vec<_>>()
//     } else {
//         // BlockchainProvider
//         arg.configure(l1_node_config, exec, |ctx| ctx.node(GwynethNode::default()).launch())
//             .await
//             .iter()
//             .map(|handle| GwynethFullNode::Provider1(handle.node.clone()))
//             .collect::<Vec<_>>()
//     }
// }