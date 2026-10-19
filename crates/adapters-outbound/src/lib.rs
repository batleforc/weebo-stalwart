//! Outbound adapters: the JMAP client implementing
//! `application::ports::RemoteGateway`, the factories building one gateway
//! and one secret store per `StalwartInstance` or `StalwartLocalInstance`,
//! and the cluster reads (`ClusterReader`, `PolicySource`).

pub mod cluster_reader;
pub mod gateway_factory;
pub mod jmap;
pub mod secret_store_factory;

pub use cluster_reader::KubeClusterReader;
pub use gateway_factory::{JmapGatewayFactory, OperatorInstances};
pub use jmap::{JmapClient, JmapGateway};
pub use secret_store_factory::StalwartSecretStoreFactory;
