//! Test harness of the operator: the kit's envtest control plane with this
//! operator's CRDs, status polling, in-memory ports (a Stalwart, a secret
//! store, the cluster reads) and the live suites' real Stalwart.

pub mod envtest;
pub mod live;
pub mod polling;
pub mod static_gateway_factory;
pub mod static_secret_store_factory;

pub use application::test_support::{FakeCluster, FakeGateway, FakeSecretStore};
pub use live::LiveStalwart;
pub use static_gateway_factory::StaticGatewayFactory;
pub use static_secret_store_factory::StaticSecretStoreFactory;
