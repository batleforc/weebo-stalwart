//! Test-only `SecretStoreFactory`: the one store it was built with,
//! whatever the instance.

use std::sync::Arc;

use application::ports::{BoundInstance, SecretStore, SecretStoreError, SecretStoreFactory};

pub struct StaticSecretStoreFactory(pub Arc<dyn SecretStore>);

#[async_trait::async_trait]
impl SecretStoreFactory for StaticSecretStoreFactory {
    async fn store_for(
        &self,
        _instance: &BoundInstance,
    ) -> Result<Arc<dyn SecretStore>, SecretStoreError> {
        Ok(self.0.clone())
    }
}
