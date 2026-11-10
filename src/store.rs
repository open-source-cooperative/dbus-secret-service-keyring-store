use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use keyring_core::api::CredentialStoreApi;
use keyring_core::attributes::parse_attributes;
use keyring_core::{Entry, Error, Result};

use crate::cred::{Specifier, Wrapper};
use crate::service::Service;

/// Secret service credential store
pub struct Store {
    /// The unique ID for this store instance.
    pub id: String,
    pub(crate) ss: Arc<Service>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("vendor", &self.vendor())
            .field("id", &self.id())
            .finish()
    }
}

impl Store {
    /// Create a new store.
    ///
    /// This is the same as [`new_with_configuration`](Store::new_with_configuration)
    /// with an empty configuration.
    pub fn new() -> Result<Arc<Self>> {
        Store::new_internal(None)
    }

    /// Create a store with the specified configuration.
    ///
    /// The only supported key is `connect-timeout`. Its value is a whole
    /// number of seconds, at least 1 (for example `"5"`). With it, the store
    /// gives up connecting to the session bus if the bus has not finished
    /// authentication and its `Hello` reply within that time, and returns a
    /// [PlatformFailure](Error::PlatformFailure) instead of waiting forever
    /// for a bus that accepts connections but never answers. Opening the
    /// encryption session that follows has its own 2 second limit. See
    /// [`SecretService::connect_with_connection_timeout`](dbus_secret_service::SecretService::connect_with_connection_timeout)
    /// for what the time covers.
    ///
    /// Without that key, the store connects exactly as [`new`](Store::new) does.
    /// Any other key returns [NotSupportedByStore](Error::NotSupportedByStore),
    /// and a bad `connect-timeout` value returns [Invalid](Error::Invalid).
    pub fn new_with_configuration(config: &HashMap<&str, &str>) -> Result<Arc<Self>> {
        Store::new_internal(parse_configuration(config)?)
    }

    fn new_internal(connect_timeout: Option<Duration>) -> Result<Arc<Self>> {
        let now = SystemTime::now();
        let elapsed = if now.lt(&UNIX_EPOCH) {
            UNIX_EPOCH.duration_since(now).unwrap()
        } else {
            now.duration_since(UNIX_EPOCH).unwrap()
        };
        let id = format!(
            "Crate version {}, Instantiated at {}",
            env!("CARGO_PKG_VERSION"),
            elapsed.as_secs_f64()
        );
        let ss = Arc::new(Service::new(connect_timeout)?);
        Ok(Arc::new(Store { id, ss }))
    }
}

const CONNECT_TIMEOUT: &str = "connect-timeout";

/// Read the configuration given to [`Store::new_with_configuration`].
///
/// Returns the `connect-timeout` value, if there is one.
pub(crate) fn parse_configuration(config: &HashMap<&str, &str>) -> Result<Option<Duration>> {
    if let Some(key) = config.keys().find(|key| **key != CONNECT_TIMEOUT) {
        return Err(Error::NotSupportedByStore(format!(
            "Secret Service configuration key '{key}' is not supported"
        )));
    }
    match config.get(CONNECT_TIMEOUT) {
        None => Ok(None),
        Some(value) => match value.parse::<u64>() {
            Ok(seconds) if seconds >= 1 => Ok(Some(Duration::from_secs(seconds))),
            _ => Err(Error::Invalid(
                CONNECT_TIMEOUT.to_string(),
                "must be a whole number of seconds, at least 1".to_string(),
            )),
        },
    }
}

impl CredentialStoreApi for Store {
    fn vendor(&self) -> String {
        "Secret Service store, https://crates.io/crates/dbus-secret-service-keyring-store"
            .to_string()
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    /// See the keyring-core API docs.
    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        let mods = parse_attributes(&["target", "label"], modifiers)?;
        let label = mods.get("label").map(|s| s.as_str());
        if label.map(|l| l.is_empty()).unwrap_or(false) {
            return Err(Error::Invalid(
                "label".to_string(),
                "cannot be empty".to_string(),
            ));
        }
        let target = mods.get("target").map(|s| s.as_str());
        if target.map(|t| t.is_empty()).unwrap_or(false) {
            return Err(Error::Invalid(
                "target".to_string(),
                "cannot be empty".to_string(),
            ));
        }
        Ok(Entry::new_with_credential(Specifier::new(
            self.ss.clone(),
            label,
            target,
            service,
            user,
        )))
    }

    /// See the keyring-core API docs.
    ///
    /// All the key-value pairs are interpreted as attribute/value pairs to
    /// search for (case-sensitive) in the underlying secret service
    /// If the search matches locked items, the search will prompt the user
    /// to unlock them before returning.
    fn search(&self, spec: &HashMap<&str, &str>) -> Result<Vec<Entry>> {
        let paths = self.ss.find_matching_items(spec)?;
        let mut results = Vec::with_capacity(paths.len());
        for path in paths {
            results.push(Entry::new_with_credential(Wrapper::new(
                self.ss.clone(),
                path.clone(),
            )));
        }
        Ok(results)
    }

    /// See the keyring-core API docs.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
