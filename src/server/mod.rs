//! Module contains RADIUS Generic Server implementation and related traits definitions


use crate::protocol::error::RadiusError;


#[cfg(all(feature = "async-radius"))]
use async_trait::async_trait;
#[cfg(all(feature = "async-radius"))]
#[async_trait]
/// This trait is to be implemented by user, if they are planning to resolve AUTH, ACCT or CoA
/// RADIUS requests for Async RADIUS Server
pub trait AsyncServerTrait {
    /// Main function, that starts and keeps server running
    ///
    /// For example see `examples/async_radius_server.rs`
    async fn run(&mut self) -> Result<(), RadiusError>;

    /// Function is responsible for resolving AUTH RADIUS request
    ///
    /// For example see `examples/async_radius_server.rs`
    async fn handle_auth_request(&self) -> Result<(), RadiusError> {
        Ok(())
    }
    /// Function is responsible for resolving AUTH RADIUS request
    ///
    /// For example see `examples/async_radius_server.rs`
    async fn handle_acct_request(&self) -> Result<(), RadiusError> {
        Ok(())
    }
    /// Function is responsible for resolving AUTH RADIUS request
    ///
    /// For example see `examples/async_radius_server.rs`
    async fn handle_coa_request(&self) -> Result<(), RadiusError> {
        Ok(())
    }
}

/// This trait is to be implemented by user, if they are planning to resolve AUTH, ACCT or CoA
/// RADIUS requests for Sync RADIUS Server
pub trait SyncServerTrait {
    /// Main function, that starts and keeps server running
    ///
    /// For example see `examples/sync_radius_server.rs`
    fn run(&mut self) -> Result<(), RadiusError>;

    /// Function is responsible for resolving AUTH RADIUS request
    ///
    /// For example see `examples/sync_radius_server.rs`
    fn handle_auth_request(&self, request: &mut [u8])->Result<Vec<u8>, RadiusError> {
        Ok(request.to_vec())
    }
    /// Function is responsible for resolving ACCT RADIUS request
    ///
    /// For example see `examples/sync_radius_server.rs`
    fn handle_acct_request(&self, request: &mut [u8])->Result<Vec<u8>, RadiusError> {
        Ok(request.to_vec())
    }
    /// Function is responsible for resolving CoA RADIUS request
    ///
    /// For example see `examples/sync_radius_server.rs`
    fn handle_coa_request(&self, request: &mut [u8])->Result<Vec<u8>, RadiusError> {
        Ok(request.to_vec())
    }
}

pub mod server;
