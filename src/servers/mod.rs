//! RADIUS Server implementation
//!
//! async_server - as name suggests, it is an Async ready version of RADIUS Server
//! sync_server  - as name suggests, it is a Sync version of RADIUS Server that is build on top of `mio`


#[cfg(all(feature = "async-radius"))]
pub mod async_server;
pub mod sync_server;
