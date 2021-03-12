//! RADIUS Server implementation
//!
//! async_server - as name suggests it is an async version of RADIUS Server that is built on top of `async-std`
//! server       - simple version of RADIUS Server that is build on top of `mio`


#[cfg(all(feature = "async-radius"))]
pub mod async_server;
pub mod server;
