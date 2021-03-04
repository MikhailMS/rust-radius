//! RADIUS Client implementation
//!
//! async_client - as name suggests it is an async version of RADIUS Client that is built on top of async-std
//! client       - simple version of RADIUS Client that is build on top of mio
//! mutex_client - a bit mmore complex version of RADIUS Client that is built on top of mio 
//!
//! Difference between client & mutex_client - mutex_client binds to socket at the initialization,
//! while client binds on each call to send* functions


#[cfg(all(feature = "async-radius"))]
pub mod async_client;
pub mod client;
pub mod mutex_client;
