#![deny(
    // missing_docs, // TODO
    rust_2018_idioms,
    unused_imports,
    dead_code
)]


pub mod clients;
pub use clients::{ client, mutex_client };
#[cfg(all(feature = "async-radius"))]
pub use clients::async_client;

pub mod server;
pub mod protocol;
pub mod tools;

// Optional features
pub mod features {
    #![cfg_attr(feature = "async-radius",      doc = "## Enable Async RADIUS Server/Client")]
    #![cfg_attr(not(feature = "async-radius"), doc = "## Disable Async RADIUS Server/Client")]
}
