//! Pure Rust implementation of RADIUS Protocol/Client/Server
//!
//! If you want to see how to built RADIUS Server, a good starting point is to look inside `example/`
//! If you want to see how to build RADIUS Client, a good starting point is to look inside `tests/`


#![deny(
    missing_crate_level_docs,
    missing_doc_code_examples,
    missing_docs,
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
