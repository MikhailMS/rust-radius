//! Pure Rust implementation of RADIUS Protocol/Client/Server
//!
//! If you want to built RADIUS Server, a good starting point is to look inside `examples/*_radius_server.rs`
//!
//! If you want to build RADIUS Client, a good starting point is to look inside `examples/*_radius_client.rs`


#![deny(
    dead_code
    missing_crate_level_docs,
    missing_doc_code_examples,
    missing_docs,
    rust_2018_idioms,
    unused_imports,
)]


pub mod client;
pub use client::{ client::Client, SyncClientTrait };
#[cfg(all(feature = "async-radius"))]
pub use client::AsyncClientTrait;

pub mod server;
pub use server::{ server::Server, SyncServerTrait };
#[cfg(all(feature = "async-radius"))]
pub use server::AsyncServerTrait;

pub mod protocol;
pub mod tools;

// Optional features
pub mod features {
    #![cfg_attr(feature = "async-radius",      doc = "## Async RADIUS Server/Client Enabled")]
    #![cfg_attr(not(feature = "async-radius"), doc = "## Async RADIUS Server/Client Disabled")]
}
