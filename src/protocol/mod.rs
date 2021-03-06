//! RADIUS protocol implementation
//!
//! `dictionary` module - represents RADIUS dictionary, that hold all attributes which are to be
//! used by RADIUS Client & Server
//!
//! `radius_packet` module - represents an actual RADIUS packet, that is to be sent from RADIUS
//! Client to RADIUS Server and/or RADIUS Server to RADIUS Client
//!
//! `error` module - represents custom errors defined for `radius-rust` crate


pub mod dictionary;
pub mod radius_packet;
pub(crate) mod host;
pub mod error;
