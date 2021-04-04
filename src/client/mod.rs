//! RADIUS Client implementation
//!
//! Client           - generic version of RADIUS Client, that could be used to build Async or Sync Client
//! SyncClientTrait  - if you are planning to build Sync RADIUS Client, then you would need to
//! implement this trait 
//! AsyncClientTrait - if you are planning to build Async RADIUS Client, then you would need to
//! implement this trait

use crate::protocol::radius_packet::RadiusPacket;
use crate::protocol::error::RadiusError;


#[cfg(all(feature = "async-radius"))]
use async_trait::async_trait;
#[cfg(all(feature = "async-radius"))]
#[async_trait]
/// This trait is to be implemented by user, if they are planning to resolve AUTH, ACCT or CoA
/// RADIUS requests for Async RADIUS Client
pub trait AsyncClientTrait {
    /// Responsible for sending packets off to RADIUS Server ignoring any response received
    async fn send_packet(&self, _packet: &mut RadiusPacket) -> Result<(), RadiusError> {
        todo!()
    }
    /// Responsible for sending packets off to RADIUS Server returning response
    async fn send_and_receive_packet(&self, _packet: &mut RadiusPacket) -> Result<Vec<u8>, RadiusError> {
        todo!()
    }
}

/// This trait is to be implemented by user, if they are planning to resolve AUTH, ACCT or CoA
/// RADIUS requests for Async RADIUS Client
pub trait SyncClientTrait {
    /// Responsible for sending packets off to RADIUS Server ignoring any response received
    fn send_packet(&mut self, _packet: &mut RadiusPacket) -> Result<(), RadiusError> {
        todo!()
    }
    /// Responsible for sending packets off to RADIUS Server returning response
    fn send_and_receive_packet(&mut self, _packet: &mut RadiusPacket) -> Result<Vec<u8>, RadiusError> {
        todo!()
    }
}

pub mod client;
