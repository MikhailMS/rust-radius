//! Simple example of Async RADIUS server
//!
//! To try out the example run
//! ```bash
//! cargo run --example simple_async_radius_server 
//! ```
#![cfg(all(feature = "async-radius"))]


use radius_rust::protocol::dictionary::Dictionary;
use radius_rust::protocol::error::RadiusError;
use radius_rust::protocol::radius_packet::{ RadiusAttribute, RadiusMsgType, TypeCode };
use radius_rust::servers::async_server::AsyncServer;
use radius_rust::tools::{ ipv6_string_to_bytes, ipv4_string_to_bytes, integer_to_bytes };

use async_std::task;


// Define your own RADIUS packet handlers
// 
// Ideally, on success, each handler should return RADIUS packet, that would be send as a response to
// RADIUS client
// In case of an error, nothing would be sent to client (which isn't correct behaviour and should be
// fixed later)
fn handle_auth_request(server: &AsyncServer, request: &mut [u8]) -> Result<Vec<u8>, RadiusError> {
    let ipv6_bytes = ipv6_string_to_bytes("fc66::1/64")?;
    let ipv4_bytes = ipv4_string_to_bytes("192.168.0.1")?;
    let attributes = vec![
        server.create_attribute_by_name("Service-Type",       integer_to_bytes(2))?,
        server.create_attribute_by_name("Framed-IP-Address",  ipv4_bytes)?,
        server.create_attribute_by_name("Framed-IPv6-Prefix", ipv6_bytes)?
    ];

    let mut reply_packet = server.create_reply_packet(TypeCode::AccessAccept, attributes, request);
    Ok(reply_packet.to_bytes())
}

fn handle_acct_request(server: &AsyncServer, request: &mut [u8]) -> Result<Vec<u8>, RadiusError> {
    let attributes: Vec<RadiusAttribute> = Vec::with_capacity(1);

    let mut reply_packet = server.create_reply_packet(TypeCode::AccountingResponse, attributes, request);
    Ok(reply_packet.to_bytes())
}

fn handle_coa_request(server: &AsyncServer, request: &mut [u8]) -> Result<Vec<u8>, RadiusError> {
    let attributes: Vec<RadiusAttribute> = Vec::with_capacity(1);

    let mut reply_packet = server.create_reply_packet(TypeCode::CoAACK, attributes, request);
    Ok(reply_packet.to_bytes())
}
// ------------------------


fn main() -> Result<(), RadiusError> {
    task::block_on(async {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict")?;
        let mut server = AsyncServer::initialise_server(1812u16, 1813u16, 3799u16, dictionary, String::from("127.0.0.1"), String::from("secret"), 1u16, 2u16).await?;

        server.add_allowed_hosts(String::from("127.0.0.1"));

        server.add_request_handler(RadiusMsgType::AUTH, handle_auth_request)?;
        server.add_request_handler(RadiusMsgType::ACCT, handle_acct_request)?;
        server.add_request_handler(RadiusMsgType::COA,  handle_coa_request)?;

        server.run_server().await?;
        Ok(())
    })
}
