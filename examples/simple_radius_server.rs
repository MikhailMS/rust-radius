//! An example on how to use RADIUS Server
//! Contains both Sync & Async RADIUS Server versions
//!
//! To try out Async RADIUS Server example, run
//! ```bash
//! cargo run --example simple_radius_server --all-features
//! ```
//!
//! To try out Sync RADIUS Server example, run
//! ```bash
//! cargo run --example simple_radius_server
//! ```


use radius_rust::protocol::dictionary::Dictionary;
use radius_rust::protocol::error::RadiusError;
use radius_rust::protocol::radius_packet::{ RadiusMsgType, TypeCode };
use radius_rust::tools::{ ipv6_string_to_bytes, ipv4_string_to_bytes, integer_to_bytes };

use log::{ debug, LevelFilter };
use simple_logger::SimpleLogger;


#[cfg(all(feature = "async-radius"))]
use async_std::task;
#[cfg(all(feature = "async-radius"))]
use radius_rust::servers::async_server::AsyncServer as Server;
#[cfg(all(feature = "async-radius"))]
use radius_rust::servers::async_server::AsyncServerBuilder;
#[cfg(all(not(feature = "async-radius")))]
use radius_rust::servers::server::Server;


// Define your own RADIUS packet handlers
// 
// Ideally, on success, each handler should return RADIUS packet, that would be send as a response to
// RADIUS client
// In case of an error, nothing would be sent to client (which isn't correct behaviour and should be
// fixed later)
fn handle_auth_request(server: &Server, request: &mut [u8]) -> Result<Vec<u8>, RadiusError> {
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

fn handle_acct_request(server: &Server, request: &mut [u8]) -> Result<Vec<u8>, RadiusError> {
    let ipv6_bytes        = ipv6_string_to_bytes("fc66::1/64")?;
    let ipv4_bytes        = ipv4_string_to_bytes("192.168.0.1")?;
    let nas_ip_addr_bytes = ipv4_string_to_bytes("192.168.1.10")?;

    let attributes = vec![
        server.create_attribute_by_name("Service-Type",       integer_to_bytes(2))?,
        server.create_attribute_by_name("Framed-IP-Address",  ipv4_bytes)?,
        server.create_attribute_by_name("Framed-IPv6-Prefix", ipv6_bytes)?,
        server.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes)?
    ];

    let mut reply_packet = server.create_reply_packet(TypeCode::AccountingResponse, attributes, request);
    Ok(reply_packet.to_bytes())
}

fn handle_coa_request(server: &Server, request: &mut [u8]) -> Result<Vec<u8>, RadiusError> {
    let state = String::from("testing").into_bytes();

    let attributes = vec![
        server.create_attribute_by_name("State", state)?
    ];

    let mut reply_packet = server.create_reply_packet(TypeCode::CoAACK, attributes, request);
    Ok(reply_packet.to_bytes())
}
// ------------------------

#[cfg(all(feature = "async-radius"))]
fn main() -> Result<(), RadiusError> {
    SimpleLogger::new().with_level(LevelFilter::Debug).init().unwrap();
    debug!("Async RADIUS Server started");

    task::block_on(async {
        let dictionary    = Dictionary::from_file("./dict_examples/integration_dict")?;
        let allowed_hosts = vec![String::from("127.0.0.1")];

        let server = AsyncServerBuilder::with_dictionary(dictionary)
            .set_server(String::from("127.0.0.1"))
            .set_secret(String::from("secret"))
            .set_allowed_hosts(allowed_hosts)
            .add_protocol_port(RadiusMsgType::AUTH, 1812)
            .add_protocol_port(RadiusMsgType::ACCT, 1813)
            .add_protocol_port(RadiusMsgType::COA,  3799)
            .add_protocol_hanlder(RadiusMsgType::AUTH, handle_auth_request)
            .add_protocol_hanlder(RadiusMsgType::ACCT, handle_acct_request)
            .add_protocol_hanlder(RadiusMsgType::COA,  handle_coa_request)
            .build_server();

        server.run_server().await;
        Ok(())
    })
}

#[cfg(all(not(feature = "async-radius")))]
fn main() -> Result<(), RadiusError> {
    SimpleLogger::new().with_level(LevelFilter::Debug).init().unwrap();
    debug!("RADIUS Server started");

    let dictionary = Dictionary::from_file("./dict_examples/integration_dict")?;
    let mut server = Server::initialise_server(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2)?;

    server.add_allowed_hosts(String::from("127.0.0.1"));

    server.add_request_handler(RadiusMsgType::AUTH, handle_auth_request)?;
    server.add_request_handler(RadiusMsgType::ACCT, handle_acct_request)?;
    server.add_request_handler(RadiusMsgType::COA,  handle_coa_request)?;

    server.run_server()?;
    debug!("RADIUS Server stopped");

    Ok(())
}
