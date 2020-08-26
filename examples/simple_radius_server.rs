/*
 * Simpple example of RADIUS server
 * 
 * cargo run --example simple_radius_server 
 */

use radius_rust::protocol::dictionary::Dictionary;
use radius_rust::protocol::radius_packet::{ RadiusAttribute, TypeCode };
use radius_rust::server::{ RadiusMsgType, Server };
use radius_rust::tools::{ ipv6_string_to_bytes, ipv4_string_to_bytes, integer_to_bytes };

use std::io::Error;


// Define handlers
fn handle_auth_request(server: &Server, request: &mut [u8]) -> Result<Vec<u8>, Error> {
    let ipv6_bytes = ipv6_string_to_bytes("fc66::1/64").unwrap();
    let ipv4_bytes = ipv4_string_to_bytes("192.168.0.1").unwrap();
    let attributes = vec![
        server.create_attribute_by_name("Service-Type",       integer_to_bytes(2)).unwrap(),
        server.create_attribute_by_name("Framed-IP-Address",  ipv4_bytes).unwrap(),
        server.create_attribute_by_name("Framed-IPv6-Prefix", ipv6_bytes).unwrap()
    ];

    let mut reply_packet = server.create_reply_packet(TypeCode::AccessAccept, attributes, request);
    Ok(reply_packet.to_bytes())
}

fn handle_acct_request(server: &Server, request: &mut [u8]) -> Result<Vec<u8>, Error> {
    let attributes: Vec<RadiusAttribute> = Vec::with_capacity(1);

    let mut reply_packet = server.create_reply_packet(TypeCode::AccountingResponse, attributes, request);
    Ok(reply_packet.to_bytes())
}

fn handle_coa_request(server: &Server, request: &mut [u8]) -> Result<Vec<u8>, Error> {
    let attributes: Vec<RadiusAttribute> = Vec::with_capacity(1);

    let mut reply_packet = server.create_reply_packet(TypeCode::CoAACK, attributes, request);
    Ok(reply_packet.to_bytes())
}
// ------------------------


fn main() {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let mut server = Server::initialise_server(1812, 1813, 3799, &dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

    server.add_allowed_hosts(String::from("127.0.0.1"));

    server.add_request_handler(RadiusMsgType::AUTH, handle_auth_request).unwrap();
    server.add_request_handler(RadiusMsgType::ACCT, handle_acct_request).unwrap();
    server.add_request_handler(RadiusMsgType::COA,  handle_coa_request).unwrap();

    server.run_server().unwrap();
}
