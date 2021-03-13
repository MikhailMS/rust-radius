#![feature(test)]

extern crate test;
use test::Bencher;

use radius_rust::clients::client::Client;
use radius_rust::protocol::dictionary::Dictionary;
use radius_rust::tools::{ integer_to_bytes, ipv4_string_to_bytes};


// === AUTH benches ===
#[bench]
fn test_auth_client_wo_response_against_server(b: &mut Bencher) {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let client     = Client::initialise_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

    let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10").unwrap();
    let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100").unwrap();


    let attributes = vec![
        client.create_attribute_by_name("User-Name",          String::from("testing").into_bytes()).unwrap(),
        client.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes).unwrap(),
        client.create_attribute_by_name("NAS-Port-Id",        integer_to_bytes(0)).unwrap(),
        client.create_attribute_by_name("Service-Type",       integer_to_bytes(2)).unwrap(),
        client.create_attribute_by_name("NAS-Identifier",     String::from("trillian").into_bytes()).unwrap(),
        client.create_attribute_by_name("Called-Station-Id",  String::from("00-04-5F-00-0F-D1").into_bytes()).unwrap(),
        client.create_attribute_by_name("Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
        client.create_attribute_by_name("Framed-IP-Address",  framed_ip_addr_bytes).unwrap()
    ];
    
    let mut auth_packet = client.create_auth_packet(attributes);

    b.iter(|| client.send_packet(&mut auth_packet))
}

#[bench]
fn test_auth_client_w_response_against_server(b: &mut Bencher) {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let client     = Client::initialise_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

    let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10").unwrap();
    let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100").unwrap();


    let attributes = vec![
        client.create_attribute_by_name("User-Name",          String::from("testing").into_bytes()).unwrap(),
        client.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes).unwrap(),
        client.create_attribute_by_name("NAS-Port-Id",        integer_to_bytes(0)).unwrap(),
        client.create_attribute_by_name("Service-Type",       integer_to_bytes(2)).unwrap(),
        client.create_attribute_by_name("NAS-Identifier",     String::from("trillian").into_bytes()).unwrap(),
        client.create_attribute_by_name("Called-Station-Id",  String::from("00-04-5F-00-0F-D1").into_bytes()).unwrap(),
        client.create_attribute_by_name("Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
        client.create_attribute_by_name("Framed-IP-Address",  framed_ip_addr_bytes).unwrap()
    ];
    
    let mut auth_packet = client.create_auth_packet(attributes);

    b.iter(|| client.send_and_receive_packet(&mut auth_packet))
}
// ====================


// === ACCT benches ===
#[bench]
fn test_acct_client_wo_response_against_server(b: &mut Bencher) {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let client     = Client::initialise_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

    let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10").unwrap();
    let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100").unwrap();

    let attributes = vec![
        client.create_attribute_by_name("User-Name",          String::from("testing").into_bytes()).unwrap(),
        client.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes).unwrap(),
        client.create_attribute_by_name("NAS-Port-Id",        integer_to_bytes(0)).unwrap(),
        client.create_attribute_by_name("Service-Type",       integer_to_bytes(2)).unwrap(),
        client.create_attribute_by_name("NAS-Identifier",     String::from("trillian").into_bytes()).unwrap(),
        client.create_attribute_by_name("Called-Station-Id",  String::from("00-04-5F-00-0F-D1").into_bytes()).unwrap(),
        client.create_attribute_by_name("Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
        client.create_attribute_by_name("Framed-IP-Address",  framed_ip_addr_bytes).unwrap()
    ];
    
    let mut acct_packet = client.create_acct_packet(attributes);

    b.iter(|| client.send_packet(&mut acct_packet))
}

#[bench]
fn test_acct_client_w_response_against_server(b: &mut Bencher) {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let client     = Client::initialise_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

    let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10").unwrap();
    let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100").unwrap();

    let attributes = vec![
        client.create_attribute_by_name("User-Name",          String::from("testing").into_bytes()).unwrap(),
        client.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes).unwrap(),
        client.create_attribute_by_name("NAS-Port-Id",        integer_to_bytes(0)).unwrap(),
        client.create_attribute_by_name("Service-Type",       integer_to_bytes(2)).unwrap(),
        client.create_attribute_by_name("NAS-Identifier",     String::from("trillian").into_bytes()).unwrap(),
        client.create_attribute_by_name("Called-Station-Id",  String::from("00-04-5F-00-0F-D1").into_bytes()).unwrap(),
        client.create_attribute_by_name("Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
        client.create_attribute_by_name("Framed-IP-Address",  framed_ip_addr_bytes).unwrap()
    ];
    
    let mut acct_packet = client.create_acct_packet(attributes);

    b.iter(|| client.send_and_receive_packet(&mut acct_packet))
}
// ====================


// === CoA benches  ===
#[bench]
fn test_coa_client_wo_response_against_server(b: &mut Bencher) {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let client     = Client::initialise_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

    let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10").unwrap();
    let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100").unwrap();

    let attributes = vec![
        client.create_attribute_by_name("User-Name",          String::from("testing").into_bytes()).unwrap(),
        client.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes).unwrap(),
        client.create_attribute_by_name("NAS-Port-Id",        integer_to_bytes(0)).unwrap(),
        client.create_attribute_by_name("Service-Type",       integer_to_bytes(2)).unwrap(),
        client.create_attribute_by_name("NAS-Identifier",     String::from("trillian").into_bytes()).unwrap(),
        client.create_attribute_by_name("Called-Station-Id",  String::from("00-04-5F-00-0F-D1").into_bytes()).unwrap(),
        client.create_attribute_by_name("Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
        client.create_attribute_by_name("Framed-IP-Address",  framed_ip_addr_bytes).unwrap()
    ];
    
    let mut coa_packet = client.create_coa_packet(attributes);

    b.iter(|| client.send_packet(&mut coa_packet))
}

#[bench]
fn test_coa_client_w_response_against_server(b: &mut Bencher) {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let client     = Client::initialise_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

    let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10").unwrap();
    let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100").unwrap();


    let attributes = vec![
        client.create_attribute_by_name("User-Name",          String::from("testing").into_bytes()).unwrap(),
        client.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes).unwrap(),
        client.create_attribute_by_name("NAS-Port-Id",        integer_to_bytes(0)).unwrap(),
        client.create_attribute_by_name("Service-Type",       integer_to_bytes(2)).unwrap(),
        client.create_attribute_by_name("NAS-Identifier",     String::from("trillian").into_bytes()).unwrap(),
        client.create_attribute_by_name("Called-Station-Id",  String::from("00-04-5F-00-0F-D1").into_bytes()).unwrap(),
        client.create_attribute_by_name("Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
        client.create_attribute_by_name("Framed-IP-Address",  framed_ip_addr_bytes).unwrap()
    ];
    
    let mut coa_packet = client.create_coa_packet(attributes);

    b.iter(|| client.send_and_receive_packet(&mut coa_packet))
}
// ====================
