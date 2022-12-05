#![cfg(all(feature = "async-radius"))]
#![feature(test)]

extern crate test;
use test::Bencher;

use radius_rust::client::{ client::Client, AsyncClientTrait };
use radius_rust::protocol::{
    dictionary::Dictionary,
    error::RadiusError,
    radius_packet::{ RadiusPacket, RadiusMsgType }
};
use radius_rust::tools::{ encrypt_data, ipv4_string_to_bytes, integer_to_bytes };

use async_std::net::UdpSocket;
use async_std::task;
use async_trait::async_trait;
use std::io::{Error, ErrorKind};


struct ClientWrapper {
    base_client: Client,
    socket:      UdpSocket
}

impl ClientWrapper {
    fn initialize_client(auth_port: u16, acct_port: u16, coa_port: u16, dictionary: Dictionary, server: String, secret: String, retries: u16, timeout: u16) -> Result<ClientWrapper, RadiusError> {
        // Bind socket
        let socket = task::block_on(UdpSocket::bind("0.0.0.0:0")).map_err(|error| RadiusError::SocketConnectionError(error))?;
        // --------------------
        
       let client = Client::with_dictionary(dictionary)
            .set_server(server)
            .set_secret(secret)
            .set_retries(retries)
            .set_timeout(timeout)
            .set_port(RadiusMsgType::AUTH, auth_port)
            .set_port(RadiusMsgType::ACCT, acct_port)
            .set_port(RadiusMsgType::COA,  coa_port);

        Ok(ClientWrapper {
            base_client: client,
            socket:      socket
        })
    }
}

#[async_trait]
impl AsyncClientTrait for ClientWrapper {
    async fn send_packet(&self, packet: &mut RadiusPacket) -> Result<(), RadiusError> {
        let remote_port = self.base_client.port(packet.code()).ok_or_else(|| RadiusError::MalformedPacketError { error: String::from("There is no port match for packet code") })?;
        let remote      = format!("{}:{}", &self.base_client.server(), remote_port);
        let mut retry   = 0;

        loop {
            if retry >= self.base_client.retries() {
                break;
            }

            self.socket.send_to(&packet.to_bytes(), &remote).await.map_err(|error| RadiusError::SocketConnectionError(error))?;

            let mut response = [0; 4096];
            let (amount, _)  = self.socket.recv_from(&mut response).await.map_err(|error| RadiusError::SocketConnectionError(error))?;

            if amount > 0 {
                return Ok(())
            }

            retry += 1;
        }
        Err( RadiusError::SocketConnectionError(Error::new(ErrorKind::TimedOut, "")) )
    }

    async fn send_and_receive_packet(&self, packet: &mut RadiusPacket) -> Result<Vec<u8>, RadiusError> {
        let remote_port = self.base_client.port(packet.code()).ok_or_else(|| RadiusError::MalformedPacketError { error: String::from("There is no port match for packet code") })?;
        let remote      = format!("{}:{}", &self.base_client.server(), remote_port);
        let mut retry   = 0;

        loop {
            if retry >= self.base_client.retries() {
                break;
            }
            self.socket.send_to(&packet.to_bytes(), &remote).await.map_err(|error| RadiusError::SocketConnectionError(error))?;

            let mut response = [0; 4096];
            let (amount, _)  = self.socket.recv_from(&mut response).await.map_err(|error| RadiusError::SocketConnectionError(error))?;

            if amount > 0 {
                return Ok(response[0..amount].to_vec());
            }

            retry += 1;
        }

        Err( RadiusError::SocketConnectionError(Error::new(ErrorKind::TimedOut, "")) )
    }
}


// === AUTH benches ===
#[bench]
fn test_async_auth_client_wo_response_against_server(b: &mut Bencher) {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let client     = ClientWrapper::initialize_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

    let user_name            = String::from("testing").into_bytes();
    let user_pass            = b"very secure password, that noone is able to guess";
    let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10").unwrap();
    let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100").unwrap();

    let mut auth_packet = client.base_client.create_auth_packet();
    let attributes      = vec![
        client.base_client.create_attribute_by_name("User-Name",          user_name).unwrap(),
        client.base_client.create_attribute_by_name("Password",           encrypt_data(user_pass, auth_packet.authenticator(), client.base_client.secret().as_bytes())).unwrap(),
        client.base_client.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes).unwrap(),
        client.base_client.create_attribute_by_name("NAS-Port-Id",        integer_to_bytes(0)).unwrap(),
        client.base_client.create_attribute_by_name("Service-Type",       integer_to_bytes(2)).unwrap(),
        client.base_client.create_attribute_by_name("NAS-Identifier",     String::from("trillian").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Called-Station-Id",  String::from("00-04-5F-00-0F-D1").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Framed-IP-Address",  framed_ip_addr_bytes).unwrap()
    ];

    auth_packet.set_attributes(attributes);

    b.iter(|| task::block_on(async {
        client.send_packet(&mut auth_packet).await
    }) )
}

#[bench]
fn test_async_auth_client_w_response_against_server(b: &mut Bencher) {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let client     = ClientWrapper::initialize_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

    let user_name            = String::from("testing").into_bytes();
    let user_pass            = b"very secure password, that noone is able to guess";
    let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10").unwrap();
    let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100").unwrap();

    let mut auth_packet = client.base_client.create_auth_packet();
    let attributes      = vec![
        client.base_client.create_attribute_by_name("User-Name",          user_name).unwrap(),
        client.base_client.create_attribute_by_name("Password",           encrypt_data(user_pass, auth_packet.authenticator(), client.base_client.secret().as_bytes())).unwrap(),
        client.base_client.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes).unwrap(),
        client.base_client.create_attribute_by_name("NAS-Port-Id",        integer_to_bytes(0)).unwrap(),
        client.base_client.create_attribute_by_name("Service-Type",       integer_to_bytes(2)).unwrap(),
        client.base_client.create_attribute_by_name("NAS-Identifier",     String::from("trillian").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Called-Station-Id",  String::from("00-04-5F-00-0F-D1").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Framed-IP-Address",  framed_ip_addr_bytes).unwrap()
    ];

    auth_packet.set_attributes(attributes);

    b.iter(|| task::block_on(async {
        client.send_and_receive_packet(&mut auth_packet).await
    }) )
}
// ====================


// === ACCT benches ===
#[bench]
fn test_async_acct_client_wo_response_against_server(b: &mut Bencher) {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let client     = ClientWrapper::initialize_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

    let user_name            = String::from("testing").into_bytes();
    let user_pass            = b"very secure password, that noone is able to guess";
    let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10").unwrap();
    let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100").unwrap();

    let mut acct_packet = client.base_client.create_acct_packet();
    let attributes      = vec![
        client.base_client.create_attribute_by_name("User-Name",          user_name).unwrap(),
        client.base_client.create_attribute_by_name("Password",           encrypt_data(user_pass, acct_packet.authenticator(), client.base_client.secret().as_bytes())).unwrap(),
        client.base_client.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes).unwrap(),
        client.base_client.create_attribute_by_name("NAS-Port-Id",        integer_to_bytes(0)).unwrap(),
        client.base_client.create_attribute_by_name("Service-Type",       integer_to_bytes(2)).unwrap(),
        client.base_client.create_attribute_by_name("NAS-Identifier",     String::from("trillian").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Called-Station-Id",  String::from("00-04-5F-00-0F-D1").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Framed-IP-Address",  framed_ip_addr_bytes).unwrap()
    ];

    acct_packet.set_attributes(attributes);

    b.iter(|| task::block_on(async {
        client.send_packet(&mut acct_packet).await
    }) )
}

#[bench]
fn test_async_acct_client_w_response_against_server(b: &mut Bencher) {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let client     = ClientWrapper::initialize_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

    let user_name            = String::from("testing").into_bytes();
    let user_pass            = b"very secure password, that noone is able to guess";
    let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10").unwrap();
    let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100").unwrap();

    let mut acct_packet = client.base_client.create_acct_packet();
    let attributes      = vec![
        client.base_client.create_attribute_by_name("User-Name",          user_name).unwrap(),
        client.base_client.create_attribute_by_name("Password",           encrypt_data(user_pass, acct_packet.authenticator(), client.base_client.secret().as_bytes())).unwrap(),
        client.base_client.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes).unwrap(),
        client.base_client.create_attribute_by_name("NAS-Port-Id",        integer_to_bytes(0)).unwrap(),
        client.base_client.create_attribute_by_name("Service-Type",       integer_to_bytes(2)).unwrap(),
        client.base_client.create_attribute_by_name("NAS-Identifier",     String::from("trillian").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Called-Station-Id",  String::from("00-04-5F-00-0F-D1").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Framed-IP-Address",  framed_ip_addr_bytes).unwrap()
    ];

    acct_packet.set_attributes(attributes);

    b.iter(|| task::block_on(async {
        client.send_and_receive_packet(&mut acct_packet).await
    }) )
}
// ====================


// === CoA benches  ===
#[bench]
fn test_async_coa_client_wo_response_against_server(b: &mut Bencher) {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let client     = ClientWrapper::initialize_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

    let user_name            = String::from("testing").into_bytes();
    let user_pass            = b"very secure password, that noone is able to guess";
    let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10").unwrap();
    let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100").unwrap();

    let mut coa_packet = client.base_client.create_coa_packet();
    let attributes     = vec![
        client.base_client.create_attribute_by_name("User-Name",          user_name).unwrap(),
        client.base_client.create_attribute_by_name("Password",           encrypt_data(user_pass, coa_packet.authenticator(), client.base_client.secret().as_bytes())).unwrap(),
        client.base_client.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes).unwrap(),
        client.base_client.create_attribute_by_name("NAS-Port-Id",        integer_to_bytes(0)).unwrap(),
        client.base_client.create_attribute_by_name("Service-Type",       integer_to_bytes(2)).unwrap(),
        client.base_client.create_attribute_by_name("NAS-Identifier",     String::from("trillian").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Called-Station-Id",  String::from("00-04-5F-00-0F-D1").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Framed-IP-Address",  framed_ip_addr_bytes).unwrap()
    ];

    coa_packet.set_attributes(attributes);

    b.iter(|| task::block_on(async {
        client.send_packet(&mut coa_packet).await
    }) )
}

#[bench]
fn test_async_coa_client_w_response_against_server(b: &mut Bencher) {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let client     = ClientWrapper::initialize_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

    let user_name            = String::from("testing").into_bytes();
    let user_pass            = b"very secure password, that noone is able to guess";
    let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10").unwrap();
    let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100").unwrap();

    let mut coa_packet = client.base_client.create_coa_packet();
    let attributes     = vec![
        client.base_client.create_attribute_by_name("User-Name",          user_name).unwrap(),
        client.base_client.create_attribute_by_name("Password",           encrypt_data(user_pass, coa_packet.authenticator(), client.base_client.secret().as_bytes())).unwrap(),
        client.base_client.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes).unwrap(),
        client.base_client.create_attribute_by_name("NAS-Port-Id",        integer_to_bytes(0)).unwrap(),
        client.base_client.create_attribute_by_name("Service-Type",       integer_to_bytes(2)).unwrap(),
        client.base_client.create_attribute_by_name("NAS-Identifier",     String::from("trillian").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Called-Station-Id",  String::from("00-04-5F-00-0F-D1").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Framed-IP-Address",  framed_ip_addr_bytes).unwrap()
    ];

    coa_packet.set_attributes(attributes);

    b.iter(|| task::block_on(async {
        client.send_and_receive_packet(&mut coa_packet).await
    }) )
}
// ====================
