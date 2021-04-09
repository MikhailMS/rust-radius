// fn main() {}

//! An example on how to use RADIUS AsyncServer
//!
//! To run Async RADIUS Server example
//! ```bash
//! cargo run --example async_radius_server --all-features
//! ```


use radius_rust::protocol::dictionary::Dictionary;
use radius_rust::protocol::error::RadiusError;
use radius_rust::protocol::radius_packet::{ RadiusMsgType, TypeCode };
use radius_rust::tools::{ ipv6_string_to_bytes, ipv4_string_to_bytes, integer_to_bytes };
use radius_rust::server::{ server::Server, AsyncServerTrait };

use async_std::task;
use async_std::net::UdpSocket;
use async_trait::async_trait;
use futures::{
    future::FutureExt,
    pin_mut,
    select,
};
use log::{ debug, LevelFilter };
use simple_logger::SimpleLogger;


struct CustomServer {
    base_server: Server,
    auth_socket: UdpSocket,
    acct_socket: UdpSocket,
    coa_socket: UdpSocket
}

impl CustomServer {
    async fn initialise_server(auth_port: u16, acct_port: u16, coa_port: u16, dictionary: Dictionary, server: String, secret: String, retries: u16, timeout: u16, allowed_hosts: Vec<String>) -> Result<CustomServer, RadiusError> {
        // Initialise sockets
        let auth_socket = UdpSocket::bind(format!("{}:{}", &server, auth_port)).await?;
        let acct_socket = UdpSocket::bind(format!("{}:{}", &server, acct_port)).await?;
        let coa_socket  = UdpSocket::bind(format!("{}:{}", &server, coa_port)).await?;

        debug!("Authentication Server is started on {}", &auth_socket.local_addr()?);
        debug!("Acconting Server is started on {}",      &acct_socket.local_addr()?);
        debug!("CoA Server is started on {}",            &coa_socket.local_addr()?);
        // =====================

        let server = Server::with_dictionary(dictionary)
            .set_server(server)
            .set_secret(secret)
            .set_port(RadiusMsgType::AUTH, auth_port)
            .set_port(RadiusMsgType::ACCT, acct_port)
            .set_port(RadiusMsgType::COA,  coa_port)
            .set_allowed_hosts(allowed_hosts)
            .set_retries(retries)
            .set_timeout(timeout)
            .build_server();

        Ok(
            CustomServer {
                base_server: server,
                auth_socket: auth_socket,
                acct_socket: acct_socket,
                coa_socket:  coa_socket,
            }
        )
    }
}

#[async_trait]
impl AsyncServerTrait for CustomServer {
    async fn run(&mut self) -> Result<(), RadiusError> {

        let auth_task = self.handle_auth_request().fuse();
        let acct_task = self.handle_acct_request().fuse();
        let coa_task  = self.handle_coa_request().fuse();

        pin_mut!(auth_task, acct_task, coa_task);

        select! {
            _ = auth_task => {
                Ok(())
            },
            _ = acct_task => {
                Ok(())
            },
            _ = coa_task  => {
                Ok(())
            }
        }

    }

    // Define your own RADIUS packet handlers
    async fn handle_auth_request(&self) -> Result<(), RadiusError> {
        loop {
            debug!("Handling AUTH request");

            // Read RADIUS packet from socket
            let mut request      = [0u8; 4096];
            let (_, source_addr) = self.auth_socket.recv_from(&mut request).await.unwrap();
            // ============================

            // Build response RADIUS packet
            let ipv6_bytes = ipv6_string_to_bytes("fc66::1/64")?;
            let ipv4_bytes = ipv4_string_to_bytes("192.168.0.1")?;

            let attributes = vec![
                self.base_server.create_attribute_by_name("Service-Type",       integer_to_bytes(2))?,
                self.base_server.create_attribute_by_name("Framed-IP-Address",  ipv4_bytes)?,
                self.base_server.create_attribute_by_name("Framed-IPv6-Prefix", ipv6_bytes)?
            ];

            let mut reply_packet = self.base_server.create_reply_packet(TypeCode::AccessAccept, attributes, &mut request);
            // ============================

            // Send RADIUS packet
            self.auth_socket.send_to(&reply_packet.to_bytes(), &source_addr).await.map_err(|error| RadiusError::SocketConnectionError(error))?;
            // ============================
        }
    }
    async fn handle_acct_request(&self) -> Result<(), RadiusError> {
        loop {
            debug!("Handling ACCT request");

            // Read RADIUS packet from socket
            let mut request      = [0u8; 4096];
            let (_, source_addr) = self.acct_socket.recv_from(&mut request).await.unwrap();
            // ============================

            // Build response RADIUS packet
            let ipv6_bytes        = ipv6_string_to_bytes("fc66::1/64")?;
            let ipv4_bytes        = ipv4_string_to_bytes("192.168.0.1")?;
            let nas_ip_addr_bytes = ipv4_string_to_bytes("192.168.1.10")?;

            let attributes = vec![
                self.base_server.create_attribute_by_name("Service-Type",       integer_to_bytes(2))?,
                self.base_server.create_attribute_by_name("Framed-IP-Address",  ipv4_bytes)?,
                self.base_server.create_attribute_by_name("Framed-IPv6-Prefix", ipv6_bytes)?,
                self.base_server.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes)?
            ];

            let mut reply_packet = self.base_server.create_reply_packet(TypeCode::AccountingResponse, attributes, &mut request);
            // ============================

            // Send RADIUS packet
            self.acct_socket.send_to(&reply_packet.to_bytes(), &source_addr).await.map_err(|error| RadiusError::SocketConnectionError(error))?;
            // ============================
        }
    }
    async fn handle_coa_request(&self) -> Result<(), RadiusError> {
        loop {
            debug!("Handling CoA request");

            // Read RADIUS packet from socket
            let mut request      = [0u8; 4096];
            let (_, source_addr) = self.coa_socket.recv_from(&mut request).await.unwrap();
            // ============================

            // Build response RADIUS packet
            let state = String::from("testing").into_bytes();

            let attributes = vec![
                self.base_server.create_attribute_by_name("State", state)?
            ];
            let mut reply_packet = self.base_server.create_reply_packet(TypeCode::CoAACK, attributes, &mut request);
            // ============================

            // Send RADIUS packet
            self.coa_socket.send_to(&reply_packet.to_bytes(), &source_addr).await.map_err(|error| RadiusError::SocketConnectionError(error))?;
            // ============================
        }
    }
    // ============================
}


fn main() -> Result<(), RadiusError> {
    SimpleLogger::new().with_level(LevelFilter::Debug).init().expect("Failed to create new logger");
    debug!("Async RADIUS Server started");

    task::block_on(async {
        let dictionary    = Dictionary::from_file("./dict_examples/integration_dict").expect("Failed to load or parse file");
        let allowed_hosts = vec![String::from("127.0.0.1")];
        let mut server    = CustomServer::initialise_server(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2, allowed_hosts).await.expect("Failed to create RADIUS Server");

        server.run().await
    })
}
