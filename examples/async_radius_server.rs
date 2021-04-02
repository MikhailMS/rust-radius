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
use radius_rust::servers::async_server::{ Server, ServerTrait };

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
    base_server: Server
}

impl CustomServer {
    fn initialise_server(auth_port: u16, acct_port: u16, coa_port: u16, dictionary: Dictionary, server: String, secret: String, retries: u16, timeout: u16, allowed_hosts: Vec<String>) -> Result<CustomServer, RadiusError> {
        let server = Server::with_dictionary(dictionary)
            .set_server(server)
            .set_secret(secret)
            .add_protocol_port(RadiusMsgType::AUTH, auth_port)
            .add_protocol_port(RadiusMsgType::ACCT, acct_port)
            .add_protocol_port(RadiusMsgType::COA,  coa_port)
            .set_allowed_hosts(allowed_hosts)
            .set_retries(retries)
            .set_timeout(timeout)
            .build_server()?;
        Ok(
            CustomServer { base_server: server }
        )
    }
}

#[async_trait]
impl ServerTrait for CustomServer {
    async fn run(&mut self) -> Result<(), RadiusError> {
        // Possibly below block should be moved to async_server::Server implementation, under build_server()
        // function
        let auth_server = UdpSocket::bind(format!("{}:{}", &self.base_server.server(), self.base_server.socket_ports().get(&RadiusMsgType::AUTH).unwrap())).await?;
        let acct_server = UdpSocket::bind(format!("{}:{}", &self.base_server.server(), self.base_server.socket_ports().get(&RadiusMsgType::ACCT).unwrap())).await?;
        let coa_server  = UdpSocket::bind(format!("{}:{}", &self.base_server.server(), self.base_server.socket_ports().get(&RadiusMsgType::COA).unwrap())).await?;

        debug!("Authentication Server is started on {}", &auth_server.local_addr()?);
        debug!("Acconting Server is started on {}",      &acct_server.local_addr()?);
        debug!("CoA Server is started on {}",            &coa_server.local_addr()?);
        // =====================

        let auth_task = self.handle_auth_request(auth_server).fuse();
        let acct_task = self.handle_acct_request(acct_server).fuse();
        let coa_task  = self.handle_coa_request(coa_server).fuse();

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
    async fn handle_auth_request(&self, socket: UdpSocket) -> Result<(), RadiusError> {
        let mut request = vec![0u8; 1024];

        loop {
            let (req_size, source_addr) = socket.recv_from(&mut request).await?;
            println!("Received AUTH request from [{}], of size {} bytes", source_addr, req_size);
            // Process logic
            let ipv6_bytes = ipv6_string_to_bytes("fc66::1/64")?;
            let ipv4_bytes = ipv4_string_to_bytes("192.168.0.1")?;

            let attributes = vec![
                self.base_server.create_attribute_by_name("Service-Type",       integer_to_bytes(2))?,
                self.base_server.create_attribute_by_name("Framed-IP-Address",  ipv4_bytes)?,
                self.base_server.create_attribute_by_name("Framed-IPv6-Prefix", ipv6_bytes)?
            ];

            let mut reply_packet = self.base_server.create_reply_packet(TypeCode::AccessAccept, attributes, &mut request[..req_size]);
            // ============

            socket.send_to(&reply_packet.to_bytes().as_slice(), &source_addr).await?;
        }
    }
    async fn handle_acct_request(&self, socket: UdpSocket) -> Result<(), RadiusError> {
        let mut request = vec![0u8; 1024];

        loop {
            let (req_size, source_addr) = socket.recv_from(&mut request).await?;
            println!("Received ACCT request from [{}], of size {} bytes", source_addr, req_size);
            // Process logic
            let ipv6_bytes        = ipv6_string_to_bytes("fc66::1/64")?;
            let ipv4_bytes        = ipv4_string_to_bytes("192.168.0.1")?;
            let nas_ip_addr_bytes = ipv4_string_to_bytes("192.168.1.10")?;

            let attributes = vec![
                self.base_server.create_attribute_by_name("Service-Type",       integer_to_bytes(2))?,
                self.base_server.create_attribute_by_name("Framed-IP-Address",  ipv4_bytes)?,
                self.base_server.create_attribute_by_name("Framed-IPv6-Prefix", ipv6_bytes)?,
                self.base_server.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes)?
            ];

            let mut reply_packet = self.base_server.create_reply_packet(TypeCode::AccessAccept, attributes, &mut request[..req_size]);
            // ============

            socket.send_to(&reply_packet.to_bytes().as_slice(), &source_addr).await?;
        }
    }
    async fn handle_coa_request(&self, socket: UdpSocket) -> Result<(), RadiusError> {
        let mut request = vec![0u8; 1024];

        loop {
            let (req_size, source_addr) = socket.recv_from(&mut request).await?;
            println!("Received CoA request from [{}], of size {} bytes", source_addr, req_size);
            // Process logic
            let state = String::from("testing").into_bytes();

            let attributes = vec![
                self.base_server.create_attribute_by_name("State", state)?
            ];

            let mut reply_packet = self.base_server.create_reply_packet(TypeCode::AccessAccept, attributes, &mut request[..req_size]);
            // ============

            socket.send_to(&reply_packet.to_bytes().as_slice(), &source_addr).await?;
        }
    }
    // ======================
}


fn main() -> Result<(), RadiusError> {
    SimpleLogger::new().with_level(LevelFilter::Debug).init().expect("Failed to create new logger");
    debug!("Async RADIUS Server started");

    task::block_on(async {
        let dictionary    = Dictionary::from_file("./dict_examples/integration_dict").expect("Failed to load or parse file");
        let allowed_hosts = vec![String::from("127.0.0.1")];
        let mut server    = CustomServer::initialise_server(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2, allowed_hosts).expect("Failed to create RADIUS Server");

        server.run().await
    })
}
