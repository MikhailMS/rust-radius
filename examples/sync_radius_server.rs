//! An example on how to use RADIUS Server
//!
//! To run Sync RADIUS Server example
//! ```bash
//! cargo run --example sync_radius_server
//! ```


use radius_rust::protocol::dictionary::Dictionary;
use radius_rust::protocol::error::RadiusError;
use radius_rust::protocol::radius_packet::{ RadiusMsgType, TypeCode };
use radius_rust::server::{ server::Server, SyncServerTrait };
use radius_rust::tools::{ ipv6_string_to_bytes, ipv4_string_to_bytes, integer_to_bytes };

use log::{ debug, warn, LevelFilter };
use mio::net::UdpSocket;
use mio::{ Events, Interest, Poll, Token };
use simple_logger::SimpleLogger;
use std::io::{Error, ErrorKind};

struct CustomServer {
    base_server: Server,
    socket_poll: Poll,
    auth_socket: UdpSocket,
    acct_socket: UdpSocket,
    coa_socket:  UdpSocket,
}

impl CustomServer {
    /// Exists to allow mapping between AUTH socket and AUTH requests processing
    pub const AUTH_SOCKET: Token = Token(1);
    /// Exists to allow mapping between ACCT socket and ACCT requests processing
    pub const ACCT_SOCKET: Token = Token(2);
    /// Exists to allow mapping between CoA socket and CoA requests processing
    pub const COA_SOCKET:  Token = Token(3);

    fn initialise_server(auth_port: u16, acct_port: u16, coa_port: u16, dictionary: Dictionary, server: String, secret: String, retries: u16, timeout: u16, allowed_hosts: Vec<String>) -> Result<CustomServer, RadiusError> {
        let auth_bind_addr = format!("{}:{}", &server, auth_port).parse().map_err(|error| RadiusError::SocketAddrParseError(error))?;
        let acct_bind_addr = format!("{}:{}", &server, acct_port).parse().map_err(|error| RadiusError::SocketAddrParseError(error))?;
        let coa_bind_addr  = format!("{}:{}", &server, coa_port).parse().map_err(|error| RadiusError::SocketAddrParseError(error))?;

        let server = Server::with_dictionary(dictionary)
            .set_server(server)
            .set_secret(secret)
            .set_allowed_hosts(allowed_hosts)
            .set_retries(retries)
            .set_timeout(timeout)
            .set_port(RadiusMsgType::AUTH, auth_port)
            .set_port(RadiusMsgType::ACCT, acct_port)
            .set_port(RadiusMsgType::COA,  coa_port)
            .build_server();

        // Bind sockets
        let socket_poll = Poll::new()?;

        let mut auth_server = UdpSocket::bind(auth_bind_addr).map_err(|error| RadiusError::SocketConnectionError(error))?;
        let mut acct_server = UdpSocket::bind(acct_bind_addr).map_err(|error| RadiusError::SocketConnectionError(error))?;
        let mut coa_server  = UdpSocket::bind(coa_bind_addr).map_err(|error| RadiusError::SocketConnectionError(error))?;

        socket_poll.registry().register(&mut auth_server, CustomServer::AUTH_SOCKET, Interest::READABLE)?;
        socket_poll.registry().register(&mut acct_server, CustomServer::ACCT_SOCKET, Interest::READABLE)?;
        socket_poll.registry().register(&mut coa_server,  CustomServer::COA_SOCKET,  Interest::READABLE)?;

        debug!("Authentication is initialised to accepts RADIUS packets on {}", &auth_server.local_addr()?);
        debug!("Accounting is initialised to accepts RADIUS packets on {}",     &acct_server.local_addr()?);
        debug!("CoA is initialised to accepts RADIUS packets on {}",            &coa_server.local_addr()?);
        // ============

        Ok(
            CustomServer {
                base_server: server,
                socket_poll: socket_poll,
                auth_socket: auth_server,
                acct_socket: acct_server,
                coa_socket:  coa_server,
            }
        )
    }
}

impl SyncServerTrait for CustomServer {
    // Define general behaviour of RADIUS Server
    fn run(&mut self) -> Result<(), RadiusError> {
        let mut events = Events::with_capacity(1024);
        
        loop {
            self.socket_poll.poll(&mut events, None)?;

            for event in events.iter() {
                match event.token() {
                    CustomServer::AUTH_SOCKET => loop {
                        debug!("Received AUTH request");
                        let mut request = [0; 4096];
                        
                        match self.auth_socket.recv_from(&mut request) {
                            Ok((packet_size, source_address)) => {
                                if self.base_server.host_allowed(&source_address) {
                                    let response = self.handle_auth_request(&mut request[..packet_size])?;
                                    self.auth_socket.send_to(&response.as_slice(), source_address)?;
                                    break;
                                } else {
                                    warn!("{:?} is not listed as allowed", &source_address);
                                    break;
                                }
                            },
                            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                                break;
                            },
                            Err(error) => {
                                return Err( RadiusError::SocketConnectionError(error) );
                            }
                        }
                    },
                    CustomServer::ACCT_SOCKET => loop {
                        debug!("Received ACCT request");
                        let mut request = [0; 4096];
                        
                        match self.acct_socket.recv_from(&mut request) {
                            Ok((packet_size, source_address)) => {
                                if self.base_server.host_allowed(&source_address) {
                                    let response = self.handle_acct_request(&mut request[..packet_size])?;
                                    self.acct_socket.send_to(&response.as_slice(), source_address)?;
                                    break;
                                } else {
                                    warn!("{:?} is not listed as allowed", &source_address);
                                    break;
                                }
                            },
                            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                                break;
                            },
                            Err(error) => {
                                return Err( RadiusError::SocketConnectionError(error) );
                            }
                        }
                    },
                    CustomServer::COA_SOCKET  => loop {
                        debug!("Received CoA  request");
                        let mut request = [0; 4096];
                        
                        match self.coa_socket.recv_from(&mut request) {
                            Ok((packet_size, source_address)) => {
                                if self.base_server.host_allowed(&source_address) {
                                    let response = self.handle_coa_request(&mut request[..packet_size])?;
                                    self.coa_socket.send_to(&response.as_slice(), source_address)?;
                                    break;
                                } else {
                                    warn!("{:?} is not listed as allowed", &source_address);
                                    break;
                                }
                            },
                            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                                break;
                            },
                            Err(error) => {
                                return Err( RadiusError::SocketConnectionError(error) );
                            }
                        }
                    },
                    _ => {
                        return Err( RadiusError::SocketConnectionError(Error::new(ErrorKind::Other, format!("Non-supported UDP request: {:?}", event))) );
                    }
                }
            }
        }
    }

    // Define your own RADIUS packet handlers
    fn handle_auth_request(&self, request: &mut [u8]) -> Result<Vec<u8>, RadiusError> {
        let ipv6_bytes = ipv6_string_to_bytes("fc66::1/64")?;
        let ipv4_bytes = ipv4_string_to_bytes("192.168.0.1")?;

        let attributes = vec![
            self.base_server.create_attribute_by_name("Service-Type",       integer_to_bytes(2))?,
            self.base_server.create_attribute_by_name("Framed-IP-Address",  ipv4_bytes)?,
            self.base_server.create_attribute_by_name("Framed-IPv6-Prefix", ipv6_bytes)?
        ];

        let mut reply_packet = self.base_server.create_reply_packet(TypeCode::AccessAccept, attributes, request);
        Ok(reply_packet.to_bytes())
    }

    fn handle_acct_request(&self, request: &mut [u8]) -> Result<Vec<u8>, RadiusError> {
        let ipv6_bytes        = ipv6_string_to_bytes("fc66::1/64")?;
        let ipv4_bytes        = ipv4_string_to_bytes("192.168.0.1")?;
        let nas_ip_addr_bytes = ipv4_string_to_bytes("192.168.1.10")?;

        let attributes = vec![
            self.base_server.create_attribute_by_name("Service-Type",       integer_to_bytes(2))?,
            self.base_server.create_attribute_by_name("Framed-IP-Address",  ipv4_bytes)?,
            self.base_server.create_attribute_by_name("Framed-IPv6-Prefix", ipv6_bytes)?,
            self.base_server.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes)?
        ];

        let mut reply_packet = self.base_server.create_reply_packet(TypeCode::AccountingResponse, attributes, request);
        Ok(reply_packet.to_bytes())
    }

    fn handle_coa_request(&self, request: &mut [u8]) -> Result<Vec<u8>, RadiusError> {
        let state = String::from("testing").into_bytes();

        let attributes = vec![
            self.base_server.create_attribute_by_name("State", state)?
        ];

        let mut reply_packet = self.base_server.create_reply_packet(TypeCode::CoAACK, attributes, request);
        Ok(reply_packet.to_bytes())
    }
    // ------------------------
}

fn main() -> Result<(), RadiusError> {
    SimpleLogger::new().with_level(LevelFilter::Debug).init().expect("Failed to create new logger");
    debug!("RADIUS Server started");

    let dictionary = Dictionary::from_file("./dict_examples/integration_dict")?;
    let mut server = CustomServer::initialise_server(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2, vec![String::from("127.0.0.1")])?;

    server.run()
}
