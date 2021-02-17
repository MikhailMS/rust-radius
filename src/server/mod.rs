use super::protocol::host::Host;
use super::protocol::radius_packet::{ RadiusPacket, RadiusAttribute, TypeCode };
use super::protocol::dictionary::Dictionary;
use super::protocol::error::RadiusError;

use crypto::digest::Digest;
use crypto::md5::Md5;
use log::{ debug, warn };
use mio::{ Events, Interest, Poll, Token };
use mio::net::UdpSocket;
use std::collections::HashMap;
use std::fmt;
use std::io::{Error, ErrorKind};


const AUTH_SOCKET: Token = Token(1);
const ACCT_SOCKET: Token = Token(2);
const COA_SOCKET:  Token = Token(3);


#[derive(PartialEq, Eq, Hash)]
/// Allowed types of RADIUS messages/packets
pub enum RadiusMsgType {
    /// Authentication packet
    AUTH,
    /// Accounting packet
    ACCT,
    /// Change of Authorisation packet
    COA
}

impl fmt::Display for RadiusMsgType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RadiusMsgType::AUTH => f.write_str("Auth"),
            RadiusMsgType::ACCT => f.write_str("Acct"),
            RadiusMsgType::COA  => f.write_str("CoA"),
        }
    }
}


/// Represents RADIUS server instance
pub struct Server {
    host:          Host,
    allowed_hosts: Vec<String>,
    server:        String,
    secret:        String,
    retries:       u16,
    timeout:       u16,
    socket_poll:   Poll,
    auth_socket:   UdpSocket,
    acct_socket:   UdpSocket,
    coa_socket:    UdpSocket,
    handlers:      HashMap<RadiusMsgType, fn(server: &Server,request: &mut [u8])->Result<Vec<u8>, RadiusError>>
}

impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
         .field("host",          &self.host)
         .field("allowed_hosts", &self.allowed_hosts)
         .field("server",        &self.server)
         .field("secret",        &self.server)
         .field("retries",       &self.retries)
         .field("timeout",       &self.timeout)
         .field("socket_poll",   &self.socket_poll)
         .finish()
    }
}

impl Server {
    /// Initialises RADIUS server instance
    pub fn initialise_server(auth_port: u16, acct_port: u16, coa_port: u16, dictionary: Dictionary, server: String, secret: String, retries: u16, timeout: u16) -> Result<Server, RadiusError> {
        let socket_poll = Poll::new()?;
        let host        = Host::initialise_host(auth_port, acct_port, coa_port, dictionary);

        let auth_port = host.get_port(&TypeCode::AccessRequest).ok_or_else(|| RadiusError::SocketInvalidConnection { error: String::from("There is no port match for AccessRequest") })?;
        let acct_port = host.get_port(&TypeCode::AccountingRequest).ok_or_else(|| RadiusError::SocketInvalidConnection { error: String::from("There is no port match for AccountingRequest") })?;
        let coa_port  = host.get_port(&TypeCode::CoARequest).ok_or_else(|| RadiusError::SocketInvalidConnection { error: String::from("There is no port match for CoARequest") })?;

        let auth_bind_addr = format!("{}:{}", server, auth_port).parse().map_err(|error| RadiusError::SocketAddrParseError(error))?;
        let acct_bind_addr = format!("{}:{}", server, acct_port).parse().map_err(|error| RadiusError::SocketAddrParseError(error))?;
        let coa_bind_addr  = format!("{}:{}", server, coa_port).parse().map_err(|error| RadiusError::SocketAddrParseError(error))?;

        let mut auth_server = UdpSocket::bind(auth_bind_addr).map_err(|error| RadiusError::SocketConnectionError(error))?;
        let mut acct_server = UdpSocket::bind(acct_bind_addr).map_err(|error| RadiusError::SocketConnectionError(error))?;
        let mut coa_server  = UdpSocket::bind(coa_bind_addr).map_err(|error| RadiusError::SocketConnectionError(error))?;

        socket_poll.registry().register(&mut auth_server, AUTH_SOCKET, Interest::READABLE)?;
        socket_poll.registry().register(&mut acct_server, ACCT_SOCKET, Interest::READABLE)?;
        socket_poll.registry().register(&mut coa_server,  COA_SOCKET,  Interest::READABLE)?;

        Ok(
            Server {
                host:          host,
                allowed_hosts: Vec::new(),
                server:        server,
                secret:        secret,
                retries:       retries,
                timeout:       timeout,
                socket_poll:   socket_poll,
                auth_socket:   auth_server,
                acct_socket:   acct_server,
                coa_socket:    coa_server,
                handlers:      HashMap::with_capacity(3)
            }
        )
    }

    /// Adds client host address to allowed hosts list
    pub fn add_allowed_hosts(&mut self, host_addr: String) {
        self.allowed_hosts.push(host_addr);
    }

    /// Returns allowed hosts list
    pub fn get_allowed_hosts(&self) -> &[String] {
        &self.allowed_hosts
    }

    /// Adds packet handller function to server instance
    ///
    /// Note: server can only have 3 handlers, 1 for each Radius message/packet type
    ///
    /// For example refer to `examples/simple_radius_server.rs`
    pub fn add_request_handler(&mut self, handler_type: RadiusMsgType, handler_function: fn(server: &Server,request: &mut [u8])->Result<Vec<u8>, RadiusError>) -> Result<(), RadiusError> {
        match handler_type {
            RadiusMsgType::AUTH => {
                self.handlers.insert(handler_type, handler_function);
                Ok(())
            },
            RadiusMsgType::ACCT => {
                self.handlers.insert(handler_type, handler_function);
                Ok(())
            },
            RadiusMsgType::COA  => {
                self.handlers.insert(handler_type, handler_function);
                Ok(())
            }
        }
    }

    /// Returns HashMap with packet handler functions
    pub fn get_request_handlers(&self) -> &HashMap<RadiusMsgType, fn(server: &Server,request: &mut [u8])->Result<Vec<u8>, RadiusError>> {
        &self.handlers
    }

    /// Creates RADIUS packet attribute by name, that is defined in dictionary file
    ///
    /// For example, see Client (these function are same)
    pub fn create_attribute_by_name(&self, attribute_name: &str, value: Vec<u8>) -> Result<RadiusAttribute, RadiusError> {
        self.host.create_attribute_by_name(attribute_name, value)
    }

    /// Creates RADIUS packet attribute by id, that is defined in dictionary file
    ///
    /// For example, see Client (these function are same)
    pub fn create_attribute_by_id(&self, attribute_id: u8, value: Vec<u8>) -> Result<RadiusAttribute, RadiusError> {
        self.host.create_attribute_by_id(attribute_id, value)
    }

    /// Creates reply RADIUS packet
    ///
    /// Similar to Client **create_packet()**, however also sets correct packet ID and authenticator
    pub fn create_reply_packet(&self, reply_code: TypeCode, attributes: Vec<RadiusAttribute>, request: &mut [u8]) -> RadiusPacket {
        let mut reply_packet = RadiusPacket::initialise_packet(reply_code, attributes);

        // We can only create new authenticator after we set reply packet ID to the request's ID
        reply_packet.override_id(request[1]);

        let authenticator = self.create_reply_authenticator(&reply_packet.to_bytes(), &request[4..20]);
        reply_packet.override_authenticator(authenticator);

        reply_packet
    }

    fn create_reply_authenticator(&self, raw_reply_packet: &[u8], request_authenticator: &[u8]) -> Vec<u8> {
        // We need to create authenticator as MD5 hash (similar to how client verifies server reply)
        let mut md5_hasher    = Md5::new();
        let mut authenticator = [0; 16];

        md5_hasher.input(&raw_reply_packet[0..4]); // Append reply's   type code, reply ID and reply length
        md5_hasher.input(&request_authenticator);  // Append request's authenticator
        md5_hasher.input(&raw_reply_packet[20..]); // Append reply's   attributes
        md5_hasher.input(&self.secret.as_bytes()); // Append server's  secret. Possibly it should be client's secret, which sould be stored together with allowed hostnames ?
        
        md5_hasher.result(&mut authenticator);
        // ----------------

        authenticator.to_vec()
    }

    /// Main function, that starts and keeps server running
    ///
    /// For example see `examples/simple_radius_server.rs`
    pub fn run_server(&mut self) -> Result<(), RadiusError> {
        let mut events = Events::with_capacity(1024);
        
        loop {
            self.socket_poll.poll(&mut events, None)?;

            for event in events.iter() {
                match event.token() {
                    AUTH_SOCKET => loop {
                        debug!("Received AUTH request");
                        let mut request = [0; 4096];
                        
                        match self.auth_socket.recv_from(&mut request) {
                            Ok((packet_size, source_address)) => {
                                if self.host_allowed(&source_address) {
                                    let handle_auth_request = self.handlers.get(&RadiusMsgType::AUTH).expect("Auth handler is not defined!");
                                    let response            = handle_auth_request(&self, &mut request[..packet_size])?;
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
                    ACCT_SOCKET => loop {
                        debug!("Received ACCT request");
                        let mut request = [0; 4096];
                        
                        match self.acct_socket.recv_from(&mut request) {
                            Ok((packet_size, source_address)) => {
                                if self.host_allowed(&source_address) {
                                    let handle_acct_request = self.handlers.get(&RadiusMsgType::ACCT).expect("Acct handler is not defined!");
                                    let response            = handle_acct_request(&self, &mut request[..packet_size])?;
                                    
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
                    COA_SOCKET  => loop {
                        debug!("Received CoA  request");
                        let mut request = [0; 4096];
                        
                        match self.coa_socket.recv_from(&mut request) {
                            Ok((packet_size, source_address)) => {
                                if self.host_allowed(&source_address) {
                                    let handle_coa_request = self.handlers.get(&RadiusMsgType::COA).expect("CoA handler is not defined!");
                                    let response           = handle_coa_request(&self, &mut request[..packet_size])?;
                                    
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

    /// Verifies incoming RADIUS packet:
    ///
    /// Server would try to build RadiusPacket from raw bytes, and if it succeeds then packet is
    /// valid, otherwise would return RadiusError
    pub fn verify_request(&self, request: &[u8]) -> Result<(), RadiusError> {
        match RadiusPacket::initialise_packet_from_bytes(&self.host.get_dictionary(), request) {
            Err(err) => Err(err),
            _        => Ok(())
        }
    }

    /// Verifies RadiusAttributes's values of incoming RADIUS packet:
    ///
    /// Server would try to build RadiusPacket from raw bytes, and then it would try to restore
    /// RadiusAttribute original value from bytes, based on the attribute data type (see SupportedAttributeTypes)
    pub fn verify_request_attributes(&self, request: &[u8]) -> Result<(), RadiusError> {
        self.host.verify_packet_attributes(&request)
    }

    /// Initialises RadiusPacket from bytes
    ///
    /// Unlike validate_request() returns new RadiusPacket (if valid), so user can get data out of it
    pub fn initialise_packet_from_bytes(&self, request: &[u8]) -> Result<RadiusPacket, RadiusError> {
        self.host.initialise_packet_from_bytes(request)
    }

    fn host_allowed(&self, remote_host: &std::net::SocketAddr) -> bool {
        let remote_host_name            = remote_host.to_string();
        let remote_host_name: Vec<&str> = remote_host_name.split(":").collect();

        self.allowed_hosts.iter().any(|host| host==remote_host_name[0]) 
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn handle_coa_request(server: &Server, request: &mut [u8]) -> Result<Vec<u8>, RadiusError> {
        let attributes: Vec<RadiusAttribute> = Vec::with_capacity(1);

        let mut reply_packet = server.create_reply_packet(TypeCode::CoAACK, attributes, request);
        Ok(reply_packet.to_bytes())
    }

    #[test]
    fn test_add_allowed_hosts_and_add_request_handler() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let mut server = Server::initialise_server(1810, 1809, 3790, dictionary, String::from("0.0.0.0"), String::from("secret"), 1, 2).unwrap();

        assert_eq!(server.get_allowed_hosts().len(), 0);

        server.add_allowed_hosts(String::from("127.0.0.1"));
        assert_eq!(server.get_allowed_hosts().len(), 1);

        assert_eq!(server.get_request_handlers().len(), 0);

        server.add_request_handler(RadiusMsgType::COA, handle_coa_request).unwrap();
        assert_eq!(server.get_request_handlers().len(), 1);
    }
}
