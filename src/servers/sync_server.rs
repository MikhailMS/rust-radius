//! RADIUS Sync Server implementation


use crate::protocol::host::Host;
use crate::protocol::radius_packet::{ RadiusAttribute, RadiusMsgType, RadiusPacket, TypeCode };
use crate::protocol::dictionary::Dictionary;
use crate::protocol::error::RadiusError;

use crypto::digest::Digest;
use crypto::md5::Md5;
use log::info;
use mio::net::UdpSocket;
use mio::{ Interest, Poll, Token };
use std::cell::{ RefCell, RefMut };
use std::collections::HashMap;
use std::fmt;


/// Represents RADIUS sync server instance
pub struct Server {
    host:          Host,
    allowed_hosts: Vec<String>,
    server:        String,
    secret:        String,
    retries:       u16,
    timeout:       u16,
    socket_poll:   RefCell<Poll>,
    sockets:       HashMap<RadiusMsgType, UdpSocket>
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
    /// Exists to allow mapping between AUTH socket and AUTH requests processing
    pub const AUTH_SOCKET: Token = Token(1);
    /// Exists to allow mapping between ACCT socket and ACCT requests processing
    pub const ACCT_SOCKET: Token = Token(2);
    /// Exists to allow mapping between CoA socket and CoA requests processing
    pub const COA_SOCKET:  Token = Token(3);

    // === Builder for Async Server ===
    /// Initialize Server instance
    /// To be called **first** when creating RADIUS Sync Server instance
    pub fn with_dictionary(dictionary: Dictionary) -> Result<Server, RadiusError> {
        let host = Host::with_dictionary(dictionary);
        let poll = Poll::new()?;

        Ok(Server {
            host:          host,
            allowed_hosts: Vec::new(),
            server:        String::from(""),
            secret:        String::from(""),
            retries:       1,
            timeout:       2,
            socket_poll:   RefCell::new(poll),
            sockets:       HashMap::with_capacity(3)
        })
    }

    /// *Required*
    /// Sets hostname to which server would try to bind
    pub fn set_server(mut self, server: String) -> Server {
        self.server = server;
        self
    }

    /// *Required*
    /// Sets secret which is used to encode/decode RADIUS packet
    pub fn set_secret(mut self, secret: String) -> Server {
        self.secret = secret;
        self
    }

    /// *Optional*
    /// Sets socket retries
    pub fn set_retries(mut self, retries: u16) -> Server {
        self.retries = retries;
        self
    }

    /// *Optional*
    /// Sets socket timeout
    pub fn set_timeout(mut self, timeout: u16) -> Server {
        self.timeout = timeout;
        self
    }

    /// *Required*
    /// Sets allowed hosts, ie hosts from where server is allowed to accept RADIUS packets
    pub fn set_allowed_hosts(mut self, allowed_hosts: Vec<String>) -> Server {
        self.allowed_hosts = allowed_hosts;
        self
    }

    /// *Required*
    /// Sets ports, to which server would be bind depending on the RADIUS Message Type (AUTH, ACCT
    /// or CoA)
    pub fn add_protocol_port(mut self, protocol: RadiusMsgType, port: u16) -> Result<Server, RadiusError> {
        let bind_addr = format!("{}:{}", self.server, port).parse().map_err(|error| RadiusError::SocketAddrParseError(error))?;
        match protocol {
            RadiusMsgType::AUTH => {
                let mut socket = UdpSocket::bind(bind_addr).map_err(|error| RadiusError::SocketConnectionError(error))?;
                info!("Authentication is initialised to accepts RADIUS packets on {}", &socket.local_addr()?);
                self.socket_poll.borrow().registry().register(&mut socket, Server::AUTH_SOCKET, Interest::READABLE)?;
                self.sockets.insert(protocol, socket);
            },
            RadiusMsgType::ACCT => {
                let mut socket = UdpSocket::bind(bind_addr).map_err(|error| RadiusError::SocketConnectionError(error))?;
                info!("Accounting is initialised to accepts RADIUS packets on {}", &socket.local_addr()?);
                self.socket_poll.borrow().registry().register(&mut socket, Server::ACCT_SOCKET, Interest::READABLE)?;
                self.sockets.insert(protocol, socket);
            },
            RadiusMsgType::COA => {
                let mut socket = UdpSocket::bind(bind_addr).map_err(|error| RadiusError::SocketConnectionError(error))?;
                info!("CoA is initialised to accepts RADIUS packets on {}", &socket.local_addr()?);
                self.socket_poll.borrow().registry().register(&mut socket, Server::COA_SOCKET, Interest::READABLE)?;
                self.sockets.insert(protocol, socket);
            }
        }

        Ok(self)
    }

    /// *Required*
    /// Build Server instance
    pub fn build_server(self) -> Result<Server, RadiusError> {
        Ok(self)
    }
    // ===================

    /// Returns allowed hosts list
    pub fn allowed_hosts(&self) -> &[String] {
        &self.allowed_hosts
    }

    /// Returns socket poll
    pub fn socket_poll(&mut self) -> RefMut<'_, Poll> {
        self.socket_poll.borrow_mut()
    }

    /// Returns sockets
    pub fn sockets(&self) -> &HashMap<RadiusMsgType, UdpSocket> {
        &self.sockets
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

    /// Verifies incoming RADIUS packet:
    ///
    /// Server would try to build RadiusPacket from raw bytes, and if it succeeds then packet is
    /// valid, otherwise would return RadiusError
    pub fn verify_request(&self, request: &[u8]) -> Result<(), RadiusError> {
        match RadiusPacket::initialise_packet_from_bytes(&self.host.dictionary(), request) {
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

    /// Checks if host from where Server received RADIUS request is allowed host, meaning RADIUS
    /// Server can process such request
    pub fn host_allowed(&self, remote_host: &std::net::SocketAddr) -> bool {
        let remote_host_name            = remote_host.to_string();
        let remote_host_name: Vec<&str> = remote_host_name.split(":").collect();

        self.allowed_hosts.iter().any(|host| host==remote_host_name[0]) 
    }
}


/// This trait is to be implemented by user, if they are planning to resolve AUTH, ACCT or CoA
/// RADIUS requests
pub trait ServerTrait {
    /// Main function, that starts and keeps server running
    ///
    /// For example see `examples/sync_radius_server.rs`
    fn run(&mut self) -> Result<(), RadiusError>;

    /// Function is responsible for resolving AUTH RADIUS request
    ///
    /// For example see `examples/sync_radius_server.rs`
    fn handle_auth_request(&self, request: &mut [u8])->Result<Vec<u8>, RadiusError> {
        Ok(request.to_vec())
    }
    /// Function is responsible for resolving ACCT RADIUS request
    ///
    /// For example see `examples/sync_radius_server.rs`
    fn handle_acct_request(&self, request: &mut [u8])->Result<Vec<u8>, RadiusError> {
        Ok(request.to_vec())
    }
    /// Function is responsible for resolving CoA RADIUS request
    ///
    /// For example see `examples/sync_radius_server.rs`
    fn handle_coa_request(&self, request: &mut [u8])->Result<Vec<u8>, RadiusError> {
        Ok(request.to_vec())
    }
}


/// Main function, that starts and keeps server running
pub fn run_server<T: ServerTrait>(server: &mut T) -> Result<(), RadiusError> {
    server.run()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_allowed_hosts_and_add_request_handler() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let server     = Server::with_dictionary(dictionary).unwrap()
            .set_server(String::from("0.0.0.0"))
            .set_secret(String::from("secret"))
            .set_allowed_hosts(vec![String::from("127.0.0.1")])
            .build_server().unwrap();

        assert_eq!(server.allowed_hosts().len(), 1);
    }
}
