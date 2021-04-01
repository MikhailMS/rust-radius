//! RADIUS Server implementation


use crate::protocol::host::Host;
use crate::protocol::radius_packet::{ RadiusAttribute, RadiusPacket, TypeCode };
use crate::protocol::dictionary::Dictionary;
use crate::protocol::error::RadiusError;

use crypto::digest::Digest;
use crypto::md5::Md5;
use log::info;
use mio::{ Interest, Poll, Token };
use mio::net::UdpSocket;
use std::fmt;


/// Represents RADIUS server instance
pub struct Server {
    host:          Host,
    allowed_hosts: Vec<String>,
    server:        String,
    secret:        String,
    retries:       u16,
    timeout:       u16,
    socket_poll:   Poll,
    // Field is only used if SyncServer is fully implemented, so compiler would complain
    // otherwise
    #[allow(dead_code)]
    auth_socket:   UdpSocket,
    // Field is only used if SyncServer is fully implemented, so compiler would complain
    // otherwise
    #[allow(dead_code)]
    acct_socket:   UdpSocket,
    // Field is only used if SyncServer is fully implemented, so compiler would complain
    // otherwise
    #[allow(dead_code)]
    coa_socket:    UdpSocket,
    // handlers:      HashMap<RadiusMsgType, fn(server: &Server,request: &mut [u8])->Result<Vec<u8>, RadiusError>>
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


    /// Initialises RADIUS server instance
    pub fn initialise_server(auth_port: u16, acct_port: u16, coa_port: u16, dictionary: Dictionary, server: String, secret: String, retries: u16, timeout: u16) -> Result<Server, RadiusError> {
        let socket_poll = Poll::new()?;
        let host        = Host::initialise_host(auth_port, acct_port, coa_port, dictionary);

        let auth_port = host.port(&TypeCode::AccessRequest).ok_or_else(|| RadiusError::SocketInvalidConnectionError { error: String::from("There is no port match for AccessRequest") })?;
        let acct_port = host.port(&TypeCode::AccountingRequest).ok_or_else(|| RadiusError::SocketInvalidConnectionError { error: String::from("There is no port match for AccountingRequest") })?;
        let coa_port  = host.port(&TypeCode::CoARequest).ok_or_else(|| RadiusError::SocketInvalidConnectionError { error: String::from("There is no port match for CoARequest") })?;

        let auth_bind_addr = format!("{}:{}", server, auth_port).parse().map_err(|error| RadiusError::SocketAddrParseError(error))?;
        let acct_bind_addr = format!("{}:{}", server, acct_port).parse().map_err(|error| RadiusError::SocketAddrParseError(error))?;
        let coa_bind_addr  = format!("{}:{}", server, coa_port).parse().map_err(|error| RadiusError::SocketAddrParseError(error))?;

        let mut auth_server = UdpSocket::bind(auth_bind_addr).map_err(|error| RadiusError::SocketConnectionError(error))?;
        let mut acct_server = UdpSocket::bind(acct_bind_addr).map_err(|error| RadiusError::SocketConnectionError(error))?;
        let mut coa_server  = UdpSocket::bind(coa_bind_addr).map_err(|error| RadiusError::SocketConnectionError(error))?;

        socket_poll.registry().register(&mut auth_server, Server::AUTH_SOCKET, Interest::READABLE)?;
        socket_poll.registry().register(&mut acct_server, Server::ACCT_SOCKET, Interest::READABLE)?;
        socket_poll.registry().register(&mut coa_server,  Server::COA_SOCKET,  Interest::READABLE)?;

        info!("Authentication is initialised to accepts RADIUS packets on {}", &auth_server.local_addr()?);
        info!("Accounting is initialised to accepts RADIUS packet on {}",      &acct_server.local_addr()?);
        info!("CoA is initialised to accepts RADIUS packets on {}",            &coa_server.local_addr()?);

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
            }
        )
    }

    // pub fn register_sockets(&self) -> Result<(), RadiusError> {

    // }

    /// Adds client host address to allowed hosts list
    pub fn add_allowed_hosts(&mut self, host_addr: String) {
        self.allowed_hosts.push(host_addr);
    }

    /// Returns allowed hosts list
    pub fn allowed_hosts(&self) -> &[String] {
        &self.allowed_hosts
    }

    /// Returns socket poll
    pub fn socket_poll(&mut self) -> &mut Poll {
        &mut self.socket_poll
    }
    /// Returns auth socket
    pub fn auth_socket(&self) -> &UdpSocket {
        &self.auth_socket
    }
    /// Returns acct socket
    pub fn acct_socket(&self) -> &UdpSocket {
        &self.acct_socket
    }
    /// Returns coa socket
    pub fn coa_socket(&self) -> &UdpSocket {
        &self.coa_socket
    }

    /// Adds packet handller function to server instance
    ///
    /// Note: server can only have 3 handlers, 1 for each Radius message/packet type
    ///
    /// For example refer to `examples/simple_radius_server.rs`
    // pub fn add_request_handler(&mut self, handler_type: RadiusMsgType, handler_function: fn(server: &Server,request: &mut [u8])->Result<Vec<u8>, RadiusError>) -> Result<(), RadiusError> {
    //     match handler_type {
    //         RadiusMsgType::AUTH => {
    //             self.handlers.insert(handler_type, handler_function);
    //             Ok(())
    //         },
    //         RadiusMsgType::ACCT => {
    //             self.handlers.insert(handler_type, handler_function);
    //             Ok(())
    //         },
    //         RadiusMsgType::COA  => {
    //             self.handlers.insert(handler_type, handler_function);
    //             Ok(())
    //         }
    //     }
    // }

    // /// Returns HashMap with packet handler functions
    // pub fn request_handlers(&self) -> &HashMap<RadiusMsgType, fn(server: &Server,request: &mut [u8])->Result<Vec<u8>, RadiusError>> {
    //     &self.handlers
    // }

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

    // Function is only used if SyncServer is fully implemented, so compiler would complain
    // otherwise
    #[allow(dead_code)]
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
pub trait SyncServer {
    /// Main function, that starts and keeps server running
    ///
    /// For example see `examples/simple_radius_server.rs`
    fn run(&mut self) -> Result<(), RadiusError>;

    /// Function is responsible for resolving AUTH RADIUS request
    ///
    /// For example see `examples/simple_radius_server.rs`
    fn handle_auth_request(&self, _request: &mut [u8])->Result<Vec<u8>, RadiusError> {
        todo!();
    }
    /// Function is responsible for resolving ACCT RADIUS request
    ///
    /// For example see `examples/simple_radius_server.rs`
    fn handle_acct_request(&self, _request: &mut [u8])->Result<Vec<u8>, RadiusError> {
        todo!();
    }
    /// Function is responsible for resolving CoA RADIUS request
    ///
    /// For example see `examples/simple_radius_server.rs`
    fn handle_coa_request(&self, _request: &mut [u8])->Result<Vec<u8>, RadiusError> {
        todo!();
    }
    // =======
}


/// Main function, that starts and keeps server running
pub fn run_server<T: SyncServer>(server: &mut T) -> Result<(), RadiusError> {
    server.run()
}

#[cfg(test)]
mod tests {
    use super::*;

    // fn handle_coa_request(server: &Server, request: &mut [u8]) -> Result<Vec<u8>, RadiusError> {
    //     let attributes: Vec<RadiusAttribute> = Vec::with_capacity(1);

    //     let mut reply_packet = server.create_reply_packet(TypeCode::CoAACK, attributes, request);
    //     Ok(reply_packet.to_bytes())
    // }

    #[test]
    fn test_add_allowed_hosts_and_add_request_handler() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let mut server = Server::initialise_server(1810, 1809, 3790, dictionary, String::from("0.0.0.0"), String::from("secret"), 1, 2).unwrap();

        assert_eq!(server.allowed_hosts().len(), 0);

        server.add_allowed_hosts(String::from("127.0.0.1"));
        assert_eq!(server.allowed_hosts().len(), 1);

        // assert_eq!(server.get_request_handlers().len(), 0);

        // server.add_request_handler(RadiusMsgType::COA, handle_coa_request).unwrap();
        // assert_eq!(server.get_request_handlers().len(), 1);
    }
}
