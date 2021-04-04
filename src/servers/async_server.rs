//! Async RADIUS Server implementation


use crate::protocol::dictionary::Dictionary;
use crate::protocol::error::RadiusError;
use crate::protocol::host::Host;
use crate::protocol::radius_packet::{ RadiusAttribute, RadiusMsgType, RadiusPacket, TypeCode };

use async_trait::async_trait;
use async_std::net::UdpSocket;
use crypto::digest::Digest;
use crypto::md5::Md5;
use std::collections::HashMap;
use std::fmt;


/// Represents RADIUS async server instance
pub struct Server {
    host:          Host,
    allowed_hosts: Vec<String>,
    server:        String,
    secret:        String,
    retries:       u16,
    timeout:       u16,
    socket_ports:  HashMap<RadiusMsgType, u16>,
}

impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
         .field("host",          &self.host)
         .field("allowed_hosts", &self.allowed_hosts)
         .field("server",        &self.server)
         .field("secret",        &self.secret)
         .field("retries",       &self.retries)
         .field("timeout",       &self.timeout)
         .finish()
    }
}

impl Server {
    // === Builder for Async Server ===
    /// Initialize Server instance
    /// To be called **first** when creating RADIUS AsyncServer instance
    pub fn with_dictionary(dictionary: Dictionary) -> Server {
        let host = Host::with_dictionary(dictionary);

        Server {
            host:          host,
            allowed_hosts: Vec::new(),
            server:        String::from(""),
            secret:        String::from(""),
            retries:       1,
            timeout:       2,
            socket_ports:  HashMap::with_capacity(3)
        }
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
    pub fn add_protocol_port(mut self, protocol: RadiusMsgType, port: u16) -> Server {
        self.socket_ports.insert(protocol, port);
        self
    }

    /// *Required*
    /// Build Server instance
    pub fn build_server(self) -> Result<Server, RadiusError> {
        Ok(self)
    }
    // ===================

    /// Returns allowed hosts list
    pub fn server(&self) -> &str {
        &self.server
    }
    /// Returns allowed hosts list
    pub fn allowed_hosts(&self) -> &[String] {
        &self.allowed_hosts
    }

    /// Returns sockets
    pub fn socket_ports(&self) -> &HashMap<RadiusMsgType, u16> {
        &self.socket_ports
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


#[async_trait]
/// This trait is to be implemented by user, if they are planning to resolve AUTH, ACCT or CoA
/// RADIUS requests
pub trait ServerTrait {
    /// Main function, that starts and keeps server running
    ///
    /// For example see `examples/async_radius_server.rs`
    async fn run(&mut self) -> Result<(), RadiusError>;

    /// Function is responsible for resolving AUTH RADIUS request
    ///
    /// For example see `examples/async_radius_server.rs`
    async fn handle_auth_request(&self, _socket: UdpSocket) -> Result<(), RadiusError> {
        Ok(())
    }
    /// Function is responsible for resolving AUTH RADIUS request
    ///
    /// For example see `examples/async_radius_server.rs`
    async fn handle_acct_request(&self, _socket: UdpSocket) -> Result<(), RadiusError> {
        Ok(())
    }
    /// Function is responsible for resolving AUTH RADIUS request
    ///
    /// For example see `examples/async_radius_server.rs`
    async fn handle_coa_request(&self, _socket: UdpSocket) -> Result<(), RadiusError> {
        Ok(())
    }
}

/// Main function, that starts and keeps server running
pub async fn run_server<T: ServerTrait>(server: &mut T) -> Result<(), RadiusError> {
    server.run().await?;
    Ok(())
}
