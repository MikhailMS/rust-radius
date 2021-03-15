//! Async RADIUS Server implementation


use crate::protocol::dictionary::Dictionary;
use crate::protocol::error::RadiusError;
use crate::protocol::host::Host;
use crate::protocol::radius_packet::{ RadiusAttribute, RadiusMsgType, RadiusPacket, TypeCode };

use async_std::net::{ SocketAddr, UdpSocket };
// use async_std::task;
use crypto::digest::Digest;
use crypto::md5::Md5;
use futures::executor::block_on;
use futures::StreamExt;
use log::{ debug };//, info, warn };
use std::collections::HashMap;
use std::fmt;


/// Represents RADIUS server instance
pub struct AsyncServer {
    host:          Host,
    allowed_hosts: Vec<String>,
    server:        String,
    secret:        String,
    retries:       u16,
    timeout:       u16,
    socket_ports:  HashMap<RadiusMsgType, u16>,
    handlers:      HashMap<RadiusMsgType, fn(server: &AsyncServer, request: &mut [u8])-> Result<Vec<u8>, RadiusError>>
}

impl fmt::Debug for AsyncServer {
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

impl AsyncServer {

    /// Returns HashMap with packet handler functions
    pub fn request_handlers(&self) -> &HashMap<RadiusMsgType, fn(server: &AsyncServer,request: &mut [u8])->Result<Vec<u8>, RadiusError>> {
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

    // === Work happens here ===
    /// Main function that runs server process
    pub async fn run_server(&self) {
        let sockets: Vec<_> = self.socket_ports.iter().map(|(protocol, port)| {
            let socket = block_on(UdpSocket::bind(format!("{}:{}", &self.server, port))).unwrap();

            debug!("Listening {} socket on {}", &protocol, &socket.local_addr().unwrap());

            let socket         = Box::new(socket);
            // let socket_handler = self.get_socket_handler(protocol);
            let fut            = futures::stream::unfold(socket, AsyncServer::read_socket_data);
            Box::pin(fut)
        }).collect();

        let stream = futures::stream::select_all(sockets);

        stream.for_each_concurrent(None, debug_out).await;
    }

    async fn read_socket_data(socket: Box<UdpSocket>) -> Option<((usize, SocketAddr, [u8; 4096]), Box<UdpSocket>)> {
        // This function is sort of a description on how to get the data from the stream and where the
        // next one is
        let mut buf = [0u8; 4096];
        let (len, addr) = socket.recv_from(&mut buf).await.unwrap();

        Some(((len, addr, buf), socket))
    }
    // =========================
    
}


async fn debug_out((len, addr, buf): (usize, SocketAddr, [u8; 4096])) {
    // While this function is actually the place, where I can do data manipulation (even thou I can
    // do so in unfold_socket (technically))
    debug!("Received {} bytes from {}, first byte is {}", len, addr, buf[0]);
}
// =========================


/// Represents builder for RADIUS server instance
pub struct AsyncServerBuilder {
    allowed_hosts: Vec<String>,
    dictionary:    Dictionary,
    retries:       u16,
    timeout:       u16,
    secret:        String,
    server:        String,
    socket_ports:  HashMap<RadiusMsgType, u16>,
    handlers:      HashMap<RadiusMsgType, fn(server: &AsyncServer, request: &mut [u8])-> Result<Vec<u8>, RadiusError>>,
}

impl AsyncServerBuilder {
    /// Initialise Builder with Dictionary (it cannot be defaulted, so has to be set at the
    /// beginning)
    pub fn with_dictionary(dictionary: Dictionary) -> AsyncServerBuilder {
        AsyncServerBuilder {
            allowed_hosts: Vec::new(),
            dictionary:    dictionary,
            retries:       1,
            server:        String::from(""),
            secret:        String::from(""),
            timeout:       2,
            socket_ports:  HashMap::with_capacity(3),
            handlers:      HashMap::with_capacity(3)
        }
    }

    /// *Required*
    /// Sets hostname to which server would try to bind
    pub fn set_server(mut self, server: String) -> AsyncServerBuilder {
        self.server = server;
        self
    }

    /// *Required*
    /// Sets secret which is used to encode/decode RADIUS packet
    pub fn set_secret(mut self, secret: String) -> AsyncServerBuilder {
        self.secret = secret;
        self
    }

    /// *Optional*
    /// Sets socket retries
    pub fn set_retries(mut self, retries: u16) -> AsyncServerBuilder {
        self.retries = retries;

        self
    }

    /// *Optional*
    /// Sets socket timeout
    pub fn set_timeout(mut self, timeout: u16) -> AsyncServerBuilder {
        self.timeout = timeout;

        self
    }

    /// *Required*
    /// Sets allowed hosts, ie hosts from where server is allowed to accept RADIUS packets
    pub fn set_allowed_hosts(mut self, allowed_hosts: Vec<String>) -> AsyncServerBuilder {
        self.allowed_hosts = allowed_hosts;

        self
    }

    /// *Required*
    /// Sets ports, to which server would be bind depending on the RADIUS Message Type (AUTH, ACCT
    /// or CoA)
    pub fn add_protocol_port(mut self, protocol: RadiusMsgType, port: u16) -> AsyncServerBuilder {
        self.socket_ports.insert(protocol, port);

        self
    }

    /// *Required*
    /// Sets functions that would be responsible for RADIUS packets processing (depending on their
    /// type, ie AUTH, ACCT or CoA)
    pub fn add_protocol_hanlder(mut self, protocol: RadiusMsgType, handler: fn(server: &AsyncServer, request: &mut [u8])-> Result<Vec<u8>, RadiusError>) -> AsyncServerBuilder {
        self.handlers.insert(protocol, handler);

        self
    }

    /// *Required*
    /// Build AsyncServer instance
    pub fn build_server(self) -> AsyncServer {
        let auth_port = self.socket_ports.get(&RadiusMsgType::AUTH).unwrap_or(&0);
        let acct_port = self.socket_ports.get(&RadiusMsgType::ACCT).unwrap_or(&0);
        let coa_port  = self.socket_ports.get(&RadiusMsgType::COA).unwrap_or(&0);

        let host = Host::initialise_host(*auth_port, *acct_port, *coa_port, self.dictionary);

        AsyncServer {
            host:          host,
            allowed_hosts: self.allowed_hosts,
            server:        self.server,
            secret:        self.secret,
            retries:       self.retries,
            timeout:       self.timeout,
            socket_ports:  self.socket_ports,
            handlers:      self.handlers
        }
    }
}
