use crate::protocol::dictionary::Dictionary;
use crate::protocol::error::RadiusError;
use crate::protocol::host::Host;
use crate::protocol::radius_packet::{ RadiusPacket, RadiusAttribute, TypeCode };

use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::mac::Mac;
use crypto::hmac::Hmac;
use log::debug;
use mio::{ Events, Interest, Poll, Token };
use mio::net::UdpSocket;
use std::io::{Error, ErrorKind};
use std::time::Duration;
use std::sync::Mutex;


#[derive(Debug)]
/// Represents RADIUS client instance
///
/// The key difference between this client and the one from `radius_rust::client::client::Client`
/// is that this client's socket poll is wrapped into Mutex (there are cases when we cannot use mut
/// reference to Client and socket_poll is the only thing which blocks the Client usage in such
/// cases)
pub struct Client {
    host:           Host,
    server:         String,
    secret:         String,
    retries:        u16,
    timeout:        u16,
    socket_poll:    Mutex<Poll>,
    socket_handler: UdpSocket
}

impl Client {
    /// Initialise RADIUS client instance
    pub fn initialise_client(auth_port: u16, acct_port: u16, coa_port: u16, dictionary: Dictionary, server: String, secret: String, retries: u16, timeout: u16) -> Result<Client, RadiusError> {
        let local_bind  = "0.0.0.0:0".parse().map_err(|error| RadiusError::SocketAddrParseError(error))?;
        let mut socket  = UdpSocket::bind(local_bind).map_err(|error| RadiusError::SocketConnectionError(error))?;
        let socket_poll = Poll::new()?;

        socket_poll.registry().register(&mut socket, Token(0), Interest::READABLE).map_err(|error| RadiusError::SocketConnectionError(error))?;

        Ok(
            Client {
                host:           Host::initialise_host(auth_port, acct_port, coa_port, dictionary),
                server:         server,
                secret:         secret,
                retries:        retries,
                timeout:        timeout,
                socket_poll:    Mutex::new(socket_poll),
                socket_handler: socket
            }
        )
    }

    /// Creates RADIUS packet with any TypeCode
    pub fn create_packet(&self, code: TypeCode, attributes: Vec<RadiusAttribute>) -> RadiusPacket {
        RadiusPacket::initialise_packet(code, attributes)
    }

    /// Creates RADIUS Access Request packet
    pub fn create_auth_packet(&self, attributes: Vec<RadiusAttribute>) -> RadiusPacket {
        RadiusPacket::initialise_packet(TypeCode::AccessRequest, attributes)
    }

    /// Creates RADIUS Accounting Request packet
    pub fn create_acct_packet(&self, attributes: Vec<RadiusAttribute>) -> RadiusPacket {
        RadiusPacket::initialise_packet(TypeCode::AccountingRequest, attributes)
    }

    /// Creates RADIUS CoA Request packet
    pub fn create_coa_packet(&self, attributes: Vec<RadiusAttribute>) -> RadiusPacket {
        RadiusPacket::initialise_packet(TypeCode::CoARequest, attributes)
    }

    /// Creates RADIUS packet attribute by name, that is defined in dictionary file
    /// # Examples
    ///
    /// ```
    /// use radius_rust::client::mutex_client::Client;
    /// use radius_rust::protocol::dictionary::Dictionary;
    /// use radius_rust::protocol::radius_packet::TypeCode;
    ///
    /// fn main() {
    ///     let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    ///     let client     = Client::initialise_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();
    ///
    ///     client.create_attribute_by_name("User-Name", String::from("testing").into_bytes());
    /// }
    /// ```
    pub fn create_attribute_by_name(&self, attribute_name: &str, value: Vec<u8>) -> Result<RadiusAttribute, RadiusError> {
        self.host.create_attribute_by_name(attribute_name, value)
    }

    /// Creates RADIUS packet attribute by ID, that is defined in dictionary file
    /// # Examples
    ///
    /// ```
    /// use radius_rust::client::mutex_client::Client;
    /// use radius_rust::protocol::dictionary::Dictionary;
    /// use radius_rust::protocol::radius_packet::TypeCode;
    ///
    /// fn main() {
    ///     let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    ///     let client     = Client::initialise_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();
    ///
    ///     client.create_attribute_by_id(1, String::from("testing").into_bytes());
    /// }
    /// ```
    pub fn create_attribute_by_id(&self, attribute_id: u8, value: Vec<u8>) -> Result<RadiusAttribute, RadiusError> {
        self.host.create_attribute_by_id(attribute_id, value)
    }

    /// Generates HMAC-MD5 hash for Message-Authenticator attribute
    ///
    /// Note: this function assumes that RadiusAttribute Message-Authenticator already exists in RadiusPacket 
    pub fn generate_message_hash(&self, packet: &mut RadiusPacket) -> Vec<u8> {
        let mut hash = Hmac::new(Md5::new(), self.secret.as_bytes());

        hash.input(&packet.to_bytes());
        hash.result().code().to_vec()
    }

    /// Gets the original value as a String if the RadiusAttribute respresents dictionary attribute
    /// that has type: string, ipaddr, ipv6addr or ipv6prefix
    pub fn get_radius_attr_original_string_value(&self, attribute: &RadiusAttribute) -> Result<String, RadiusError> {
        let dict_attr = self.host.get_dictionary_attribute_by_id(attribute.get_id()).ok_or_else(|| RadiusError::MalformedAttribute {error: format!("No attribute with ID: {} found in dictionary", attribute.get_id())} )?;
        attribute.get_original_string_value(dict_attr.get_code_type())
    }

    /// Gets the original value as a String if the RadiusAttribute respresents dictionary attribute
    /// that has type:integer or date
    pub fn get_radius_attr_original_integer_value(&self, attribute: &RadiusAttribute) -> Result<u64, RadiusError> {
        let dict_attr = self.host.get_dictionary_attribute_by_id(attribute.get_id()).ok_or_else(|| RadiusError::MalformedAttribute {error: format!("No attribute with ID: {} found in dictionary", attribute.get_id())} )?;
        attribute.get_original_integer_value(dict_attr.get_code_type())
    }

    /// Initialises RadiusPacket from bytes
    pub fn initialise_packet_from_bytes(&self, reply: &[u8]) -> Result<RadiusPacket, RadiusError> {
        self.host.initialise_packet_from_bytes(reply)
    }

    /// Sends packet to RADIUS server but does not return a response
    pub fn send_packet(&self, packet: &mut RadiusPacket) -> Result<(), RadiusError> {
        let remote_port = self.host.get_port(packet.get_code()).ok_or_else(|| RadiusError::MalformedPacket { error: String::from("There is no port match for packet code") })?;
        let remote      = format!("{}:{}", &self.server, remote_port).parse().map_err(|error| RadiusError::SocketAddrParseError(error))?;

        let timeout         = Duration::from_secs(self.timeout as u64);
        let mut events      = Events::with_capacity(1024);
        let mut retry       = 0;
        let mut socket_poll = self.socket_poll.lock().map_err(|error| RadiusError::MutexLockFailure { error: error.to_string() })?;

        loop {
            if retry >= self.retries {
                break;
            }
            debug!("Sending: {:?}", &packet.to_bytes());
            self.socket_handler.send_to(&packet.to_bytes(), remote).map_err(|error| RadiusError::SocketConnectionError(error))?;
            
            socket_poll.poll(&mut events, Some(timeout)).map_err(|error| RadiusError::SocketConnectionError(error))?;

            for event in events.iter() {
                match event.token() {
                    Token(0) => {
                        let mut response = [0; 4096];
                        let amount = self.socket_handler.recv(&mut response).map_err(|error| RadiusError::SocketConnectionError(error))?;

                        if amount > 0 {
                            debug!("Received reply: {:?}", &response[0..amount]);
                            return Ok(());
                        }
                    },
                    _ => return Err( RadiusError::SocketInvalidConnection { error: String::from("Received data from invalid Token") } ),
                }
            }
            retry += 1;
        }
        Err( RadiusError::SocketConnectionError(Error::new(ErrorKind::TimedOut, "")) )
    }

    /// Sends packet to RADIUS server and returns a response
    pub fn send_and_receive_packet(&self, packet: &mut RadiusPacket) -> Result<Vec<u8>, RadiusError> {
        let remote_port = self.host.get_port(packet.get_code()).ok_or_else(|| RadiusError::MalformedPacket { error: String::from("There is no port match for packet code") })?;
        let remote      = format!("{}:{}", &self.server, remote_port).parse().map_err(|error| RadiusError::SocketAddrParseError(error))?;

        let timeout         = Duration::from_secs(self.timeout as u64);
        let mut events      = Events::with_capacity(1024);
        let mut retry       = 0;
        let mut socket_poll = self.socket_poll.lock().map_err(|error| RadiusError::MutexLockFailure { error: error.to_string() })?;

        loop {
            if retry >= self.retries {
                break;
            }
            debug!("Sending: {:?}", &packet.to_bytes());
            self.socket_handler.send_to(&packet.to_bytes(), remote).map_err(|error| RadiusError::SocketConnectionError(error))?;

            socket_poll.poll(&mut events, Some(timeout)).map_err(|error| RadiusError::SocketConnectionError(error))?;

            for event in events.iter() {
                match event.token() {
                    Token(0) => {
                        let mut response = [0; 4096];
                        let amount = self.socket_handler.recv(&mut response).map_err(|error| RadiusError::SocketConnectionError(error))?;

                        if amount > 0 {
                            debug!("Received reply: {:?}", &response[0..amount]);
                            return Ok(response[0..amount].to_vec());
                        }
                    },
                    _ => return Err( RadiusError::SocketInvalidConnection { error: String::from("Received data from invalid Token") } ),
                }
            }

            retry += 1;
        }
        Err( RadiusError::SocketConnectionError(Error::new(ErrorKind::TimedOut, "")) )
    }

    /// Verifies that reply packet's ID and authenticator are a match
    pub fn verify_reply(&self, request: &RadiusPacket, reply: &[u8]) -> Result<(), RadiusError> {
        if request.get_id() != reply[1] {
            return Err( RadiusError::ValidationError { error: String::from("Packet identifier mismatch") } )
        };

        let mut md5_hasher = Md5::new();
        let mut hash       = [0; 16];

        md5_hasher.input(&reply[0..4]);                 // Append reply type code, reply ID and reply length
        md5_hasher.input(&request.get_authenticator()); // Append request authenticator
        md5_hasher.input(&reply[20..]);                 // Append rest of the reply
        md5_hasher.input(&self.secret.as_bytes());      // Append secret

        md5_hasher.result(&mut hash);

        debug!("{:?}", &hash);
        debug!("{:?}", &reply[4..20]);

        if hash == reply[4..20] {
            Ok(())
        } else {
            Err( RadiusError::ValidationError { error: String::from("Packet authenticator mismatch") } )
        }
    }

    /// Verifies that reply packet's Message-Authenticator attribute is valid
    pub fn verify_message_authenticator(&self, packet: &[u8]) -> Result<(), RadiusError> {
        self.host.verify_message_authenticator(&self.secret, &packet)
    }

    /// Verifies that reply packet's attributes have valid values
    pub fn verify_packet_attributes(&self, packet: &[u8]) -> Result<(), RadiusError> {
        self.host.verify_packet_attributes(&packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::integer_to_bytes;

    #[test]
    fn test_get_radius_attr_original_string_value() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let client     = Client::initialise_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

        let attributes = vec![client.create_attribute_by_name("User-Name", String::from("testing").into_bytes()).unwrap()];

        match client.get_radius_attr_original_string_value(&attributes[0]) {
            Ok(value) => assert_eq!(String::from("testing"), value),
            _         => assert!(false)
        }
    }

    #[test]
    fn test_get_radius_attr_original_string_value_error() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let client     = Client::initialise_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

        let invalid_string = vec![215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73];
        let attributes     = vec![client.create_attribute_by_name("User-Name", invalid_string).unwrap()];

        match client.get_radius_attr_original_string_value(&attributes[0]) {
            Ok(_)      => assert!(false),
            Err(error) => assert_eq!(String::from("Radius packet attribute is malformed"), error.to_string())
        }
    }

    #[test]
    fn test_get_radius_attr_original_integer_value() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let client     = Client::initialise_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

        let attributes = vec![client.create_attribute_by_name("NAS-Port-Id", integer_to_bytes(0)).unwrap()];

        match client.get_radius_attr_original_integer_value(&attributes[0]) {
            Ok(value) => assert_eq!(0, value),
            _         => assert!(false)
        }
    }

    #[test]
    fn test_get_radius_attr_original_integer_value_error() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let client     = Client::initialise_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

        let invalid_integer = vec![215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73];
        let attributes      = vec![client.create_attribute_by_name("NAS-Port-Id", invalid_integer).unwrap()];

        match client.get_radius_attr_original_integer_value(&attributes[0]) {
            Ok(_)      => assert!(false),
            Err(error) => assert_eq!(String::from("Radius packet attribute is malformed"), error.to_string())
        }
    }
}
