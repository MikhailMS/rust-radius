//! RADIUS Generic Server implementation


use crate::protocol::host::Host;
use crate::protocol::radius_packet::{ RadiusAttribute, RadiusMsgType, RadiusPacket, TypeCode };
use crate::protocol::dictionary::Dictionary;
use crate::protocol::error::RadiusError;

use md5::{ Digest, Md5 };

use std::collections::HashMap;


#[derive(Debug)]
/// Represents RADIUS Generic Server instance
pub struct Server {
    host:          Host,
    allowed_hosts: HashMap<String, String>,
    server:        String,
    retries:       u16,
    timeout:       u16,
}

impl Server {
    // === Builder for Server ===
    /// Initialise Server instance with dictionary (other fields would be set to default values)
    ///
    /// To be called **first** when creating RADIUS Server instance
    pub fn with_dictionary(dictionary: Dictionary) -> Server {
        let host = Host::with_dictionary(dictionary);

        Server {
            host,
            allowed_hosts: HashMap::new(),
            server:        String::from(""),
            retries:       1,
            timeout:       2,
        }
    }

    /// **Required**
    ///
    /// Sets hostname to which server would bind
    pub fn set_server(mut self, server: String) -> Server {
        self.server = server;
        self
    }

    /// Sets allowed hosts, from where Server would be allowed to accept RADIUS requests
    pub fn set_allowed_hosts(mut self, allowed_hosts: HashMap<String, String>) -> Server {
        self.allowed_hosts = allowed_hosts;
        self
    }

    /// **Required/Optional**
    ///
    /// Sets remote port, that responsible for specific RADIUS Message Type
    pub fn set_port(mut self, msg_type: RadiusMsgType, port: u16) -> Server {
        self.host.set_port(msg_type, port);
        self
    }

    /// **Optional**
    ///
    /// Sets socket retries, otherwise you would have a default value of 1
    pub fn set_retries(mut self, retries: u16) -> Server {
        self.retries = retries;
        self
    }

    /// **Optional**
    ///
    /// Sets socket timeout, otherwise you would have a default value of 2
    pub fn set_timeout(mut self, timeout: u16) -> Server {
        self.timeout = timeout;
        self
    }
    // ===================

    /// Returns port of RADIUS server, that receives given type of RADIUS message/packet
   pub fn port(&self, code: &TypeCode) -> Option<u16> {
        self.host.port(code)
    }

    /// Returns hostname/FQDN of RADIUS Server
    pub fn server(&self) -> &str {
        &self.server
    }

    /// Returns retries
    pub fn retries(&self) -> u16 {
        self.retries
    }

    /// Returns timeout
    pub fn timeout(&self) -> u16 {
        self.timeout
    }

    /// Returns allowed hosts list
    pub fn allowed_hosts(&self) -> &HashMap<String, String> {
        &self.allowed_hosts
    }

    /// Returns secret for given host
    pub fn retrieve_secret(&self, remote_host: &std::net::SocketAddr) -> &str {
        let remote_host_name            = remote_host.to_string();
        let remote_host_name: Vec<&str> = remote_host_name.split(":").collect();

        for (host, secret) in self.allowed_hosts.iter() {
            if host == remote_host_name[0] {
                return &secret
            }
        }

        return ""
    }

    /// Creates RADIUS packet attribute by name, that is defined in dictionary file
    ///
    /// For example, see [Client](crate::client::client::Client::create_attribute_by_name)
    pub fn create_attribute_by_name(&self, attribute_name: &str, value: Vec<u8>) -> Result<RadiusAttribute, RadiusError> {
        self.host.create_attribute_by_name(attribute_name, value)
    }

    /// Creates RADIUS packet attribute by id, that is defined in dictionary file
    ///
    /// For example, see [Client](crate::client::client::Client::create_attribute_by_id)
    pub fn create_attribute_by_id(&self, attribute_id: u8, value: Vec<u8>) -> Result<RadiusAttribute, RadiusError> {
        self.host.create_attribute_by_id(attribute_id, value)
    }

    /// Creates reply RADIUS packet
    ///
    /// Similar to [Client's create_packet()](crate::client::client::Client::create_packet), however also sets correct packet ID and authenticator
    pub fn create_reply_packet(&self, reply_code: TypeCode, attributes: Vec<RadiusAttribute>, request: &mut [u8], secret: &str) -> RadiusPacket {
        let mut reply_packet = RadiusPacket::initialise_packet(reply_code);
        reply_packet.set_attributes(attributes);

        // We can only create new authenticator after we set reply packet ID to the request's ID
        reply_packet.override_id(request[1]);

        let authenticator = self.create_reply_authenticator(&reply_packet.to_bytes(), &request[4..20], secret);
        reply_packet.override_authenticator(authenticator);

        reply_packet
    }

    fn create_reply_authenticator(&self, raw_reply_packet: &[u8], request_authenticator: &[u8], secret: &str) -> Vec<u8> {
        // We need to create authenticator as MD5 hash (similar to how client verifies server reply)
        let mut md5_hasher    = Md5::new();

        md5_hasher.update(&raw_reply_packet[0..4]); // Append reply's   type code, reply ID and reply length
        md5_hasher.update(&request_authenticator);  // Append request's authenticator
        md5_hasher.update(&raw_reply_packet[20..]); // Append reply's   attributes
        md5_hasher.update(&secret.as_bytes()); // Append server's  secret. Possibly it should be client's secret, which sould be stored together with allowed hostnames ?
        // ----------------

        md5_hasher.finalize().to_vec()
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
    /// RadiusAttribute original value from bytes, based on the attribute data type, see [SupportedAttributeTypes](crate::protocol::dictionary::SupportedAttributeTypes)
    pub fn verify_request_attributes(&self, request: &[u8]) -> Result<(), RadiusError> {
        self.host.verify_packet_attributes(&request)
    }

    /// Initialises RadiusPacket from bytes
    ///
    /// Unlike [verify_request](Server::verify_request), on success this function would return
    /// RadiusPacket
    pub fn initialise_packet_from_bytes(&self, request: &[u8]) -> Result<RadiusPacket, RadiusError> {
        self.host.initialise_packet_from_bytes(request)
    }

    /// Checks if host from where Server received RADIUS request is allowed host, meaning RADIUS
    /// Server can process such request
    pub fn host_allowed(&self, remote_host: &std::net::SocketAddr) -> bool {
        let remote_host_name            = remote_host.to_string();
        let remote_host_name: Vec<&str> = remote_host_name.split(":").collect();

        self.allowed_hosts.iter().any(|(host, _)| host==remote_host_name[0]) 
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_add_allowed_hosts_and_add_request_handler() {
        let allowed_hosts = HashMap::from([
            ("127.0.0.1".to_string(), "secret".to_string())
        ]);
        let dictionary    = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let server        = Server::with_dictionary(dictionary)
            .set_server(String::from("0.0.0.0"))
            .set_allowed_hosts(allowed_hosts);

        assert_eq!(server.allowed_hosts().len(), 1);
    }
}
