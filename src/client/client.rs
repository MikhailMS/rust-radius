//! RADIUS Generic Client implementation


use crate::protocol::dictionary::Dictionary;
use crate::protocol::error::RadiusError;
use crate::protocol::host::Host;
use crate::protocol::radius_packet::{ RadiusAttribute, RadiusPacket, RadiusMsgType, TypeCode };

use hmac::{ Hmac, Mac };
use md5::{ Digest, Md5 };


type HmacMd5 = Hmac<Md5>;


#[derive(Debug)]
/// Represents RADIUS Generic Client instance
pub struct Client {
    host:           Host,
    server:         String,
    secret:         String,
    retries:        u16,
    timeout:        u16,
}

impl Client {
    // === Builder for Client ===
    /// Initialise Client instance with dictionary (other fields would be set to default values)
    ///
    /// To be called **first** when creating RADIUS Client instance
    pub fn with_dictionary(dictionary: Dictionary) -> Client {
        let host = Host::with_dictionary(dictionary);

        Client {
            host:    host,
            server:  String::from(""),
            secret:  String::from(""),
            retries: 1,
            timeout: 2
        }
    }

    /// **Required**
    ///
    /// Sets hostname to which client would attempt to send RADIUS packets
    pub fn set_server(mut self, server: String) -> Client {
        self.server = server;
        self
    }

    /// **Required**
    ///
    /// Sets secret which is used to encode/decode RADIUS packet
    pub fn set_secret(mut self, secret: String) -> Client {
        self.secret = secret;
        self
    }

    /// **Required/Optional**
    ///
    /// Sets remote port, that responsible for specific RADIUS Message Type
    pub fn set_port(mut self, msg_type: RadiusMsgType, port: u16) -> Client {
        self.host.set_port(msg_type, port);
        self
    }

    /// **Optional**
    ///
    /// Sets socket retries, otherwise you would have a default value of 1
    pub fn set_retries(mut self, retries: u16) -> Client {
        self.retries = retries;
        self
    }

    /// **Optional**
    ///
    /// Sets socket timeout, otherwise you would have a default value of 2
    pub fn set_timeout(mut self, timeout: u16) -> Client {
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

    /// Returns secret
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// Returns retries
    pub fn retries(&self) -> u16 {
        self.retries
    }

    /// Returns timeout
    pub fn timeout(&self) -> u16 {
        self.timeout
    }

    /// Creates RADIUS packet with any TypeCode without attributes
    ///
    /// You would need to set attributes manually via *set_attributes()* function
    pub fn create_packet(&self, code: TypeCode) -> RadiusPacket {
        RadiusPacket::initialise_packet(code)
    }

    /// Creates RADIUS Access Request packet
    ///
    /// You would need to set attributes manually via *set_attributes()* function
    pub fn create_auth_packet(&self) -> RadiusPacket {
        RadiusPacket::initialise_packet(TypeCode::AccessRequest)
    }

    /// Creates RADIUS Accounting Request packet without attributes
    ///
    /// You would need to set attributes manually via *set_attributes()* function
    pub fn create_acct_packet(&self) -> RadiusPacket {
        RadiusPacket::initialise_packet(TypeCode::AccountingRequest)
    }

    /// Creates RADIUS CoA Request packet without attributes
    ///
    /// You would need to set attributes manually via *set_attributes()* function
    pub fn create_coa_packet(&self) -> RadiusPacket {
        RadiusPacket::initialise_packet(TypeCode::CoARequest)
    }

    /// Creates RADIUS packet attribute by name, that is defined in dictionary file
    ///
    /// # Examples
    ///
    /// ```
    /// use radius_rust::client::client::Client;
    /// use radius_rust::protocol::dictionary::Dictionary;
    /// use radius_rust::protocol::radius_packet::TypeCode;
    ///
    /// fn main() {
    ///     let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    ///     let client     = Client::with_dictionary(dictionary)
    ///        .set_server(String::from("127.0.0.1"))
    ///        .set_secret(String::from("secret"))
    ///        .set_retries(1)
    ///        .set_timeout(2);
    ///
    ///     client.create_attribute_by_name("User-Name", String::from("testing").into_bytes());
    /// }
    /// ```
    pub fn create_attribute_by_name(&self, attribute_name: &str, value: Vec<u8>) -> Result<RadiusAttribute, RadiusError> {
        self.host.create_attribute_by_name(attribute_name, value)
    }

    /// Creates RADIUS packet attribute by ID, that is defined in dictionary file
    ///
    /// # Examples
    ///
    /// ```
    /// use radius_rust::client::client::Client;
    /// use radius_rust::protocol::dictionary::Dictionary;
    /// use radius_rust::protocol::radius_packet::TypeCode;
    ///
    /// fn main() {
    ///     let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    ///     let client     = Client::with_dictionary(dictionary)
    ///        .set_server(String::from("127.0.0.1"))
    ///        .set_secret(String::from("secret"))
    ///        .set_retries(1)
    ///        .set_timeout(2);
    ///
    ///     client.create_attribute_by_id(1, String::from("testing").into_bytes());
    /// }
    /// ```
    pub fn create_attribute_by_id(&self, attribute_id: u8, value: Vec<u8>) -> Result<RadiusAttribute, RadiusError> {
        self.host.create_attribute_by_id(attribute_id, value)
    }

    /// Generates HMAC-MD5 hash for Message-Authenticator attribute
    ///
    /// Note 1: this function assumes that RadiusAttribute Message-Authenticator already exists in RadiusPacket
    /// Note 2: this function only works correctly when Message-Authenticator is set to exactly [0;16]
    /// Note 3: this function would be removed in 0.5.0
    #[deprecated(since="0.4.1", note="This function may work incorrectly, please use radius_packet's `generate_message_authenticator` instead")]
    pub fn generate_message_hash(&self, packet: &mut RadiusPacket) -> Vec<u8> {
        let mut hash = HmacMd5::new_from_slice(self.secret.as_bytes()).unwrap();

        hash.update(&packet.to_bytes());
        hash.finalize().into_bytes().to_vec()
    }

    /// Gets the original value as a String
    ///
    /// If the RadiusAttribute respresents dictionary attribute of type: string, ipaddr, ipv6addr or ipv6prefix
    pub fn radius_attr_original_string_value(&self, attribute: &RadiusAttribute) -> Result<String, RadiusError> {
        let dict_attr = self.host.dictionary_attribute_by_id(attribute.id()).ok_or_else(|| RadiusError::MalformedAttributeError {error: format!("No attribute with ID: {} found in dictionary", attribute.id())} )?;
        attribute.original_string_value(dict_attr.code_type())
    }

    /// Gets the original value as an Integer
    ///
    /// If the RadiusAttribute respresents dictionary attribute of type: integer or date
    pub fn radius_attr_original_integer_value(&self, attribute: &RadiusAttribute) -> Result<u32, RadiusError> {
        let dict_attr = self.host.dictionary_attribute_by_id(attribute.id()).ok_or_else(|| RadiusError::MalformedAttributeError {error: format!("No attribute with ID: {} found in dictionary", attribute.id())} )?;
        attribute.original_integer_value(dict_attr.code_type())
    }

    /// Initialises RadiusPacket from bytes
    pub fn initialise_packet_from_bytes(&self, reply: &[u8]) -> Result<RadiusPacket, RadiusError> {
        self.host.initialise_packet_from_bytes(reply)
    }

    /// Verifies that reply packet's ID and authenticator are a match
    pub fn verify_reply(&self, request: &RadiusPacket, reply: &[u8]) -> Result<(), RadiusError> {
        if reply.is_empty() {
            return Err( RadiusError::ValidationError { error: String::from("Empty reply") } )
        }
        if request.id() != reply[1] {
            return Err( RadiusError::ValidationError { error: String::from("Packet identifier mismatch") } )
        };

        let mut md5_hasher = Md5::new();

        md5_hasher.update(&reply[0..4]);             // Append reply type code, reply ID and reply length
        md5_hasher.update(&request.authenticator()); // Append request authenticator
        md5_hasher.update(&reply[20..]);             // Append rest of the reply
        md5_hasher.update(&self.secret.as_bytes());  // Append secret

        if md5_hasher.finalize().as_slice() == &reply[4..20] {
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
        let client     = Client::with_dictionary(dictionary)
            .set_server(String::from("127.0.0.1"))
            .set_secret(String::from("secret"))
            .set_retries(1)
            .set_timeout(2)
            .set_port(RadiusMsgType::AUTH, 1812)
            .set_port(RadiusMsgType::ACCT, 1813)
            .set_port(RadiusMsgType::COA,  3799);

        let attributes = vec![client.create_attribute_by_name("User-Name", String::from("testing").into_bytes()).unwrap()];

        match client.radius_attr_original_string_value(&attributes[0]) {
            Ok(value) => assert_eq!(String::from("testing"), value),
            _         => assert!(false)
        }
    }

    #[test]
    fn test_get_radius_attr_original_string_value_error() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let client     = Client::with_dictionary(dictionary)
            .set_server(String::from("127.0.0.1"))
            .set_secret(String::from("secret"))
            .set_retries(1)
            .set_timeout(2)
            .set_port(RadiusMsgType::AUTH, 1812)
            .set_port(RadiusMsgType::ACCT, 1813)
            .set_port(RadiusMsgType::COA,  3799);

        let invalid_string = vec![215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73];
        let attributes     = vec![client.create_attribute_by_name("User-Name", invalid_string).unwrap()];

        match client.radius_attr_original_string_value(&attributes[0]) {
            Ok(_)      => assert!(false),
            Err(error) => assert_eq!(String::from("Attribute in Radius packet is malformed: invalid ASCII bytes"), error.to_string())
        }
    }

    #[test]
    fn test_get_radius_attr_original_integer_value() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let client     = Client::with_dictionary(dictionary)
            .set_server(String::from("127.0.0.1"))
            .set_secret(String::from("secret"))
            .set_retries(1)
            .set_timeout(2)
            .set_port(RadiusMsgType::AUTH, 1812)
            .set_port(RadiusMsgType::ACCT, 1813)
            .set_port(RadiusMsgType::COA,  3799);

        let attributes = vec![client.create_attribute_by_name("NAS-Port-Id", integer_to_bytes(0)).unwrap()];

        match client.radius_attr_original_integer_value(&attributes[0]) {
            Ok(value) => assert_eq!(0, value),
            _         => assert!(false)
        }
    }

    #[test]
    fn test_get_radius_attr_original_integer_value_error() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let client     = Client::with_dictionary(dictionary)
            .set_server(String::from("127.0.0.1"))
            .set_secret(String::from("secret"))
            .set_retries(1)
            .set_timeout(2)
            .set_port(RadiusMsgType::AUTH, 1812)
            .set_port(RadiusMsgType::ACCT, 1813)
            .set_port(RadiusMsgType::COA,  3799);

        let invalid_integer = vec![215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73];
        let attributes      = vec![client.create_attribute_by_name("NAS-Port-Id", invalid_integer).unwrap()];

        match client.radius_attr_original_integer_value(&attributes[0]) {
            Ok(_)      => assert!(false),
            Err(error) => assert_eq!(String::from("Attribute in Radius packet is malformed: invalid Integer bytes"), error.to_string())
        }
    }

    #[test]
    fn test_verify_empty_reply() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let attributes = vec![ RadiusAttribute::create_by_name(&dictionary, "Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap() ];

        let client     = Client::with_dictionary(dictionary)
            .set_server(String::from("127.0.0.1"))
            .set_secret(String::from("secret"))
            .set_retries(1)
            .set_timeout(2)
            .set_port(RadiusMsgType::AUTH, 1812)
            .set_port(RadiusMsgType::ACCT, 1813)
            .set_port(RadiusMsgType::COA,  3799);

        let authenticator     = vec![215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73];
        let reply             = vec![];
        let mut radius_packet = RadiusPacket::initialise_packet(TypeCode::AccountingRequest);

        radius_packet.set_attributes(attributes);
        radius_packet.override_id(43);
        radius_packet.override_authenticator(authenticator);

        match client.verify_reply(&radius_packet, &reply) {
            Err(error) => assert_eq!(String::from("Verification failed for incoming Radius packet: Empty reply"), error.to_string()),
            _          => assert!(false)
        }
    }

    #[test]
    fn test_verify_malformed_reply() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let attributes = vec![ RadiusAttribute::create_by_name(&dictionary, "Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap() ];

        let client     = Client::with_dictionary(dictionary)
            .set_server(String::from("127.0.0.1"))
            .set_secret(String::from("secret"))
            .set_retries(1)
            .set_timeout(2)
            .set_port(RadiusMsgType::AUTH, 1812)
            .set_port(RadiusMsgType::ACCT, 1813)
            .set_port(RadiusMsgType::COA,  3799);

        let authenticator     = vec![215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73];
        let reply             = vec![43, 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73];
        let mut radius_packet = RadiusPacket::initialise_packet(TypeCode::AccountingRequest);

        radius_packet.set_attributes(attributes);
        radius_packet.override_id(43);
        radius_packet.override_authenticator(authenticator);

        match client.verify_reply(&radius_packet, &reply) {
            Err(error) => assert_eq!(String::from("Verification failed for incoming Radius packet: Packet identifier mismatch"), error.to_string()),
            _          => assert!(false)
        }
    }

    #[test]
    fn test_verify_reply() {
        let dictionary    = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let authenticator = vec![152, 137, 115, 14, 56, 250, 103, 56, 57, 57, 104, 246, 226, 80, 71, 167];
        let attributes    = vec![ RadiusAttribute::create_by_name(&dictionary, "User-Name", String::from("testing").into_bytes()).unwrap() ];

        let reply             = vec![2, 220, 0, 52, 165, 196, 239, 87, 197, 230, 219, 74, 148, 177, 209, 155, 35, 36, 236, 63, 6, 6, 0, 0, 0, 2, 8, 6, 192, 168, 0, 1, 97, 20, 0, 64, 252, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut radius_packet = RadiusPacket::initialise_packet(TypeCode::AccessRequest);
        radius_packet.set_attributes(attributes);
        radius_packet.override_id(220);
        radius_packet.override_authenticator(authenticator);

        let client = Client::with_dictionary(dictionary)
            .set_server(String::from("127.0.0.1"))
            .set_secret(String::from("secret"))
            .set_retries(1)
            .set_timeout(2)
            .set_port(RadiusMsgType::AUTH, 1812)
            .set_port(RadiusMsgType::ACCT, 1813)
            .set_port(RadiusMsgType::COA,  3799);

        match client.verify_reply(&radius_packet, &reply) {
            Err(_error) => assert!(false),
            _           => assert!(true)
        }
    }

    #[test]
    fn test_generate_message_hash() {
        let expected_message_autthenticator = vec![85, 134, 2, 170, 83, 101, 202, 79, 109, 163, 59, 12, 66, 170, 183, 220];

        let dictionary    = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let authenticator = vec![152, 137, 115, 14, 56, 250, 103, 56, 57, 57, 104, 246, 226, 80, 71, 167];
        let attributes    = vec![
            RadiusAttribute::create_by_name(&dictionary, "User-Name", String::from("testing").into_bytes()).unwrap(),
            RadiusAttribute::create_by_name(&dictionary, "Message-Authenticator", [0;16].to_vec()).unwrap()
        ];

        let mut radius_packet = RadiusPacket::initialise_packet(TypeCode::AccessRequest);
        radius_packet.set_attributes(attributes);
        radius_packet.override_id(220);
        radius_packet.override_authenticator(authenticator);

        let client = Client::with_dictionary(dictionary)
            .set_server(String::from("127.0.0.1"))
            .set_secret(String::from("secret"))
            .set_retries(1)
            .set_timeout(2)
            .set_port(RadiusMsgType::AUTH, 1812)
            .set_port(RadiusMsgType::ACCT, 1813)
            .set_port(RadiusMsgType::COA,  3799);

        let generated_message_authenticator = client.generate_message_hash(&mut radius_packet);

        assert_eq!(expected_message_autthenticator, generated_message_authenticator)
    }
}
