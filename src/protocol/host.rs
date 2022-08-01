//! Shared base for RADIUS Client & Server implementations


use super::dictionary::{ Dictionary, DictionaryAttribute, DictionaryValue };
use super::error::RadiusError;
use super::radius_packet::{ RadiusAttribute, RadiusMsgType, RadiusPacket, TypeCode };

use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::md5::Md5;

const IGNORE_VERIFY_ATTRIBUTE: &str = "Message-Authenticator";

#[derive(Debug)]
/// Generic struct that holds Server & Client common functions and attributes
pub struct Host {
    auth_port:  u16,
    acct_port:  u16,
    coa_port:   u16,
    dictionary: Dictionary
}

impl Host{
    /// Initialises host instance only with Dictionary (ports should be set through *set_port()*,
    /// otherwise default to 0)
    pub fn with_dictionary(dictionary: Dictionary) -> Host {
        Host {
            auth_port:  0,
            acct_port:  0,
            coa_port:   0,
            dictionary: dictionary
        }
    }

    /// Sets remote port, that responsible for specific RADIUS Message Type
    pub fn set_port(&mut self, msg_type: RadiusMsgType, port: u16) {
        match msg_type {
            RadiusMsgType::AUTH => self.auth_port = port,
            RadiusMsgType::ACCT => self.acct_port = port,
            RadiusMsgType::COA  => self.coa_port  = port,
        }
    }

    #[allow(dead_code)]
    /// Initialises host instance with all required fields
    pub fn initialise_host(auth_port: u16, acct_port: u16, coa_port: u16, dictionary: Dictionary) -> Host {
        Host { auth_port, acct_port, coa_port, dictionary }
    }


    /// Creates RadiusAttribute with given name (name is checked against Dictionary)
    pub fn create_attribute_by_name(&self, attribute_name: &str, value: Vec<u8>) -> Result<RadiusAttribute, RadiusError> {
        RadiusAttribute::create_by_name(&self.dictionary, attribute_name, value).ok_or(RadiusError::MalformedAttributeError { error: format!("Failed to create: {:?} attribute. Check if attribute exists in provided dictionary file", attribute_name) })
    }

    /// Creates RadiusAttribute with given id (id is checked against Dictionary)
    pub fn create_attribute_by_id(&self, attribute_id: u8, value: Vec<u8>) -> Result<RadiusAttribute, RadiusError> {
        RadiusAttribute::create_by_id(&self.dictionary, attribute_id, value).ok_or(RadiusError::MalformedAttributeError { error: format!("Failed to create: attribute with ID {}. Check if attribute exists in provided dictionary file", attribute_id) })
    }

    /// Returns port of RADIUS server, that receives given type of RADIUS message/packet
    pub fn port(&self, code: &TypeCode) -> Option<u16> {
        match code {
            TypeCode::AccessRequest     => Some(self.auth_port),
            TypeCode::AccountingRequest => Some(self.acct_port),
            TypeCode::CoARequest        => Some(self.coa_port),
            _                           => None
        }
    }

    /// Returns host's dictionary instance
    pub fn dictionary(&self) -> &Dictionary {
        &self.dictionary
    }

    #[allow(dead_code)]
    /// Returns VALUE from dictionary with given attribute & value name
    pub fn dictionary_value_by_attr_and_value_name(&self, attr_name: &str, value_name: &str) -> Option<&DictionaryValue> {
        self.dictionary.values().iter().find(|&value| value.name() == value_name && value.attribute_name() == attr_name)
    }

    /// Returns ATTRIBUTE from dictionary with given id
    pub fn dictionary_attribute_by_id(&self, packet_attr_id: u8) -> Option<&DictionaryAttribute> {
        self.dictionary.attributes().iter().find(|&attr| attr.code() == packet_attr_id.to_string())
    }

    #[allow(dead_code)]
    /// Returns ATTRIBUTE from dictionary with given name
    pub fn dictionary_attribute_by_name(&self, packet_attr_name: &str) -> Option<&DictionaryAttribute> {
        self.dictionary.attributes().iter().find(|&attr| attr.name() == packet_attr_name)
    }

    /// Initialises RadiusPacket from bytes
    pub fn initialise_packet_from_bytes(&self, packet: &[u8]) -> Result<RadiusPacket, RadiusError> {
        RadiusPacket::initialise_packet_from_bytes(&self.dictionary, packet)
    }

    /// Verifies that RadiusPacket attributes have valid values
    ///
    /// Note: doesn't verify Message-Authenticator attribute, because it is HMAC-MD5 hash, not an
    /// ASCII string
    pub fn verify_packet_attributes(&self, packet: &[u8]) -> Result<(), RadiusError> {
        let _packet_tmp = RadiusPacket::initialise_packet_from_bytes(&self.dictionary, &packet)?;

        for packet_attr in _packet_tmp.attributes().iter().filter(|&attr| attr.name() != IGNORE_VERIFY_ATTRIBUTE) {
            match self.dictionary_attribute_by_id(packet_attr.id()) {
                None             => return Err( RadiusError::ValidationError {error: format!("Attribute with ID {} may not exist in provided dictionary file, thus verification failed", packet_attr.id())} ),
                Some(_dict_attr) => {
                    let _dict_attr_data_type = _dict_attr.code_type();
                    match packet_attr.verify_original_value(_dict_attr_data_type) {
                        Err(err) => return Err( RadiusError::ValidationError {error: err.to_string()} ),
                        _        => continue
                    }
                }
            }
        }
        Ok(())
    }

    /// Verifies Message-Authenticator value
    pub fn verify_message_authenticator(&self, secret: &str, packet: &[u8]) -> Result<(), RadiusError> {
        // Step 1. Get Message-Authenticator from packet
        let mut _packet_tmp   = RadiusPacket::initialise_packet_from_bytes(&self.dictionary, &packet)?;
        let original_msg_auth = _packet_tmp.message_authenticator()?.to_vec();

        // Step 2. Set Message-Authenticator in packet to [0; 16]
        let zeroed_authenticator = [0; 16];
        _packet_tmp.override_message_authenticator(zeroed_authenticator.to_vec())?;

        // Step 3. Calculate HMAC-MD5 for the packet
        let mut calculated_msg_auth = Hmac::new(Md5::new(), secret.as_bytes());
        calculated_msg_auth.input(&_packet_tmp.to_bytes());

        // Step 4. Compare calculated hash with the one extracted in Step 1
        if calculated_msg_auth.result().code() == original_msg_auth {
            Ok(())
        } else {
            Err( RadiusError::ValidationError {error: String::from("Packet Message-Authenticator mismatch")} )
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::dictionary::SupportedAttributeTypes;

    #[test]
    fn test_get_dictionary_value_by_attr_and_value_name() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let host       = Host::initialise_host(1812, 1813, 3799, dictionary);

        let dict_value = host.dictionary_value_by_attr_and_value_name("Service-Type", "Login-User").unwrap();

        assert_eq!("Service-Type", dict_value.attribute_name());
        assert_eq!("Login-User",   dict_value.name());
        assert_eq!("1",            dict_value.value());
    }

    #[test]
    fn test_get_dictionary_value_by_attr_and_value_name_error() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let host       = Host::initialise_host(1812, 1813, 3799, dictionary);

        let dict_value = host.dictionary_value_by_attr_and_value_name("Service-Type", "Lin-User");
        assert_eq!(None, dict_value);
    }

    #[test]
    fn test_get_dictionary_attribute_by_id() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let host       = Host::initialise_host(1812, 1813, 3799, dictionary);

        let dict_attr = host.dictionary_attribute_by_id(80).unwrap();

        assert_eq!("Message-Authenticator",                    dict_attr.name());
        assert_eq!("80",                                       dict_attr.code());
        assert_eq!(&Some(SupportedAttributeTypes::ByteString), dict_attr.code_type());
    }

    #[test]
    fn test_get_dictionary_attribute_by_id_error() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let host       = Host::initialise_host(1812, 1813, 3799, dictionary);

        let dict_attr = host.dictionary_attribute_by_id(255);
        assert_eq!(None, dict_attr);
    }

    #[test]
    fn test_verify_packet_attributes() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let host       = Host::initialise_host(1812, 1813, 3799, dictionary);

        let packet_bytes = [4, 43, 0, 83, 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73, 4, 6, 192, 168, 1, 10, 5, 6, 0, 0, 0, 0, 32, 10, 116, 114, 105, 108, 108, 105, 97, 110, 30, 19, 48, 48, 45, 48, 52, 45, 53, 70, 45, 48, 48, 45, 48, 70, 45, 68, 49, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 8, 6, 10, 0, 0, 100];

        match host.verify_packet_attributes(&packet_bytes) {
            Err(_err) => {
                assert!(false)
            },
            _        => assert!(true)
        }
    }

    #[test]
    fn test_verify_packet_attributes_fail() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let host       = Host::initialise_host(1812, 1813, 3799, dictionary);

        let packet_bytes = [4, 43, 0, 82, 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73, 4, 5, 192, 168, 10, 5, 6, 0, 0, 0, 0, 32, 10, 116, 114, 105, 108, 108, 105, 97, 110, 30, 19, 48, 48, 45, 48, 52, 45, 53, 70, 45, 48, 48, 45, 48, 70, 45, 68, 49, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 8, 6, 10, 0, 0, 100];

        match host.verify_packet_attributes(&packet_bytes) {
            Err(err) => {
                assert_eq!(err.to_string(), String::from("Verification failed for incoming Radius packet: Attribute in Radius packet is malformed: invalid IPv4 bytes"))
            },
            _        => assert!(false)
        }
    }

    #[test]
    fn test_verify_message_authenticator_valid() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let host       = Host::initialise_host(1812, 1813, 3799, dictionary);
        let secret     = "secret";

        let packet_bytes = [1, 120, 0, 185, 49, 79, 108, 150, 27, 203, 166, 51, 193, 68, 15, 76, 208, 114, 171, 48, 1, 9, 116, 101, 115, 116, 105, 110, 103, 80, 18, 164, 201, 132, 0, 209, 101, 200, 189, 252, 251, 120, 224, 74, 190, 232, 197, 2, 66, 85, 125, 163, 190, 40, 210, 235, 231, 112, 96, 7, 94, 27, 95, 241, 63, 23, 81, 25, 136, 36, 209, 238, 119, 131, 113, 118, 14, 160, 16, 94, 184, 143, 37, 193, 138, 124, 238, 85, 197, 21, 17, 206, 158, 87, 132, 239, 59, 82, 183, 175, 54, 124, 138, 5, 245, 166, 195, 181, 106, 41, 31, 129, 183, 4, 6, 192, 168, 1, 10, 5, 6, 0, 0, 0, 0, 6, 6, 0, 0, 0, 2, 32, 10, 116, 114, 105, 108, 108, 105, 97, 110, 30, 19, 48, 48, 45, 48, 52, 45, 53, 70, 45, 48, 48, 45, 48, 70, 45, 68, 49, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 8, 6, 10, 0, 0, 100];

        match host.verify_message_authenticator(&secret, &packet_bytes) {
            Err(_err) => {
                assert!(false)
            },
            _        => assert!(true)
        }
    }

    #[test]
    fn test_verify_message_authenticator_wo_authenticator() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let host       = Host::initialise_host(1812, 1813, 3799, dictionary);
        let secret     = "secret";

        let packet_bytes = [4, 43, 0, 83, 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73, 4, 6, 192, 168, 1, 10, 5, 6, 0, 0, 0, 0, 32, 10, 116, 114, 105, 108, 108, 105, 97, 110, 30, 19, 48, 48, 45, 48, 52, 45, 53, 70, 45, 48, 48, 45, 48, 70, 45, 68, 49, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 8, 6, 10, 0, 0, 100];

        match host.verify_message_authenticator(&secret, &packet_bytes) {
            Err(err) => {
                assert_eq!(err.to_string(), String::from("Radius packet is malformed: Message-Authenticator attribute not found in packet"))
            },
            _        => assert!(false)
        }
    }

    #[test]
    fn test_verify_message_authenticator_invalid() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let host       = Host::initialise_host(1812, 1813, 3799, dictionary);
        let secret     = "secret";

        let packet_bytes = [1, 94, 0, 190, 241, 228, 181, 142, 185, 194, 157, 205, 159, 0, 91, 199, 171, 119, 68, 44, 1, 9, 116, 101, 115, 116, 105, 110, 103, 80, 23, 109, 101, 115, 115, 97, 103, 101, 45, 97, 117, 116, 104, 101, 110, 116, 105, 99, 97, 116, 111, 114, 2, 66, 167, 81, 185, 84, 173, 104, 91, 10, 145, 109, 156, 169, 227, 109, 100, 76, 86, 227, 61, 253, 129, 35, 109, 115, 54, 140, 66, 106, 193, 70, 145, 39, 106, 105, 142, 215, 21, 166, 142, 80, 145, 217, 202, 252, 172, 33, 17, 12, 159, 105, 157, 144, 221, 221, 94, 48, 158, 22, 62, 191, 16, 177, 137, 131, 4, 6, 192, 168, 1, 10, 5, 6, 0, 0, 0, 0, 6, 6, 0, 0, 0, 2, 32, 10, 116, 114, 105, 108, 108, 105, 97, 110, 30, 19, 48, 48, 45, 48, 52, 45, 53, 70, 45, 48, 48, 45, 48, 70, 45, 68, 49, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 8, 6, 10, 0, 0, 100];

        match host.verify_message_authenticator(&secret, &packet_bytes) {
            Err(err) => {
                assert_eq!(err.to_string(), String::from("Verification failed for incoming Radius packet: Packet Message-Authenticator mismatch"))
            },
            _        => assert!(false)
        }
    }
}
