use super::dictionary::{ Dictionary, DictionaryAttribute, DictionaryValue };
use super::radius_packet::{ RadiusPacket, RadiusAttribute, TypeCode };

use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::mac::Mac;
use crypto::hmac::Hmac;
use std::io::{Error, ErrorKind};


#[derive(Debug)]
pub struct Host<'host> {
    auth_port:      u16,
    acct_port:      u16,
    coa_port:       u16,
    pub dictionary: &'host Dictionary
}

impl<'host> Host<'host> {
    pub fn initialise_host(auth_port: u16, acct_port: u16, coa_port: u16, dictionary: &Dictionary) -> Host {
        Host { auth_port, acct_port, coa_port, dictionary }
    }

    pub fn create_attribute_by_name(&self, attribute_name: &str, value: Vec<u8>) -> Result<RadiusAttribute, Error> {
        RadiusAttribute::create_by_name(&self.dictionary, attribute_name, value).ok_or(Error::new(ErrorKind::Other, format!("Failed to create: {:?} attribute. Check if attribute exists in provided dictionary file", attribute_name)))
    }

    pub fn create_attribute_by_id(&self, attribute_id: u8, value: Vec<u8>) -> Result<RadiusAttribute, Error> {
        RadiusAttribute::create_by_id(&self.dictionary, attribute_id, value).ok_or(Error::new(ErrorKind::Other, format!("Failed to create: attribute with ID {}. Check if attribute exists in provided dictionary file", attribute_id)))
    }

    pub fn get_port(&self, code: &TypeCode) -> u16 {
        match code {
            TypeCode::AccessRequest     => self.auth_port,
            TypeCode::AccountingRequest => self.acct_port,
            TypeCode::CoARequest        => self.coa_port,
            _                           => 0u16
        }
    }

    pub fn get_dictionary_value_by_attr_and_value_name(&self, attr_name: &str, value_name: &str) -> Option<&DictionaryValue> {
        match self.dictionary.get_values().iter().find(|&value| value.get_name() == value_name && value.get_attribute_name() == attr_name) {
            Some(value) => Some(value),
            _           => None
        }
    }

    pub fn get_dictionary_attribute_by_id(&self, packet_attr_id: u8) -> Option<&DictionaryAttribute> {
        match self.dictionary.get_attributes().iter().find(|&attr| attr.get_code() == packet_attr_id.to_string()) {
            Some(value) => Some(value),
            _           => None
        }
    }

    pub fn get_dictionary_attribute_by_name(&self, packet_attr_name: &str) -> Option<&DictionaryAttribute> {
        match self.dictionary.get_attributes().iter().find(|&attr| attr.get_name() == packet_attr_name) {
            Some(value) => Some(value),
            _           => None
        }
    }

    pub fn verify_packet_attributes(&self, packet: &[u8]) -> Result<(), Error> {
        let ignore_attribute = "Message-Authenticator";
        let _packet_tmp      = match RadiusPacket::initialise_packet_from_bytes(&self.dictionary, &packet) {
            Ok(value) => value,
            Err(err)  => return Err(Error::new(ErrorKind::InvalidData, err))
        };

        for packet_attr in _packet_tmp.get_attributes().iter().filter(|&attr| attr.get_name() != ignore_attribute) {
            let _dict_attr           = self.get_dictionary_attribute_by_id(packet_attr.get_id()).unwrap();
            let _dict_attr_data_type = _dict_attr.get_code_type();

            match packet_attr.verify_original_value(_dict_attr_data_type) {
                Err(err) => return Err(Error::new(ErrorKind::InvalidData, err)),
                _        => continue
            }
        }
        Ok(())
    }

    pub fn verify_message_authenticator(&self, secret: &str, packet: &[u8]) -> Result<(), Error> {
        let _packet_tmp     = match RadiusPacket::initialise_packet_from_bytes(&self.dictionary, &packet) {
            Ok(value) => value,
            Err(err)  => return Err(Error::new(ErrorKind::InvalidData, err))
        };
        let packet_msg_auth = match _packet_tmp.get_message_authenticator() {
            Ok(value) => value,
            Err(err)  => return Err(Error::new(ErrorKind::InvalidData, err))
        };

        let mut hash = Hmac::new(Md5::new(), secret.as_bytes());
        hash.input(&packet);

        if hash.result().code() == packet_msg_auth {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::InvalidData, String::from("Packet Message-Authenticator mismatch")))
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
        let host       = Host::initialise_host(1812, 1813, 3799, &dictionary);

        let dict_value = host.get_dictionary_value_by_attr_and_value_name("Service-Type", "Login-User").unwrap();

        assert_eq!("Service-Type", dict_value.get_attribute_name());
        assert_eq!("Login-User",   dict_value.get_name());
        assert_eq!("1",            dict_value.get_value());
    }

    #[test]
    fn test_get_dictionary_value_by_attr_and_value_name_error() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let host       = Host::initialise_host(1812, 1813, 3799, &dictionary);

        let dict_value = host.get_dictionary_value_by_attr_and_value_name("Service-Type", "Lin-User");
        assert_eq!(None, dict_value);
    }

    #[test]
    fn test_get_dictionary_attribute_by_id() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let host       = Host::initialise_host(1812, 1813, 3799, &dictionary);

        let dict_attr = host.get_dictionary_attribute_by_id(80).unwrap();

        assert_eq!("Message-Authenticator",                    dict_attr.get_name());
        assert_eq!("80",                                       dict_attr.get_code());
        assert_eq!(&Some(SupportedAttributeTypes::AsciiString), dict_attr.get_code_type());
    }

    #[test]
    fn test_get_dictionary_attribute_by_id_error() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let host       = Host::initialise_host(1812, 1813, 3799, &dictionary);

        let dict_attr = host.get_dictionary_attribute_by_id(255);
        assert_eq!(None, dict_attr);
    }

    #[test]
    fn test_verify_packet_attributes() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let host       = Host::initialise_host(1812, 1813, 3799, &dictionary);

        let packet_bytes = [4, 43, 0, 83, 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73, 4, 6, 192, 168, 1, 10, 5, 6, 0, 0, 0, 0, 32, 10, 116, 114, 105, 108, 108, 105, 97, 110, 30, 19, 48, 48, 45, 48, 52, 45, 53, 70, 45, 48, 48, 45, 48, 70, 45, 68, 49, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 8, 6, 10, 0, 0, 100];

        match host.verify_packet_attributes(&packet_bytes) {
            Err(err) => {
                println!("{:?}", err);
                assert!(false)
            },
            _        => assert!(true)
        }
    }

    #[test]
    fn test_verify_packet_attributes_fail() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let host       = Host::initialise_host(1812, 1813, 3799, &dictionary);

        let packet_bytes = [4, 43, 0, 82, 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73, 4, 5, 192, 168, 10, 5, 6, 0, 0, 0, 0, 32, 10, 116, 114, 105, 108, 108, 105, 97, 110, 30, 19, 48, 48, 45, 48, 52, 45, 53, 70, 45, 48, 48, 45, 48, 70, 45, 68, 49, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 8, 6, 10, 0, 0, 100];

        match host.verify_packet_attributes(&packet_bytes) {
            Err(err) => {
                println!("{:?}", err);
                assert!(true)
            },
            _        => assert!(false)
        }
    }
}
