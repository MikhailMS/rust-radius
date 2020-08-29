use super::dictionary::{ Dictionary, DictionaryAttribute };
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

    pub fn get_dictionary_attribute_by_id(&self, packet_attr_id: u8) -> Option<&DictionaryAttribute> {
        match self.dictionary.get_attributes().iter().find(|&attr| attr.get_code() == packet_attr_id.to_string()) {
            Some(value) => Some(value),
            _           => None
        }
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
