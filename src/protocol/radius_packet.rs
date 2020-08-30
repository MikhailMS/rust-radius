use super::dictionary::{ Dictionary, SupportedAttributeTypes };
use crate::tools::{ bytes_to_integer, bytes_to_timestamp, bytes_to_ipv4_string, bytes_to_ipv6_string };

use rand::Rng;

use std::fmt;
use std::error::Error;
use std::convert::TryInto;


#[derive(Debug, Clone, PartialEq)]
pub enum TypeCode {
    // AccessRequest      = 1
    AccessRequest,
    // AccessAccept       = 2
    AccessAccept,
    // AccessReject       = 3
    AccessReject,
    // AccountingRequest  = 4
    AccountingRequest,
    // AccountingResponse = 5
    AccountingResponse,
    // AccessChallenge    = 11
    AccessChallenge,
    // StatusServer       = 12
    StatusServer,
    // StatusClient       = 13
    StatusClient,
    // DisconnectRequest  = 40
    DisconnectRequest,
    // DisconnectACK      = 41
    DisconnectACK,
    // DisconnectNAK      = 42
    DisconnectNAK,
    // CoARequest         = 43
    CoARequest,
    // CoAACK             = 44
    CoAACK,
    // CoANAK             = 45
    CoANAK
}

impl TypeCode {
    pub fn from_u8(code: u8) -> Result<TypeCode, String> {
        match code {
            1u8  => Ok(TypeCode::AccessRequest),
            2u8  => Ok(TypeCode::AccessAccept),
            3u8  => Ok(TypeCode::AccessReject),
            4u8  => Ok(TypeCode::AccountingRequest),
            5u8  => Ok(TypeCode::AccountingResponse),
            11u8 => Ok(TypeCode::AccessChallenge),
            12u8 => Ok(TypeCode::StatusServer),
            13u8 => Ok(TypeCode::StatusClient),
            40u8 => Ok(TypeCode::DisconnectRequest),
            41u8 => Ok(TypeCode::DisconnectACK),
            42u8 => Ok(TypeCode::DisconnectNAK),
            43u8 => Ok(TypeCode::CoARequest ),
            44u8 => Ok(TypeCode::CoAACK),
            45u8 => Ok(TypeCode::CoANAK),
            _ => Err(format!("Unknown RADIUS code {}", code)),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            TypeCode::AccessRequest      => 1u8,
            TypeCode::AccessAccept       => 2u8,
            TypeCode::AccessReject       => 3u8,
            TypeCode::AccountingRequest  => 4u8,
            TypeCode::AccountingResponse => 5u8,
            TypeCode::AccessChallenge    => 11u8,
            TypeCode::StatusServer       => 12u8,
            TypeCode::StatusClient       => 13u8,
            TypeCode::DisconnectRequest  => 40u8,
            TypeCode::DisconnectACK      => 41u8,
            TypeCode::DisconnectNAK      => 42u8,
            TypeCode::CoARequest         => 43u8,
            TypeCode::CoAACK             => 44u8,
            TypeCode::CoANAK             => 45u8
        }
    }
}


#[derive(Debug, PartialEq)]
pub struct MalformedPacket(String);

impl fmt::Display for MalformedPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "malformed RADIUS packet: \"{}\"", self.0)
    }
}

impl Error for MalformedPacket {
    fn description(&self) -> &str {
        "RADIUS packet contains unsupported attributes"
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}

#[derive(Debug, PartialEq)]
pub struct MalformedAttribute(String);

impl fmt::Display for MalformedAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "malformed RADIUS packet attribute: \"{}\"", self.0)
    }
}

impl MalformedAttribute {
    pub fn new(msg: String) -> MalformedAttribute {
        MalformedAttribute(msg)
    }
}

impl Error for MalformedAttribute {
    fn description(&self) -> &str {
        "RADIUS packet attribute is malformed"
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}


#[derive(Debug, PartialEq)]
pub struct RadiusAttribute {
    id:    u8,
    value: Vec<u8>
}

impl RadiusAttribute {
    pub fn create_by_name(dictionary: &Dictionary, attribute_name: &str, value: Vec<u8>) -> Option<RadiusAttribute> {
        match dictionary.get_attributes().iter().find(|&attr| attr.get_name() == attribute_name) {
            Some(attr) => Some(RadiusAttribute { id: attr.get_code().parse::<u8>().unwrap(), value: value }),
            _          => None
        }
    }

    pub fn create_by_id(dictionary: &Dictionary, attribute_code: u8, value: Vec<u8>) -> Option<RadiusAttribute> {
        match dictionary.get_attributes().iter().find(|&attr| attr.get_code() == attribute_code.to_string()) {
            Some(attr) => Some(RadiusAttribute { id: attribute_code, value: value }),
            _          => None
        }
    }

    pub fn override_value(&mut self, new_value: Vec<u8>) {
        self.value = new_value
    }

    pub fn get_id(&self) -> u8 {
        self.id
    }

    pub fn get_value(&self) -> &[u8] {
        &self.value
    }

    pub fn get_original_string_value(&self, allowed_type: &Option<SupportedAttributeTypes>) -> Result<String, MalformedAttribute> {
        match allowed_type {
            Some(SupportedAttributeTypes::AsciiString) => {
                match String::from_utf8(self.get_value().to_vec()) {
                    Ok(value) => Ok(value),
                    _         => Err(MalformedAttribute(String::from("invalid ASCII bytes")))
                }
            },
            Some(SupportedAttributeTypes::IPv4Addr)    => {
                match bytes_to_ipv4_string(self.get_value()) {
                    Ok(value) => Ok(value),
                    _         => Err(MalformedAttribute(String::from("invalid IPv4 bytes")))
                }
            },
            Some(SupportedAttributeTypes::IPv6Addr)    => {
                match bytes_to_ipv6_string(self.get_value()) {
                    Ok(value) => Ok(value),
                    _         => Err(MalformedAttribute(String::from("invalid IPv6 bytes")))
                }
            },
            Some(SupportedAttributeTypes::IPv6Prefix)  => {
                match bytes_to_ipv6_string(self.get_value()) {
                    Ok(value) => Ok(value),
                    _         => Err(MalformedAttribute(String::from("invalid IPv6 bytes")))
                }
            },
            _                                          => Err(MalformedAttribute(String::from("not a String data type")))
        }
    }

    pub fn get_original_integer_value(&self, allowed_type: &Option<SupportedAttributeTypes>) -> Result<u64, MalformedAttribute> {
        match allowed_type {
            Some(SupportedAttributeTypes::Integer) => {
                match self.get_value().try_into() {
                    Ok(value) => Ok(bytes_to_integer(value) as u64),
                    _         => Err(MalformedAttribute(String::from("invalid Integer bytes")))
                }
            } ,
            Some(SupportedAttributeTypes::Date)    => {
                match self.get_value().try_into() {
                    Ok(value) => Ok(bytes_to_timestamp(value) as u64),
                    _         => Err(MalformedAttribute(String::from("invalid Date bytes")))
                }
            },
            _                                      => Err(MalformedAttribute(String::from("not an Integer data type")))
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        /*
         *    
         *         0               1              2
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
           |     Type      |    Length     |  Value ...
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
        *  Taken from https://tools.ietf.org/html/rfc2865#page-23 
        */
        [ &[self.id], &[(2 + self.value.len()) as u8], self.value.as_slice() ].concat()
    }
}


#[derive(Debug, PartialEq)]
pub struct RadiusPacket {
    id:            u8,
    code:          TypeCode,
    authenticator: Vec<u8>,
    attributes:    Vec<RadiusAttribute>
}

impl RadiusPacket {
    pub fn initialise_packet(code: TypeCode, attributes: Vec<RadiusAttribute>) -> RadiusPacket {
        RadiusPacket {
            id:            RadiusPacket::create_id(),
            code:          code,
            authenticator: RadiusPacket::create_authenticator(),
            attributes:    attributes
        }
    }

    pub fn initialise_packet_from_bytes(dictionary: &Dictionary, bytes: &[u8]) -> Result<RadiusPacket, MalformedPacket> {
        let code           = match TypeCode::from_u8(bytes[0]) {
            Err(error) => return Err(MalformedPacket(error)),
            Ok(code)   => code
        };
        let id             = bytes[1];
        let authenticator  = bytes[4..20].to_vec();
        let mut attributes = Vec::new();

        let mut last_index = 20;

        while last_index != bytes.len() {
            let attr_id     = bytes[last_index];
            let attr_length = bytes[last_index + 1] as usize;
            let attr_value  = &bytes[(last_index + 2)..=(last_index + attr_length - 1)];

            match RadiusAttribute::create_by_id(dictionary, attr_id, attr_value.to_vec()) {
                Some(attr) => {
                    attributes.push(attr);
                    last_index += attr_length;
                },
                _ => {
                    return Err(MalformedPacket(format!("attribute with ID: {} is not found in dictionary", attr_id)))
                }
            }
        }

        Ok(RadiusPacket{
            id:            id,
            code:          code,
            authenticator: authenticator,
            attributes:    attributes
        })
    }

    pub fn override_id(&mut self, new_id: u8) {
        self.id = new_id
    }

    pub fn override_authenticator(&mut self, new_authenticator: Vec<u8>) {
        self.authenticator = new_authenticator
    }

    pub fn override_message_authenticator(&mut self, new_message_authenticator: Vec<u8>) -> Result<(), MalformedPacket> {
        match self.attributes.iter_mut().find(|attr| attr.get_id() == 80) {
            Some(attr) => {
                attr.override_value(new_message_authenticator);
                Ok(())
            },
            None       => Err(MalformedPacket(String::from("Message-Authenticator attribute not found in packet")))
        }
    }

    pub fn get_message_authenticator(&self) -> Result<&[u8], MalformedPacket> {
        match self.attributes.iter().find(|attr| attr.get_id() == 80) {
            Some(attr) => {
                Ok(attr.get_value())
            },
            None       => Err(MalformedPacket(String::from("Message-Authenticator attribute not found in packet")))
        }
    }

    pub fn get_id(&self) -> u8 {
        self.id
    }

    pub fn get_authenticator(&self) -> &[u8] {
        &self.authenticator
    }

    pub fn get_code(&self) -> &TypeCode {
        &self.code
    }

    pub fn to_bytes(&mut self) -> Vec<u8> {
        /* Prepare packet for a transmission to server/client
         *
         *          0               1               2         3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Code      |  Identifier   |            Length             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           |                         Authenticator                         |
           |                                                               |
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Attributes ...
           +-+-+-+-+-+-+-+-+-+-+-+-+-
         * Taken from https://tools.ietf.org/html/rfc2865#page-14
         * 
         */

        let mut packet_bytes = Vec::new();
        let mut packet_attr  = Vec::new();

        if self.authenticator.is_empty() {
            self.authenticator = Self::create_authenticator();
        }

        for attr in self.attributes.iter() {
            packet_attr.extend(&attr.to_bytes());
        }

        packet_bytes.push(self.code.to_u8());
        packet_bytes.push(self.id);
        packet_bytes.append(&mut Self::packet_length_to_bytes(((20 + packet_attr.len()) as u16).to_be()).to_vec());
        packet_bytes.append(&mut self.authenticator.as_slice().to_vec());
        packet_bytes.append(&mut packet_attr);

        packet_bytes
    }

    fn create_id() -> u8 {
        rand::thread_rng().gen_range(0u8, 255u8)
    }
    
    fn create_authenticator() -> Vec<u8> {
        let mut authenticator: Vec<u8> = Vec::with_capacity(16);
        for _ in 0..16 {
            authenticator.push(rand::thread_rng().gen_range(0u8, 255u8))
        }

        authenticator
    }

    fn packet_length_to_bytes(length: u16) -> [u8; 2] {
        RadiusPacket::u16_to_u8(length)
    }

    fn u16_to_u8(u16_data: u16) -> [u8;2] {
        [u16_data as u8, (u16_data >> 8) as u8]
    }
}

#[cfg(test)]
mod tests {
    use crate::tools::{ integer_to_bytes, ipv4_string_to_bytes};
    use super::*;

    #[test]
    fn test_radius_attribute_create_by_name() {
        let dictionary_path = "./dict_examples/test_dictionary_dict";
        let dict            = Dictionary::from_file(dictionary_path).unwrap();

        let expected = RadiusAttribute { id: 1, value: vec![1,2,3] };

        assert_eq!(Some(expected), RadiusAttribute::create_by_name(&dict, "User-Name", vec![1,2,3]));
    }
    #[test]
    fn test_radius_attribute_create_by_id() {
        let dictionary_path = "./dict_examples/test_dictionary_dict";
        let dict            = Dictionary::from_file(dictionary_path).unwrap();
        
        let expected = RadiusAttribute { id: 5, value: vec![1,2,3] };

        assert_eq!(Some(expected), RadiusAttribute::create_by_id(&dict, 5, vec![1,2,3]));
    }
    

    #[test]
    fn test_initialise_packet_from_bytes() {
        let dictionary_path = "./dict_examples/integration_dict";
        let dict            = Dictionary::from_file(dictionary_path).unwrap();

        let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10").unwrap();
        let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100").unwrap();
        let attributes          = vec![
            RadiusAttribute::create_by_name(&dict, "NAS-IP-Address",     nas_ip_addr_bytes).unwrap(),
            RadiusAttribute::create_by_name(&dict, "NAS-Port-Id",        integer_to_bytes(0)).unwrap(),
            RadiusAttribute::create_by_name(&dict, "NAS-Identifier",     String::from("trillian").into_bytes()).unwrap(),
            RadiusAttribute::create_by_name(&dict, "Called-Station-Id",  String::from("00-04-5F-00-0F-D1").into_bytes()).unwrap(),
            RadiusAttribute::create_by_name(&dict, "Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
            RadiusAttribute::create_by_name(&dict, "Framed-IP-Address",  framed_ip_addr_bytes).unwrap()
        ];
        let authenticator       = vec![215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73];
        let mut expected_packet = RadiusPacket::initialise_packet(TypeCode::AccountingRequest, attributes);
        expected_packet.override_id(43);
        expected_packet.override_authenticator(authenticator);

        let bytes             = [4, 43, 0, 83, 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73, 4, 6, 192, 168, 1, 10, 5, 6, 0, 0, 0, 0, 32, 10, 116, 114, 105, 108, 108, 105, 97, 110, 30, 19, 48, 48, 45, 48, 52, 45, 53, 70, 45, 48, 48, 45, 48, 70, 45, 68, 49, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 8, 6, 10, 0, 0, 100];
        let packet_from_bytes = RadiusPacket::initialise_packet_from_bytes(&dict, &bytes).unwrap();

        assert_eq!(expected_packet, packet_from_bytes);
    }

    #[test]
    fn test_radius_packet_override_id() {
        let attributes: Vec<RadiusAttribute> = Vec::with_capacity(1);
        let new_id: u8                       = 50;

        let mut packet = RadiusPacket::initialise_packet(TypeCode::AccessRequest, attributes);
        packet.override_id(new_id);

        assert_eq!(new_id, packet.get_id());
    }
    #[test]
    fn test_radius_packet_override_authenticator() {
        let attributes: Vec<RadiusAttribute> = Vec::with_capacity(1);
        let new_authenticator: Vec<u8>       = vec![0, 25, 100, 56, 13];

        let mut packet = RadiusPacket::initialise_packet(TypeCode::AccessRequest, attributes);
        packet.override_authenticator(new_authenticator.to_vec());

        assert_eq!(new_authenticator, packet.get_authenticator());
    }
    #[test]
    fn test_radius_packet_to_bytes() {
        let attributes: Vec<RadiusAttribute> = Vec::with_capacity(1);
        let new_id: u8                       = 50;
        let new_authenticator: Vec<u8>       = vec![0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153, 0, 1, 2, 3];
        
        let exepcted_bytes = vec![1, 50, 0, 20, 0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153, 0, 1, 2, 3];
        let mut packet = RadiusPacket::initialise_packet(TypeCode::AccessRequest, attributes);

        packet.override_id(new_id);
        packet.override_authenticator(new_authenticator);
        
        assert_eq!(exepcted_bytes, packet.to_bytes());
    }

    #[test]
    fn test_override_message_authenticator_fail() {
        let dictionary_path = "./dict_examples/integration_dict";
        let dict            = Dictionary::from_file(dictionary_path).unwrap();

        let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10").unwrap();
        let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100").unwrap();
        let attributes          = vec![
            RadiusAttribute::create_by_name(&dict, "NAS-IP-Address",     nas_ip_addr_bytes).unwrap(),
            RadiusAttribute::create_by_name(&dict, "NAS-Port-Id",        integer_to_bytes(0)).unwrap(),
            RadiusAttribute::create_by_name(&dict, "NAS-Identifier",     String::from("trillian").into_bytes()).unwrap(),
            RadiusAttribute::create_by_name(&dict, "Called-Station-Id",  String::from("00-04-5F-00-0F-D1").into_bytes()).unwrap(),
            RadiusAttribute::create_by_name(&dict, "Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
            RadiusAttribute::create_by_name(&dict, "Framed-IP-Address",  framed_ip_addr_bytes).unwrap()
        ];

        let new_message_authenticator = vec![1, 50, 0, 20, 0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153];
        let mut packet = RadiusPacket::initialise_packet(TypeCode::AccountingRequest, attributes);

        match packet.override_message_authenticator(new_message_authenticator) {
            Err(err) => assert_eq!(MalformedPacket(String::from("Message-Authenticator attribute not found in packet")), err),
            _        => assert!(false)
        }
    }

    fn test_override_message_authenticator_success() {
        let dictionary_path = "./dict_examples/integration_dict";
        let dict            = Dictionary::from_file(dictionary_path).unwrap();

        let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10").unwrap();
        let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100").unwrap();
        let attributes          = vec![
            RadiusAttribute::create_by_name(&dict, "Calling-Station-Id",    String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
            RadiusAttribute::create_by_name(&dict, "Message-Authenticator", vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap()
        ];

        let new_message_authenticator  = vec![1, 50, 0, 20, 0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153];
        let mut packet                 = RadiusPacket::initialise_packet(TypeCode::AccountingRequest, attributes);
        let new_id: u8                 = 50;
        let new_authenticator: Vec<u8> = vec![0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153, 0, 1, 2, 3];

        packet.override_id(new_id);
        packet.override_authenticator(new_authenticator);

        let expected_packet_bytes: Vec<u8> = vec![1, 50, 0, 57, 0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153, 0, 1, 2, 3, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 80, 18, 1, 50, 0, 20, 0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153];

        match packet.override_message_authenticator(new_message_authenticator) {
            Err(_) => assert!(false),
            _      => assert_eq!(expected_packet_bytes, packet.to_bytes())
        }
    }
}
