use super::dictionary::{ Dictionary, SupportedAttributeTypes };
use super::error::RadiusError;
use crate::tools::{ bytes_to_integer, bytes_to_timestamp, bytes_to_ipv4_string, bytes_to_ipv6_string };

use rand::Rng;

use std::convert::TryInto;


#[derive(Debug, Clone, PartialEq)]
/// Contains all supported Codes of RADIUS message/packet
/// as defined in RFC 2865 & RFC 3576
pub enum TypeCode {
    /// AccessRequest      = 1
    AccessRequest,
    /// AccessAccept       = 2
    AccessAccept,
    /// AccessReject       = 3
    AccessReject,
    /// AccountingRequest  = 4
    AccountingRequest,
    /// AccountingResponse = 5
    AccountingResponse,
    /// AccessChallenge    = 11
    AccessChallenge,
    /// StatusServer       = 12
    StatusServer,
    /// StatusClient       = 13
    StatusClient,
    /// DisconnectRequest  = 40
    DisconnectRequest,
    /// DisconnectACK      = 41
    DisconnectACK,
    /// DisconnectNAK      = 42
    DisconnectNAK,
    /// CoARequest         = 43
    CoARequest,
    /// CoAACK             = 44
    CoAACK,
    /// CoANAK             = 45
    CoANAK
}

impl TypeCode {
    pub fn from_u8(code: u8) -> Result<TypeCode, RadiusError> {
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
            _ => Err( RadiusError::UnsupportedTypeCode { error: format!("Unknown RADIUS code: {}", code) }),
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
/// Represents an attribute, which would be sent to RADIUS Server/client as a part of RadiusPacket
pub struct RadiusAttribute {
    id:    u8,
    name:  String,
    value: Vec<u8>
}

impl RadiusAttribute {
    /// Creates RadiusAttribute with given name
    ///
    /// Returns None, if ATTRIBUTE with such name is not found in Dictionary
    pub fn create_by_name(dictionary: &Dictionary, attribute_name: &str, value: Vec<u8>) -> Option<RadiusAttribute> {
        match dictionary.attributes().iter().find(|&attr| attr.name() == attribute_name) {
            Some(attr) => Some(RadiusAttribute {
                id:    attr.code().parse::<u8>().unwrap(),
                name:  attr.name().to_string(),
                value: value
            }),
            _          => None
        }
    }

    /// Creates RadiusAttribute with given id
    ///
    /// Returns None, if ATTRIBUTE with such id is not found in Dictionary
    pub fn create_by_id(dictionary: &Dictionary, attribute_code: u8, value: Vec<u8>) -> Option<RadiusAttribute> {
        match dictionary.attributes().iter().find(|&attr| attr.code() == attribute_code.to_string()) {
            Some(attr) => Some(RadiusAttribute {
                id:    attribute_code,
                name:  attr.name().to_string(),
                value: value
            }),
            _          => None
        }
    }

    /// Overriddes RadiusAttribute value
    ///
    /// Mainly used when building Message-Authenticator
    pub fn override_value(&mut self, new_value: Vec<u8>) {
        self.value = new_value
    }

    /// Returns RadiusAttribute id
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns RadiusAttribute value
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Returns RadiusAttribute name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Verifies RadiusAttribute value, based on the ATTRIBUTE code type
    pub fn verify_original_value(&self, allowed_type: &Option<SupportedAttributeTypes>) -> Result<(), RadiusError> {
        match allowed_type {
            Some(SupportedAttributeTypes::AsciiString) => {
                match String::from_utf8(self.value().to_vec()) {
                    Ok(_) => Ok(()),
                    _     => Err( RadiusError::MalformedAttribute {error: String::from("invalid ASCII bytes")} )
                }
            },
            Some(SupportedAttributeTypes::IPv4Addr)    => {
                match bytes_to_ipv4_string(self.value()) {
                    Ok(_) => Ok(()),
                    _     => Err( RadiusError::MalformedAttribute {error: String::from("invalid IPv4 bytes")} )
                }
            },
            Some(SupportedAttributeTypes::IPv6Addr)    => {
                match bytes_to_ipv6_string(self.value()) {
                    Ok(_) => Ok(()),
                    _     => Err( RadiusError::MalformedAttribute {error: String::from("invalid IPv6 bytes")} )
                }
            },
            Some(SupportedAttributeTypes::IPv6Prefix)  => {
                match bytes_to_ipv6_string(self.value()) {
                    Ok(_) => Ok(()),
                    _     => Err( RadiusError::MalformedAttribute {error: String::from("invalid IPv6 bytes")} )
                }
            },
            Some(SupportedAttributeTypes::Integer)     => {
                match self.value().try_into() {
                    Ok(value) => {
                        bytes_to_integer(value);
                        Ok(())
                    },
                    _         => Err( RadiusError::MalformedAttribute {error: String::from("invalid Integer bytes")} )
                }
            } ,
            Some(SupportedAttributeTypes::Date)        => {
                match self.value().try_into() {
                    Ok(value) => {
                        bytes_to_timestamp(value);
                        Ok(())
                    },
                    _         => Err( RadiusError::MalformedAttribute {error: String::from("invalid Date bytes")} )
                }
            },
            _                                          => Err( RadiusError::MalformedAttribute {error: String::from("unsupported attribute code type")} )
        }
    }

    /// Returns RadiusAttribute value, if the attribute is dictionary's ATTRIBUTE with code type string, ipaddr,
    /// ipv6addr or aipv6prefix
    pub fn original_string_value(&self, allowed_type: &Option<SupportedAttributeTypes>) -> Result<String, RadiusError> {
        match allowed_type {
            Some(SupportedAttributeTypes::AsciiString) => {
                match String::from_utf8(self.value().to_vec()) {
                    Ok(value) => Ok(value),
                    _         => Err( RadiusError::MalformedAttribute {error: String::from("invalid ASCII bytes")} )
                }
            },
            Some(SupportedAttributeTypes::IPv4Addr)    => {
                match bytes_to_ipv4_string(self.value()) {
                    Ok(value) => Ok(value),
                    _         => Err( RadiusError::MalformedAttribute {error: String::from("invalid IPv4 bytes")} )
                }
            },
            Some(SupportedAttributeTypes::IPv6Addr)    => {
                match bytes_to_ipv6_string(self.value()) {
                    Ok(value) => Ok(value),
                    _         => Err( RadiusError::MalformedAttribute {error: String::from("invalid IPv6 bytes")} )
                }
            },
            Some(SupportedAttributeTypes::IPv6Prefix)  => {
                match bytes_to_ipv6_string(self.value()) {
                    Ok(value) => Ok(value),
                    _         => Err( RadiusError::MalformedAttribute {error: String::from("invalid IPv6 bytes")} )
                }
            },
            _                                          => Err( RadiusError::MalformedAttribute {error: String::from("not a String data type")} )
        }
    }

    /// Returns RadiusAttribute value, if the attribute is dictionary's ATTRIBUTE with code type
    /// integer of date
    pub fn original_integer_value(&self, allowed_type: &Option<SupportedAttributeTypes>) -> Result<u64, RadiusError> {
        match allowed_type {
            Some(SupportedAttributeTypes::Integer) => {
                match self.value().try_into() {
                    Ok(value) => Ok(bytes_to_integer(value) as u64),
                    _         => Err( RadiusError::MalformedAttribute {error: String::from("invalid Integer bytes")} )
                }
            } ,
            Some(SupportedAttributeTypes::Date)    => {
                match self.value().try_into() {
                    Ok(value) => Ok(bytes_to_timestamp(value) as u64),
                    _         => Err( RadiusError::MalformedAttribute {error: String::from("invalid Date bytes")} )
                }
            },
            _                                      => Err( RadiusError::MalformedAttribute {error: String::from("not an Integer data type")} )
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
/// Represents RADIUS packet
pub struct RadiusPacket {
    id:            u8,
    code:          TypeCode,
    authenticator: Vec<u8>,
    attributes:    Vec<RadiusAttribute>
}

impl RadiusPacket {
    /// Initialises RADIUS packet with random ID and authenticator
    pub fn initialise_packet(code: TypeCode, attributes: Vec<RadiusAttribute>) -> RadiusPacket {
        RadiusPacket {
            id:            RadiusPacket::create_id(),
            code:          code,
            authenticator: RadiusPacket::create_authenticator(),
            attributes:    attributes
        }
    }

    /// Initialises RADIUS packet from raw bytes
    pub fn initialise_packet_from_bytes(dictionary: &Dictionary, bytes: &[u8]) -> Result<RadiusPacket, RadiusError> {
        let code           = TypeCode::from_u8(bytes[0])?;
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
                _          => return Err( RadiusError::MalformedPacket {error:format!("attribute with ID: {} is not found in dictionary", attr_id)} )
            }
        }

        Ok(RadiusPacket{
            id:            id,
            code:          code,
            authenticator: authenticator,
            attributes:    attributes
        })
    }

    /// Overrides RadiusPacket id
    pub fn override_id(&mut self, new_id: u8) {
        self.id = new_id
    }

    /// Overrides RadiusPacket authenticator
    pub fn override_authenticator(&mut self, new_authenticator: Vec<u8>) {
        self.authenticator = new_authenticator
    }

    /// Overrides RadiusPacket Message-Authenticator
    ///
    /// Note: would fail if RadiusPacket has no Message-Authenticator attribute defined
    pub fn override_message_authenticator(&mut self, new_message_authenticator: Vec<u8>) -> Result<(), RadiusError> {
        match self.attributes.iter_mut().find(|attr| attr.name() == "Message-Authenticator") {
            Some(attr) => {
                attr.override_value(new_message_authenticator);
                Ok(())
            },
            _          => Err( RadiusError::MalformedPacket {error:String::from("Message-Authenticator attribute not found in packet")} )
        }
    }

    /// Returns Message-Authenticator value, if exists in RadiusPacket
    pub fn message_authenticator(&self) -> Result<&[u8], RadiusError> {
        match self.attributes.iter().find(|attr| attr.name() == "Message-Authenticator") {
            Some(attr) => {
                Ok(attr.value())
            },
            _          => Err( RadiusError::MalformedPacket {error: String::from("Message-Authenticator attribute not found in packet")} )
        }
    }

    /// Returns RadiusPacket id
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns RadiusPacket authenticator
    pub fn authenticator(&self) -> &[u8] {
        &self.authenticator
    }

    /// Returns RadiusPacket code
    pub fn code(&self) -> &TypeCode {
        &self.code
    }

    /// Returns RadiusPacket attributes
    pub fn attributes(&self) -> &[RadiusAttribute] {
        &self.attributes
    }

    /// Returns RadiusAttribute with given name
    pub fn attribute_by_name(&self, name: &str) -> Option<&RadiusAttribute> {
        self.attributes.iter().find(|&attr| attr.name() == name)
    }

    /// Returns RadiusAttribute with given id
    pub fn attribute_by_id(&self, id: u8) -> Option<&RadiusAttribute> {
        self.attributes.iter().find(|&attr| attr.id() == id)
    }

    /// Converts RadiusPacket into ready-to-be-sent bytes vector
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

        let expected = RadiusAttribute {
            id:    1,
            name:  String::from("User-Name"),
            value: vec![1,2,3]
        };

        assert_eq!(Some(expected), RadiusAttribute::create_by_name(&dict, "User-Name", vec![1,2,3]));
    }
    #[test]
    fn test_radius_attribute_create_by_id() {
        let dictionary_path = "./dict_examples/test_dictionary_dict";
        let dict            = Dictionary::from_file(dictionary_path).unwrap();
        
        let expected = RadiusAttribute {
            id:    5,
            name:  String::from("NAS-Port-Id"),
            value: vec![1,2,3]
        };

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

        assert_eq!(new_id, packet.id());
    }
    #[test]
    fn test_radius_packet_override_authenticator() {
        let attributes: Vec<RadiusAttribute> = Vec::with_capacity(1);
        let new_authenticator: Vec<u8>       = vec![0, 25, 100, 56, 13];

        let mut packet = RadiusPacket::initialise_packet(TypeCode::AccessRequest, attributes);
        packet.override_authenticator(new_authenticator.to_vec());

        assert_eq!(new_authenticator, packet.authenticator());
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
            Err(err) => assert_eq!(String::from("Radius packet is malformed"), err.to_string()),
            _        => assert!(false)
        }
    }

    #[test]
    fn test_override_message_authenticator_success() {
        let dictionary_path = "./dict_examples/integration_dict";
        let dict            = Dictionary::from_file(dictionary_path).unwrap();

        let attributes = vec![
            RadiusAttribute::create_by_name(&dict, "Calling-Station-Id",    String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
            RadiusAttribute::create_by_name(&dict, "Message-Authenticator", vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap()
        ];

        let new_message_authenticator  = vec![1, 50, 0, 20, 0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153];
        let mut packet                 = RadiusPacket::initialise_packet(TypeCode::AccessRequest, attributes);
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
