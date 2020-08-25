use super::dictionary::Dictionary;

use rand::Rng;


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
pub struct RadiusAttribute {
    id:    u8,
    value: Vec<u8>
}

impl RadiusAttribute {
    pub fn create_by_name(dictionary: &Dictionary, attribute_name: &str, value: Vec<u8>) -> Option<RadiusAttribute> {
        match dictionary.attributes.iter().find(|&attr| attr.name == attribute_name) {
            Some(attr) => Some(RadiusAttribute { id: attr.code.parse::<u8>().unwrap(), value: value }),
            _          => None
        }
    }

    pub fn create_by_id(attribute_code: u8, value: Vec<u8>) -> Option<RadiusAttribute> {
        Some(RadiusAttribute{
            id:    attribute_code,
            value: value
        })
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

        // This is an ugly hack to ensure, that single integer is encoded
        // as 4 bytes, not 1, ie: b'\x00\x00\x00\x00', not b'\x00'
        // Should be a better way to do so, but cannot think of it rn
        if self.value.len() == 1 {
            let mut data: Vec<u8> = Vec::new();
            let attr_length       = 6u8;

            data.push(self.id);
            data.push(attr_length);
            data.push(0u8);
            data.push(0u8);
            data.push(0u8);
            data.push(self.value[0]);

            data
        } else {
            [ &[self.id], &[(2 + self.value.len()) as u8], self.value.as_slice() ].concat()
        }
    }
}


#[derive(Debug)]
pub struct RadiusPacket {
    id:            u8,
    code:          TypeCode,
    authenticator: Vec<u8>,
    attributes:    Vec<RadiusAttribute>
}

impl RadiusPacket {
    pub fn initialise_packet(code: TypeCode, attributes: Vec<RadiusAttribute>) -> RadiusPacket{
        RadiusPacket {
            id:            RadiusPacket::create_id(),
            code:          code,
            authenticator: RadiusPacket::create_authenticator(),
            attributes:    attributes
        }
    }

    pub fn override_id(&mut self, new_id: u8) {
        self.id = new_id
    }

    pub fn override_authenticator(&mut self, new_authenticator: Vec<u8>) {
        self.authenticator = new_authenticator
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
        let expected = RadiusAttribute { id: 50, value: vec![1,2,3] };

        assert_eq!(Some(expected), RadiusAttribute::create_by_id(50, vec![1,2,3]));
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
}
