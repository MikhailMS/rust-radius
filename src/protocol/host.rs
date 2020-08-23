use super::dictionary::Dictionary;
use super::radius_packet::TypeCode;


#[derive(Debug)]
pub struct Host<'host> {
    pub auth_port:  u16,
    pub acct_port:  u16,
    pub coa_port:   u16,
    pub dictionary: &'host Dictionary
}

impl<'host> Host<'host> {
    // fn create_packet(&self, code: TypeCode) -> Packet {
    //     RadiusPacket {
    //         code:                  code,
    //         id:                    Packet::create_id(),
    //         authenticator:         Packet::create_authenticator(),
    //         dictionary:            &self.dictionary,
    //         raw_packet:            Vec::<u8>::new(),
    //         message_authenticator: String::new()
    //     }
    // }

    pub fn get_port(&self, code: &TypeCode) -> u16 {
        match code {
            TypeCode::AccessRequest     => self.auth_port,
            TypeCode::AccountingRequest => self.acct_port,
            TypeCode::CoARequest        => self.coa_port,
            _                           => 0u16
        }
    }
}
