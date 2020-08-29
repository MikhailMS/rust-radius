use super::protocol::host::Host;
use super::protocol::radius_packet::{ RadiusPacket, RadiusAttribute, TypeCode };
use super::protocol::dictionary::Dictionary;

use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::mac::Mac;
use crypto::hmac::Hmac;
use mio::{ Events, Interest, Poll, Token };
use mio::net::UdpSocket;
use std::io::{Error, ErrorKind};
use std::time::Duration;


#[derive(Debug)]
pub struct Client<'client> {
    pub host:    Host<'client>,
    server:      String,
    secret:      String,
    retries:     u16,
    timeout:     u16,
    socket_poll: Poll
}

impl<'client> Client<'client> {
    pub fn initialise_client(auth_port: u16, acct_port: u16, coa_port: u16, dictionary: &Dictionary, server: String, secret: String, retries: u16, timeout: u16) -> Result<Client, Error> {
        Ok(
            Client {
                host:        Host::initialise_host(auth_port, acct_port, coa_port, dictionary),
                server:      server,
                secret:      secret,
                retries:     retries,
                timeout:     timeout,
                socket_poll: Poll::new()?
            }
        )
    }

    pub fn create_packet(&self, code: TypeCode, attributes: Vec<RadiusAttribute>) -> RadiusPacket {
        RadiusPacket::initialise_packet(code, attributes)
    }

    pub fn create_auth_packet(&self, attributes: Vec<RadiusAttribute>) -> RadiusPacket {
        RadiusPacket::initialise_packet(TypeCode::AccessRequest, attributes)
    }

    pub fn create_acct_packet(&self, attributes: Vec<RadiusAttribute>) -> RadiusPacket {
        RadiusPacket::initialise_packet(TypeCode::AccountingRequest, attributes)
    }

    pub fn create_coa_packet(&self, attributes: Vec<RadiusAttribute>) -> RadiusPacket {
        RadiusPacket::initialise_packet(TypeCode::CoARequest, attributes)
    }

    pub fn create_attribute_by_name(&self, attribute_name: &str, value: Vec<u8>) -> Result<RadiusAttribute, Error> {
        self.host.create_attribute_by_name(attribute_name, value)
    }

    pub fn create_attribute_by_id(&self, attribute_id: u8, value: Vec<u8>) -> Result<RadiusAttribute, Error> {
        self.host.create_attribute_by_id(attribute_id, value)
    }

    pub fn generate_message_hash(&self, packet: &mut RadiusPacket) -> Vec<u8> {
        let mut hash = Hmac::new(Md5::new(), self.secret.as_bytes());

        hash.input(&packet.to_bytes());
        hash.result().code().to_vec()
    }

    pub fn send_packet(&mut self, packet: &mut RadiusPacket) -> Result<(), Error> {
        let local_bind = "0.0.0.0:0".parse().map_err(|e| Error::new(ErrorKind::Other, e))?;
        let remote     = format!("{}:{}", &self.server, self.host.get_port(packet.get_code())).parse().map_err(|e| Error::new(ErrorKind::Other, e))?;

        let mut socket = UdpSocket::bind(local_bind)?;
        self.socket_poll.registry().register(&mut socket, Token(0), Interest::READABLE)?;

        let timeout    = Duration::from_secs(self.timeout as u64);
        let mut events = Events::with_capacity(1024);
        let mut retry  = 0;

        loop {
            if retry >= self.retries {
                break;
            }
            println!("Sending: {:?}", &packet.to_bytes());
            socket.send_to(&packet.to_bytes(), remote)?;

            self.socket_poll.poll(&mut events, Some(timeout))?;

            for event in events.iter() {
                match event.token() {
                    Token(0) => {
                        let mut response = [0; 4096];
                        let amount = socket.recv(&mut response)?;

                        if amount > 0 {
                            println!("Received reply: {:?}", &response[0..amount]);
                            return self.verify_reply(&packet, &response[0..amount]);
                        }
                    },
                    _ => return Err(Error::new(ErrorKind::Other, "Invalid Token")),
                }
            }

            retry += 1;
        }
        Err(Error::new(ErrorKind::TimedOut, ""))
    }

    fn verify_reply(&self, request: &RadiusPacket, reply: &[u8]) -> Result<(), Error> {
        if request.get_id() != reply[1] {
            return Err(Error::new(ErrorKind::InvalidData, String::from("Packet identifier mismatch")));
        };

        let mut md5_hasher = Md5::new();
        let mut hash       = [0; 16];

        md5_hasher.input(&reply[0..4]);                 // Append reply type code, reply ID and reply length
        md5_hasher.input(&request.get_authenticator()); // Append request authenticator
        md5_hasher.input(&reply[20..]);                 // Append rest of the reply
        md5_hasher.input(&self.secret.as_bytes());      // Append secret

        md5_hasher.result(&mut hash);

        println!("{:?}", &hash);
        println!("{:?}", &reply[4..20]);

        if hash == reply[4..20] {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::InvalidData, String::from("Packet authenticator mismatch")))
        }
    }

    fn verify_message_authenticator(&self, packet: &[u8]) -> Result<(), Error> {
        self.host.verify_message_authenticator(&self.secret, &packet)
    }
}
