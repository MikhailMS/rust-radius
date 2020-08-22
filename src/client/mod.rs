use super::protocol::host::Host;
use super::protocol::radius_packet::{ RadiusPacket, RadiusAttribute, TypeCode };
use super::protocol::dictionary::Dictionary;

use crypto::digest::Digest;
use crypto::md5::Md5;
use mio::{ Events, Ready, Poll, PollOpt, Token };
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
                host:        Host { auth_port, acct_port, coa_port, dictionary },
                server:      server,
                secret:      secret,
                retries:     retries,
                timeout:     timeout,
                socket_poll: Poll::new()?
            }
        )
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
    
    pub fn send_packet(&self, packet: &mut RadiusPacket) -> Result<(), Error> {
        let local_bind = "0.0.0.0:0".parse().map_err(|e| Error::new(ErrorKind::Other, e))?;
        let remote     = &format!("{}:{}", &self.server, self.host.get_port(&packet.code)).parse().map_err(|e| Error::new(ErrorKind::Other, e))?;

        let socket = UdpSocket::bind(&local_bind)?;
        self.socket_poll.register(&socket, Token(0), Ready::readable(), PollOpt::edge())?;

        let timeout    = Duration::from_secs(self.timeout as u64);
        let mut events = Events::with_capacity(1024);
        let mut retry  = 0;

        loop {
            if retry >= self.retries {
                break;
            }
            socket.send_to(&packet.to_bytes(), remote)?;

            self.socket_poll.poll(&mut events, Some(timeout));

            for event in events.iter() {
                match event.token() {
                    Token(0) => {
                        let mut response = [0; 4096];
                        let amount = socket.recv(&mut response)?;

                        if amount > 0 {
                            return self.verify_reply(&packet, &mut response[0..amount]);
                        }
                    },
                    _ => return Err(Error::new(ErrorKind::Other, "Invalid Token")),
                }
            }

            retry += 1;
        }

        Err(Error::new(ErrorKind::TimedOut, ""))
    }

    fn verify_reply(&self, request: &RadiusPacket, reply: &mut [u8]) -> Result<(), Error> {
        if request.id != reply[1] {
            return Err(Error::new(ErrorKind::InvalidData, String::from("Packet identifier mismatch")));
        };

        let mut raw_data: Vec<u8> = Vec::new();

        raw_data.append(&mut reply[0..4].to_vec());                  // Append reply type code, reply ID and reply length
        raw_data.append(&mut request.get_authenticator().to_vec());  // Append request authenticator 
        raw_data.append(&mut reply[20..].to_vec());                  // Append rest of the reply
        raw_data.append(&mut self.secret.as_bytes().to_vec());       // Append secret

        let mut md5_hasher = Md5::new();
        let mut hash       = [0; 16];
        
        md5_hasher.input(&raw_data);
        md5_hasher.result(&mut hash);

        println!("{:?}", &raw_data);
        println!("{:?}", &hash);
        println!("{:?}", &reply[4..20]);

        if hash == reply[4..20] {
            Ok(())
        } else {
            return Err(Error::new(ErrorKind::InvalidData, String::from("Packet authenticator mismatch")));
        }
    }
}
