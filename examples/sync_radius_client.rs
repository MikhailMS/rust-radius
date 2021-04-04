//! An example on how to create Sync RADIUS Client from generic RADIUS Client which is provided in
//! this crate
//!
//! ```bash
//! cargo run --example sync_radius_client
//! ```


use radius_rust::client::{ client::Client, SyncClientTrait };
use radius_rust::protocol::dictionary::Dictionary;
use radius_rust::protocol::error::RadiusError;
use radius_rust::protocol::radius_packet::{ RadiusPacket, RadiusMsgType };
use radius_rust::tools::{ ipv4_string_to_bytes, integer_to_bytes };

use log::{ debug, LevelFilter };
use mio::net::UdpSocket;
use mio::{ Events, Interest, Poll, Token };
use simple_logger::SimpleLogger;
use std::io::{Error, ErrorKind};
use std::time::Duration;

struct ClientWrapper {
    base_client: Client,
    socket_poll: Poll,
    socket:      UdpSocket
}

impl ClientWrapper {
    const TOKEN: Token = Token(0);

    fn initialise_client(auth_port: u16, dictionary: Dictionary, server: String, secret: String, retries: u16, timeout: u16) -> Result<ClientWrapper, RadiusError> {
        // Bind socket
        let local_bind  = "0.0.0.0:0".parse().map_err(|error| RadiusError::SocketAddrParseError(error))?;
        let mut socket  = UdpSocket::bind(local_bind).map_err(|error| RadiusError::SocketConnectionError(error))?;
        let socket_poll = Poll::new()?;

        socket_poll.registry().register(&mut socket, Token(0), Interest::READABLE).map_err(|error| RadiusError::SocketConnectionError(error))?;
        // --------------------
        
       let client = Client::with_dictionary(dictionary)
            .set_server(server)
            .set_secret(secret)
            .set_retries(retries)
            .set_timeout(timeout)
            .set_port(RadiusMsgType::AUTH, auth_port)
            .build_client();

        Ok(ClientWrapper {
            base_client: client,
            socket_poll: socket_poll,
            socket:      socket
        })
    }
}

impl SyncClientTrait for ClientWrapper {
    fn send_packet(&mut self, packet: &mut RadiusPacket) -> Result<(), RadiusError> {
        let remote_port = self.base_client.port(packet.code()).ok_or_else(|| RadiusError::MalformedPacketError { error: String::from("There is no port match for packet code") })?;
        let remote      = format!("{}:{}", &self.base_client.server(), remote_port).parse().map_err(|error| RadiusError::SocketAddrParseError(error))?;
        let timeout     = Duration::from_secs(self.base_client.timeout() as u64);
        let mut events  = Events::with_capacity(1024);
        let mut retry   = 0;
        
        loop {
            if retry >= self.base_client.retries() {
                break;
            }
            debug!("Sending: {:?}", &packet.to_bytes());
            self.socket.send_to(&packet.to_bytes(), remote).map_err(|error| RadiusError::SocketConnectionError(error))?;
            self.socket_poll.poll(&mut events, Some(timeout)).map_err(|error| RadiusError::SocketConnectionError(error))?;

            for event in events.iter() {
                match event.token() {
                    ClientWrapper::TOKEN => {
                        let mut response = [0; 4096];
                        let amount = self.socket.recv(&mut response).map_err(|error| RadiusError::SocketConnectionError(error))?;

                        if amount > 0 {
                            debug!("Received reply: {:?}", &response[0..amount]);
                            return Ok(());
                        }
                    },
                    _ => return Err( RadiusError::SocketInvalidConnectionError { error: String::from("Received data from invalid Token") } ),
                }
            }
            retry += 1;
        }
        Err( RadiusError::SocketConnectionError(Error::new(ErrorKind::TimedOut, "")) )
    }
}


fn main() -> Result<(), RadiusError> {
    SimpleLogger::new().with_level(LevelFilter::Debug).init().expect("Failed to create new logger");
    debug!("RADIUS Client started");
    
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict")?;
    let mut client = ClientWrapper::initialise_client(1812, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2)?;

    let user_name            = String::from("testing").into_bytes();
    let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10")?;
    let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100")?;
    let nas_id               = String::from("trillian").into_bytes();
    let called_station_id    = String::from("00-04-5F-00-0F-D1").into_bytes();
    let calling_station_id   = String::from("00-01-24-80-B3-9C").into_bytes();

    let attributes = vec![
        client.base_client.create_attribute_by_name("User-Name",          user_name)?,
        client.base_client.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes)?,
        client.base_client.create_attribute_by_name("NAS-Port-Id",        integer_to_bytes(0))?,
        client.base_client.create_attribute_by_name("Service-Type",       integer_to_bytes(2))?,
        client.base_client.create_attribute_by_name("NAS-Identifier",     nas_id)?,
        client.base_client.create_attribute_by_name("Called-Station-Id",  called_station_id)?,
        client.base_client.create_attribute_by_name("Calling-Station-Id", calling_station_id)?,
        client.base_client.create_attribute_by_name("Framed-IP-Address",  framed_ip_addr_bytes)?
    ];
    
    let mut auth_packet = client.base_client.create_auth_packet(attributes);

    match client.send_packet(&mut auth_packet) {
        Err(error) => {
            println!("{:?}", error);
        },
        Ok(()) => {
            println!("{:?}", &auth_packet);
        }
    }

    debug!("RADIUS Client stopped");
    Ok(())
}
