//! An example on how to create Async RADIUS Client from generic RADIUS Client which is provided in
//! this crate
//!
//! ```bash
//! cargo run --example async_radius_client --all-features
//! ```


use radius_rust::client::{ client::Client, AsyncClientTrait };
use radius_rust::protocol::dictionary::Dictionary;
use radius_rust::protocol::error::RadiusError;
use radius_rust::protocol::radius_packet::{ RadiusPacket, RadiusMsgType };
use radius_rust::tools::{ ipv4_string_to_bytes, integer_to_bytes };

use async_std::net::UdpSocket;
use async_std::task;
use async_trait::async_trait;
use log::{ debug, LevelFilter };
use simple_logger::SimpleLogger;
use std::io::{Error, ErrorKind};


struct ClientWrapper {
    base_client: Client,
    socket:      UdpSocket
}

impl ClientWrapper {
    async fn initialise_client(auth_port: u16, dictionary: Dictionary, server: String, secret: String, retries: u16, timeout: u16) -> Result<ClientWrapper, RadiusError> {
        // Bind socket
        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|error| RadiusError::SocketConnectionError(error))?;
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
            socket:      socket
        })
    }
}

#[async_trait]
impl AsyncClientTrait for ClientWrapper {
    async fn send_packet(&self, packet: &mut RadiusPacket) -> Result<(), RadiusError> {
        let remote_port = self.base_client.port(packet.code()).ok_or_else(|| RadiusError::MalformedPacketError { error: String::from("There is no port match for packet code") })?;
        let remote      = format!("{}:{}", &self.base_client.server(), remote_port);
        let mut retry   = 0;
        
        loop {
            if retry >= self.base_client.retries() {
                break;
            }

            debug!("Sending: {:?}", &packet.to_bytes());
            self.socket.send_to(&packet.to_bytes(), &remote).await.map_err(|error| RadiusError::SocketConnectionError(error))?;

            let mut response = [0; 4096];
            let (amount, _)  = self.socket.recv_from(&mut response).await.map_err(|error| RadiusError::SocketConnectionError(error))?;

            if amount > 0 {
                debug!("Received reply: {:?}", &response[0..amount]);
                return Ok(())
            }

            retry += 1;
        }
        Err( RadiusError::SocketConnectionError(Error::new(ErrorKind::TimedOut, "")) )
    }
}


fn main() -> Result<(), RadiusError> {
    SimpleLogger::new().with_level(LevelFilter::Debug).init().expect("Failed to create new logger");
    debug!("Async RADIUS Client started");
    
    task::block_on(async {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict")?;
        let client     = ClientWrapper::initialise_client(1812, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).await?;

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

        match client.send_packet(&mut auth_packet).await {
            Err(error) => {
                println!("{:?}", error);
            },
            Ok(()) => {
                println!("{:?}", &auth_packet);
            }
        }

        debug!("Async RADIUS Client finished");

        Ok(())
    })
}
