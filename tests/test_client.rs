use radius_rust::client::{ client::Client, SyncClientTrait };
use radius_rust::protocol::dictionary::Dictionary;
use radius_rust::protocol::error::RadiusError;
use radius_rust::protocol::radius_packet::{ RadiusPacket, RadiusMsgType };
use radius_rust::tools::{ integer_to_bytes, ipv4_string_to_bytes};

use mio::net::UdpSocket;
use mio::{ Events, Interest, Poll, Token };
use std::io::{Error, ErrorKind};
use std::time::Duration;


struct ClientWrapper {
    base_client: Client,
    socket_poll: Poll,
    socket:      UdpSocket
}

impl ClientWrapper {
    const TOKEN: Token = Token(0);

    fn initialise_client(auth_port: u16, acct_port: u16, coa_port: u16, dictionary: Dictionary, server: String, secret: String, retries: u16, timeout: u16) -> Result<ClientWrapper, RadiusError> {
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
            .set_port(RadiusMsgType::ACCT, acct_port)
            .set_port(RadiusMsgType::COA,  coa_port);

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
            self.socket.send_to(&packet.to_bytes(), remote).map_err(|error| RadiusError::SocketConnectionError(error))?;
            self.socket_poll.poll(&mut events, Some(timeout)).map_err(|error| RadiusError::SocketConnectionError(error))?;

            for event in events.iter() {
                match event.token() {
                    ClientWrapper::TOKEN => {
                        let mut response = [0; 4096];
                        let amount = self.socket.recv(&mut response).map_err(|error| RadiusError::SocketConnectionError(error))?;

                        if amount > 0 {
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

    fn send_and_receive_packet(&mut self, packet: &mut RadiusPacket) -> Result<Vec<u8>, RadiusError> {
        let remote_port = self.base_client.port(packet.code()).ok_or_else(|| RadiusError::MalformedPacketError { error: String::from("There is no port match for packet code") })?;
        let remote      = format!("{}:{}", &self.base_client.server(), remote_port).parse().map_err(|error| RadiusError::SocketAddrParseError(error))?;
        let timeout     = Duration::from_secs(self.base_client.timeout() as u64);
        let mut events  = Events::with_capacity(1024);
        let mut retry   = 0;

        loop {
            if retry >= self.base_client.retries() {
                break;
            }
            self.socket.send_to(&packet.to_bytes(), remote).map_err(|error| RadiusError::SocketConnectionError(error))?;

            self.socket_poll.poll(&mut events, Some(timeout)).map_err(|error| RadiusError::SocketConnectionError(error))?;

            for event in events.iter() {
                match event.token() {
                    ClientWrapper::TOKEN => {
                        let mut response = [0; 4096];
                        let amount = self.socket.recv(&mut response).map_err(|error| RadiusError::SocketConnectionError(error))?;

                        if amount > 0 {
                            return Ok(response[0..amount].to_vec());
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


// Test Sync RADIUS Client
#[test]
#[cfg_attr(miri, ignore)]
fn test_client_auth_request() {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let mut client = ClientWrapper::initialise_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).expect("Failed to create Client Wrapper");

    let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10").unwrap();
    let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100").unwrap();

    let attributes = vec![
        client.base_client.create_attribute_by_name("User-Name",          String::from("testing").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes).unwrap(),
        client.base_client.create_attribute_by_name("NAS-Port-Id",        integer_to_bytes(0)).unwrap(),
        client.base_client.create_attribute_by_name("Service-Type",       integer_to_bytes(2)).unwrap(),
        client.base_client.create_attribute_by_name("NAS-Identifier",     String::from("trillian").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Called-Station-Id",  String::from("00-04-5F-00-0F-D1").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Framed-IP-Address",  framed_ip_addr_bytes).unwrap()
    ];
    
    let mut auth_packet = client.base_client.create_auth_packet();
    auth_packet.set_attributes(attributes);

    match client.send_packet(&mut auth_packet) {
        Err(error) => {
            println!("{:?}", error);
            assert!(false)
        },
        _ => {
            assert!(true)
        }
    }

    match client.send_and_receive_packet(&mut auth_packet) {
        Err(error) => {
            println!("{:?}", error);
            assert!(false)
        },
        _ => {
            assert!(true)
        }
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn test_client_acct_request() {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let mut client = ClientWrapper::initialise_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).expect("Failed to create Client Wrapper");

    let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10").unwrap();
    let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100").unwrap();

    let attributes = vec![
        client.base_client.create_attribute_by_name("User-Name",          String::from("testing").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes).unwrap(),
        client.base_client.create_attribute_by_name("NAS-Port-Id",        integer_to_bytes(0)).unwrap(),
        client.base_client.create_attribute_by_name("NAS-Identifier",     String::from("trillian").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Called-Station-Id",  String::from("00-04-5F-00-0F-D1").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Framed-IP-Address",  framed_ip_addr_bytes).unwrap()
    ];

    let mut acct_packet = client.base_client.create_acct_packet();
    acct_packet.set_attributes(attributes);

    match client.send_packet(&mut acct_packet) {
        Err(error) => {
            println!("{:?}", error);
            assert!(false)
        },
        _ => {
            assert!(true)
        }
    }

    match client.send_and_receive_packet(&mut acct_packet) {
        Err(error) => {
            println!("{:?}", error);
            assert!(false)
        },
        _ => {
            assert!(true)
        }
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn test_client_coa_request() {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let mut client = ClientWrapper::initialise_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).expect("Failed to create Client Wrapper");

    let attributes = vec![
        client.base_client.create_attribute_by_name("User-Name",          String::from("testing").into_bytes()).unwrap(),
        client.base_client.create_attribute_by_name("Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
    ];
    
    let mut coa_packet = client.base_client.create_coa_packet();
    coa_packet.set_attributes(attributes);

    match client.send_packet(&mut coa_packet) {
        Err(error) => {
            println!("{:?}", error);
            assert!(false)
        },
        _ => {
            assert!(true)
        }
    }

    match client.send_and_receive_packet(&mut coa_packet) {
        Err(error) => {
            println!("{:?}", error);
            assert!(false)
        },
        _ => {
            assert!(true)
        }
    }
}
// ------------------------
