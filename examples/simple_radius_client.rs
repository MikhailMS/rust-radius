//! An example on how to use RADIUS Client
//! Contains both Sync & Async RADIUS Server versions
//!
//! To try out Async RADIUS Client example, run
//! ```bash
//! cargo run --example simple_radius_client --all-features
//! ```
//!
//! To try out Sync RADIUS Client example, run
//! ```bash
//! cargo run --example simple_radius_client
//! ```


use radius_rust::protocol::dictionary::Dictionary;
use radius_rust::protocol::error::RadiusError;
use radius_rust::tools::{ ipv4_string_to_bytes, integer_to_bytes };

#[cfg(all(feature = "async-radius"))]
use async_std::task;
#[cfg(all(feature = "async-radius"))]
use radius_rust::clients::async_client::Client;
#[cfg(all(not(feature = "async-radius")))]
use radius_rust::clients::client::Client;


#[cfg(all(feature = "async-radius"))]
fn main() -> Result<(), RadiusError> {
    task::block_on(async {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict")?;
        let client     = Client::initialise_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2)?;

        let user_name            = String::from("testing").into_bytes();
        let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10")?;
        let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100")?;
        let nas_id               = String::from("trillian").into_bytes();
        let called_station_id    = String::from("00-04-5F-00-0F-D1").into_bytes();
        let calling_station_id   = String::from("00-01-24-80-B3-9C").into_bytes();

        let attributes = vec![
            client.create_attribute_by_name("User-Name",          user_name)?,
            client.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes)?,
            client.create_attribute_by_name("NAS-Port-Id",        integer_to_bytes(0))?,
            client.create_attribute_by_name("Service-Type",       integer_to_bytes(2))?,
            client.create_attribute_by_name("NAS-Identifier",     nas_id)?,
            client.create_attribute_by_name("Called-Station-Id",  called_station_id)?,
            client.create_attribute_by_name("Calling-Station-Id", calling_station_id)?,
            client.create_attribute_by_name("Framed-IP-Address",  framed_ip_addr_bytes)?
        ];
        
        let mut auth_packet = client.create_auth_packet(attributes);

        match client.send_and_receive_packet(&mut auth_packet).await {
            Err(error) => {
                println!("{:?}", error);
            },
            Ok(packet) => {
                println!("{:?}", &auth_packet);
                println!("{:?}", &packet);
            }
        }

        Ok(())
    })
}

#[cfg(all(not(feature = "async-radius")))]
fn main() -> Result<(), RadiusError> {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict")?;
    let client     = Client::initialise_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2)?;

    let user_name            = String::from("testing").into_bytes();
    let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10")?;
    let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100")?;
    let nas_id               = String::from("trillian").into_bytes();
    let called_station_id    = String::from("00-04-5F-00-0F-D1").into_bytes();
    let calling_station_id   = String::from("00-01-24-80-B3-9C").into_bytes();

    let attributes = vec![
        client.create_attribute_by_name("User-Name",          user_name)?,
        client.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes)?,
        client.create_attribute_by_name("NAS-Port-Id",        integer_to_bytes(0))?,
        client.create_attribute_by_name("Service-Type",       integer_to_bytes(2))?,
        client.create_attribute_by_name("NAS-Identifier",     nas_id)?,
        client.create_attribute_by_name("Called-Station-Id",  called_station_id)?,
        client.create_attribute_by_name("Calling-Station-Id", calling_station_id)?,
        client.create_attribute_by_name("Framed-IP-Address",  framed_ip_addr_bytes)?
    ];
    
    let mut auth_packet = client.create_auth_packet(attributes);

    match client.send_and_receive_packet(&mut auth_packet) {
        Err(error) => {
            println!("{:?}", error);
        },
        Ok(packet) => {
            println!("{:?}", &auth_packet);
            println!("{:?}", &packet);
        }
    }

    Ok(())
}
