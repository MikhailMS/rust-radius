//! An example on how to use RADIUS AsyncServer
//!
//! To run Async RADIUS Server example
//! ```bash
//! cargo run --example async_radius_server
//! ```


use radius_rust::protocol::dictionary::Dictionary;
use radius_rust::protocol::error::RadiusError;
use radius_rust::protocol::radius_packet::{ RadiusMsgType, TypeCode };
use radius_rust::tools::{ ipv6_string_to_bytes, ipv4_string_to_bytes, integer_to_bytes };
use radius_rust::servers::async_server::{ Server, ServerTrait };

use async_std::task;
use async_trait::async_trait;
use log::{ debug, LevelFilter };
use simple_logger::SimpleLogger;


struct CustomServer {
    base_server: Server
}

impl CustomServer {
    fn initialise_server(auth_port: u16, acct_port: u16, coa_port: u16, dictionary: Dictionary, server: String, secret: String, retries: u16, timeout: u16, allowed_hosts: Vec<String>) -> Result<CustomServer, RadiusError> {
        let server = Server::with_dictionary(dictionary)
            .set_server(server)
            .set_secret(secret)
            .add_protocol_port(RadiusMsgType::AUTH, auth_port)
            .add_protocol_port(RadiusMsgType::ACCT, acct_port)
            .add_protocol_port(RadiusMsgType::COA,  coa_port)
            .set_allowed_hosts(allowed_hosts)
            .set_retries(retries)
            .set_timeout(timeout)
            .build_server()?;
        Ok(
            CustomServer { base_server: server }
        )
    }
}

#[async_trait]
impl ServerTrait for CustomServer {
    async fn run(&mut self) -> Result<(), RadiusError> {
        Ok(())
        // let auth_task = self.handle_auth_request().fuse();
        // let acct_task = self.handle_acct_request().fuse();
        // let coa_task  = self.handle_coa_request().fuse();

        // pin_mut!(auth_task, acct_task, coa_task);

        // select! {
        //     () = auth_task => {},
        //     () = acct_task => {},
        //     () = coa_task => {}
        // }
    }

    // Define your own RADIUS packet handlers
    async fn handle_auth_request(&self, request: &mut [u8]) -> Result<Vec<u8>, RadiusError> {
        Ok(request.to_vec())
    }
    async fn handle_acct_request(&self, request: &mut [u8]) -> Result<Vec<u8>, RadiusError> {
        Ok(request.to_vec())
    }
    async fn handle_coa_request(&self, request: &mut [u8]) -> Result<Vec<u8>, RadiusError> {
        Ok(request.to_vec())
    }
    // ======================
}

// ------------------------

fn main() -> Result<(), RadiusError> {
    SimpleLogger::new().with_level(LevelFilter::Debug).init().expect("Failed to create new logger");
    debug!("Async RADIUS Server started");

    task::block_on(async {
        let dictionary    = Dictionary::from_file("./dict_examples/integration_dict")?;
        let allowed_hosts = vec![String::from("127.0.0.1")];
        let mut server    = CustomServer::initialise_server(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2, allowed_hosts)?;

        server.run().await;
        Ok(())
    })
}
