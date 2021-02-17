use radius_rust::client::mutex_client::Client;
use radius_rust::protocol::dictionary::Dictionary;
use radius_rust::tools::{ integer_to_bytes, ipv4_string_to_bytes};


// Test Mutex RadiusClient
#[test]
fn test_mutex_client_auth_request() {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let client     = Client::initialise_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

    let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10").unwrap();
    let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100").unwrap();


    let attributes = vec![
        client.create_attribute_by_name("User-Name",          String::from("testing").into_bytes()).unwrap(),
        client.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes).unwrap(),
        client.create_attribute_by_name("NAS-Port-Id",        integer_to_bytes(0)).unwrap(),
        client.create_attribute_by_name("Service-Type",       integer_to_bytes(2)).unwrap(),
        client.create_attribute_by_name("NAS-Identifier",     String::from("trillian").into_bytes()).unwrap(),
        client.create_attribute_by_name("Called-Station-Id",  String::from("00-04-5F-00-0F-D1").into_bytes()).unwrap(),
        client.create_attribute_by_name("Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
        client.create_attribute_by_name("Framed-IP-Address",  framed_ip_addr_bytes).unwrap()
    ];
    
    let mut auth_packet = client.create_auth_packet(attributes);

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
fn test_mutex_client_acct_request() {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let client     = Client::initialise_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

    let nas_ip_addr_bytes    = ipv4_string_to_bytes("192.168.1.10").unwrap();
    let framed_ip_addr_bytes = ipv4_string_to_bytes("10.0.0.100").unwrap();

    let attributes = vec![
        client.create_attribute_by_name("User-Name",          String::from("testing").into_bytes()).unwrap(),
        client.create_attribute_by_name("NAS-IP-Address",     nas_ip_addr_bytes).unwrap(),
        client.create_attribute_by_name("NAS-Port-Id",        integer_to_bytes(0)).unwrap(),
        client.create_attribute_by_name("NAS-Identifier",     String::from("trillian").into_bytes()).unwrap(),
        client.create_attribute_by_name("Called-Station-Id",  String::from("00-04-5F-00-0F-D1").into_bytes()).unwrap(),
        client.create_attribute_by_name("Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
        client.create_attribute_by_name("Framed-IP-Address",  framed_ip_addr_bytes).unwrap()
    ];
    let mut acct_packet = client.create_acct_packet(attributes);

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
fn test_mutex_client_coa_request() {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let client     = Client::initialise_client(1812, 1813, 3799, dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

    let attributes = vec![
        client.create_attribute_by_name("User-Name",          String::from("testing").into_bytes()).unwrap(),
        client.create_attribute_by_name("Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
    ];
    
    let mut coa_packet = client.create_coa_packet(attributes);

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
