use radius_rust::protocol::dictionary::Dictionary;
use radius_rust::protocol::radius_packet::RadiusAttribute;
use radius_rust::client::Client;

#[test]
fn test_client_auth_request() {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let client     = Client::initialise_client(1812, 1813, 3799, &dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

    let attributes = vec![
        RadiusAttribute::create_by_name(&dictionary, "User-Name",          String::from("testing").into_bytes()).unwrap(),
        RadiusAttribute::create_by_name(&dictionary, "NAS-IP-Address",     vec![192, 168, 1, 10]).unwrap(),
        RadiusAttribute::create_by_name(&dictionary, "NAS-Port-Id",        vec![0]).unwrap(),
        RadiusAttribute::create_by_name(&dictionary, "Service-Type",       vec![2]).unwrap(),
        RadiusAttribute::create_by_name(&dictionary, "NAS-Identifier",     String::from("trillian").into_bytes()).unwrap(),
        RadiusAttribute::create_by_name(&dictionary, "Called-Station-Id",  String::from("00-04-5F-00-0F-D1").into_bytes()).unwrap(),
        RadiusAttribute::create_by_name(&dictionary, "Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
        RadiusAttribute::create_by_name(&dictionary, "Framed-IP-Address",  vec![10, 0, 0, 100]).unwrap()
    ];
    
    let mut auth_packet = client.create_auth_packet(attributes);

    match client.send_packet(&mut auth_packet) {
        Err(error) => {
            println!("{:?}", error);
            assert!(false)
        },
        _ => assert!(true)
    }
}

#[test]
fn test_client_acct_request() {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let client     = Client::initialise_client(1812, 1813, 3799, &dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

    let attributes = vec![
        RadiusAttribute::create_by_name(&dictionary, "User-Name",          String::from("testing").into_bytes()).unwrap(),
        RadiusAttribute::create_by_name(&dictionary, "NAS-IP-Address",     vec![192, 168, 1, 10]).unwrap(),
        RadiusAttribute::create_by_name(&dictionary, "NAS-Port-Id",        vec![0]).unwrap(),
        RadiusAttribute::create_by_name(&dictionary, "NAS-Identifier",     String::from("trillian").into_bytes()).unwrap(),
        RadiusAttribute::create_by_name(&dictionary, "Called-Station-Id",  String::from("00-04-5F-00-0F-D1").into_bytes()).unwrap(),
        RadiusAttribute::create_by_name(&dictionary, "Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
        RadiusAttribute::create_by_name(&dictionary, "Framed-IP-Address",  vec![10, 0, 0, 100]).unwrap()
    ];
    let mut acct_packet = client.create_acct_packet(attributes);

    match client.send_packet(&mut acct_packet) {
        Err(error) => {
            println!("{:?}", error);
            assert!(false)
        },
        _ => assert!(true)
    }
}

#[test]
fn test_client_coa_request() {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let client     = Client::initialise_client(1812, 1813, 3799, &dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

    let attributes = vec![
        RadiusAttribute::create_by_name(&dictionary, "User-Name",          String::from("testing").into_bytes()).unwrap(),
        RadiusAttribute::create_by_name(&dictionary, "Calling-Station-Id", String::from("00-01-24-80-B3-9C").into_bytes()).unwrap(),
    ];
    
    let mut coa_packet = client.create_coa_packet(attributes);

    match client.send_packet(&mut coa_packet) {
        Err(error) => {
            println!("{:?}", error);
            assert!(false)
        },
        _ => assert!(true)
    }
}


#[test]
fn test_radius_attribute_create() {
    let expected_attr = RadiusAttribute::create_by_id(4,  vec![172, 25, 0, 2]).unwrap();

    let dictionary  = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let tested_attr = RadiusAttribute::create_by_name(&dictionary, "NAS-IP-Address", vec![172, 25, 0, 2]).unwrap();

    assert_eq!(expected_attr, tested_attr)
}
