use radius_rust::protocol::dictionary::Dictionary;
use radius_rust::server::Server;


#[test]
fn test_server() {
    let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
    let mut server = Server::initialise_server(1812, 1813, 3799, &dictionary, String::from("127.0.0.1"), String::from("secret"), 1, 2).unwrap();

    server.add_allowed_hosts(String::from("127.0.0.1"));

    match server.run_server() {
        Err(error) => {
            println!("{:?}", error);
            assert!(false)
        },
        _ => assert!(true)
    }
}
