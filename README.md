[![MIT licensed][mit-badge]][mit-url]
[![Actions Status][action-badge]][action-url]

[action-badge]: https://github.com/MikhailMS/rust-radius/workflows/RustRadius/badge.svg
[action-url]:   https://github.com/MikhailMS/rust-radius/actions
[mit-badge]:    https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]:      LICENSE


# Rust RADIUS 
Pure (as far as this code goes) Rust implementation of RADIUS.
Not all functionality supported yet, but it would be. Eventually

Rationale behind this project:
1. I am getting in love with Rust and would love to use it in my day-to-day job.
2. There are a number of small projects involving RADIUS, where I can start using Rust
3. However there were no good RADIUS implementations in Rust
4. ????
5. Profit - now there is one, so I can try to push Rust internally in my team ^_^


## Usage
1. The crate is not published, so for now use any of the following options:
   - `git clone` & In your **Cargo.toml** add `radius-rust = { path = "/path/to/radius-rust" }`
   - In your **Cargo.toml** add `radius-rust = { git = "https://github.com/MikhailMS/rust-radius" }`


## Tests
1. `cargo run --example simple_radius_server &` or you can spin up any other RADIUS server of your choice
2. `cargo test --verbose`


## TODO
- [x] Client should be able to
  - [x] create auth  packet
  - [x] create acct  packet
  - [x] create coa   packet
  - [x] send         packet
  - [x] verify reply packet
  - [x] generate hash for message-authenticator
  - [x] verify message-authenticator hash
- [x] Server
  - [x] handle auth packet
  - [x] handle acct packet
  - [x] handle coa  packet
  - [x] create reply packet
  - [x] run
  - [x] find a way to keep **initialise_server, add_allowed_hosts, run_server, create_reply_authenticator** functions as is, BUT allow users to implement custom **handle_auth_request, handle_acct_request, handle_coa_request** functions
- [ ] Protocol
  - [ ] dictionary
    - [x] dictionary attribute struct
    - [x] dictionary struct
    - [x] parse dictionary from file
    - [ ] parse dictionary from string
  - [x] radius attribute 
    - [x] contains attribute ID and attribute value
    - [x] converts itself into bytes
  - [x] radius packet
    - [x] accepts  radius attributes
    - [x] converts itself into bytes
    - [x] packet verification
      - [x] verify that incoming attributes exist in server/client dictionary, otherwise reject/ignore the packet
      - [x] verify that incoming attributes of the correct data type,          otherwise reject/ignore the packet
        - [x] add SupportedAttributeType enum that holds all RADIUS data types currently supported
        - [x] add verification for all currently supported types **Note2**
- [ ] Tools
  - [x] add **IPv6**    to **Vec<u8>** conversion
  - [ ] add **Vec<u8>** to **IPv6**    conversion
  - [x] add **IPv4**    to **Vec<u8>** conversion
  - [x] add **Vec<u8>** to **IPv4**    conversion
  - [x] add **Integer** to **Vec<u8>** conversion
  - [x] add **Vec<u8>** to **Integer** conversion
  - [x] add **Date**    to **Vec<u8>** conversion
  - [x] add **Vec<u8>** to **Date**    conversion
  - [x] encrypt password
  - [x] decrypt password
- [x] tests
  - [x] client
  - [x] server
  - [x] protocol
    - [x] dictionary
    - [x] radius attribute
    - [x] radius packet
- [ ] review the code to ensure there are no unnecessary allocations, redundant code and etc:
  - [x] redesign **Host** (atm it only serves to map TypeCode to port value)
    - [x] would have **get_dictionary_attribute_by_id** function, that returns reference to **DictionaryAttribute** so we can get SupportedAttributeType value to make type verification
    - [x] bring all shared functions that currently defined in Client & Server
  - [x] **Client** should have a method(s) **create_attribute_by...** so it is inline with **Server**
  - [ ] redesign `run_server()` function (if that's possible)
  - [x] redesign `send_*()`     function - it would try to bind to socket on each function call
  - [x] better error handling - at the moment there is no standard to errors from different modules, so need to have a look into it (`https://nick.groenen.me/posts/rust-error-handling/`)
  - [x] **example/simple_radius_server.rs** -> handle Result better than `.unwrap()`
  - [x] pass **Dictionary** to **Host** instead of **&Dictionary**
  - [ ] check that it is well written


## Notes
1. Big thanks to [pyrad](https://github.com/pyradius/pyrad) and [radius-rust-client](https://github.com/athonet-open/rust-radius-client) projects, which helped me to start this project
2. Value of **Message-Authenticator** RadiusAttribute won't be validated, because in RADIUS dictionary it has **string** type, however it is not valid ASCII string (**Message-Authenticator** is a HMAC-MD5 hash)
