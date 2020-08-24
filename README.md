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
   - `git clone` & In your **Cargo.toml** add **radius-rust = { path = "/path/to/radius-rust" }**
   - In your **Cargo.toml** add **radius-rust = { git = "https://github.com/MikhailMS/rust-radius" }**


## Tests
1. Client tests relies on the fact, that you do have RADIUS server instance running on **127.0.0.1**, so
   - `cargo run --example simple_radius_server` or use any other implementation of RADIUS server
   - `cargo test`


## TODO
- [x] Client should be able to
  - [x] create auth  packet
  - [x] create acct  packet
  - [x] create coa   packet
  - [x] send         packet
  - [x] verify reply packet
  - [ ] hash password
  - [ ] hash message-authenticator
- [ ] Server
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
    - [x] accepts  radius attributtes
    - [x] converts itself into bytes
- [x] add IPv6         to **Vec<u8>** conversion
- [ ] add  **Vec<u8>** to IPv6        conversion
- [ ] add  IPv4        to **Vec<u8>** conversion
- [ ] add  **Vec<u8>** to IPv4        conversion
- [ ] tests
  - [x] client
  - [ ] server
  - [ ] protocol
    - [x] dictionary
    - [ ] radius packet


## Notes
1. Big thanks to [pyrad](https://github.com/pyradius/pyrad) and [radius-rust-client](https://github.com/athonet-open/rust-radius-client) projects, which helped me to start this project
