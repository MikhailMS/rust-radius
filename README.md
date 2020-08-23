# Rust RADIUS 

## Requirements
1. Rust **1.45.2**


## Install
1. `git clone `
2. `cargo build`


## Tests
1. `cargo test`


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
  - [ ] handle auth packet (could be custom, so looks like interface with default impl)
  - [ ] handle acct packet (could be custom, so looks like interface with default impl)
  - [ ] handle coa  packet (could be custom, so looks like interface with default impl)
  - [x] create reply packet
  - [x] run
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
- [ ] add IPv6 to **Vec<u8>** conversion
- [ ] add IPv4 to **Vec<u8>** conversion
- [ ] tests
  - [x] client
  - [x] server
  - [ ] protocol
    - [x] dictionary
    - [ ] radius packet


## Notes
1. Heavily inspired by [pyrad](https://github.com/pyradius/pyrad) and [radius-rust-client](https://github.com/athonet-open/rust-radius-client)
