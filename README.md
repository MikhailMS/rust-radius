[![MIT licensed][mit-badge]][mit-url]
[![Actions Status][action-badge]][action-url]

[action-badge]: https://github.com/MikhailMS/rust-radius/workflows/RustRadius/badge.svg
[action-url]:   https://github.com/MikhailMS/rust-radius/actions
[mit-badge]:    https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]:      LICENSE


# Rust RADIUS 
Pure (as far as this code goes) implementation of RADIUS in Rust


Rationale behind this project:
1. I am getting in love with Rust and would love to use it in my day-to-day job.
2. There are a number of small projects involving RADIUS, where I can start using Rust
3. However there were no good RADIUS implementations in Rust
4. ????
5. Profit - now there is one, so I can try to push Rust internally in my team ^_^


## Usage
1. The crate is not published, so for now you can:
   - Add `radius-rust = { git = "https://github.com/MikhailMS/rust-radius" }` to your **Cargo.toml** and that's it


## Tests
1. `cargo run --example simple_radius_server &` or you can spin up any other RADIUS server of your choice
2. `cargo test --verbose`


## TODO
- [ ] Protocol
  - [ ] dictionary
    - [x] dictionary attribute struct
    - [x] dictionary struct
    - [x] parse dictionary from file
    - [ ] parse dictionary from string
- [ ] review the code to ensure there are no unnecessary allocations, redundant code and etc:
  - [ ] redesign `run_server()` function (if that's possible)
  - [ ] check that it is well written


## Notes
1. Main core functionality is completed, but there is a chance that I've missed something here and there because it is not needed for my projects yet. If this is the case, raise an issue and I'll see what could be done to get it resolved
2. Big thanks to [pyrad](https://github.com/pyradius/pyrad) and [radius-rust-client](https://github.com/athonet-open/rust-radius-client) projects, which helped me to start this project
3. Value of **Message-Authenticator** RadiusAttribute won't be validated, because in RADIUS dictionary it has **string** type, however it is not valid ASCII string (**Message-Authenticator** is a HMAC-MD5 hash)
