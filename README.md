[![MIT licensed][mit-badge]][mit-url]
[![Actions Status][action-badge]][action-url]
[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]


[action-badge]: https://github.com/MikhailMS/rust-radius/workflows/RustRadius/badge.svg
[action-url]:   https://github.com/MikhailMS/rust-radius/actions
[crates-badge]: https://img.shields.io/crates/v/radius-rust.svg
[crates-url]:   https://crates.io/crates/radius-rust
[docs-badge]:   https://docs.rs/radius-rust/badge.svg
[docs-url]:     https://docs.rs/radius-rust
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


## Installation
```
[dependencies]
radius-rust = "0.2.1"

OR if you need Async RADIUS Client/Server

[dependencies]
radius-rust = { version = "0.2.1", features = ["async-radius"] }

OR

[dependencies]
radius-rust = { git = "https://github.com/MikhailMS/rust-radius" }
```


## Tests
1. `cargo run --example simple_radius_server &` or you can spin up any other RADIUS server of your choice
2. `cargo test --verbose`


## TODO
- [x] Maybe it is worth adding [async_std](https://github.com/async-rs/async-std) for RADIUS Client?                      **Part of prob_add_async_std feature**
- [x] Maybe it is worth adding [async_std](https://github.com/async-rs/async-std) for RADIUS Server?                      **Part of prob_add_async_std feature**
- [ ] Read up on [Rust API Guidelines](https://rust-lang.github.io/api-guidelines) and implement whatever possible        **Part of prob_add_async_std feature**
- [x] If `async_std` is to be added, ensure it is disabled by default and requires cargo feature option to become enabled **Part of prob_add_async_std feature**
- [ ] Review RADIUS code to ensure:
  - [ ] RADIUS Sync Server has builder pattern for creation (possibly this way we can make it more dynamic, ie can only have single socket if others aren't required)
  - [ ] RADIUS Async Server is similar to Sync Server in a way that it also has only core functionality defined, rest goes into `AsyncServer` trait
  - [ ] RADIUS Client has builder pattern for creation (possibly this way we can make it more dynamic, ie can only have single socket if others aren't required)
  - [ ] RADIUS Sync Client is similar to Sync Server in a way that it also has only core functionality defined, rest goes into `SyncClient` trait
  - [ ] RADIUS Async Client is similar to Sync Server in a way that it also has only core functionality defined, rest goes into `AsyncClient` trait
  - [ ] Review RADIUS client implementations (in case I can improve Socket binding, because atm socket binds on each call to **send_*()** function)
    - [ ] RADIUS Client       implementation
    - [ ] Async RADIUS Client implementation
- [ ] Review the code to ensure there are no unnecessary allocations, redundant code and etc:
  - [ ] redesign `run_server()` function for RADIUS Server (if that's possible) (looks like would be a part of refactoring to enable traits)
  - [ ] check that it is well written (fingers crossed for a code review)
- [ ] Protocol
  - [ ] dictionary
    - [x] dictionary attribute struct
    - [x] dictionary struct
    - [x] parse dictionary from file
    - [ ] parse dictionary from string


## Benchmarks
1. RADIUS Client       against RADIUS Server
```
test test_acct_client_w_response_against_server  ... bench:     164,113 ns/iter (+/- 147,270)
test test_acct_client_wo_response_against_server ... bench:     151,562 ns/iter (+/- 75,603)
test test_auth_client_w_response_against_server  ... bench:     321,856 ns/iter (+/- 62,515)
test test_auth_client_wo_response_against_server ... bench:     154,482 ns/iter (+/- 37,838)
test test_coa_client_w_response_against_server   ... bench:     290,571 ns/iter (+/- 77,585)
test test_coa_client_wo_response_against_server  ... bench:     406,400 ns/iter (+/- 78,116)
```
2. Mutex RADIUS Client against RADIUS Server
```
test test_mutex_acct_client_w_response_against_server  ... bench:     205,098 ns/iter (+/- 3,337)
test test_mutex_acct_client_wo_response_against_server ... bench:     208,970 ns/iter (+/- 6,541)
test test_mutex_auth_client_w_response_against_server  ... bench:      87,672 ns/iter (+/- 3,280)
test test_mutex_auth_client_wo_response_against_server ... bench:      87,312 ns/iter (+/- 4,286)
test test_mutex_coa_client_w_response_against_server   ... bench:      56,014 ns/iter (+/- 2,345)
test test_mutex_coa_client_wo_response_against_server  ... bench:      55,938 ns/iter (+/- 1,741)
```
3. Async RADIUS Client against RADIUS Server
```
test test_async_acct_client_w_response_against_server  ... bench:     114,350 ns/iter (+/- 38,509)
test test_async_acct_client_wo_response_against_server ... bench:     227,224 ns/iter (+/- 165,856)
test test_async_auth_client_w_response_against_server  ... bench:     192,181 ns/iter (+/- 54,271)
test test_async_auth_client_wo_response_against_server ... bench:     178,511 ns/iter (+/- 73,771)
test test_async_coa_client_w_response_against_server   ... bench:     314,094 ns/iter (+/- 138,657)
test test_async_coa_client_wo_response_against_server  ... bench:     169,961 ns/iter (+/- 42,073)
```
4. RADIUS Client       against Async RADIUS Server
```

```
5. Mutex RADIUS Client against Async RADIUS Server
```

```
6. Async RADIUS Client against Async RADIUS Server
```

```


## Notes
1. Main core functionality is completed, but there is a chance that I've missed something here and there because it is not needed for my projects yet. If this is the case, **raise an issue and I'll see what could be done to get it resolved**
2. Minimum required version of Rust:
    1. `1.43.0` if you want to use `async-radius` feature
    2. `1.42.0` if you want to use `default`      feature
3. Big thanks to [pyrad](https://github.com/pyradius/pyrad) and [radius-rust-client](https://github.com/athonet-open/rust-radius-client) projects, which helped me to start this project
4. Value of **Message-Authenticator** RadiusAttribute won't be validated, because in RADIUS dictionary it has **string** type, however it is not valid ASCII string (**Message-Authenticator** is a HMAC-MD5 hash)
5. **Benchmarks** are
    1. Run locally on *Mac Mini (2018, RAM: 32 GB 2667 MHz DDR4, CPU: 3.2 GHz Intel Core i7)*
    2. Present here only as a comparison between different RADIUS Client/Server implementations, that crate offers (basically just for myself to see if it worth adding features like async and etc)
