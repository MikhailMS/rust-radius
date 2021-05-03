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
radius-rust = "0.3.0"

OR if you are planning to build Async RADIUS Client/Server

[dependencies]
radius-rust = { version = "0.3.0", features = ["async-radius"] }
```


## Tests
1. `cargo run --example sync_radius_server &` or you can spin up any other RADIUS server of your choice
2. `cargo test --verbose`
2. `cargo test --all-features --verbose`


## TODO
- [ ] Read up on [Rust API Guidelines](https://rust-lang.github.io/api-guidelines) and implement whatever possible
- [ ] Review the code to ensure there are no unnecessary allocations, redundant code and etc:
  - [ ] check that it is well written (fingers crossed for a code review)
- [ ] Protocol
  - [ ] parse dictionary from string


## Contributing
Would you love to contribute to this project? I'd really appreciate your input!

1. Raise an issue, if you believe some functionality is missing, something is broken and etc
2. Create a PR, if you already sorted out some issues yourself. **Please ensure** to submit PR to **development branch**


## Benchmarks
1. RADIUS Client       against RADIUS Server
```
test test_acct_client_w_response_against_server        ... bench:     106,383 ns/iter (+/- 4,014)
test test_acct_client_wo_response_against_server       ... bench:     106,075 ns/iter (+/- 10,151)
test test_auth_client_w_response_against_server        ... bench:     100,156 ns/iter (+/- 5,719)
test test_auth_client_wo_response_against_server       ... bench:     100,470 ns/iter (+/- 4,690)
test test_coa_client_w_response_against_server         ... bench:      79,086 ns/iter (+/- 37,158)
test test_coa_client_wo_response_against_server        ... bench:      78,813 ns/iter (+/- 6,330)
```
2. Async RADIUS Client against RADIUS Server
```
test test_async_acct_client_w_response_against_server  ... bench:     120,529 ns/iter (+/- 6,305)
test test_async_acct_client_wo_response_against_server ... bench:     120,881 ns/iter (+/- 5,505)
test test_async_auth_client_w_response_against_server  ... bench:     113,678 ns/iter (+/- 6,219)
test test_async_auth_client_wo_response_against_server ... bench:     113,324 ns/iter (+/- 8,135)
test test_async_coa_client_w_response_against_server   ... bench:      93,113 ns/iter (+/- 12,394)
test test_async_coa_client_wo_response_against_server  ... bench:      92,298 ns/iter (+/- 10,021)
```
3. RADIUS Client       against Async RADIUS Server
```
test test_acct_client_w_response_against_server        ... bench:     116,303 ns/iter (+/- 22,485)
test test_acct_client_wo_response_against_server       ... bench:     115,774 ns/iter (+/- 5,040)
test test_auth_client_w_response_against_server        ... bench:     110,263 ns/iter (+/- 4,067)
test test_auth_client_wo_response_against_server       ... bench:     109,771 ns/iter (+/- 3,831)
test test_coa_client_w_response_against_server         ... bench:      87,650 ns/iter (+/- 25,813)
test test_coa_client_wo_response_against_server        ... bench:      84,563 ns/iter (+/- 2,856)
```
4. Async RADIUS Client against Async RADIUS Server
```
test test_async_acct_client_w_response_against_server  ... bench:     129,056 ns/iter (+/- 6,221)
test test_async_acct_client_wo_response_against_server ... bench:     127,969 ns/iter (+/- 7,174)
test test_async_auth_client_w_response_against_server  ... bench:     127,812 ns/iter (+/- 37,821)
test test_async_auth_client_wo_response_against_server ... bench:     124,807 ns/iter (+/- 12,565)
test test_async_coa_client_w_response_against_server   ... bench:      96,329 ns/iter (+/- 6,898)
test test_async_coa_client_wo_response_against_server  ... bench:      97,011 ns/iter (+/- 10,322)
```


## Notes
1. All dev works happens on **development** branch, so if you feel that project is abandoned, check out **development** branch or raise an issue
2. Main core functionality is completed, but there is a chance that I've missed something here and there because it is not needed for my projects yet. **If this is the case, raise an issue or PR and I'll see what could be done to get it resolved**
3. Minimum required version of Rust:
    1. `1.43.0` if you want to use `async-radius` feature
    2. `1.42.0` if you want to use `default`      feature
4. Big thanks to [pyrad](https://github.com/pyradius/pyrad) and [radius-rust-client](https://github.com/athonet-open/rust-radius-client) projects, which helped me to start this project
5. Value of **Message-Authenticator** RadiusAttribute won't be validated, because in RADIUS dictionary it has **string** type, however it is not valid ASCII string (**Message-Authenticator** is a HMAC-MD5 hash)
6. **Benchmarks** are
    1. Run locally on *Mac Mini (2018, RAM: 32 GB 2667 MHz DDR4, CPU: 3.2 GHz Intel Core i7)*
    2. Present here only as a comparison between different RADIUS Client/Server implementations, that crate offers (basically just for myself to see if it worth adding features like async and etc)
