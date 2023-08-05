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
radius-rust = "0.4.2"

OR if you are planning to build Async RADIUS Client/Server

[dependencies]
radius-rust = { version = "0.4.2", features = ["async-radius"] }
```


## Tests
1. Project has some tests, that require RADIUS Server running, so:
    1. `cargo run --example sync_radius_server &` OR
    2. `cargo run --example async_radius_server --all-features &` OR
    3. You can spin up any other RADIUS server of your choice
2. `cargo test --verbose` or `cargo test --all-features --verbose`


## Contributing
Would you love to contribute to this project? I'd really appreciate your input!

1. Raise an issue, if you believe some functionality is missing, something is broken and etc
2. Create a PR, if you already sorted out some issues yourself. **Please ensure** to submit PR to **development branch**


## Minimum Supported Version of Rust (MSVR)
As far as I can tell from Github Action
1. `1.43.0` when you use `default` feature (sync only)
2. `1.46.0` when you use `async-radius` feature (async & sync)

Prior to 18/09/2021 MSVR was:
1. `1.42.0` when you use `default` feature (sync only)
2. `1.43.0` when you use `async-radius` feature (async & sync)
so there is a chance everything would be working for you and it just Github Action having some issues


## Benchmarks
1. To run benchmarks, you need to have RADIUS Server running, so
    1. `cargo run --example sync_radius_server &` OR
    2. `cargo run --example async_radius_server --all-features &`
2. Then run `cargo +nightly bench` or `cargo +nightly bench --all-features`
3. Run locally on *Mac Mini (2018, RAM: 32 GB 2667 MHz DDR4, CPU: 3.2 GHz Intel Core i7)*
4. Present here only as a comparison between different RADIUS Client/Server implementations, that crate offers (basically just for myself to see if it worth adding features like async and etc)
5. Results:
```
1. RADIUS Client       against RADIUS Server
test test_acct_client_w_response_against_server        ... bench:     106,383 ns/iter (+/- 4,014)
test test_acct_client_wo_response_against_server       ... bench:     106,075 ns/iter (+/- 10,151)
test test_auth_client_w_response_against_server        ... bench:     100,156 ns/iter (+/- 5,719)
test test_auth_client_wo_response_against_server       ... bench:     100,470 ns/iter (+/- 4,690)
test test_coa_client_w_response_against_server         ... bench:      79,086 ns/iter (+/- 37,158)
test test_coa_client_wo_response_against_server        ... bench:      78,813 ns/iter (+/- 6,330)
``` 
```
2. Async RADIUS Client against RADIUS Server
test test_async_acct_client_w_response_against_server  ... bench:     120,529 ns/iter (+/- 6,305)
test test_async_acct_client_wo_response_against_server ... bench:     120,881 ns/iter (+/- 5,505)
test test_async_auth_client_w_response_against_server  ... bench:     113,678 ns/iter (+/- 6,219)
test test_async_auth_client_wo_response_against_server ... bench:     113,324 ns/iter (+/- 8,135)
test test_async_coa_client_w_response_against_server   ... bench:      93,113 ns/iter (+/- 12,394)
test test_async_coa_client_wo_response_against_server  ... bench:      92,298 ns/iter (+/- 10,021)
```
```
3. RADIUS Client       against Async RADIUS Server
test test_acct_client_w_response_against_server        ... bench:     116,303 ns/iter (+/- 22,485)
test test_acct_client_wo_response_against_server       ... bench:     115,774 ns/iter (+/- 5,040)
test test_auth_client_w_response_against_server        ... bench:     110,263 ns/iter (+/- 4,067)
test test_auth_client_wo_response_against_server       ... bench:     109,771 ns/iter (+/- 3,831)
test test_coa_client_w_response_against_server         ... bench:      87,650 ns/iter (+/- 25,813)
test test_coa_client_wo_response_against_server        ... bench:      84,563 ns/iter (+/- 2,856)
```
```
4. Async RADIUS Client against Async RADIUS Server
test test_async_acct_client_w_response_against_server  ... bench:     129,056 ns/iter (+/- 6,221)
test test_async_acct_client_wo_response_against_server ... bench:     127,969 ns/iter (+/- 7,174)
test test_async_auth_client_w_response_against_server  ... bench:     127,812 ns/iter (+/- 37,821)
test test_async_auth_client_wo_response_against_server ... bench:     124,807 ns/iter (+/- 12,565)
test test_async_coa_client_w_response_against_server   ... bench:      96,329 ns/iter (+/- 6,898)
test test_async_coa_client_wo_response_against_server  ... bench:      97,011 ns/iter (+/- 10,322)
```


## Notes
1. All works happens on **development** branch, so if you feel that project is abandoned, check out **development** branch or raise an issue
2. Main core functionality is completed, but there is a chance that I've missed something here and there because it is not needed for my projects yet. **If this is the case, raise an issue or PR and I'll see what could be done to get it resolved**
3. Big thanks to [pyrad](https://github.com/pyradius/pyrad) and [radius-rust-client](https://github.com/athonet-open/rust-radius-client) projects, which helped me to start this project
4. Value of **Message-Authenticator** RadiusAttribute won't be validated, because in RADIUS dictionary it has **string** type, however it is not valid ASCII string (**Message-Authenticator** is a HMAC-MD5 hash)
