=============
# v0.3.0 (Coming soon)

This time round it was decided to add support for async via `async-std` (it looks a bit lighter than `tokio`, but I could be wrong)

## What's new
* Add `async-std` as alternative to `mio`
* There is now Async RADIUS Client implementation
* There is now Async RADIUS Server implementation (work still in progress, imo)
* Add new error - **IncorrrectSourceIpError**, which is thrown in Async RADIUS Server in case when RADIUS Client host is not in *allowed_hosts*
* Add a few more rust versions to Actions pipeline (crate compiles on `1.43.0+` for **async version**, and `1.42.0+` for **sync version**)

## What's removed or deprecated

## What's changed
* Breaking change - **client** module has been renamed into **clients**
* Breaking change - **server** module has been renamed into **servers**
* Breaking change - **RadiusMsgType** code as been moved from **servers** module into **radius_packet** module
* Breaking change - **get** prefix was removed for all functions where it was used before ([C-GETTER Rust convention](https://rust-lang.github.io/api-guidelines/naming.html#c-getter))
* Breaking change - **client** & **server** implementations now require related traits to be implemented. For more information have a look into `examples/`
* All RADIUS defined errors now have *Error* suffix, ie **MalformedPacketError**


=============
# v0.2.1 (17 February 2021)

Last minor release before [publishing](https://crates.io/)

## What's new
* Add `log` crate to handle logs (instead of `println!`)
* Add a few more rust versions to Actions pipeline (crate compiles on `1.45.0+` and `nightly` versions)

## What's removed or deprecated

## What's changed
* Upgrade dependencies so non of them are yanked


=============
# v0.2.0 (12 September 2020)

First proper release with basic functionality in place, so it could be moved into more production-like environments

## What's new
* Add GitHub action, so it checks library against stable/nightly Rust on Linux. Unfortunately macOS isn't nicely supported by GitHub Action, however development is done on macOS and all tests pass
* Message-Authenticator HMAC-MD5 hash generation and verification
* Various RADIUS packet verification methods, ie verify that all received RADIUS attributes match those defined in dictionary file (for the full list refer to docs)
* Various helper methods to ensure data is encoded/decoded correctly, ie convert IPv4/6 to bytes and bytes to IPv4/6 (for the full list, look into `tools` module)
* User-Password now could be encoded/decoded (it is important one, since RADIUS packets are sent in plaintext by default)
* Add tests to ensure the core functionality is covered and all works as expected
* Add custom error struct (with the help of `thiserror` crate). This way, crate users would only need to handle single `RadiusError` error

## What's removed or deprecated 

## What's changed
* Various code refactoring and cleaning
* `Dictionary` is now should be passed to Server/Client, instead of `&Dictionary`
* `simple_radius_server.rs` example now has better error handling (removed all **unwrap** calls)


=============
# v0.1.0 (22 August 2020)

Initial version with limited support - basically a PoC to see, how feasible is to create RADIUS server/client library from scratch.
PoC turned out to be a great starting point for a future development
