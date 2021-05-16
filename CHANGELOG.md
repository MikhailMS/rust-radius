=============
# v0.4.0 (16 May 2021)

Got a couple of PRs & issues raised with some of them introducing breaking changes(read details below), so had to increase minor version to reflect that

## What's new
* Added a few more tests for **encrypt_data()** & **decrypt_data()** (thanks to Istvan91 [!2](/../../pull/2))
* Added **salt_encrypt_data()** & **salt_decrypt_data()** functions, which are handling salting (thanks to Istvan91 [!3](/../../pull/3))

## What's removed or deprecated

## What's changed
* Breaking change - Changed **encrypt_data()** function signature, so **data** parameter is now of type **&[u8]** instead of **&str**. Was reported in [#4](/../../issues/4) by Istvan91
* Breaking change - RADIUS packet creation now doesn't require **Vec<RadiusAttribute>**. To set attributes for packet, call **set_attributes()** function. For examples have a look at **examples/*_client.rs** (Fixes #11)
* Rewrote **encrypt_data()** a bit to remove unneeded allocations (thanks to Istvan91 [!2](/../../pull/2))
* Rewrote **decrypt_data()** a bit to remove unneeded allocations (thanks to Istvan91 [!2](/../../pull/2))


=============
# v0.3.0 (18 April 2021)

I've decided to rewrite previous implementations of RADIUS Client and Server so they are now only have bare minimum in order to allow
users to decide on the crates they want to use to get UdpSockets, async and runtimes

## What's new
* There is now Generic RADIUS Client implementation
* There is now Generic RADIUS Server implementation
* Added SyncClientTrait & AsyncClientTrait
* Added SyncServerTrait & AsyncServerTrait
* Added dependency on `async-trait` crate to allow Async traits
* Add a few more rust versions to Actions pipeline (crate compiles on `1.43.0+` for **async version**, and `1.42.0+` for **sync version**)

## What's removed or deprecated
* `mio` dependency is removed, so user can choose `mio`'s UdpSocket implementation, `async-std` UdpSocket or any other
* Any actual implementations related to UdpSockets and etc have been removed

## What's changed
* Breaking change - **client** module now only has Generic RADIUS Client implementation
* Breaking change - **server** module now only has Generic RADIUS Server implementation
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
