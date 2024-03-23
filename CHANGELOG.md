=============
# v0.4.3 (XX Mar 2024)

This release fixes issue reported in [#28](/../../issues/28) (thanks to CoderChristopher for reporting and suggesting the solution)

## What's new
* Added `1.72.0, 1.72.1,1.73.0, 1.74.0, 1.74.1, 1.75.0, 1.76.0, 1.77.0` Rust versions to Action pipeline

## What's removed or deprecated
* Removed `1.63.0 & 1.64.0` Rust versions from Action pipeline as they were failing to install `cargo-make` (those versions are still supported by library)

## What's changed
* Changed `initialise_packet_from_bytes` function of `radius_packet` to:
    * Handle packets of the length less than 20 or more than 4096 octets - returns `RadiusError` (to comply with [RFC2865](https://datatracker.ietf.org/doc/html/rfc2865))
    * Derive packet length from `RadiusPacket` (Length field) instead of relying on `bytes.len()`
    * If derived packet length is greater than `bytes.len()` - returns `RadiusError` (to comply with [RFC2865](https://datatracker.ietf.org/doc/html/rfc2865))
* Fixed incorrect tests in `protocol/host.rs` (flagged by the changed above)


=============
# v0.4.2 (05 Aug 2023)

This release fixes some outstanding items and, hopefully, makes it's easier to use the library

## What's new
* Add new Error Type to handle exceptions when working with `InterfaceId`
* Add functions to encode to/decode from `InterfaceId` bytes
* Add tests for `InterfaceId` related functions
* Add function to encode to/decode from `Integer64` bytes
* Add tests for `Integer64` related functions
* Add `original_integer64_value` function to retrieve `Integer64` value from `RadiusAttribute`

## What's removed or deprecated
* `timestamp_to_bytes` function for `u64` is substituted with `u32` (see section below)
* Remove validation in `verify_original_value` for `ByteString` & `Concat` because it is not really possible to validate those values once received

## What's changed
* Closes [#17](/../../issues/17)
* Fix for `timestamp_to_bytes` function - it was incorrectly expecting `u64` while RADIUS expects timestamps to be `u32`
* `verify_original_value` function now handles verify for `Integer64` & `InterfaceId` data types
* `original_string_value` function now handles retrieval of string value for `IPv4Prefix` & `InterfaceId` data types
* Functions to encode to/decode from `IPv4` bytes now also handle values with prefix/subnet
* Functions to encode to/decode from `IPv6` bytes now also handle values with prefix/subnet
* Not related to RADIUS implementation - Github Action CI/CD add support for newer Rust versions and drop support for older versions (because unfortunately Action fails on those)


=============
# v0.4.1 (10 Aug 2022)

This is small release/patch fixing a few bits here & there

## What's new
* Now all `unwrap()` calls are removed - with exception for a `generate_message_authenticator` in `client.rs`
* Now using `md-5` & `hmac` libraries instead of `rust-crypto`
* Added more tests

## What's removed or deprecated
* `client.rs` --> `generate_message_authenticator` function is marked as **deprecated** and would be removed in release 0.5.0
* `rust-crypto` library has been removed from dependencies as it is no longer maintained and Miri was flagging it as unsafe

## What's changed
* Re-work functions to generate Message-Authenticator, so now it should work correctly - previous function was only working if RADIUS packet had Message-Authenticator attribute set to zeros, now it can work with any initial state of the attribute
* Re-work `RadiusError` to return better error messages
* Bumped versions of the following dependencies:
    * `rand`, `0.7.3`       --> `0.8.5`
    * `thiserror`, `1.0.23` --> `1.0.32`
* `log` library is moved into `dev-dependencies` and bumped to `0.4.17`
* Added code from PR [!24](/../../pull/24) - ensure dictionary parser not failing when file has tabs as well as whitespaces


=============
# v0.4.0 (16 May 2021)

Got a couple of PRs & issues raised with some of them introducing breaking changes(read details below), so had to increase minor version to reflect that

## What's new
* Added a few more tests for **encrypt_data()** & **decrypt_data()** (thanks to Istvan91 [!2](/../../pull/2))
* Added **salt_encrypt_data()** & **salt_decrypt_data()** functions, which are handling salting (thanks to Istvan91 [!3](/../../pull/3))

## What's removed or deprecated

## What's changed
* Breaking change - Changed **encrypt_data()** function signature, so **data** parameter is now of type **&[u8]** instead of **&str**. Was reported in [#4](/../../issues/4) by Istvan91
* Breaking change - RADIUS packet creation now doesn't require **Vec<RadiusAttribute>**. To set attributes for packet, call **set_attributes()** function. For examples have a look at **examples/*_client.rs** (Fixes [#11](/../../issues/11))
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
