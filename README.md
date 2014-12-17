**NOTE**: The crate name used by rust-crypto has recently changed from `rust-crypto` to
just `crypto`. Please see the Usage section if you are running into issues due to this
change.

# Rust-Crypto

[![Build Status](https://travis-ci.org/DaGenix/rust-crypto.png?branch=master)](https://travis-ci.org/DaGenix/rust-crypto)

A (mostly) pure-Rust implementation of various common cryptographic algorithms.

Rust-Crypto seeks to create practical, auditable, pure-Rust implementations of common cryptographic algorithms
with a minimum amount of assembly code where appropriate. Rust-Crypto supports both x86 and
ARM architectures, although the x86 architecture receives considerably more testing. Rust-Crypto has not been thoroughly
audited for correctness, so any use where security is important is not recommended at this time.

## Usage

To use Rust-Crypto, add the following to your Cargo.toml:

```toml
[dependencies]
rust-crypto = "*"
```

and the following to your crate root:

```rust
extern crate crypto;
```

## Contributions

Contributions are extremely welcome. The most significant needs are help
keeping up with breaking Rust changes, adding documentation, implementing new algorithms,
and general cleanup and improvement of the code. Rust-Crypto is not a
great place for experimenting with new algorithms, however. I generally will not
merge pull requests for at least a day after they are submitted to make sure that everyone who contributes
to Rust-Crypto has a chance to comment, voice concerns, or suggest improvements.
Pull requests that make trivial improvements (such as updates to documentation) or fix compiling
against the latest Rust nightly release will be merged as soon as possible, however.

By submitting a pull request you are agreeing to make you work available under the license
terms of the Rust-Crypto project.

## License

Rust-Crypto is dual licensed under the MIT and Apache 2.0 licenses, the same licenses
as the Rust compiler.

## Algorithms

Rust-Crypto already supports a significant number of algorithms and with your help
it will support even more in the future. Currently supported algorithms include:

* MD5
* RIPEMD-160
* Sha1
* Sha2 (All fixed output size variants)
* HMAC
* PBKDF2
* Scrypt
* AES
* RC4
* ECB, CBC, and CTR block cipher modes
* PKCS padding for CBC block cipher mode
* Salsa20 and XSalsa20
* Blowfish
* Bcrypt
* Blake2B
* ChaCha20
* Fortuna
* Ghash
* Poly1305

