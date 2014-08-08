# Rust-Crypto

[![Build Status](https://travis-ci.org/DaGenix/rust-crypto.png?branch=master)](https://travis-ci.org/DaGenix/rust-crypto)

A (mostly) pure-Rust implementation of various cryptographic algorithms.

## Goals

Rust-Crypto seeks to create a pratical, pure Rust implementation of useful cryptographic algorithms,
with a minimum amount of assembly helper code where appropriate. Rust-Crypto has not been thoroughly
audited for correctness at this point, so any use where security is important is not recommended at
this time.

## Implemented Algorithms

These algorithms are already implemented in the main branch.

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

## Desired Algorithms

These algorithms are planned.

* RSA
* DSA
* AES-GCM
* Diffie-Hellman
* CFB and OFB Cipher Block Modes
* PKCS Password Based Encryption
* TLS

## Interesting Algorithms

The algorithms aren't really planned, but would probably be suitable additions to the library.

* DES / 3DES (But only fixed time implementations!)
* Various Elliptic Curve Algorithms
* Twofish
* CTS Padding for CBC Block Cipher Mode

