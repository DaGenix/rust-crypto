# Rust-Crypto

A (mostly) pure-Rust implementation of various cryptographic algorithms.

## Goals

Rust-Crypto seeks to create a pratical, pure Rust implementation of useful cryptographic algorithms,
with a minimum amount of assembly helper code where appropriate. Rust-Crypto has not been thoroughly
audited for correctness at this point, so any use where security is important is not recommended at
this time.

## Implemented Algorithms

These algorithms are already implemented in the main branch.

* MD5
* Sha1
* Sha2 (All fixed output size variants)
* HMAC
* PBKDF2
* Scrypt

## In Development

These algorithms are under development. Development branches might be rebased before being merged
into master, so be careful.

* AES
* ECB, CBC, and CTR Block Cipher Modes
* PKCS7 Padding and No Padding modes for CBC Block Cipher Mode

## Desired Algorithms

These algorithms are planned.

* RSA
* DSA
* Bcrypt
* AES-GCM
* RC4
* Diffie-Hellman
* CFB and OFB Cipher Block Modes
* PKCS Password Based Encryption
* TLS

## Interesting Algorithms

The algorithms aren't really planned, but would probably be suitable additions to the library.

* DES / 3DES (But only fixed time implementations!)
* Salsa20
* Various Elliptic Curve Algorithms
* Blowfish
* Twofish
* CTS Padding for CBC Block Cipher Mode
