# Rust-Crypto

A (mostly) pure-Rust implementation of various cryptographic algorithms.

## Goals

Rust-Crypto seeks to create a pure Rust implementation of useful cryptographic algorithms, with a
minimum amount of assembly helper code where appropriate.

Specific goals, in order of priority:

1. **Safe**. All algorithms are implemented so as to be invulnerable to known side channel attacks. As
a minor exception, power side channel attacks are not considered.
2. **Readable**. All code is written to be as easy to read, audit, and understand as possible.
3. **Usable**. Rust-Crypto tries to provide all of the cryptographic algorithms that most programs need
with easy to use, native Rust interfaces.
4. **Fast**. Rust-Crypto seeks to be as fast as possible, but without sacrificing on any of the
previous goals.

## Implemented Algorithms

These algorithms are already implemented in the main branch.

* MD5
* Sha1
* Sha2 (All fixed output size variants)
* HMAC
* PBKDF2
* Scrypt

## In Development

These algorithms are under development in a separate branch. Development branches might be
rebased before being merged into master, so be careful.

* AES
* ECB, CBC, and CTR Block Cipher Modes
* PKCS7 Padding and No Padding modes for CBC Block Cipher Mode

## Desired Algorithms

These algorithms are planned.

* RSA
* DSA
* Bcrypt
* AES-GCM (But only a fixed time implementation!)
* RC4
* Diffie-Hellman
* CFB and OFB Cipher Block Modes
* PKCS5 Password Based Encryption
* TLS

## Interesting Algorithms

The algorithms aren't really planned, but would probably be suitable additions to the library.

* DES / 3DES (But only fixed time implementations!)
* Salsa20
* Various Elliptic Curve Algorithms
* Blowfish
* Twofish
* CTS Padding for CBC Block Cipher Mode

## Non-Interesting Algorithms

These algorithms would likely not be desirable in Rust-Crypto.

* Any RNG. Most operating systems already provide good algorithms for strong random number generation.
* Key generation functions for public key algorithms. This is just too easy to get wrong and too hard
to test to ensure that weak keys aren't being generated.
* Anything too new or experimental. If its newer or less analyzed that Scrypt, its probably not a good
fit.
* Anything thats considered insecure and isn't in wide use.

