// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::iter::repeat;
use std::hash::{Hash, Hasher};

/*
 * The purpose of this type is to implement `Hasher` so that it can extract data from any type
 * which implements `Hash` and write the data to a `Digest`. This type is private to this module
 * and used to implement the `input_hashable` method.
 */
struct DigestHasher<'a, T: 'a + ?Sized> {
    digest: &'a mut T,
}

impl<'a, T: ?Sized + Digest> Hasher for DigestHasher<'a, T> {
    fn finish(&self) -> u64 {
        // This should never be called.
        panic!()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.digest.input(bytes);
    }
}

/**
 * The Digest trait specifies an interface common to digest functions, such as SHA-1 and the SHA-2
 * family of digest functions.
 */
pub trait Digest {
    /**
     * Provide message data.
     *
     * # Arguments
     *
     * * input - A vector of message data
     */
    fn input(&mut self, input: &[u8]);

    /**
     * Retrieve the digest result. This method may be called multiple times.
     *
     * # Arguments
     *
     * * out - the vector to hold the result. Must be large enough to contain output_bits().
     */
    fn result(&mut self, out: &mut [u8]);

    /**
     * Reset the digest. This method must be called after result() and before supplying more
     * data.
     */
    fn reset(&mut self);

    /**
     * Get the output size in bits.
     */
    fn output_bits(&self) -> usize;

    /**
     * Get the output size in bytes.
     */
    fn output_bytes(&self) -> usize {
        (self.output_bits() + 7) / 8
    }

    /**
     * Get the block size in bytes.
     */
    fn block_size(&self) -> usize;

    /**
     * Convenience function that feeds a string into a digest.
     *
     * # Arguments
     *
     * * `input` The string to feed into the digest
     */
    fn input_str(&mut self, input: &str) {
        self.input(input.as_bytes());
    }

    /**
     * Convenience function that retrieves the result of a digest as a
     * String in hexadecimal format.
     */
    fn result_str(&mut self) -> String {
        use serialize::hex::ToHex;

        let mut buf: Vec<u8> = repeat(0).take((self.output_bits()+7)/8).collect();
        self.result(&mut buf);
        buf[..].to_hex()
    }

    /**
     * Provide data from anything that implements `Hash`.
     */
    fn input_hashable<H: Hash>(&mut self, hashable: &H) {
        let mut digest_hasher = DigestHasher {
            digest: self,
        };
        hashable.hash(&mut digest_hasher);
    }
}
