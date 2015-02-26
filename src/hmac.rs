// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/*!
 * This module implements the Hmac function - a Message Authentication Code using a Digest.
 */

use std::iter::repeat;
use std::slice;

use digest::Digest;
use mac::{Mac, MacResult};

/**
 * The Hmac struct represents an Hmac function - a Message Authentication Code using a Digest.
 */
pub struct Hmac<D> {
    digest: D,
    i_key: Vec<u8>,
    o_key: Vec<u8>,
    finished: bool
}

fn derive_key(key: &mut [u8], mask: u8) {
    for elem in key.iter_mut() {
        *elem ^= mask;
    }
}

// The key that Hmac processes must be the same as the block size of the underlying Digest. If the
// provided key is smaller than that, we just pad it with zeros. If its larger, we hash it and then
// pad it with zeros.
fn expand_key<D: Digest>(digest: &mut D, key: &[u8]) -> Vec<u8> {
    let bs = digest.block_size();
    let mut expanded_key: Vec<u8> = repeat(0).take(bs).collect();

    if key.len() <= bs {
        slice::bytes::copy_memory(expanded_key.as_mut_slice(), key);
    } else {
        let output_size = digest.output_bytes();
        digest.input(key);
        digest.result(&mut expanded_key[..output_size]);
        digest.reset();
    }
    expanded_key
}

// Hmac uses two keys derived from the provided key - one by xoring every byte with 0x36 and another
// with 0x5c.
fn create_keys<D: Digest>(digest: &mut D, key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut i_key = expand_key(digest, key);
    let mut o_key = i_key.clone();
    derive_key(i_key.as_mut_slice(), 0x36);
    derive_key(o_key.as_mut_slice(), 0x5c);
    (i_key, o_key)
}

impl <D: Digest> Hmac<D> {
    /**
     * Create a new Hmac instance.
     *
     * # Arguments
     * * digest - The Digest to use.
     * * key - The key to use.
     *
     */
    pub fn new(mut digest: D, key: &[u8]) -> Hmac<D> {
        let (i_key, o_key) = create_keys(&mut digest, key);
        digest.input(&i_key[..]);
        Hmac {
            digest: digest,
            i_key: i_key,
            o_key: o_key,
            finished: false
        }
    }
}

impl <D: Digest> Mac for Hmac<D> {
    fn input(&mut self, data: &[u8]) {
        assert!(!self.finished);
        self.digest.input(data);
    }

    fn reset(&mut self) {
        self.digest.reset();
        self.digest.input(&self.i_key[..]);
        self.finished = false;
    }

    fn result(&mut self) -> MacResult {
        let output_size = self.digest.output_bytes();
        let mut code: Vec<u8> = repeat(0).take(output_size).collect();

        self.raw_result(code.as_mut_slice());

        MacResult::new_from_owned(code)
    }

    fn raw_result(&mut self, output: &mut [u8]) {
        if !self.finished {
            self.digest.result(output);

            self.digest.reset();
            self.digest.input(&self.o_key[..]);
            self.digest.input(output);

            self.finished = true;
        }

        self.digest.result(output);
    }

    fn output_bytes(&self) -> usize { self.digest.output_bytes() }
}

#[cfg(test)]
mod test {
    use std::iter::repeat;

    use mac::{Mac, MacResult};
    use hmac::Hmac;
    use digest::Digest;
    use md5::Md5;

    struct Test {
        key: Vec<u8>,
        data: Vec<u8>,
        expected: Vec<u8>
    }

    // Test vectors from: http://tools.ietf.org/html/rfc2104

    fn tests() -> Vec<Test> {
        vec![
            Test {
                key: repeat(0x0bu8).take(16).collect(),
                data: b"Hi There".to_vec(),
                expected: vec![
                    0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
                    0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d ]
            },
            Test {
                key: b"Jefe".to_vec(),
                data: b"what do ya want for nothing?".to_vec(),
                expected: vec![
                    0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
                    0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38 ]
            },
            Test {
                key: repeat(0xaau8).take(16).collect(),
                data: repeat(0xddu8).take(50).collect(),
                expected: vec![
                    0x56, 0xbe, 0x34, 0x52, 0x1d, 0x14, 0x4c, 0x88,
                    0xdb, 0xb8, 0xc7, 0x33, 0xf0, 0xe8, 0xb3, 0xf6 ]
            }
        ]
    }

    #[test]
    fn test_hmac_md5() {
        let tests = tests();
        for t in tests.iter() {
            let mut hmac = Hmac::new(Md5::new(), &t.key[..]);

            hmac.input(&t.data[..]);
            let result = hmac.result();
            let expected = MacResult::new(&t.expected[..]);
            assert!(result == expected);

            hmac.reset();

            hmac.input(&t.data[..]);
            let result2 = hmac.result();
            let expected2 = MacResult::new(&t.expected[..]);
            assert!(result2 == expected2);
        }
    }

    #[test]
    fn test_hmac_md5_incremental() {
        let tests = tests();
        for t in tests.iter() {
            let mut hmac = Hmac::new(Md5::new(), &t.key[..]);
            for i in range(0, t.data.len()) {
                hmac.input(&t.data[i..i + 1]);
            }
            let result = hmac.result();
            let expected = MacResult::new(&t.expected[..]);
            assert!(result == expected);
        }
    }
}
