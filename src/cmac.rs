// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/*!
 * This module implements the CMAC function - a Message Authentication Code using symmetric encryption.
 */

use std::iter::repeat;

use mac::{Mac, MacResult};
use symmetriccipher::{BlockEncryptor};

/**
 * The CMAC struct represents a CMAC function - a Message Authentication Code using symmetric encryption.
 */
pub struct Cmac<C: BlockEncryptor> {
    cipher: C,
    key_one: Vec<u8>,
    key_two: Vec<u8>,
    result: Vec<u8>,
    finished: bool,
}

fn do_shift_one_bit_left(a: &[u8], block_size: usize) -> (Vec<u8>, u8) {

    let mut carry = 0;

    let mut b: Vec<u8> = repeat(0).take(block_size).collect();

    for i in (0..(block_size)).rev() {
        b[i] = (a[i] << 1) | carry;

        if a[i] & 0x80 != 0 {
            carry = 1;
        }
        else {
            carry = 0;
        }
    }

    (b, carry)
}

fn generate_subkey(key: &[u8], block_size: usize) -> Vec<u8> {

    let (mut subkey, carry) = do_shift_one_bit_left(key, block_size);

    // Only two block sizes are defined, 64 and 128
    let r_b = if block_size == 16 {
        0x87
    }
    else {
        0x1b
    };

    if carry == 1 {
        subkey[block_size - 1] ^= r_b;
    }

    subkey
}

// Cmac uses two keys derived from the provided key
fn create_keys<C: BlockEncryptor>(cipher: &C) -> (Vec<u8>, Vec<u8>) {

    let zeroes: Vec<u8> = repeat(0).take(cipher.block_size()).collect();
    let mut l: Vec<u8> = repeat(0).take(cipher.block_size()).collect();

    cipher.encrypt_block(zeroes.as_slice(), l.as_mut_slice());

    let key_one = generate_subkey(l.as_slice(), cipher.block_size());
    let key_two = generate_subkey(key_one.as_slice(), cipher.block_size());

    (key_one, key_two)
}

fn do_inplace_xor(a: &[u8], b: &mut [u8]) {

    for (x, y) in a.iter().zip(b) {
        *y ^= *x;
    }
}

fn do_pad(data: &mut [u8], len: usize, block_size: usize) {

    data[len] = 0x80;

    for i in (len + 1)..block_size {
        data[i] = 0x00;
    }
}

// Perform simil-CBC encryption with last block tweaking
fn cmac_encrypt<C: BlockEncryptor>(cipher: &C, key_one: &[u8], key_two: &[u8], data: &[u8]) -> Vec<u8> {

    let block_size = cipher.block_size();

    let n_blocks = if data.len() == 0 {
        0
    }
    else {
        (data.len() + (block_size - 1)) / block_size - 1
    };

    let remaining_bytes = data.len() % block_size;

    let (head, tail) = if n_blocks == 0 {
        (&[] as &[u8], data)
    }
    else {
        data.split_at((block_size * n_blocks))
    };

    let mut mac: Vec<u8> = repeat(0).take(block_size).collect();
    let mut work_block: Vec<u8> = Vec::with_capacity(block_size);

    for block in head.chunks(block_size) {
        do_inplace_xor(block, mac.as_mut_slice());

        work_block.clone_from(&mac);
        cipher.encrypt_block(work_block.as_slice(), mac.as_mut_slice());
    }

    work_block.truncate(0);
    if remaining_bytes == 0 {
        if data.len() != 0 {
            work_block.extend_from_slice(tail);
            do_inplace_xor(key_one, work_block.as_mut_slice());
        }
        else {
            work_block = repeat(0).take(block_size).collect();
            do_pad(work_block.as_mut_slice(), 0, block_size);
            do_inplace_xor(key_two, work_block.as_mut_slice());
        }
    }
    else {
        work_block.extend_from_slice(tail);
        work_block.extend_from_slice(vec![0; block_size - remaining_bytes].as_slice()); // NOTE(adma): try to use a FixedBuffer
        do_pad(work_block.as_mut_slice(), remaining_bytes, block_size);
        do_inplace_xor(key_two, work_block.as_mut_slice());
    }

    do_inplace_xor(work_block.as_slice(), mac.as_mut_slice());

    cipher.encrypt_block(mac.as_slice(), work_block.as_mut_slice());

    work_block
}

impl <C: BlockEncryptor> Cmac<C> {
    /**
     * Create a new CMAC instance.
     *
     * # Arguments
     * * cipher - The Cipher to use.
     *
     */
    pub fn new(cipher: C) -> Cmac<C> {
        let (key_one, key_two) = create_keys(&cipher);

        Cmac {
            result: Vec::with_capacity(cipher.block_size()), // NOTE(adma): try to use a FixedBuffer
            cipher: cipher,
            key_one: key_one,
            key_two: key_two,
            finished: false
        }
        // NOTE(adma): cipher should be either AES or TDEA
    }
}

impl <C: BlockEncryptor> Mac for Cmac<C> {
    fn input(&mut self, data: &[u8]) {
        assert!(!self.finished);
        self.result = cmac_encrypt(&self.cipher, self.key_one.as_slice(), self.key_two.as_slice(), data);
        self.finished = true;
    }

    fn reset(&mut self) {
        self.finished = false;
    }

    fn result(&mut self) -> MacResult {
        let output_size = self.cipher.block_size();
        let mut code: Vec<u8> = repeat(0).take(output_size).collect();

        self.raw_result(&mut code);

        MacResult::new_from_owned(code)
    }

    fn raw_result(&mut self, output: &mut [u8]) {
        if !self.finished {
            output.clone_from_slice(&[]);
        }

        output.clone_from_slice(self.result.as_slice());
    }

    fn output_bytes(&self) -> usize { self.cipher.block_size() }
}

#[cfg(test)]
mod test {
    use mac::{Mac, MacResult};
    use cmac::Cmac;

    use aessafe;

    struct Test {
        key: Vec<u8>,
        data: Vec<u8>,
        expected: Vec<u8>
    }

    // Test vectors from: http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf

    fn tests_aes128() -> Vec<Test> {
        vec![
            Test {
                key: vec![
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c ],
                data: b"".to_vec(),
                expected: vec![
                    0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
                    0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46 ]

            },
            Test {
                key: vec![
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c ],
                data: vec![
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a ],
                expected: vec![
                    0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
                    0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c ]

            },
            Test {
                key: vec![
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c ],
                data: vec![
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11 ],
                expected: vec![
                    0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
                    0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27 ]

            },
            Test {
                key: vec![
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c ],
                data: vec![
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 ],
                expected: vec![
                    0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
                    0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe ]

            },
        ]
    }

    fn tests_aes192() -> Vec<Test> {
        vec![
            Test {
                key: vec![
                    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                    0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b ],
                data: b"".to_vec(),
                expected: vec![
                    0xd1, 0x7d, 0xdf, 0x46, 0xad, 0xaa, 0xcd, 0xe5,
                    0x31, 0xca, 0xc4, 0x83, 0xde, 0x7a, 0x93, 0x67 ]

            },
            Test {
                key: vec![
                    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                    0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b ],
                data: vec![
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a ],
                expected: vec![
                    0x9e, 0x99, 0xa7, 0xbf, 0x31, 0xe7, 0x10, 0x90,
                    0x06, 0x62, 0xf6, 0x5e, 0x61, 0x7c, 0x51, 0x84 ]

            },
            Test {
                key: vec![
                    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                    0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b ],
                data: vec![
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11 ],
                expected: vec![
                    0x8a, 0x1d, 0xe5, 0xbe, 0x2e, 0xb3, 0x1a, 0xad,
                    0x08, 0x9a, 0x82, 0xe6, 0xee, 0x90, 0x8b, 0x0e ]

            },
            Test {
                key: vec![
                    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                    0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b],
                data: vec![
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 ],
                expected: vec![
                    0xa1, 0xd5, 0xdf, 0x0e, 0xed, 0x79, 0x0f, 0x79,
                    0x4d, 0x77, 0x58, 0x96, 0x59, 0xf3, 0x9a, 0x11 ]

            },
        ]
    }

    fn tests_aes256() -> Vec<Test> {
        vec![
            Test {
                key: vec![
                    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 ],
                data: b"".to_vec(),
                expected: vec![
                    0x02, 0x89, 0x62, 0xf6, 0x1b, 0x7b, 0xf8, 0x9e,
                    0xfc, 0x6b, 0x55, 0x1f, 0x46, 0x67, 0xd9, 0x83 ]

            },
            Test {
                key: vec![
                    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 ],
                data: vec![
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a ],
                expected: vec![
                    0x28, 0xa7, 0x02, 0x3f, 0x45, 0x2e, 0x8f, 0x82,
                    0xbd, 0x4b, 0xf2, 0x8d, 0x8c, 0x37, 0xc3, 0x5c ]

            },
            Test {
                key: vec![
                    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 ],
                data: vec![
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11 ],
                expected: vec![
                    0xaa, 0xf3, 0xd8, 0xf1, 0xde, 0x56, 0x40, 0xc2,
                    0x32, 0xf5, 0xb1, 0x69, 0xb9, 0xc9, 0x11, 0xe6 ]

            },
            Test {
                key: vec![
                    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 ],
                data: vec![
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 ],
                expected: vec![
                    0xe1, 0x99, 0x21, 0x90, 0x54, 0x9f, 0x6e, 0xd5,
                    0x69, 0x6a, 0x2c, 0x05, 0x6c, 0x31, 0x54, 0x10 ]

            },
        ]
    }

    #[test]
    fn test_cmac_aes128() {
        let tests = tests_aes128();
        for t in tests.iter() {
            let aes_enc = aessafe::AesSafe128Encryptor::new(&t.key[..]);
            let mut cmac = Cmac::new(aes_enc);

            cmac.input(&t.data[..]);
            let result = cmac.result();
            let expected = MacResult::new(&t.expected[..]);
            assert!(result == expected);

            cmac.reset();

            cmac.input(&t.data[..]);
            let result2 = cmac.result();
            let expected2 = MacResult::new(&t.expected[..]);
            assert!(result2 == expected2);
        }
    }

    #[test]
    fn test_cmac_aes192() {
        let tests = tests_aes192();
        for t in tests.iter() {
            let aes_enc = aessafe::AesSafe192Encryptor::new(&t.key[..]);
            let mut cmac = Cmac::new(aes_enc);

            cmac.input(&t.data[..]);
            let result = cmac.result();
            let expected = MacResult::new(&t.expected[..]);
            assert!(result == expected);

            cmac.reset();

            cmac.input(&t.data[..]);
            let result2 = cmac.result();
            let expected2 = MacResult::new(&t.expected[..]);
            assert!(result2 == expected2);
        }
    }

    #[test]
    fn test_cmac_aes256() {
        let tests = tests_aes256();
        for t in tests.iter() {
            let aes_enc = aessafe::AesSafe256Encryptor::new(&t.key[..]);
            let mut cmac = Cmac::new(aes_enc);

            cmac.input(&t.data[..]);
            let result = cmac.result();
            let expected = MacResult::new(&t.expected[..]);
            assert!(result == expected);

            cmac.reset();

            cmac.input(&t.data[..]);
            let result2 = cmac.result();
            let expected2 = MacResult::new(&t.expected[..]);
            assert!(result2 == expected2);
        }
    }
}
