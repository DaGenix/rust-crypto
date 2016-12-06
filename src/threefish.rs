// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ops::BitXor;

use cryptoutil::{read_u64v_le, write_u64v_le};
use symmetriccipher::{BlockDecryptor, BlockEncryptor};

// Magic constant for key schedule
const C240: u64 = 0x1BD11BDAA9FC1A22;

// Rotation constants for the different key lengths
const R_256: [[u32; 2]; 8] = [[14, 16], [52, 57], [23, 40], [ 5, 37],
                              [25, 33], [46, 12], [58, 22], [32, 32]];
const R_512: [[u32; 4]; 8] = [[46, 36, 19, 37], [33, 27, 14, 42],
                              [17, 49, 36, 39], [ 44, 9, 54, 56],
                              [39, 30, 34, 24], [13, 50, 10, 17],
                              [25, 29, 39, 43], [ 8, 35, 56, 22]];
const R_1024: [[u32; 8]; 8] = [[24, 13,  8, 47,  8, 17, 22, 37],
                               [38, 19, 10, 55, 49, 18, 23, 52],
                               [33,  4, 51, 13, 34, 41, 59, 17],
                               [ 5, 20, 48, 41, 47, 28, 16, 25],
                               [41,  9, 37, 31, 12, 47, 44, 30],
                               [16, 34, 56, 51,  4, 53, 42, 41],
                               [31, 44, 47, 46, 19, 42, 44, 25],
                               [ 9, 48, 35, 52, 23, 31, 37, 20]];

// Permutation tables for the different key lengths
const P_256: [usize; 4] = [0, 3, 2, 1];
const P_512: [usize; 8] = [6, 1, 0, 7, 2, 5, 4, 3];
const P_1024: [usize; 16] = [ 0, 15, 2, 11,  6, 13,  4, 9,
                             14,  1, 8,  5, 10,  3, 12, 7];

macro_rules! define_threefish_struct(
    (
        $name:ident,
        $rounds:expr,
        $key_size:expr
    ) => (
        #[derive(Clone, Copy)]
        pub struct $name {
            sk: [[u64; $key_size / 8]; $rounds / 4 + 1]
        }
    )
);

macro_rules! define_threefish_impl(
    (
        $name:ident,
        $rounds:expr,
        $key_size:expr
    ) => (
        impl $name {
            pub fn new(key: &[u8], tweak: &[u8]) -> $name {
                assert!(key.len() == $key_size, "{:?} key length should be {}",
                        stringify!($name), $key_size);
                assert!(tweak.len() == 16, "{:?} tweak length should be 16",
                        stringify!($name));

                const N_W: usize = $key_size / 8;

                let mut k = [0u64; N_W + 1];
                read_u64v_le(&mut k[..N_W], key);
                k[N_W] = k[..N_W].iter().fold(C240, BitXor::bitxor);

                let mut t = [0u64; 3];
                read_u64v_le(&mut t[..2], tweak);
                t[2] = t[0] ^ t[1];

                let mut sk = [[0u64; N_W]; $rounds / 4 + 1];
                for s in 0..($rounds / 4 + 1) {
                    for i in 0..N_W {
                        sk[s][i] = k[(s + i) % (N_W + 1)];
                        if i == N_W - 3 {
                            sk[s][i] = sk[s][i].wrapping_add(t[s % 3]);
                        } else if i == N_W - 2 {
                            sk[s][i] = sk[s][i].wrapping_add(t[(s + 1) % 3]);
                        } else if i == N_W - 1 {
                            sk[s][i] = sk[s][i].wrapping_add(s as u64);
                        }
                    }
                }

                $name { sk: sk }
            }
        }
    )
);

macro_rules! define_threefish_enc(
    (
        $name:ident,
        $rounds:expr,
        $key_size:expr,
        $rot_table:expr,
        $perm_table:expr
    ) => (
        impl BlockEncryptor for $name {
            fn block_size(&self) -> usize { $key_size }
            fn encrypt_block(&self, input: &[u8], output: &mut [u8]) {
                assert!(input.len() == $key_size,
                        "{:?} input length should be {} bytes",
                        stringify!($name), $key_size);
                assert!(output.len() == $key_size,
                        "{:?} output length should be {} bytes",
                        stringify!($name), $key_size);

                const N_W: usize = $key_size / 8;

                let mut v = [0u64; N_W];
                read_u64v_le(&mut v, input);

                for d in 0..$rounds {
                    let v_tmp = v.clone();
                    for j in 0..(N_W / 2) {
                        let (v0, v1) = (v_tmp[2 * j], v_tmp[2 * j + 1]);
                        let (e0, e1) =
                            if d % 4 == 0 {
                                (v0.wrapping_add(self.sk[d / 4][2 * j]),
                                 v1.wrapping_add(self.sk[d / 4][2 * j + 1]))
                            } else {
                                (v0, v1)
                            };
                        let r = $rot_table[d % 8][j];
                        let (f0, f1) = mix(r, (e0, e1));
                        let (pi0, pi1) =
                            ($perm_table[2 * j], $perm_table[2 * j + 1]);
                        v[pi0] = f0;
                        v[pi1] = f1;
                    }
                }

                for i in 0..N_W {
                    v[i] = v[i].wrapping_add(self.sk[$rounds / 4][i]);
                }

                write_u64v_le(output, &v);
            }
        }
    )
);

macro_rules! define_threefish_dec(
    (
        $name:ident,
        $rounds:expr,
        $key_size:expr,
        $rot_table:expr,
        $perm_table:expr
    ) => (
        impl BlockDecryptor for $name {
            fn block_size(&self) -> usize { $key_size }
            fn decrypt_block(&self, input: &[u8], output: &mut [u8]) {
                assert!(input.len() == $key_size,
                        "{:?} input length should be {} bytes",
                        stringify!($name), $key_size);
                assert!(output.len() == $key_size,
                        "{:?} output length should be {} bytes",
                        stringify!($name), $key_size);

                const N_W: usize = $key_size / 8;

                let mut v = [0u64; N_W];
                read_u64v_le(&mut v, input);

                for i in 0..N_W {
                    v[i] = v[i].wrapping_sub(self.sk[$rounds / 4][i]);
                }

                for d in (0..$rounds).rev() {
                    let v_tmp = v.clone();
                    for j in 0..(N_W / 2) {
                        let (inv_pi0, inv_pi1) =
                            ($perm_table[2 * j], $perm_table[2 * j + 1]);
                        let (f0, f1) = (v_tmp[inv_pi0], v_tmp[inv_pi1]);
                        let r = $rot_table[d % 8][j];
                        let (e0, e1) = inv_mix(r, (f0, f1));
                        let (v0, v1) =
                            if d % 4 == 0 {
                                (e0.wrapping_sub(self.sk[d / 4][2 * j]),
                                 e1.wrapping_sub(self.sk[d / 4][2 * j + 1]))
                             } else {
                                 (e0, e1)
                             };
                        v[2 * j] = v0;
                        v[2 * j + 1] = v1;
                    }
                }

                write_u64v_le(output, &v);
            }
        }
    )
);

define_threefish_struct!(Threefish256, 72, 32);
define_threefish_impl!(Threefish256, 72, 32);
define_threefish_enc!(Threefish256, 72, 32, R_256, P_256);
define_threefish_dec!(Threefish256, 72, 32, R_256, P_256);

define_threefish_struct!(Threefish512, 72, 64);
define_threefish_impl!(Threefish512, 72, 64);
define_threefish_enc!(Threefish512, 72, 64, R_512, P_512);
define_threefish_dec!(Threefish512, 72, 64, R_512, P_512);

define_threefish_struct!(Threefish1024, 80, 128);
define_threefish_impl!(Threefish1024, 80, 128);
define_threefish_enc!(Threefish1024, 80, 128, R_1024, P_1024);
define_threefish_dec!(Threefish1024, 80, 128, R_1024, P_1024);

fn mix(r: u32, x: (u64, u64)) -> (u64, u64) {
    let y0 = x.0.wrapping_add(x.1);
    let y1 = x.1.rotate_left(r) ^ y0;
    (y0, y1)
}

fn inv_mix(r: u32, y: (u64, u64)) -> (u64, u64) {
    let x1 = (y.0 ^ y.1).rotate_right(r);
    let x0 = y.0.wrapping_sub(x1);
    (x0, x1)
}

#[cfg(test)]
mod test {
    use super::*;
    use symmetriccipher::{BlockDecryptor, BlockEncryptor};

    struct TestCase {
        tweak: [u8; 16],
        key: Vec<u8>,
        plaintext: Vec<u8>,
        ciphertext: Vec<u8>,
    }

    // These test vectors come directly from the Skein NIST submission CD.

    fn tests256() -> Vec<TestCase> {
        vec![
            TestCase {
                tweak: [0x00; 16],
                key: vec![0x00; 32],
                plaintext: vec![0x00; 32],
                ciphertext: vec![0x84, 0xDA, 0x2A, 0x1F, 0x8B, 0xEA, 0xEE, 0x94,
                                 0x70, 0x66, 0xAE, 0x3E, 0x31, 0x03, 0xF1, 0xAD,
                                 0x53, 0x6D, 0xB1, 0xF4, 0xA1, 0x19, 0x24, 0x95,
                                 0x11, 0x6B, 0x9F, 0x3C, 0xE6, 0x13, 0x3F, 0xD8],
            },
            TestCase {
                tweak: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
                key: vec![0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                          0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                          0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                          0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F],
                plaintext: vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
                                0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
                                0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8,
                                0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0],
                ciphertext: vec![0xE0, 0xD0, 0x91, 0xFF, 0x0E, 0xEA, 0x8F, 0xDF,
                                 0xC9, 0x81, 0x92, 0xE6, 0x2E, 0xD8, 0x0A, 0xD5,
                                 0x9D, 0x86, 0x5D, 0x08, 0x58, 0x8D, 0xF4, 0x76,
                                 0x65, 0x70, 0x56, 0xB5, 0x95, 0x5E, 0x97, 0xDF],
            },
        ]
    }

    fn tests512() -> Vec<TestCase> {
        vec![
            TestCase {
                tweak: [0x00; 16],
                key: vec![0x00; 64],
                plaintext: vec![0x00; 64],
                ciphertext: vec![0xB1, 0xA2, 0xBB, 0xC6, 0xEF, 0x60, 0x25, 0xBC,
                                 0x40, 0xEB, 0x38, 0x22, 0x16, 0x1F, 0x36, 0xE3,
                                 0x75, 0xD1, 0xBB, 0x0A, 0xEE, 0x31, 0x86, 0xFB,
                                 0xD1, 0x9E, 0x47, 0xC5, 0xD4, 0x79, 0x94, 0x7B,
                                 0x7B, 0xC2, 0xF8, 0x58, 0x6E, 0x35, 0xF0, 0xCF,
                                 0xF7, 0xE7, 0xF0, 0x30, 0x84, 0xB0, 0xB7, 0xB1,
                                 0xF1, 0xAB, 0x39, 0x61, 0xA5, 0x80, 0xA3, 0xE9,
                                 0x7E, 0xB4, 0x1E, 0xA1, 0x4A, 0x6D, 0x7B, 0xBE],
            },
            TestCase {
                tweak: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
                key: vec![0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                          0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                          0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                          0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
                          0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                          0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
                          0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                          0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F],
                plaintext: vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
                                0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
                                0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8,
                                0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0,
                                0xDF, 0xDE, 0xDD, 0xDC, 0xDB, 0xDA, 0xD9, 0xD8,
                                0xD7, 0xD6, 0xD5, 0xD4, 0xD3, 0xD2, 0xD1, 0xD0,
                                0xCF, 0xCE, 0xCD, 0xCC, 0xCB, 0xCA, 0xC9, 0xC8,
                                0xC7, 0xC6, 0xC5, 0xC4, 0xC3, 0xC2, 0xC1, 0xC0],
                ciphertext: vec![0xE3, 0x04, 0x43, 0x96, 0x26, 0xD4, 0x5A, 0x2C,
                                 0xB4, 0x01, 0xCA, 0xD8, 0xD6, 0x36, 0x24, 0x9A,
                                 0x63, 0x38, 0x33, 0x0E, 0xB0, 0x6D, 0x45, 0xDD,
                                 0x8B, 0x36, 0xB9, 0x0E, 0x97, 0x25, 0x47, 0x79,
                                 0x27, 0x2A, 0x0A, 0x8D, 0x99, 0x46, 0x35, 0x04,
                                 0x78, 0x44, 0x20, 0xEA, 0x18, 0xC9, 0xA7, 0x25,
                                 0xAF, 0x11, 0xDF, 0xFE, 0xA1, 0x01, 0x62, 0x34,
                                 0x89, 0x27, 0x67, 0x3D, 0x5C, 0x1C, 0xAF, 0x3D],
            }
        ]
    }

    fn tests1024() -> Vec<TestCase> {
        vec![
            TestCase {
                tweak: [0x00; 16],
                key: vec![0x00; 128],
                plaintext: vec![0x00; 128],
                ciphertext: vec![0xF0, 0x5C, 0x3D, 0x0A, 0x3D, 0x05, 0xB3, 0x04,
                                 0xF7, 0x85, 0xDD, 0xC7, 0xD1, 0xE0, 0x36, 0x01,
                                 0x5C, 0x8A, 0xA7, 0x6E, 0x2F, 0x21, 0x7B, 0x06,
                                 0xC6, 0xE1, 0x54, 0x4C, 0x0B, 0xC1, 0xA9, 0x0D,
                                 0xF0, 0xAC, 0xCB, 0x94, 0x73, 0xC2, 0x4E, 0x0F,
                                 0xD5, 0x4F, 0xEA, 0x68, 0x05, 0x7F, 0x43, 0x32,
                                 0x9C, 0xB4, 0x54, 0x76, 0x1D, 0x6D, 0xF5, 0xCF,
                                 0x7B, 0x2E, 0x9B, 0x36, 0x14, 0xFB, 0xD5, 0xA2,
                                 0x0B, 0x2E, 0x47, 0x60, 0xB4, 0x06, 0x03, 0x54,
                                 0x0D, 0x82, 0xEA, 0xBC, 0x54, 0x82, 0xC1, 0x71,
                                 0xC8, 0x32, 0xAF, 0xBE, 0x68, 0x40, 0x6B, 0xC3,
                                 0x95, 0x00, 0x36, 0x7A, 0x59, 0x29, 0x43, 0xFA,
                                 0x9A, 0x5B, 0x4A, 0x43, 0x28, 0x6C, 0xA3, 0xC4,
                                 0xCF, 0x46, 0x10, 0x4B, 0x44, 0x31, 0x43, 0xD5,
                                 0x60, 0xA4, 0xB2, 0x30, 0x48, 0x83, 0x11, 0xDF,
                                 0x4F, 0xEE, 0xF7, 0xE1, 0xDF, 0xE8, 0x39, 0x1E],
            },
            TestCase {
                tweak: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
                key: vec![0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                          0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                          0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                          0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
                          0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                          0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
                          0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                          0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
                          0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                          0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
                          0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                          0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
                          0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
                          0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
                          0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                          0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F],
                plaintext: vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
                                0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
                                0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8,
                                0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0,
                                0xDF, 0xDE, 0xDD, 0xDC, 0xDB, 0xDA, 0xD9, 0xD8,
                                0xD7, 0xD6, 0xD5, 0xD4, 0xD3, 0xD2, 0xD1, 0xD0,
                                0xCF, 0xCE, 0xCD, 0xCC, 0xCB, 0xCA, 0xC9, 0xC8,
                                0xC7, 0xC6, 0xC5, 0xC4, 0xC3, 0xC2, 0xC1, 0xC0,
                                0xBF, 0xBE, 0xBD, 0xBC, 0xBB, 0xBA, 0xB9, 0xB8,
                                0xB7, 0xB6, 0xB5, 0xB4, 0xB3, 0xB2, 0xB1, 0xB0,
                                0xAF, 0xAE, 0xAD, 0xAC, 0xAB, 0xAA, 0xA9, 0xA8,
                                0xA7, 0xA6, 0xA5, 0xA4, 0xA3, 0xA2, 0xA1, 0xA0,
                                0x9F, 0x9E, 0x9D, 0x9C, 0x9B, 0x9A, 0x99, 0x98,
                                0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, 0x90,
                                0x8F, 0x8E, 0x8D, 0x8C, 0x8B, 0x8A, 0x89, 0x88,
                                0x87, 0x86, 0x85, 0x84, 0x83, 0x82, 0x81, 0x80],
                ciphertext: vec![0xA6, 0x65, 0x4D, 0xDB, 0xD7, 0x3C, 0xC3, 0xB0,
                                 0x5D, 0xD7, 0x77, 0x10, 0x5A, 0xA8, 0x49, 0xBC,
                                 0xE4, 0x93, 0x72, 0xEA, 0xAF, 0xFC, 0x55, 0x68,
                                 0xD2, 0x54, 0x77, 0x1B, 0xAB, 0x85, 0x53, 0x1C,
                                 0x94, 0xF7, 0x80, 0xE7, 0xFF, 0xAA, 0xE4, 0x30,
                                 0xD5, 0xD8, 0xAF, 0x8C, 0x70, 0xEE, 0xBB, 0xE1,
                                 0x76, 0x0F, 0x3B, 0x42, 0xB7, 0x37, 0xA8, 0x9C,
                                 0xB3, 0x63, 0x49, 0x0D, 0x67, 0x03, 0x14, 0xBD,
                                 0x8A, 0xA4, 0x1E, 0xE6, 0x3C, 0x2E, 0x1F, 0x45,
                                 0xFB, 0xD4, 0x77, 0x92, 0x2F, 0x83, 0x60, 0xB3,
                                 0x88, 0xD6, 0x12, 0x5E, 0xA6, 0xC7, 0xAF, 0x0A,
                                 0xD7, 0x05, 0x6D, 0x01, 0x79, 0x6E, 0x90, 0xC8,
                                 0x33, 0x13, 0xF4, 0x15, 0x0A, 0x57, 0x16, 0xB3,
                                 0x0E, 0xD5, 0xF5, 0x69, 0x28, 0x8A, 0xE9, 0x74,
                                 0xCE, 0x2B, 0x43, 0x47, 0x92, 0x6F, 0xCE, 0x57,
                                 0xDE, 0x44, 0x51, 0x21, 0x77, 0xDD, 0x7C, 0xDE],
            },
        ]
    }

    fn test_encryptor<T: BlockEncryptor>(encryptor: &T, test_case: &TestCase) {
        assert_eq!(encryptor.block_size(), test_case.key.len());
        assert_eq!(encryptor.block_size(), test_case.plaintext.len());
        assert_eq!(encryptor.block_size(), test_case.ciphertext.len());

        let mut output = vec![0u8; test_case.ciphertext.len()];
        encryptor.encrypt_block(&test_case.plaintext[..], &mut output[..]);
        assert_eq!(output, test_case.ciphertext);
    }

    fn test_decryptor<T: BlockDecryptor>(decryptor: &T, test_case: &TestCase) {
        assert_eq!(decryptor.block_size(), test_case.key.len());
        assert_eq!(decryptor.block_size(), test_case.plaintext.len());
        assert_eq!(decryptor.block_size(), test_case.ciphertext.len());

        let mut output = vec![0u8; test_case.plaintext.len()];
        decryptor.decrypt_block(&test_case.ciphertext[..], &mut output[..]);
        assert_eq!(output, test_case.plaintext);
    }

    #[test]
    fn test_threefish_256() {
        for test_case in tests256() {
            let threefish = Threefish256::new(&test_case.key[..],
                                              &test_case.tweak[..]);
            test_encryptor(&threefish, &test_case);
            test_decryptor(&threefish, &test_case);
        }
    }

    #[test]
    fn test_threefish_512() {
        for test_case in tests512() {
            let threefish = Threefish512::new(&test_case.key[..],
                                              &test_case.tweak[..]);
            test_encryptor(&threefish, &test_case);
            test_decryptor(&threefish, &test_case);
        }
    }

    #[test]
    fn test_threefish_1024() {
        for test_case in tests1024() {
            let threefish = Threefish1024::new(&test_case.key[..],
                                               &test_case.tweak[..]);
            test_encryptor(&threefish, &test_case);
            test_decryptor(&threefish, &test_case);
        }
    }
}

// TODO: Benchmark tests
