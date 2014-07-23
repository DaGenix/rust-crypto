// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(target_arch = "x86")]
#[cfg(target_arch = "x86_64")]
use aesni;

use aessafe;
use blockmodes::{PaddingProcessor, EcbEncryptor, EcbDecryptor, CbcEncryptor, CbcDecryptor, CtrMode,
    CtrModeX8};
use symmetriccipher::{Encryptor, Decryptor, SynchronousStreamCipher};
use util;

/// AES key size
pub enum KeySize {
    KeySize128,
    KeySize192,
    KeySize256
}

/// Get the best implementation of an EcbEncryptor
#[cfg(target_arch = "x86")]
#[cfg(target_arch = "x86_64")]
pub fn ecb_encryptor<X: PaddingProcessor + Send>(
        key_size: KeySize,
        key: &[u8],
        padding: X) -> Box<Encryptor> {
    if util::supports_aesni() {
        match key_size {
            KeySize128 => {
                let aes_enc = aesni::AesNi128Encryptor::new(key);
                let enc = box EcbEncryptor::new(aes_enc, padding);
                enc as Box<Encryptor>
            }
            KeySize192 => {
                let aes_enc = aesni::AesNi192Encryptor::new(key);
                let enc = box EcbEncryptor::new(aes_enc, padding);
                enc as Box<Encryptor>
            }
            KeySize256 => {
                let aes_enc = aesni::AesNi256Encryptor::new(key);
                let enc = box EcbEncryptor::new(aes_enc, padding);
                enc as Box<Encryptor>
            }
        }
    } else {
        match key_size {
            KeySize128 => {
                let aes_enc = aessafe::AesSafe128Encryptor::new(key);
                let enc = box EcbEncryptor::new(aes_enc, padding);
                enc as Box<Encryptor>
            }
            KeySize192 => {
                let aes_enc = aessafe::AesSafe192Encryptor::new(key);
                let enc = box EcbEncryptor::new(aes_enc, padding);
                enc as Box<Encryptor>
            }
            KeySize256 => {
                let aes_enc = aessafe::AesSafe256Encryptor::new(key);
                let enc = box EcbEncryptor::new(aes_enc, padding);
                enc as Box<Encryptor>
            }
        }
    }
}

/// Get the best implementation of an EcbEncryptor
#[cfg(not(target_arch = "x86"), not(target_arch = "x86_64"))]
pub fn ecb_encryptor<X: PaddingProcessor + Send>(
        key_size: KeySize,
        key: &[u8],
        padding: X) -> Box<Encryptor> {
    match key_size {
        KeySize128 => {
            let aes_enc = aessafe::AesSafe128Encryptor::new(key);
            let enc = box EcbEncryptor::new(aes_enc, padding);
            enc as Box<Encryptor>
        }
        KeySize192 => {
            let aes_enc = aessafe::AesSafe192Encryptor::new(key);
            let enc = box EcbEncryptor::new(aes_enc, padding);
            enc as Box<Encryptor>
        }
        KeySize256 => {
            let aes_enc = aessafe::AesSafe256Encryptor::new(key);
            let enc = box EcbEncryptor::new(aes_enc, padding);
            enc as Box<Encryptor>
        }
    }
}

/// Get the best implementation of an EcbDecryptor
#[cfg(target_arch = "x86")]
#[cfg(target_arch = "x86_64")]
pub fn ecb_decryptor<X: PaddingProcessor + Send>(
        key_size: KeySize,
        key: &[u8],
        padding: X) -> Box<Decryptor> {
    if util::supports_aesni() {
        match key_size {
            KeySize128 => {
                let aes_dec = aesni::AesNi128Decryptor::new(key);
                let dec = box EcbDecryptor::new(aes_dec, padding);
                dec as Box<Decryptor>
            }
            KeySize192 => {
                let aes_dec = aesni::AesNi192Decryptor::new(key);
                let dec = box EcbDecryptor::new(aes_dec, padding);
                dec as Box<Decryptor>
            }
            KeySize256 => {
                let aes_dec = aesni::AesNi256Decryptor::new(key);
                let dec = box EcbDecryptor::new(aes_dec, padding);
                dec as Box<Decryptor>
            }
        }
    } else {
        match key_size {
            KeySize128 => {
                let aes_dec = aessafe::AesSafe128Decryptor::new(key);
                let dec = box EcbDecryptor::new(aes_dec, padding);
                dec as Box<Decryptor>
            }
            KeySize192 => {
                let aes_dec = aessafe::AesSafe192Decryptor::new(key);
                let dec = box EcbDecryptor::new(aes_dec, padding);
                dec as Box<Decryptor>
            }
            KeySize256 => {
                let aes_dec = aessafe::AesSafe256Decryptor::new(key);
                let dec = box EcbDecryptor::new(aes_dec, padding);
                dec as Box<Decryptor>
            }
        }
    }
}

/// Get the best implementation of an EcbDecryptor
#[cfg(not(target_arch = "x86"), not(target_arch = "x86_64"))]
pub fn ecb_decryptor<X: PaddingProcessor + Send>(
        key_size: KeySize,
        key: &[u8],
        padding: X) -> Box<Decryptor> {
    match key_size {
        KeySize128 => {
            let aes_dec = aessafe::AesSafe128Decryptor::new(key);
            let dec = box EcbDecryptor::new(aes_dec, padding);
            dec as Box<Decryptor>
        }
        KeySize192 => {
            let aes_dec = aessafe::AesSafe192Decryptor::new(key);
            let dec = box EcbDecryptor::new(aes_dec, padding);
            dec as Box<Decryptor>
        }
        KeySize256 => {
            let aes_dec = aessafe::AesSafe256Decryptor::new(key);
            let dec = box EcbDecryptor::new(aes_dec, padding);
            dec as Box<Decryptor>
        }
    }
}

/// Get the best implementation of a CbcEncryptor
#[cfg(target_arch = "x86")]
#[cfg(target_arch = "x86_64")]
pub fn cbc_encryptor<X: PaddingProcessor + Send>(
        key_size: KeySize,
        key: &[u8],
        iv: &[u8],
        padding: X) -> Box<Encryptor> {
    if util::supports_aesni() {
        match key_size {
            KeySize128 => {
                let aes_enc = aesni::AesNi128Encryptor::new(key);
                let enc = box CbcEncryptor::new(aes_enc, padding, Vec::from_slice(iv));
                enc as Box<Encryptor>
            }
            KeySize192 => {
                let aes_enc = aesni::AesNi192Encryptor::new(key);
                let enc = box CbcEncryptor::new(aes_enc, padding, Vec::from_slice(iv));
                enc as Box<Encryptor>
            }
            KeySize256 => {
                let aes_enc = aesni::AesNi256Encryptor::new(key);
                let enc = box CbcEncryptor::new(aes_enc, padding, Vec::from_slice(iv));
                enc as Box<Encryptor>
            }
        }
    } else {
        match key_size {
            KeySize128 => {
                let aes_enc = aessafe::AesSafe128Encryptor::new(key);
                let enc = box CbcEncryptor::new(aes_enc, padding, Vec::from_slice(iv));
                enc as Box<Encryptor>
            }
            KeySize192 => {
                let aes_enc = aessafe::AesSafe192Encryptor::new(key);
                let enc = box CbcEncryptor::new(aes_enc, padding, Vec::from_slice(iv));
                enc as Box<Encryptor>
            }
            KeySize256 => {
                let aes_enc = aessafe::AesSafe256Encryptor::new(key);
                let enc = box CbcEncryptor::new(aes_enc, padding, Vec::from_slice(iv));
                enc as Box<Encryptor>
            }
        }
    }
}

/// Get the best implementation of a CbcEncryptor
#[cfg(not(target_arch = "x86"), not(target_arch = "x86_64"))]
pub fn cbc_encryptor<X: PaddingProcessor + Send>(
        key_size: KeySize,
        key: &[u8],
        iv: &[u8],
        padding: X) -> Box<Encryptor> {
    match key_size {
        KeySize128 => {
            let aes_enc = aessafe::AesSafe128Encryptor::new(key);
            let enc = box CbcEncryptor::new(aes_enc, padding, Vec::from_slice(iv));
            enc as Box<Encryptor>
        }
        KeySize192 => {
            let aes_enc = aessafe::AesSafe192Encryptor::new(key);
            let enc = box CbcEncryptor::new(aes_enc, padding, Vec::from_slice(iv));
            enc as Box<Encryptor>
        }
        KeySize256 => {
            let aes_enc = aessafe::AesSafe256Encryptor::new(key);
            let enc = box CbcEncryptor::new(aes_enc, padding, Vec::from_slice(iv));
            enc as Box<Encryptor>
        }
    }
}

/// Get the best implementation of a CbcDecryptor
#[cfg(target_arch = "x86")]
#[cfg(target_arch = "x86_64")]
pub fn cbc_decryptor<X: PaddingProcessor + Send>(
        key_size: KeySize,
        key: &[u8],
        iv: &[u8],
        padding: X) -> Box<Decryptor> {
    if util::supports_aesni() {
        match key_size {
            KeySize128 => {
                let aes_dec = aesni::AesNi128Decryptor::new(key);
                let dec = box CbcDecryptor::new(aes_dec, padding, Vec::from_slice(iv));
                dec as Box<Decryptor>
            }
            KeySize192 => {
                let aes_dec = aesni::AesNi192Decryptor::new(key);
                let dec = box CbcDecryptor::new(aes_dec, padding, Vec::from_slice(iv));
                dec as Box<Decryptor>
            }
            KeySize256 => {
                let aes_dec = aesni::AesNi256Decryptor::new(key);
                let dec = box CbcDecryptor::new(aes_dec, padding, Vec::from_slice(iv));
                dec as Box<Decryptor>
            }
        }
    } else {
        match key_size {
            KeySize128 => {
                let aes_dec = aessafe::AesSafe128Decryptor::new(key);
                let dec = box CbcDecryptor::new(aes_dec, padding, Vec::from_slice(iv));
                dec as Box<Decryptor>
            }
            KeySize192 => {
                let aes_dec = aessafe::AesSafe192Decryptor::new(key);
                let dec = box CbcDecryptor::new(aes_dec, padding, Vec::from_slice(iv));
                dec as Box<Decryptor>
            }
            KeySize256 => {
                let aes_dec = aessafe::AesSafe256Decryptor::new(key);
                let dec = box CbcDecryptor::new(aes_dec, padding, Vec::from_slice(iv));
                dec as Box<Decryptor>
            }
        }
    }
}

/// Get the best implementation of a CbcDecryptor
#[cfg(not(target_arch = "x86"), not(target_arch = "x86_64"))]
pub fn cbc_decryptor<X: PaddingProcessor + Send>(
        key_size: KeySize,
        key: &[u8],
        iv: &[u8],
        padding: X) -> Box<Decryptor> {
    match key_size {
        KeySize128 => {
            let aes_dec = aessafe::AesSafe128Decryptor::new(key);
            let dec = box CbcDecryptor::new(aes_dec, padding, Vec::from_slice(iv));
            dec as Box<Decryptor>
        }
        KeySize192 => {
            let aes_dec = aessafe::AesSafe192Decryptor::new(key);
            let dec = box CbcDecryptor::new(aes_dec, padding, Vec::from_slice(iv));
            dec as Box<Decryptor>
        }
        KeySize256 => {
            let aes_dec = aessafe::AesSafe256Decryptor::new(key);
            let dec = box CbcDecryptor::new(aes_dec, padding, Vec::from_slice(iv));
            dec as Box<Decryptor>
        }
    }
}

/// Get the best implementation of a Ctr
#[cfg(target_arch = "x86")]
#[cfg(target_arch = "x86_64")]
pub fn ctr(
        key_size: KeySize,
        key: &[u8],
        iv: &[u8]) -> Box<SynchronousStreamCipher> {
    if util::supports_aesni() {
        match key_size {
            KeySize128 => {
                let aes_dec = aesni::AesNi128Encryptor::new(key);
                let dec = box CtrMode::new(aes_dec, Vec::from_slice(iv));
                dec as Box<SynchronousStreamCipher>
            }
            KeySize192 => {
                let aes_dec = aesni::AesNi192Encryptor::new(key);
                let dec = box CtrMode::new(aes_dec, Vec::from_slice(iv));
                dec as Box<SynchronousStreamCipher>
            }
            KeySize256 => {
                let aes_dec = aesni::AesNi256Encryptor::new(key);
                let dec = box CtrMode::new(aes_dec, Vec::from_slice(iv));
                dec as Box<SynchronousStreamCipher>
            }
        }
    } else {
        match key_size {
            KeySize128 => {
                let aes_dec = aessafe::AesSafe128EncryptorX8::new(key);
                let dec = box CtrModeX8::new(aes_dec, iv);
                dec as Box<SynchronousStreamCipher>
            }
            KeySize192 => {
                let aes_dec = aessafe::AesSafe192EncryptorX8::new(key);
                let dec = box CtrModeX8::new(aes_dec, iv);
                dec as Box<SynchronousStreamCipher>
            }
            KeySize256 => {
                let aes_dec = aessafe::AesSafe256EncryptorX8::new(key);
                let dec = box CtrModeX8::new(aes_dec, iv);
                dec as Box<SynchronousStreamCipher>
            }
        }
    }
}

/// Get the best implementation of a Ctr
#[cfg(not(target_arch = "x86"), not(target_arch = "x86_64"))]
pub fn ctr(
        key_size: KeySize,
        key: &[u8],
        iv: &[u8]) -> Box<SynchronousStreamCipher> {
    match key_size {
        KeySize128 => {
            let aes_dec = aessafe::AesSafe128EncryptorX8::new(key);
            let dec = box CtrModeX8::new(aes_dec, iv);
            dec as Box<SynchronousStreamCipher>
        }
        KeySize192 => {
            let aes_dec = aessafe::AesSafe192EncryptorX8::new(key);
            let dec = box CtrModeX8::new(aes_dec, iv);
            dec as Box<SynchronousStreamCipher>
        }
        KeySize256 => {
            let aes_dec = aessafe::AesSafe256EncryptorX8::new(key);
            let dec = box CtrModeX8::new(aes_dec, iv);
            dec as Box<SynchronousStreamCipher>
        }
    }
}

#[cfg(test)]
mod test {
    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    use aesni;

    use aessafe;
    use symmetriccipher::{BlockEncryptor, BlockDecryptor, BlockEncryptorX8, BlockDecryptorX8};
    use util;

    // Test vectors from:
    // http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors

    struct Test {
        key: Vec<u8>,
        data: Vec<TestData>
    }

    struct TestData {
        plain: Vec<u8>,
        cipher: Vec<u8>
    }

    fn tests128() -> Vec<Test> {
        return vec![
            Test {
                key: vec![0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
                data: vec![
                    TestData {
                        plain:  vec![0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a],
                        cipher: vec![0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
                                 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97]
                    },
                    TestData {
                        plain:  vec![0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                                 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51],
                        cipher: vec![0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
                                 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf]
                    },
                    TestData {
                        plain:  vec![0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                                 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef],
                        cipher: vec![0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23,
                                 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88]
                    },
                    TestData {
                        plain:  vec![0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                                 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
                        cipher: vec![0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f,
                                 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4]
                    }
                ]
            }
        ];
    }

    fn tests192() -> Vec<Test> {
        return vec![
            Test {
                key: vec![0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
                       0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b],
                data: vec![
                    TestData {
                        plain:  vec![0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                  0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a],
                        cipher: vec![0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
                                  0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc]
                    },
                    TestData {
                        plain:  vec![0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                                  0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51],
                        cipher: vec![0x97, 0x41, 0x04, 0x84, 0x6d, 0x0a, 0xd3, 0xad,
                                  0x77, 0x34, 0xec, 0xb3, 0xec, 0xee, 0x4e, 0xef]
                    },
                    TestData {
                        plain:  vec![0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                                  0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef],
                        cipher: vec![0xef, 0x7a, 0xfd, 0x22, 0x70, 0xe2, 0xe6, 0x0a,
                                  0xdc, 0xe0, 0xba, 0x2f, 0xac, 0xe6, 0x44, 0x4e]
                    },
                    TestData {
                        plain:  vec![0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                                  0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
                        cipher: vec![0x9a, 0x4b, 0x41, 0xba, 0x73, 0x8d, 0x6c, 0x72,
                                  0xfb, 0x16, 0x69, 0x16, 0x03, 0xc1, 0x8e, 0x0e]
                    }
                ]
            }
        ];
    }

    fn tests256() -> Vec<Test> {
        return vec![
            Test {
                key: vec![0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                       0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                       0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                       0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4],
                data: vec![
                    TestData {
                        plain:  vec![0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                  0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a],
                        cipher: vec![0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
                                  0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8]
                    },
                    TestData {
                        plain:  vec![0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                                  0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51],
                        cipher: vec![0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26,
                                  0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70]
                    },
                    TestData {
                        plain:  vec![0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                                  0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef],
                        cipher: vec![0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9,
                                  0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d]
                    },
                    TestData {
                        plain:  vec![0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                                  0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
                        cipher: vec![0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff,
                                  0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7]
                    }
                ]
            }
        ];
    }

    fn run_test<E: BlockEncryptor, D: BlockDecryptor>(enc: &mut E, dec: &mut D, test: &Test) {
        let mut tmp = [0u8, ..16];
        for data in test.data.iter() {
            enc.encrypt_block(data.plain.as_slice(), tmp);
            assert!(tmp == data.cipher.as_slice());
            dec.decrypt_block(data.cipher.as_slice(), tmp);
            assert!(tmp == data.plain.as_slice());
        }
    }

    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_aesni_128() {
        if util::supports_aesni() {
            let tests = tests128();
            for t in tests.iter() {
                let mut enc = aesni::AesNi128Encryptor::new(t.key.as_slice());
                let mut dec = aesni::AesNi128Decryptor::new(t.key.as_slice());
                run_test(&mut enc, &mut dec, t);
            }
        }
    }

    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_aesni_192() {
        if util::supports_aesni() {
            let tests = tests192();
            for t in tests.iter() {
                let mut enc = aesni::AesNi192Encryptor::new(t.key.as_slice());
                let mut dec = aesni::AesNi192Decryptor::new(t.key.as_slice());
                run_test(&mut enc, &mut dec, t);
            }
        }
    }

    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_aesni_256() {
        if util::supports_aesni() {
            let tests = tests256();
            for t in tests.iter() {
                let mut enc = aesni::AesNi256Encryptor::new(t.key.as_slice());
                let mut dec = aesni::AesNi256Decryptor::new(t.key.as_slice());
                run_test(&mut enc, &mut dec, t);
            }
        }
    }

    #[test]
    fn test_aessafe_128() {
        let tests = tests128();
        for t in tests.iter() {
            let mut enc = aessafe::AesSafe128Encryptor::new(t.key.as_slice());
            let mut dec = aessafe::AesSafe128Decryptor::new(t.key.as_slice());
            run_test(&mut enc, &mut dec, t);
        }
    }

    #[test]
    fn test_aessafe_192() {
        let tests = tests192();
        for t in tests.iter() {
            let mut enc = aessafe::AesSafe192Encryptor::new(t.key.as_slice());
            let mut dec = aessafe::AesSafe192Decryptor::new(t.key.as_slice());
            run_test(&mut enc, &mut dec, t);
        }
    }

    #[test]
    fn test_aessafe_256() {
        let tests = tests256();
        for t in tests.iter() {
            let mut enc = aessafe::AesSafe256Encryptor::new(t.key.as_slice());
            let mut dec = aessafe::AesSafe256Decryptor::new(t.key.as_slice());
            run_test(&mut enc, &mut dec, t);
        }
    }

    // The following test vectors are all from NIST SP 800-38A

    #[test]
    fn test_aessafe_128_x8() {
        let key: [u8, ..16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c ];
        let plain: [u8, ..128] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
            0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
            0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 ];
        let cipher: [u8, ..128] = [
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
            0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
            0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
            0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
            0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23,
            0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
            0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f,
            0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4,
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
            0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
            0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
            0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
            0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23,
            0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
            0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f,
            0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4 ];

        let enc = aessafe::AesSafe128EncryptorX8::new(key);
        let dec = aessafe::AesSafe128DecryptorX8::new(key);
        let mut tmp = [0u8, ..128];
        enc.encrypt_block_x8(plain, tmp);
        assert!(tmp == cipher);
        dec.decrypt_block_x8(cipher, tmp);
        assert!(tmp == plain);
    }

    #[test]
    fn test_aessafe_192_x8() {
        let key: [u8, ..24] = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
            0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b ];
        let plain: [u8, ..128] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
            0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
            0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 ];
        let cipher: [u8, ..128] = [
            0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
            0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc,
            0x97, 0x41, 0x04, 0x84, 0x6d, 0x0a, 0xd3, 0xad,
            0x77, 0x34, 0xec, 0xb3, 0xec, 0xee, 0x4e, 0xef,
            0xef, 0x7a, 0xfd, 0x22, 0x70, 0xe2, 0xe6, 0x0a,
            0xdc, 0xe0, 0xba, 0x2f, 0xac, 0xe6, 0x44, 0x4e,
            0x9a, 0x4b, 0x41, 0xba, 0x73, 0x8d, 0x6c, 0x72,
            0xfb, 0x16, 0x69, 0x16, 0x03, 0xc1, 0x8e, 0x0e,
            0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
            0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc,
            0x97, 0x41, 0x04, 0x84, 0x6d, 0x0a, 0xd3, 0xad,
            0x77, 0x34, 0xec, 0xb3, 0xec, 0xee, 0x4e, 0xef,
            0xef, 0x7a, 0xfd, 0x22, 0x70, 0xe2, 0xe6, 0x0a,
            0xdc, 0xe0, 0xba, 0x2f, 0xac, 0xe6, 0x44, 0x4e,
            0x9a, 0x4b, 0x41, 0xba, 0x73, 0x8d, 0x6c, 0x72,
            0xfb, 0x16, 0x69, 0x16, 0x03, 0xc1, 0x8e, 0x0e ];

        let enc = aessafe::AesSafe192EncryptorX8::new(key);
        let dec = aessafe::AesSafe192DecryptorX8::new(key);
        let mut tmp = [0u8, ..128];
        enc.encrypt_block_x8(plain, tmp);
        assert!(tmp == cipher);
        dec.decrypt_block_x8(cipher, tmp);
        assert!(tmp == plain);
    }

    #[test]
    fn test_aessafe_256_x8() {
        let key: [u8, ..32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 ];
        let plain: [u8, ..128] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
            0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
            0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 ];
        let cipher: [u8, ..128] = [
            0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
            0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
            0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26,
            0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70,
            0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9,
            0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d,
            0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff,
            0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7,
            0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
            0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
            0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26,
            0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70,
            0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9,
            0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d,
            0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff,
            0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7 ];

        let enc = aessafe::AesSafe256EncryptorX8::new(key);
        let dec = aessafe::AesSafe256DecryptorX8::new(key);
        let mut tmp = [0u8, ..128];
        enc.encrypt_block_x8(plain, tmp);
        assert!(tmp == cipher);
        dec.decrypt_block_x8(cipher, tmp);
        assert!(tmp == plain);
    }
}

#[cfg(test)]
mod bench {
    use test::Bencher;

    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    use aesni;

    use aessafe;
    use symmetriccipher::{BlockEncryptor, BlockEncryptorX8};
    use util;

    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    #[bench]
    pub fn aesni_bench(bh: &mut Bencher) {
        if util::supports_aesni() {
            let key: [u8, ..16] = [1u8, ..16];
            let plain: [u8, ..16] = [2u8, ..16];

            let a = aesni::AesNi128Encryptor::new(key);

            let mut tmp = [0u8, ..16];

            bh.iter( || {
                a.encrypt_block(plain, tmp);
            });

            bh.bytes = (plain.len()) as u64;
        }
    }

    #[bench]
    pub fn aes_safe_bench(bh: &mut Bencher) {
        let key: [u8, ..16] = [1u8, ..16];
        let plain: [u8, ..16] = [2u8, ..16];

        let a = aessafe::AesSafe128Encryptor::new(key);

        let mut tmp = [0u8, ..16];

        bh.iter( || {
            a.encrypt_block(plain, tmp);
        });

        bh.bytes = (plain.len()) as u64;
    }

    #[bench]
    pub fn aes_safe_x8_bench(bh: &mut Bencher) {
        let key: [u8, ..16] = [1u8, ..16];
        let plain: [u8, ..128] = [2u8, ..128];

        let a = aessafe::AesSafe128EncryptorX8::new(key);

        let mut tmp = [0u8, ..128];

        bh.iter( || {
            a.encrypt_block_x8(plain, tmp);
        });

        bh.bytes = (plain.len()) as u64;
    }
}
