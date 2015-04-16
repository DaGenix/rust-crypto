// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module implements the HMAC-based Extract-and-Expand Key
//! Derivation Function as specified by  https://tools.ietf.org/html/rfc5869.

use std::iter::repeat;
use cryptoutil::copy_memory;

use hash::Digest;
use hmac::Hmac;
use mac::Mac;

/// Execute the HKDF-Extract function.  Applications MUST NOT use this for
/// password hashing.
///
/// # Arguments
/// * digest - The digest function to use.
/// * salt - The optional salt value (a non-secret random value) to use.
/// * ikm - The input keying material to use.
/// * prk - The output buffer to fill with a digest.output_bytes() length
///         pseudo random key.
pub fn hkdf_extract<D: Digest>(mut digest: D, salt: &[u8], ikm: &[u8], prk: &mut [u8]) {
    assert!(prk.len() == digest.output_bytes());
    digest.reset();

    let mut mac = Hmac::new(digest, salt);
    mac.input(ikm);
    mac.raw_result(prk);
    mac.reset();
}

/// Execute the HKDF-Expand function.  Applications MUST NOT use this for
/// password hashing.
///
/// # Arguments
/// * digest - The digest function to use.
/// * prk - The pseudorandom key of at least digest.output_bytes() octets.
/// * info - The optional context and application specific information to use.
/// * okm - The output buffer to fill with the derived key value.
pub fn hkdf_expand<D: Digest>(mut digest: D, prk: &[u8], info: &[u8], okm: &mut [u8]) {
    digest.reset();

    let mut mac = Hmac::new(digest, prk);
    let os = mac.output_bytes();
    let mut t: Vec<u8> = repeat(0).take(os).collect();
    let mut n: u8 = 0;

    for chunk in okm.chunks_mut(os) {
        // The block index starts at 1. So, this is supposed to run on the first execution.
        n = n.checked_add(1).expect("HKDF size limit exceeded.");

        if n != 1 {
            mac.input(&t[..]);
        }
        let nbuf = [n];
        mac.input(info);
        mac.input(&nbuf);
        mac.raw_result(&mut t);
        mac.reset();
        let chunk_len = chunk.len();
        copy_memory(&t[..chunk_len], chunk);
    }
}

#[cfg(test)]
mod test {
    use std::iter::repeat;

    use hash::Digest;
    use hash::hkdf::{hkdf_extract, hkdf_expand};
    use hash::sha1::Sha1;
    use hash::sha2::Sha256;

    struct TestVector<D: Digest>{
        digest: D,
        ikm: Vec<u8>,
        salt: Vec<u8>,
        info: Vec<u8>,
        l: usize,

        prk: Vec<u8>,
        okm: Vec<u8>,
    }

    #[test]
    fn test_hkdf_rfc5869_sha256_vectors() {
        let test_vectors = vec!(
            TestVector{
                digest: Sha256::new(),
                ikm: repeat(0x0b).take(22).collect(),
                salt: (0x00..0x0c + 1).collect(),
                info: (0xf0..0xf9 + 1).collect(),
                l: 42,
                prk: vec![
                    0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
                    0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
                    0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
                    0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5 ],
                okm: vec![
                    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
                    0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
                    0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
                    0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
                    0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
                    0x58, 0x65 ],
            },
            TestVector{
                digest: Sha256::new(),
                ikm: (0x00..0x4f + 1).collect(),
                salt: (0x60..0xaf + 1).collect(),
                info: (0xb0..0xff + 1).map(|x| x as u8).collect(),
                l: 82,
                prk: vec![
                    0x06, 0xa6, 0xb8, 0x8c, 0x58, 0x53, 0x36, 0x1a,
                    0x06, 0x10, 0x4c, 0x9c, 0xeb, 0x35, 0xb4, 0x5c,
                    0xef, 0x76, 0x00, 0x14, 0x90, 0x46, 0x71, 0x01,
                    0x4a, 0x19, 0x3f, 0x40, 0xc1, 0x5f, 0xc2, 0x44 ],
                okm: vec![
                    0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1,
                    0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
                    0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8,
                    0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
                    0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72,
                    0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
                    0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
                    0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
                    0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87,
                    0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
                    0x1d, 0x87 ],
            },
            TestVector{
                digest: Sha256::new(),
                ikm: repeat(0x0b).take(22).collect(),
                salt: vec![],
                info: vec![],
                l:42,
                prk: vec![
                    0x19, 0xef, 0x24, 0xa3, 0x2c, 0x71, 0x7b, 0x16,
                    0x7f, 0x33, 0xa9, 0x1d, 0x6f, 0x64, 0x8b, 0xdf,
                    0x96, 0x59, 0x67, 0x76, 0xaf, 0xdb, 0x63, 0x77,
                    0xac, 0x43, 0x4c, 0x1c, 0x29, 0x3c, 0xcb, 0x04 ],
                okm: vec![
                    0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f,
                    0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
                    0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e,
                    0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
                    0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a,
                    0x96, 0xc8 ],
            },
        );

        for t in test_vectors.iter() {
            let mut prk: Vec<u8> = repeat(0).take(t.prk.len()).collect();
            hkdf_extract(t.digest, &t.salt[..], &t.ikm[..], &mut prk);
            assert!(prk == t.prk);

            let mut okm: Vec<u8> = repeat(0).take(t.okm.len()).collect();
            assert!(okm.len() == t.l);
            hkdf_expand(t.digest, &prk[..], &t.info[..], &mut okm);
            assert!(okm == t.okm);
        }
    }

    #[test]
    fn test_hkdf_rfc5869_sha1_vectors() {
        let test_vectors = vec!(
            TestVector{
                digest: Sha1::new(),
                ikm: repeat(0x0b).take(11).collect(),
                salt: (0x00..0x0c + 1).collect(),
                info: (0xf0..0xf9 + 1).collect(),
                l: 42,
                prk: vec![
                    0x9b, 0x6c, 0x18, 0xc4, 0x32, 0xa7, 0xbf, 0x8f,
                    0x0e, 0x71, 0xc8, 0xeb, 0x88, 0xf4, 0xb3, 0x0b,
                    0xaa, 0x2b, 0xa2, 0x43 ],
                okm: vec![
                    0x08, 0x5a, 0x01, 0xea, 0x1b, 0x10, 0xf3, 0x69,
                    0x33, 0x06, 0x8b, 0x56, 0xef, 0xa5, 0xad, 0x81,
                    0xa4, 0xf1, 0x4b, 0x82, 0x2f, 0x5b, 0x09, 0x15,
                    0x68, 0xa9, 0xcd, 0xd4, 0xf1, 0x55, 0xfd, 0xa2,
                    0xc2, 0x2e, 0x42, 0x24, 0x78, 0xd3, 0x05, 0xf3,
                    0xf8, 0x96 ],
            },
            TestVector{
                digest: Sha1::new(),
                ikm: (0x00..0x4f + 1).collect(),
                salt: (0x60..0xaf + 1).collect(),
                info: (0xb0..0xff + 1).map(|x| x as u8).collect(),
                l: 82,
                prk: vec![
                    0x8a, 0xda, 0xe0, 0x9a, 0x2a, 0x30, 0x70, 0x59,
                    0x47, 0x8d, 0x30, 0x9b, 0x26, 0xc4, 0x11, 0x5a,
                    0x22, 0x4c, 0xfa, 0xf6 ],
                okm: vec![
                    0x0b, 0xd7, 0x70, 0xa7, 0x4d, 0x11, 0x60, 0xf7,
                    0xc9, 0xf1, 0x2c, 0xd5, 0x91, 0x2a, 0x06, 0xeb,
                    0xff, 0x6a, 0xdc, 0xae, 0x89, 0x9d, 0x92, 0x19,
                    0x1f, 0xe4, 0x30, 0x56, 0x73, 0xba, 0x2f, 0xfe,
                    0x8f, 0xa3, 0xf1, 0xa4, 0xe5, 0xad, 0x79, 0xf3,
                    0xf3, 0x34, 0xb3, 0xb2, 0x02, 0xb2, 0x17, 0x3c,
                    0x48, 0x6e, 0xa3, 0x7c, 0xe3, 0xd3, 0x97, 0xed,
                    0x03, 0x4c, 0x7f, 0x9d, 0xfe, 0xb1, 0x5c, 0x5e,
                    0x92, 0x73, 0x36, 0xd0, 0x44, 0x1f, 0x4c, 0x43,
                    0x00, 0xe2, 0xcf, 0xf0, 0xd0, 0x90, 0x0b, 0x52,
                    0xd3, 0xb4 ],
            },
            TestVector{
                digest: Sha1::new(),
                ikm: repeat(0x0b).take(22).collect(),
                salt: vec![],
                info: vec![],
                l:42,
                prk: vec![
                    0xda, 0x8c, 0x8a, 0x73, 0xc7, 0xfa, 0x77, 0x28,
                    0x8e, 0xc6, 0xf5, 0xe7, 0xc2, 0x97, 0x78, 0x6a,
                    0xa0, 0xd3, 0x2d, 0x01 ],
                okm: vec![
                    0x0a, 0xc1, 0xaf, 0x70, 0x02, 0xb3, 0xd7, 0x61,
                    0xd1, 0xe5, 0x52, 0x98, 0xda, 0x9d, 0x05, 0x06,
                    0xb9, 0xae, 0x52, 0x05, 0x72, 0x20, 0xa3, 0x06,
                    0xe0, 0x7b, 0x6b, 0x87, 0xe8, 0xdf, 0x21, 0xd0,
                    0xea, 0x00, 0x03, 0x3d, 0xe0, 0x39, 0x84, 0xd3,
                    0x49, 0x18 ],
            },
        );

        for t in test_vectors.iter() {
            let mut prk: Vec<u8> = repeat(0).take(t.prk.len()).collect();
            hkdf_extract(t.digest, &t.salt[..], &t.ikm[..], &mut prk);
            assert!(prk == t.prk);

            let mut okm: Vec<u8> = repeat(0).take(t.okm.len()).collect();
            assert!(okm.len() == t.l);
            hkdf_expand(t.digest, &prk[..], &t.info[..], &mut okm);
            assert!(okm == t.okm);
        }
    }
}
