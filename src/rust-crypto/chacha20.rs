// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
use std::simd::u32x4;

use buffer::{BufferResult, RefReadBuffer, RefWriteBuffer};
use symmetriccipher::{Encryptor, Decryptor, SynchronousStreamCipher, SymmetricCipherError};
use cryptoutil::{read_u32_le, symm_enc_or_dec, write_u32_le};

#[deriving(Copy)]
struct ChaChaState {
  a: u32x4,
  b: u32x4,
  c: u32x4,
  d: u32x4
}

#[deriving(Copy)]
pub struct ChaCha20 {
    state  : ChaChaState,
    output : [u8,  ..64],
    offset : uint,
}

impl ChaCha20 {
    pub fn new(key: &[u8], nonce: &[u8]) -> ChaCha20 {
        assert!(key.len() == 16 || key.len() == 32);
        assert!(nonce.len() == 8);

        ChaCha20{ state: ChaCha20::expand(key, nonce), output: [0u8, ..64], offset: 64 }
    }

    fn expand(key: &[u8], nonce: &[u8]) -> ChaChaState {
        
        let constant = match key.len() {
            16 => b"expand 16-byte k",
            32 => b"expand 32-byte k",
            _  => unreachable!(),
        };
        ChaChaState {
            a: u32x4(
                read_u32_le(constant[0..4]),
                read_u32_le(constant[4..8]),
                read_u32_le(constant[8..12]),
                read_u32_le(constant[12..16])
            ),
            b: u32x4(
                read_u32_le(key[0..4]),
                read_u32_le(key[4..8]),
                read_u32_le(key[8..12]),
                read_u32_le(key[12..16])
            ),
            c: if key.len() == 16 {
                    u32x4(
                        read_u32_le(key[0..4]),
                        read_u32_le(key[4..8]),
                        read_u32_le(key[8..12]),
                        read_u32_le(key[12..16])
                    )
                } else {
                    u32x4(
                        read_u32_le(key[16..20]),
                        read_u32_le(key[20..24]),
                        read_u32_le(key[24..28]),
                        read_u32_le(key[28..32])
                    )
                },
            d: u32x4(
                0,
                0,
                read_u32_le(nonce[0..4]),
                read_u32_le(nonce[4..8])
            )
        }
    }

    fn rotate(v:u32x4, c: u32x4) -> u32x4{
      let s32 = u32x4(32, 32, 32, 32);
      let r = s32 - c;
      let right = v >> r;
      (v << c) ^ right
    }

    fn round(state: &mut ChaChaState) -> () {
          let s16 = u32x4(16, 16, 16, 16);
          let s12 = u32x4(12, 12, 12, 12);
          let s8 = u32x4(8, 8, 8, 8);
          let s7 = u32x4(7, 7, 7, 7);
          
          state.a = state.a + state.b;
          state.d = ChaCha20::rotate(state.d ^ state.a, s16);
          state.c = state.c + state.d;
          state.b = ChaCha20::rotate(state.b ^ state.c, s12);
          state.a = state.a + state.b;
          state.d = ChaCha20::rotate(state.d ^ state.a, s8);
          state.c = state.c + state.d;
          state.b = ChaCha20::rotate(state.b ^ state.c, s7);
    }

    // put the the next 64 keystream bytes into self.output
    fn update(&mut self) {
        let mut state = self.state;

        for _ in range(0u, 10) {
            ChaCha20::round(&mut state);
            let u32x4(b10, b11, b12, b13) = state.b;
            state.b = u32x4(b11, b12, b13, b10);
            let u32x4(c10, c11, c12, c13) = state.c;
            state.c = u32x4(c12, c13,c10, c11);
            let u32x4(d10, d11, d12, d13) = state.d;
            state.d = u32x4(d13, d10, d11, d12);
            ChaCha20::round(&mut state);
            let u32x4(b20, b21, b22, b23) = state.b;
            state.b = u32x4(b23, b20, b21, b22);
            let u32x4(c20, c21, c22, c23) = state.c;
            state.c = u32x4(c22, c23, c20, c21);
            let u32x4(d20, d21, d22, d23) = state.d;
            state.d = u32x4(d21, d22, d23, d20);
        }
        let u32x4(a1, a2, a3, a4) = self.state.a + state.a;
        let u32x4(b1, b2, b3, b4) = self.state.b + state.b;
        let u32x4(c1, c2, c3, c4) = self.state.c + state.c;
        let u32x4(d1, d2, d3, d4) = self.state.d + state.d;
        let lens = [
            a1,a2,a3,a4,
            b1,b2,b3,b4,
            c1,c2,c3,c4,
            d1,d2,d3,d4
        ];
        for i in range(0, lens.len()) {
            write_u32_le(self.output.slice_mut(i*4,(i+1)*4), lens[i]);
        }

        self.state.d += u32x4(1, 0, 0, 0);
        let u32x4(c12, _, _, _) = self.state.d;
        if c12 == 0 {
            self.state.d += u32x4(0, 1, 0, 0);
        }

        self.offset = 0;
    }

    fn next(&mut self) -> u8 {
        if self.offset == 64 {
            self.update();
        }
        let r = self.output[self.offset];
        self.offset += 1;
        r
    }

}

impl SynchronousStreamCipher for ChaCha20 {
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        assert!(input.len() == output.len());
        for (x, y) in input.iter().zip(output.iter_mut()) {
            *y = *x ^ self.next();
        }
    }
}

impl Encryptor for ChaCha20 {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

impl Decryptor for ChaCha20 {
    fn decrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

#[cfg(test)]
mod test {
    use chacha20::ChaCha20;
    use symmetriccipher::SynchronousStreamCipher;

    #[test]
    fn test_chacha20_256_tls_vectors() {
        struct TestVector {
            key:   [u8, ..32],
            nonce: [u8, ..8],
            keystream: Vec<u8>,
        };
        // taken from http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04
        let test_vectors = vec!(
            TestVector{
                key: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                nonce: [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
                keystream: vec!(
                    0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
                    0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
                    0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
                    0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
                    0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
                    0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
                    0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
                    0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
                ),
            }, TestVector{
                key: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                ],
                nonce: [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
                keystream: vec!(
                    0x45, 0x40, 0xf0, 0x5a, 0x9f, 0x1f, 0xb2, 0x96,
                    0xd7, 0x73, 0x6e, 0x7b, 0x20, 0x8e, 0x3c, 0x96,
                    0xeb, 0x4f, 0xe1, 0x83, 0x46, 0x88, 0xd2, 0x60,
                    0x4f, 0x45, 0x09, 0x52, 0xed, 0x43, 0x2d, 0x41,
                    0xbb, 0xe2, 0xa0, 0xb6, 0xea, 0x75, 0x66, 0xd2,
                    0xa5, 0xd1, 0xe7, 0xe2, 0x0d, 0x42, 0xaf, 0x2c,
                    0x53, 0xd7, 0x92, 0xb1, 0xc4, 0x3f, 0xea, 0x81,
                    0x7e, 0x9a, 0xd2, 0x75, 0xae, 0x54, 0x69, 0x63,
                ),
            }, TestVector{
                key: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                nonce: [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ],
                keystream: vec!(
                    0xde, 0x9c, 0xba, 0x7b, 0xf3, 0xd6, 0x9e, 0xf5,
                    0xe7, 0x86, 0xdc, 0x63, 0x97, 0x3f, 0x65, 0x3a,
                    0x0b, 0x49, 0xe0, 0x15, 0xad, 0xbf, 0xf7, 0x13,
                    0x4f, 0xcb, 0x7d, 0xf1, 0x37, 0x82, 0x10, 0x31,
                    0xe8, 0x5a, 0x05, 0x02, 0x78, 0xa7, 0x08, 0x45,
                    0x27, 0x21, 0x4f, 0x73, 0xef, 0xc7, 0xfa, 0x5b,
                    0x52, 0x77, 0x06, 0x2e, 0xb7, 0xa0, 0x43, 0x3e,
                    0x44, 0x5f, 0x41, 0xe3,
                ),
            }, TestVector{
                key: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                nonce: [ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
                keystream: vec!(
                    0xef, 0x3f, 0xdf, 0xd6, 0xc6, 0x15, 0x78, 0xfb,
                    0xf5, 0xcf, 0x35, 0xbd, 0x3d, 0xd3, 0x3b, 0x80,
                    0x09, 0x63, 0x16, 0x34, 0xd2, 0x1e, 0x42, 0xac,
                    0x33, 0x96, 0x0b, 0xd1, 0x38, 0xe5, 0x0d, 0x32,
                    0x11, 0x1e, 0x4c, 0xaf, 0x23, 0x7e, 0xe5, 0x3c,
                    0xa8, 0xad, 0x64, 0x26, 0x19, 0x4a, 0x88, 0x54,
                    0x5d, 0xdc, 0x49, 0x7a, 0x0b, 0x46, 0x6e, 0x7d,
                    0x6b, 0xbd, 0xb0, 0x04, 0x1b, 0x2f, 0x58, 0x6b,
                ),
            }, TestVector{
                key: [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                ],
                nonce: [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 ],
                keystream: vec!(
                    0xf7, 0x98, 0xa1, 0x89, 0xf1, 0x95, 0xe6, 0x69,
                    0x82, 0x10, 0x5f, 0xfb, 0x64, 0x0b, 0xb7, 0x75,
                    0x7f, 0x57, 0x9d, 0xa3, 0x16, 0x02, 0xfc, 0x93,
                    0xec, 0x01, 0xac, 0x56, 0xf8, 0x5a, 0xc3, 0xc1,
                    0x34, 0xa4, 0x54, 0x7b, 0x73, 0x3b, 0x46, 0x41,
                    0x30, 0x42, 0xc9, 0x44, 0x00, 0x49, 0x17, 0x69,
                    0x05, 0xd3, 0xbe, 0x59, 0xea, 0x1c, 0x53, 0xf1,
                    0x59, 0x16, 0x15, 0x5c, 0x2b, 0xe8, 0x24, 0x1a,
                    0x38, 0x00, 0x8b, 0x9a, 0x26, 0xbc, 0x35, 0x94,
                    0x1e, 0x24, 0x44, 0x17, 0x7c, 0x8a, 0xde, 0x66,
                    0x89, 0xde, 0x95, 0x26, 0x49, 0x86, 0xd9, 0x58,
                    0x89, 0xfb, 0x60, 0xe8, 0x46, 0x29, 0xc9, 0xbd,
                    0x9a, 0x5a, 0xcb, 0x1c, 0xc1, 0x18, 0xbe, 0x56,
                    0x3e, 0xb9, 0xb3, 0xa4, 0xa4, 0x72, 0xf8, 0x2e,
                    0x09, 0xa7, 0xe7, 0x78, 0x49, 0x2b, 0x56, 0x2e,
                    0xf7, 0x13, 0x0e, 0x88, 0xdf, 0xe0, 0x31, 0xc7,
                    0x9d, 0xb9, 0xd4, 0xf7, 0xc7, 0xa8, 0x99, 0x15,
                    0x1b, 0x9a, 0x47, 0x50, 0x32, 0xb6, 0x3f, 0xc3,
                    0x85, 0x24, 0x5f, 0xe0, 0x54, 0xe3, 0xdd, 0x5a,
                    0x97, 0xa5, 0xf5, 0x76, 0xfe, 0x06, 0x40, 0x25,
                    0xd3, 0xce, 0x04, 0x2c, 0x56, 0x6a, 0xb2, 0xc5,
                    0x07, 0xb1, 0x38, 0xdb, 0x85, 0x3e, 0x3d, 0x69,
                    0x59, 0x66, 0x09, 0x96, 0x54, 0x6c, 0xc9, 0xc4,
                    0xa6, 0xea, 0xfd, 0xc7, 0x77, 0xc0, 0x40, 0xd7,
                    0x0e, 0xaf, 0x46, 0xf7, 0x6d, 0xad, 0x39, 0x79,
                    0xe5, 0xc5, 0x36, 0x0c, 0x33, 0x17, 0x16, 0x6a,
                    0x1c, 0x89, 0x4c, 0x94, 0xa3, 0x71, 0x87, 0x6a,
                    0x94, 0xdf, 0x76, 0x28, 0xfe, 0x4e, 0xaa, 0xf2,
                    0xcc, 0xb2, 0x7d, 0x5a, 0xaa, 0xe0, 0xad, 0x7a,
                    0xd0, 0xf9, 0xd4, 0xb6, 0xad, 0x3b, 0x54, 0x09,
                    0x87, 0x46, 0xd4, 0x52, 0x4d, 0x38, 0x40, 0x7a,
                    0x6d, 0xeb, 0x3a, 0xb7, 0x8f, 0xab, 0x78, 0xc9,
                ),
            },
        );

        for tv in test_vectors.iter() {
            let mut c = ChaCha20::new(&tv.key, &tv.nonce);
            let input = Vec::from_elem(tv.keystream.len(), 0u8);
            let mut output = Vec::from_elem(input.len(), 0u8);
            c.process(input[], output.as_mut_slice());
            assert_eq!(output, tv.keystream);
        }
    }
}

#[cfg(test)]
mod bench {
    use test::Bencher;
    use symmetriccipher::SynchronousStreamCipher;
    use chacha20::ChaCha20;

    #[bench]
    pub fn chacha20_10(bh: & mut Bencher) {
        let mut chacha20 = ChaCha20::new(&[0, ..32], &[0, ..8]);
        let input = [1u8, ..10];
        let mut output = [0u8, ..10];
        bh.iter( || {
            chacha20.process(&input, &mut output);
        });
        bh.bytes = input.len() as u64;
    }

    #[bench]
    pub fn chacha20_1k(bh: & mut Bencher) {
        let mut chacha20 = ChaCha20::new(&[0, ..32], &[0, ..8]);
        let input = [1u8, ..1024];
        let mut output = [0u8, ..1024];
        bh.iter( || {
            chacha20.process(&input, &mut output);
        });
        bh.bytes = input.len() as u64;
    }

    #[bench]
    pub fn chacha20_64k(bh: & mut Bencher) {
        let mut chacha20 = ChaCha20::new(&[0, ..32], &[0, ..8]);
        let input = [1u8, ..65536];
        let mut output = [0u8, ..65536];
        bh.iter( || {
            chacha20.process(&input, &mut output);
        });
        bh.bytes = input.len() as u64;
    }
}
