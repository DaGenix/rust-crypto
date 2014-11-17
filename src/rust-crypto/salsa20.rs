// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use buffer::{BufferResult, RefReadBuffer, RefWriteBuffer};
use symmetriccipher::{Encryptor, Decryptor, SynchronousStreamCipher, SymmetricCipherError};
use cryptoutil::{read_u32v_le, symm_enc_or_dec, write_u32_le};

use std::num::Int;
use std::slice::bytes::copy_memory;

pub struct Salsa20 {
    state: [u8, ..64],
    output: [u8, ..64],
    counter: u64,
    offset: uint,
}

fn doubleround(y: &mut [u32, ..16]) {
    y[ 4] = y[ 4] ^ (y[ 0]+y[12]).rotate_left( 7);
    y[ 8] = y[ 8] ^ (y[ 4]+y[ 0]).rotate_left( 9);
    y[12] = y[12] ^ (y[ 8]+y[ 4]).rotate_left(13);
    y[ 0] = y[ 0] ^ (y[12]+y[ 8]).rotate_left(18);
    
    y[ 9] = y[ 9] ^ (y[ 5]+y[ 1]).rotate_left( 7);
    y[13] = y[13] ^ (y[ 9]+y[ 5]).rotate_left( 9);
    y[ 1] = y[ 1] ^ (y[13]+y[ 9]).rotate_left(13);
    y[ 5] = y[ 5] ^ (y[ 1]+y[13]).rotate_left(18);

    y[14] = y[14] ^ (y[10]+y[ 6]).rotate_left( 7);
    y[ 2] = y[ 2] ^ (y[14]+y[10]).rotate_left( 9);
    y[ 6] = y[ 6] ^ (y[ 2]+y[14]).rotate_left(13);
    y[10] = y[10] ^ (y[ 6]+y[ 2]).rotate_left(18);

    y[ 3] = y[ 3] ^ (y[15]+y[11]).rotate_left( 7);
    y[ 7] = y[ 7] ^ (y[ 3]+y[15]).rotate_left( 9);
    y[11] = y[11] ^ (y[ 7]+y[ 3]).rotate_left(13);
    y[15] = y[15] ^ (y[11]+y[ 7]).rotate_left(18);

    y[1] = y[1] ^ (y[0]+y[3]).rotate_left( 7);
    y[2] = y[2] ^ (y[1]+y[0]).rotate_left( 9);
    y[3] = y[3] ^ (y[2]+y[1]).rotate_left(13);
    y[0] = y[0] ^ (y[3]+y[2]).rotate_left(18);

    y[6] = y[6] ^ (y[5]+y[4]).rotate_left( 7);
    y[7] = y[7] ^ (y[6]+y[5]).rotate_left( 9);
    y[4] = y[4] ^ (y[7]+y[6]).rotate_left(13);
    y[5] = y[5] ^ (y[4]+y[7]).rotate_left(18);

    y[11] = y[11] ^ (y[10]+y[ 9]).rotate_left( 7);
    y[ 8] = y[ 8] ^ (y[11]+y[10]).rotate_left( 9);
    y[ 9] = y[ 9] ^ (y[ 8]+y[11]).rotate_left(13);
    y[10] = y[10] ^ (y[ 9]+y[ 8]).rotate_left(18);

    y[12] = y[12] ^ (y[15]+y[14]).rotate_left( 7);
    y[13] = y[13] ^ (y[12]+y[15]).rotate_left( 9);
    y[14] = y[14] ^ (y[13]+y[12]).rotate_left(13);
    y[15] = y[15] ^ (y[14]+y[13]).rotate_left(18);
}

impl Salsa20 {
    pub fn new(key: &[u8], nonce: &[u8]) -> Salsa20 {
        let mut salsa20 = Salsa20 { state: [0, ..64], output: [0, ..64], counter: 0, offset: 64 };

        assert!(key.len() == 16 || key.len() == 32);
        assert!(nonce.len() == 8);
        
        if key.len() == 16 {
            salsa20.expand16(key, nonce);
        } else {
            salsa20.expand32(key, nonce);
        }

        return salsa20;
    }

    pub fn new_xsalsa20(key: &[u8], nonce: &[u8]) -> Salsa20 {
        assert!(key.len() == 32);
        assert!(nonce.len() == 24);
        let mut xsalsa20 = Salsa20 { state: [0, ..64], output: [0, ..64], counter: 0, offset: 64 };

        xsalsa20.hsalsa20_expand(key, nonce[0..16]);
        xsalsa20.hsalsa20_hash();

        let mut new_key = [0, ..32];
        copy_memory(new_key[mut 0..4], xsalsa20.output[0..4]);
        copy_memory(new_key[mut 4..8], xsalsa20.output[20..24]);
        copy_memory(new_key[mut 8..12], xsalsa20.output[40..44]);
        copy_memory(new_key[mut 12..16], xsalsa20.output[60..64]);
        copy_memory(new_key[mut 16..32], xsalsa20.output[24..40]);

        xsalsa20.expand32(new_key, nonce[16..24]);

        return xsalsa20;
    }

    fn expand16(&mut self, key: &[u8], nonce: &[u8]) {
        copy_memory(self.state[mut 0..4], [101u8, 120, 112, 97]);
        copy_memory(self.state[mut 4..20], key);
        copy_memory(self.state[mut 20..24], [110u8, 100, 32, 49]);
        copy_memory(self.state[mut 24..32], nonce);
        copy_memory(self.state[mut 40..44], [54u8, 45, 98, 121]);
        copy_memory(self.state[mut 44..60], key);
        copy_memory(self.state[mut 60..64], [116u8, 101, 32, 107]);
    }

    fn expand32(&mut self, key: &[u8], nonce: &[u8]) {
        copy_memory(self.state[mut 0..4], [101u8, 120, 112, 97]);
        copy_memory(self.state[mut 4..20], key[0..16]);
        copy_memory(self.state[mut 20..24], [110u8, 100, 32, 51]);
        copy_memory(self.state[mut 24..32], nonce);
        copy_memory(self.state[mut 40..44], [50u8, 45, 98, 121]);
        copy_memory(self.state[mut 44..60], key[16..32]);
        copy_memory(self.state[mut 60..64], [116u8, 101, 32, 107]);
    }

    fn hsalsa20_expand(&mut self, key: &[u8], nonce: &[u8]) {
        copy_memory(self.state[mut 0..4], [101u8, 120, 112, 97]);
        copy_memory(self.state[mut 4..20], key[0..16]);
        copy_memory(self.state[mut 20..24], [110u8, 100, 32, 51]);
        copy_memory(self.state[mut 24..40], nonce);
        copy_memory(self.state[mut 40..44], [50u8, 45, 98, 121]);
        copy_memory(self.state[mut 44..60], key[16..32]);
        copy_memory(self.state[mut 60..64], [116u8, 101, 32, 107]);
    }

    fn hash(&mut self) {
        write_u32_le(self.state[mut 32..36], self.counter as u32);
        write_u32_le(self.state[mut 36..40], (self.counter >> 32) as u32);
        
        let mut x = [0u32, ..16];
        let mut z = [0u32, ..16];
        read_u32v_le(x[mut], self.state);
        read_u32v_le(z[mut], self.state);
        for _ in range(0u, 10) {
            doubleround(&mut z);
        }
        for i in range(0u, 16) {
            write_u32_le(self.output[mut i*4..(i+1)*4], x[i] + z[i]);
        }
        
        self.counter += 1;
        self.offset = 0;
    }

    fn hsalsa20_hash(&mut self) {
        let mut x = [0u32, ..16];
        read_u32v_le(x[mut], self.state);
        for _ in range(0u, 10) {
            doubleround(&mut x);
        }
        for i in range(0u, 16) {
            write_u32_le(self.output[mut i*4..(i+1)*4], x[i]);
        }
    }

    fn next(&mut self) -> u8 {
        if self.offset == 64 {
            self.hash();
        }
        let ret = self.output[self.offset];
        self.offset += 1;
        return ret;
    }
}

impl SynchronousStreamCipher for Salsa20 {
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        assert!(input.len() == output.len());
        for (x, y) in input.iter().zip(output.iter_mut()) {
            *y = *x ^ self.next();
        }
    }
}

impl Encryptor for Salsa20 {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

impl Decryptor for Salsa20 {
    fn decrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

#[cfg(test)]
mod test {
    use salsa20::Salsa20;
    use symmetriccipher::SynchronousStreamCipher;

    #[test]
    fn test_salsa20_128bit_ecrypt_set_1_vector_0() {
        let key = [128u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let nonce = [0u8, ..8];
        let input = [0u8, ..64];
        let mut stream = [0u8, ..64];
        let result =
            [0x4D, 0xFA, 0x5E, 0x48, 0x1D, 0xA2, 0x3E, 0xA0,
             0x9A, 0x31, 0x02, 0x20, 0x50, 0x85, 0x99, 0x36,
             0xDA, 0x52, 0xFC, 0xEE, 0x21, 0x80, 0x05, 0x16,
             0x4F, 0x26, 0x7C, 0xB6, 0x5F, 0x5C, 0xFD, 0x7F,
             0x2B, 0x4F, 0x97, 0xE0, 0xFF, 0x16, 0x92, 0x4A, 
             0x52, 0xDF, 0x26, 0x95, 0x15, 0x11, 0x0A, 0x07,
             0xF9, 0xE4, 0x60, 0xBC, 0x65, 0xEF, 0x95, 0xDA, 
             0x58, 0xF7, 0x40, 0xB7, 0xD1, 0xDB, 0xB0, 0xAA];

        let mut salsa20 = Salsa20::new(key, nonce);
        salsa20.process(input, stream);
        assert!(stream[] == result[]);
    }
    
    #[test]
    fn test_salsa20_256bit_ecrypt_set_1_vector_0() {
        let key =
            [128u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let nonce = [0u8, ..8];
        let input = [0u8, ..64];
        let mut stream = [0u8, ..64];
        let result =
            [0xE3, 0xBE, 0x8F, 0xDD, 0x8B, 0xEC, 0xA2, 0xE3,
             0xEA, 0x8E, 0xF9, 0x47, 0x5B, 0x29, 0xA6, 0xE7,
             0x00, 0x39, 0x51, 0xE1, 0x09, 0x7A, 0x5C, 0x38,
             0xD2, 0x3B, 0x7A, 0x5F, 0xAD, 0x9F, 0x68, 0x44,
             0xB2, 0x2C, 0x97, 0x55, 0x9E, 0x27, 0x23, 0xC7,
             0xCB, 0xBD, 0x3F, 0xE4, 0xFC, 0x8D, 0x9A, 0x07,
             0x44, 0x65, 0x2A, 0x83, 0xE7, 0x2A, 0x9C, 0x46,
             0x18, 0x76, 0xAF, 0x4D, 0x7E, 0xF1, 0xA1, 0x17];

        let mut salsa20 = Salsa20::new(key, nonce);
        salsa20.process(input, stream);
        assert!(stream[] == result[]);
    }

    #[test]
    fn test_xsalsa20_cryptopp() {
        let key = 
            [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
             0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
             0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
             0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89];
        let nonce =
            [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
             0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
             0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37];
        let input = [0u8, ..139];
        let mut stream = [0u8, ..139];
        let result =
            [0xee, 0xa6, 0xa7, 0x25, 0x1c, 0x1e, 0x72, 0x91,
             0x6d, 0x11, 0xc2, 0xcb, 0x21, 0x4d, 0x3c, 0x25,
             0x25, 0x39, 0x12, 0x1d, 0x8e, 0x23, 0x4e, 0x65,
             0x2d, 0x65, 0x1f, 0xa4, 0xc8, 0xcf, 0xf8, 0x80,
             0x30, 0x9e, 0x64, 0x5a, 0x74, 0xe9, 0xe0, 0xa6,
             0x0d, 0x82, 0x43, 0xac, 0xd9, 0x17, 0x7a, 0xb5,
             0x1a, 0x1b, 0xeb, 0x8d, 0x5a, 0x2f, 0x5d, 0x70,
             0x0c, 0x09, 0x3c, 0x5e, 0x55, 0x85, 0x57, 0x96,
             0x25, 0x33, 0x7b, 0xd3, 0xab, 0x61, 0x9d, 0x61,
             0x57, 0x60, 0xd8, 0xc5, 0xb2, 0x24, 0xa8, 0x5b,
             0x1d, 0x0e, 0xfe, 0x0e, 0xb8, 0xa7, 0xee, 0x16,
             0x3a, 0xbb, 0x03, 0x76, 0x52, 0x9f, 0xcc, 0x09,
             0xba, 0xb5, 0x06, 0xc6, 0x18, 0xe1, 0x3c, 0xe7,
             0x77, 0xd8, 0x2c, 0x3a, 0xe9, 0xd1, 0xa6, 0xf9,
             0x72, 0xd4, 0x16, 0x02, 0x87, 0xcb, 0xfe, 0x60,
             0xbf, 0x21, 0x30, 0xfc, 0x0a, 0x6f, 0xf6, 0x04,
             0x9d, 0x0a, 0x5c, 0x8a, 0x82, 0xf4, 0x29, 0x23,
             0x1f, 0x00, 0x80];

        let mut xsalsa20 = Salsa20::new_xsalsa20(key, nonce);
        xsalsa20.process(input, stream);
        assert!(stream[] == result[]);
    }
}

#[cfg(test)]
mod bench {
    use test::Bencher;
    use symmetriccipher::SynchronousStreamCipher;
    use salsa20::Salsa20;

    #[bench]
    pub fn salsa20_10(bh: & mut Bencher) {
        let mut salsa20 = Salsa20::new([0, ..32], [0, ..8]);
        let input = [1u8, ..10];
        let mut output = [0u8, ..10];
        bh.iter( || {
            salsa20.process(input, output);
        });
        bh.bytes = input.len() as u64;
    }
    
    #[bench]
    pub fn salsa20_1k(bh: & mut Bencher) {
        let mut salsa20 = Salsa20::new([0, ..32], [0, ..8]);
        let input = [1u8, ..1024];
        let mut output = [0u8, ..1024];
        bh.iter( || {
            salsa20.process(input, output);
        });
        bh.bytes = input.len() as u64;
    }
 
    #[bench]
    pub fn salsa20_64k(bh: & mut Bencher) {
        let mut salsa20 = Salsa20::new([0, ..32], [0, ..8]);
        let input = [1u8, ..65536];
        let mut output = [0u8, ..65536];
        bh.iter( || {
            salsa20.process(input, output);
        });
        bh.bytes = input.len() as u64;
    }
}
