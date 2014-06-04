// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use buffer::{BufferResult, RefReadBuffer, RefWriteBuffer};
use symmetriccipher::{Encryptor, Decryptor, SynchronousStreamCipher, SymmetricCipherError};
use cryptoutil::{read_u32_le, symm_enc_or_dec, write_u32_le};

pub struct ChaCha20 {
    state  : [u32, ..16],
    output : [u8,  ..64],
    offset : uint,
}

fn rotl32(v: u32, n: uint) -> u32 { (v << n) | (v >> (32 - n)) }

macro_rules! quater_round(
    ($a:expr, $b:expr, $c:expr, $d:expr) => ({
        $a += $b; $d ^= $a; $d = rotl32($d, 16);
        $c += $d; $b ^= $c; $b = rotl32($b, 12);
        $a += $b; $d ^= $a; $d = rotl32($d, 8);
        $c += $d; $b ^= $c; $b = rotl32($b, 7);
    });
)

impl ChaCha20 {
    pub fn new(key: &[u8], nonce: &[u8]) -> ChaCha20 {
        assert!(key.len() == 16 || key.len() == 32);
        assert!(nonce.len() == 8);

        ChaCha20{ state: ChaCha20::expand(key, nonce), output: [0u8, ..64], offset: 64 }
    }

    fn expand(key: &[u8], nonce: &[u8]) -> [u32, ..16] {
        let mut state = [0u32, ..16];
        let constant = match key.len() {
            16 => bytes!("expand 16-byte k"),
            32 => bytes!("expand 32-byte k"),
            _  => unreachable!(),
        };

        state[0] = read_u32_le(constant.slice( 0,  4));
        state[1] = read_u32_le(constant.slice( 4,  8));
        state[2] = read_u32_le(constant.slice( 8, 12));
        state[3] = read_u32_le(constant.slice(12, 16));
        state[4] = read_u32_le(key.slice( 0,  4));
        state[5] = read_u32_le(key.slice( 4,  8));
        state[6] = read_u32_le(key.slice( 8, 12));
        state[7] = read_u32_le(key.slice(12, 16));
        if key.len() == 16 {
            state[ 8] = state[4];
            state[ 9] = state[5];
            state[10] = state[6];
            state[11] = state[7];
        } else {
            state[ 8] = read_u32_le(key.slice(16, 20));
            state[ 9] = read_u32_le(key.slice(20, 24));
            state[10] = read_u32_le(key.slice(24, 28));
            state[11] = read_u32_le(key.slice(28, 32));
        }
        state[12] = 0;
        state[13] = 0;
        state[14] = read_u32_le(nonce.slice(0, 4));
        state[15] = read_u32_le(nonce.slice(4, 8));

        state
    }

    // put the the next 64 keystream bytes into self.output
    fn update(&mut self) {
        let mut x = self.state;

        for _ in range(0, 10) {
            quater_round!(x[0], x[4], x[ 8], x[12]);
            quater_round!(x[1], x[5], x[ 9], x[13]);
            quater_round!(x[2], x[6], x[10], x[14]);
            quater_round!(x[3], x[7], x[11], x[15]);
            quater_round!(x[0], x[5], x[10], x[15]);
            quater_round!(x[1], x[6], x[11], x[12]);
            quater_round!(x[2], x[7], x[ 8], x[13]);
            quater_round!(x[3], x[4], x[ 9], x[14]);
        }

        for i in range(0, self.state.len()) {
            write_u32_le(self.output.mut_slice(i*4, (i+1)*4), self.state[i] + x[i]);
        }

        self.state[12] += 1;
        if self.state[12] == 0 {
            self.state[13] += 1;
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
        for (x, y) in input.iter().zip(output.mut_iter()) {
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
