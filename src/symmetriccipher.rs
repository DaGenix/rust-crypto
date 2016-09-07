// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use buffer::{BufferResult, RefReadBuffer, RefWriteBuffer};
use cryptoutil::symm_enc_or_dec;

pub trait BlockEncryptor {
    fn block_size(&self) -> usize;
    fn encrypt_block(&self, input: &[u8], output: &mut [u8]);
}

pub trait BlockEncryptorX8 {
    fn block_size(&self) -> usize;
    fn encrypt_block_x8(&self, input: &[u8], output: &mut [u8]);
}

pub trait BlockDecryptor {
    fn block_size(&self) -> usize;
    fn decrypt_block(&self, input: &[u8], output: &mut [u8]);
}

pub trait BlockDecryptorX8 {
    fn block_size(&self) -> usize;
    fn decrypt_block_x8(&self, input: &[u8], output: &mut [u8]);
}

#[derive(Debug, Clone, Copy)]
pub enum SymmetricCipherError {
    InvalidLength,
    InvalidPadding
}

pub trait Encryptor {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, eof: bool)
        -> Result<BufferResult, SymmetricCipherError>;
}

pub trait Decryptor {
    fn decrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, eof: bool)
        -> Result<BufferResult, SymmetricCipherError>;
}

pub trait SynchronousStreamCipher {
    fn process(&mut self, input: &[u8], output: &mut [u8]);
}

// TODO - Its a bit unclear to me why this is necessary
impl SynchronousStreamCipher for Box<SynchronousStreamCipher + 'static> {
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        let me = &mut **self;
        me.process(input, output);
    }
}

impl Encryptor for Box<SynchronousStreamCipher + 'static> {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

impl Decryptor for Box<SynchronousStreamCipher + 'static> {
    fn decrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SeekError {
    InvalidOffset,
}

pub trait SeekableStreamCipher {
    fn seek(&mut self, byte_offset: u64) -> Result<(), SeekError>;
}

#[cfg(test)]
pub mod test {
    use std::iter;
    use super::{SynchronousStreamCipher, SeekableStreamCipher};

    fn zero_vec(size: usize) -> Vec<u8> {
        iter::repeat(0).take(size).collect()
    }

    /// For a new cipher, ready to generate its first byte, make sure the results without
    /// doing any seeking are consistent with the results when we seek around.
    pub fn test_seek<C: SynchronousStreamCipher+SeekableStreamCipher>(cipher: &mut C) {
        let zeros = zero_vec(1000);
        let mut initial_bytes = zero_vec(1000);
        cipher.process(&zeros[..], &mut initial_bytes[..]);

        let subsequence_bounds = [(0, 40), (768, 1000), (33, 79)];
        for &(start, end) in subsequence_bounds.into_iter() {
            let mut subseqence: Vec<u8> = zero_vec(end-start);
            cipher.seek(start as u64).unwrap();
            cipher.process(&zeros[start..end], &mut subseqence[..]);
            assert_eq!(subseqence, initial_bytes[start..end].to_vec());
        }

        cipher.seek(0xffff_ffff_ffff1234).unwrap();
        let mut far_1 = zero_vec(1000);
        cipher.process(&zeros[..], &mut far_1[..]);

        let mut far_2 = zero_vec(999);
        cipher.seek(0xffff_ffff_ffff1234 + 1).unwrap();
        cipher.process(&zeros[1..], &mut far_2[..]);

        assert_eq!(far_1[1..].to_vec(), far_2);
    }
}
