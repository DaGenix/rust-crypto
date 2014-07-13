// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std;
use std::mem;
use std::num::{One, Zero, Int, CheckedAdd};
use std::ptr;
use std::slice::bytes::{MutableByteVector, copy_memory};

use buffer::{ReadBuffer, WriteBuffer, BufferResult, BufferUnderflow, BufferOverflow};
use symmetriccipher::{SynchronousStreamCipher, SymmetricCipherError};

/// Write a u64 into a vector, which must be 8 bytes long. The value is written in big-endian
/// format.
pub fn write_u64_be(dst: &mut[u8], mut input: u64) {
    assert!(dst.len() == 8);
    input = input.to_be();
    unsafe {
        let tmp = &input as *const _ as *const u8;
        ptr::copy_nonoverlapping_memory(dst.unsafe_mut(0), tmp, 8);
    }
}

/// Write a vector of u64s into a vector of bytes. The values are written in little-endian format.
pub fn write_u64v_le(dst: &mut[u8], input: &[u64]) {
    assert!(dst.len() == 8 * input.len());
    unsafe {
        let mut x: *mut u8 = dst.unsafe_mut(0);
        let mut y: *const u64 = input.unsafe_get(0);
        for _ in range(0, input.len()) {
            let tmp = (*y).to_le();
            ptr::copy_nonoverlapping_memory(x, &tmp as *const _ as *const u8, 8);
            x = x.offset(8);
            y = y.offset(1);
        }
    }
}

/// Write a u32 into a vector, which must be 4 bytes long. The value is written in big-endian
/// format.
pub fn write_u32_be(dst: &mut [u8], mut input: u32) {
    assert!(dst.len() == 4);
    input = input.to_be();
    unsafe {
        let tmp = &input as *const _ as *const u8;
        ptr::copy_nonoverlapping_memory(dst.unsafe_mut(0), tmp, 4);
    }
}

/// Write a u32 into a vector, which must be 4 bytes long. The value is written in little-endian
/// format.
pub fn write_u32_le(dst: &mut[u8], mut input: u32) {
    assert!(dst.len() == 4);
    input = input.to_le();
    unsafe {
        let tmp = &input as *const _ as *const u8;
        ptr::copy_nonoverlapping_memory(dst.unsafe_mut(0), tmp, 4);
    }
}

/// Read a vector of bytes into a vector of u64s. The values are read in big-endian format.
pub fn read_u64v_be(dst: &mut[u64], input: &[u8]) {
    assert!(dst.len() * 8 == input.len());
    unsafe {
        let mut x = dst.unsafe_mut(0) as *mut u64;
        let mut y = input.unsafe_get(0) as *const u8;
        for _ in range(0, dst.len()) {
            let mut tmp: u64 = mem::uninitialized();
            ptr::copy_nonoverlapping_memory(&mut tmp as *mut _ as *mut u8, y, 8);
            *x = Int::from_be(tmp);
            x = x.offset(1);
            y = y.offset(8);
        }
    }
}

/// Read a vector of bytes into a vector of u64s. The values are read in little-endian format.
pub fn read_u64v_le(dst: &mut[u64], input: &[u8]) {
    assert!(dst.len() * 8 == input.len());
    unsafe {
        let mut x = dst.unsafe_mut(0) as *mut u64;
        let mut y = input.unsafe_get(0) as *const u8;
        for _ in range(0, dst.len()) {
            let mut tmp: u64 = mem::uninitialized();
            ptr::copy_nonoverlapping_memory(&mut tmp as *mut _ as *mut u8, y, 8);
            *x = Int::from_le(tmp);
            x = x.offset(1);
            y = y.offset(8);
        }
    }
}

/// Read a vector of bytes into a vector of u32s. The values are read in big-endian format.
pub fn read_u32v_be(dst: &mut[u32], input: &[u8]) {
    assert!(dst.len() * 4 == input.len());
    unsafe {
        let mut x = dst.unsafe_mut(0) as *mut u32;
        let mut y = input.unsafe_get(0) as *const u8;
        for _ in range(0, dst.len()) {
            let mut tmp: u32 = mem::uninitialized();
            ptr::copy_nonoverlapping_memory(&mut tmp as *mut _ as *mut u8, y, 4);
            *x = Int::from_be(tmp);
            x = x.offset(1);
            y = y.offset(4);
        }
    }
}

/// Read a vector of bytes into a vector of u32s. The values are read in little-endian format.
pub fn read_u32v_le(dst: &mut[u32], input: &[u8]) {
    assert!(dst.len() * 4 == input.len());
    unsafe {
        let mut x = dst.unsafe_mut(0) as *mut u32;
        let mut y = input.unsafe_get(0) as *const u8;
        for _ in range(0, dst.len()) {
            let mut tmp: u32 = mem::uninitialized();
            ptr::copy_nonoverlapping_memory(&mut tmp as *mut _ as *mut u8, y, 4);
            *x = Int::from_le(tmp);
            x = x.offset(1);
            y = y.offset(4);
        }
    }
}

/// Read the value of a vector of bytes as a u32 value in little-endian format.
pub fn read_u32_le(input: &[u8]) -> u32 {
    assert!(input.len() == 4);
    unsafe {
        let mut tmp: u32 = mem::uninitialized();
        ptr::copy_nonoverlapping_memory(&mut tmp as *mut _ as *mut u8, input.unsafe_get(0), 4);
        return Int::from_le(tmp);
    }
}

/// Read the value of a vector of bytes as a u32 value in big-endian format.
pub fn read_u32_be(input: &[u8]) -> u32 {
    assert!(input.len() == 4);
    unsafe {
        let mut tmp: u32 = mem::uninitialized();
        ptr::copy_nonoverlapping_memory(&mut tmp as *mut _ as *mut u8, input.unsafe_get(0), 4);
        return Int::from_be(tmp);
    }
}


/// symm_enc_or_dec() implements the necessary functionality to turn a SynchronousStreamCipher into
/// an Encryptor or Decryptor
pub fn symm_enc_or_dec<S: SynchronousStreamCipher, R: ReadBuffer, W: WriteBuffer>(
        c: &mut S,
        input: &mut R,
        output: &mut W) ->
        Result<BufferResult, SymmetricCipherError> {
    let count = std::cmp::min(input.remaining(), output.remaining());
    c.process(input.take_next(count), output.take_next(count));
    if input.is_empty() {
        return Ok(BufferUnderflow);
    } else {
        return Ok(BufferOverflow);
    }
}


trait ToBits {
    /// Convert the value in bytes to the number of bits, a tuple where the 1st item is the
    /// high-order value and the 2nd item is the low order value.
    fn to_bits(self) -> (Self, Self);
}

impl ToBits for u64 {
    fn to_bits(self) -> (u64, u64) {
        return (self >> 61, self << 3);
    }
}

/// Adds the specified number of bytes to the bit count. fail!() if this would cause numeric
/// overflow.
pub fn add_bytes_to_bits<T: Int + CheckedAdd + ToBits>(bits: T, bytes: T) -> T {
    let (new_high_bits, new_low_bits) = bytes.to_bits();

    if new_high_bits > Zero::zero() {
        fail!("Numeric overflow occured.")
    }

    match bits.checked_add(&new_low_bits) {
        Some(x) => return x,
        None => fail!("Numeric overflow occured.")
    }
}

/// Adds the specified number of bytes to the bit count, which is a tuple where the first element is
/// the high order value. fail!() if this would cause numeric overflow.
pub fn add_bytes_to_bits_tuple
        <T: Int + Unsigned + CheckedAdd + ToBits>
        (bits: (T, T), bytes: T) -> (T, T) {
    let (new_high_bits, new_low_bits) = bytes.to_bits();
    let (hi, low) = bits;

    // Add the low order value - if there is no overflow, then add the high order values
    // If the addition of the low order values causes overflow, add one to the high order values
    // before adding them.
    match low.checked_add(&new_low_bits) {
        Some(x) => {
            if new_high_bits == Zero::zero() {
                // This is the fast path - every other alternative will rarely occur in practice
                // considering how large an input would need to be for those paths to be used.
                return (hi, x);
            } else {
                match hi.checked_add(&new_high_bits) {
                    Some(y) => return (y, x),
                    None => fail!("Numeric overflow occured.")
                }
            }
        },
        None => {
            let one: T = One::one();
            let z = match new_high_bits.checked_add(&one) {
                Some(w) => w,
                None => fail!("Numeric overflow occured.")
            };
            match hi.checked_add(&z) {
                // This re-executes the addition that was already performed earlier when overflow
                // occured, this time allowing the overflow to happen. Technically, this could be
                // avoided by using the checked add intrinsic directly, but that involves using
                // unsafe code and is not really worthwhile considering how infrequently code will
                // run in practice. This is the reason that this function requires that the type T
                // be Unsigned - overflow is not defined for Signed types. This function could be
                // implemented for signed types as well if that were needed.
                Some(y) => return (y, low + new_low_bits),
                None => fail!("Numeric overflow occured.")
            }
        }
    }
}


/// A FixedBuffer, likes its name implies, is a fixed size buffer. When the buffer becomes full, it
/// must be processed. The input() method takes care of processing and then clearing the buffer
/// automatically. However, other methods do not and require the caller to process the buffer. Any
/// method that modifies the buffer directory or provides the caller with bytes that can be modifies
/// results in those bytes being marked as used by the buffer.
pub trait FixedBuffer {
    /// Input a vector of bytes. If the buffer becomes full, process it with the provided
    /// function and then clear the buffer.
    fn input(&mut self, input: &[u8], func: |&[u8]|);

    /// Reset the buffer.
    fn reset(&mut self);

    /// Zero the buffer up until the specified index. The buffer position currently must not be
    /// greater than that index.
    fn zero_until(&mut self, idx: uint);

    /// Get a slice of the buffer of the specified size. There must be at least that many bytes
    /// remaining in the buffer.
    fn next<'s>(&'s mut self, len: uint) -> &'s mut [u8];

    /// Get the current buffer. The buffer must already be full. This clears the buffer as well.
    fn full_buffer<'s>(&'s mut self) -> &'s [u8];

     /// Get the current buffer.
    fn current_buffer<'s>(&'s mut self) -> &'s [u8];

    /// Get the current position of the buffer.
    fn position(&self) -> uint;

    /// Get the number of bytes remaining in the buffer until it is full.
    fn remaining(&self) -> uint;

    /// Get the size of the buffer
    fn size(&self) -> uint;
}

macro_rules! impl_fixed_buffer( ($name:ident, $size:expr) => (
    impl FixedBuffer for $name {
        fn input(&mut self, input: &[u8], func: |&[u8]|) {
            let mut i = 0;

            // FIXME: #6304 - This local variable shouldn't be necessary.
            let size = $size;

            // If there is already data in the buffer, copy as much as we can into it and process
            // the data if the buffer becomes full.
            if self.buffer_idx != 0 {
                let buffer_remaining = size - self.buffer_idx;
                if input.len() >= buffer_remaining {
                        copy_memory(
                            self.buffer.mut_slice(self.buffer_idx, size),
                            input.slice_to(buffer_remaining));
                    self.buffer_idx = 0;
                    func(self.buffer);
                    i += buffer_remaining;
                } else {
                    copy_memory(
                        self.buffer.mut_slice(self.buffer_idx, self.buffer_idx + input.len()),
                        input);
                    self.buffer_idx += input.len();
                    return;
                }
            }

            // While we have at least a full buffer size chunks's worth of data, process that data
            // without copying it into the buffer
            while input.len() - i >= size {
                func(input.slice(i, i + size));
                i += size;
            }

            // Copy any input data into the buffer. At this point in the method, the ammount of
            // data left in the input vector will be less than the buffer size and the buffer will
            // be empty.
            let input_remaining = input.len() - i;
            copy_memory(
                self.buffer.mut_slice(0, input_remaining),
                input.slice_from(i));
            self.buffer_idx += input_remaining;
        }

        fn reset(&mut self) {
            self.buffer_idx = 0;
        }

        fn zero_until(&mut self, idx: uint) {
            assert!(idx >= self.buffer_idx);
            self.buffer.mut_slice(self.buffer_idx, idx).set_memory(0);
            self.buffer_idx = idx;
        }

        fn next<'s>(&'s mut self, len: uint) -> &'s mut [u8] {
            self.buffer_idx += len;
            return self.buffer.mut_slice(self.buffer_idx - len, self.buffer_idx);
        }

        fn full_buffer<'s>(&'s mut self) -> &'s [u8] {
            assert!(self.buffer_idx == $size);
            self.buffer_idx = 0;
            return self.buffer.slice_to($size);
        }

        fn current_buffer<'s>(&'s mut self) -> &'s [u8] {
            let tmp = self.buffer_idx;
            self.buffer_idx = 0;
            return self.buffer.slice_to(tmp);
        }

        fn position(&self) -> uint { self.buffer_idx }

        fn remaining(&self) -> uint { $size - self.buffer_idx }

        fn size(&self) -> uint { $size }
    }
))

/// A fixed size buffer of 64 bytes useful for cryptographic operations.
pub struct FixedBuffer64 {
    buffer: [u8, ..64],
    buffer_idx: uint,
}

impl FixedBuffer64 {
    /// Create a new buffer
    pub fn new() -> FixedBuffer64 {
        return FixedBuffer64 {
            buffer: [0u8, ..64],
            buffer_idx: 0
        };
    }
}

impl_fixed_buffer!(FixedBuffer64, 64)

/// A fixed size buffer of 128 bytes useful for cryptographic operations.
pub struct FixedBuffer128 {
    buffer: [u8, ..128],
    buffer_idx: uint,
}

impl FixedBuffer128 {
    /// Create a new buffer
    pub fn new() -> FixedBuffer128 {
        return FixedBuffer128 {
            buffer: [0u8, ..128],
            buffer_idx: 0
        };
    }
}

impl_fixed_buffer!(FixedBuffer128, 128)


/// The StandardPadding trait adds a method useful for various hash algorithms to a FixedBuffer
/// struct.
pub trait StandardPadding {
    /// Add standard padding to the buffer. The buffer must not be full when this method is called
    /// and is guaranteed to have exactly rem remaining bytes when it returns. If there are not at
    /// least rem bytes available, the buffer will be zero padded, processed, cleared, and then
    /// filled with zeros again until only rem bytes are remaining.
    fn standard_padding(&mut self, rem: uint, func: |&[u8]|);
}

impl <T: FixedBuffer> StandardPadding for T {
    fn standard_padding(&mut self, rem: uint, func: |&[u8]|) {
        let size = self.size();

        self.next(1)[0] = 128;

        if self.remaining() < rem {
            self.zero_until(size);
            func(self.full_buffer());
        }

        self.zero_until(size - rem);
    }
}


#[cfg(test)]
pub mod test {
    use std::num::Bounded;

    use std::rand::IsaacRng;
    use std::rand::distributions::{IndependentSample, Range};

    use cryptoutil::{add_bytes_to_bits, add_bytes_to_bits_tuple};
    use digest::Digest;

    /// Feed 1,000,000 'a's into the digest with varying input sizes and check that the result is
    /// correct.
    pub fn test_digest_1million_random<D: Digest>(digest: &mut D, blocksize: uint, expected: &str) {
        let total_size = 1000000;
        let buffer = Vec::from_elem(blocksize * 2, 'a' as u8);
        let mut rng = IsaacRng::new_unseeded();
        let range = Range::new(0, 2 * blocksize + 1);
        let mut count = 0;

        digest.reset();

        while count < total_size {
            let next = range.ind_sample(&mut rng);
            let remaining = total_size - count;
            let size = if next > remaining { remaining } else { next };
            digest.input(buffer.slice_to(size));
            count += size;
        }

        let result_str = digest.result_str();

        assert!(expected == result_str.as_slice());
    }

    // A normal addition - no overflow occurs
    #[test]
    fn test_add_bytes_to_bits_ok() {
        assert!(add_bytes_to_bits::<u64>(100, 10) == 180);
    }

    // A simple failure case - adding 1 to the max value
    #[test]
    #[should_fail]
    fn test_add_bytes_to_bits_overflow() {
        add_bytes_to_bits::<u64>(Bounded::max_value(), 1);
    }

    // A normal addition - no overflow occurs (fast path)
    #[test]
    fn test_add_bytes_to_bits_tuple_ok() {
        assert!(add_bytes_to_bits_tuple::<u64>((5, 100), 10) == (5, 180));
    }

    // The low order value overflows into the high order value
    #[test]
    fn test_add_bytes_to_bits_tuple_ok2() {
        assert!(add_bytes_to_bits_tuple::<u64>((5, Bounded::max_value()), 1) == (6, 7));
    }

    // The value to add is too large to be converted into bits without overflowing its type
    #[test]
    fn test_add_bytes_to_bits_tuple_ok3() {
        assert!(add_bytes_to_bits_tuple::<u64>((5, 0), 0x4000000000000001) == (7, 8));
    }

    // A simple failure case - adding 1 to the max value
    #[test]
    #[should_fail]
    fn test_add_bytes_to_bits_tuple_overflow() {
        add_bytes_to_bits_tuple::<u64>((Bounded::max_value(), Bounded::max_value()), 1);
    }

    // The value to add is too large to convert to bytes without overflowing its type, but the high
    // order value from this conversion overflows when added to the existing high order value
    #[test]
    #[should_fail]
    fn test_add_bytes_to_bits_tuple_overflow2() {
        let value: u64 = Bounded::max_value();
        add_bytes_to_bits_tuple::<u64>((value - 1, 0), 0x8000000000000000);
    }
}
