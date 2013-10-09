// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cmp;

/// An iterator over a vector in (non-overlapping) mutable chunks (`size`
/// elements at a time).
///
/// When the vector len is not evenly divided by the chunk size,
/// the last slice of the iteration will be the remainder.
pub struct MutChunkIter<'self, T> {
    priv v: &'self mut [T],
    priv len: uint,
    priv size: uint,
    priv pos: uint
}

impl<'self, T> Iterator<&'self mut [T]> for MutChunkIter<'self, T> {
    #[inline]
    fn next(&mut self) -> Option<&'self mut [T]> {
        if self.pos >= self.len {
            None
        } else {
            let chunksz = cmp::min(self.len - self.pos, self.size);
            let out = self.v.mut_slice(self.pos, self.pos + chunksz);
            self.pos += chunksz;
            Some(out)
        }
    }

    #[inline]
    fn size_hint(&self) -> (uint, Option<uint>) {
        if self.len == 0 {
            (0, Some(0))
        } else {
            let (n, rem) = self.len.div_rem(&self.size);
            let n = if rem > 0 { n + 1 } else { n };
            (n, Some(n))
        }
    }
}

pub trait MutChunkIterable<'self, T> {
    /**
     * Returns an iterator over `size` elements of the vector at a
     * time. The chunks do not overlap. If `size` does not divide the
     * length of the vector, then the last chunk will not have length
     * `size`. The chunk are mutable.
     */
    fn mut_chunk_iter(self, size: uint) -> MutChunkIter<'self, T>;
}

impl<'self, T> MutChunkIterable<'self, T> for &'self mut [T] {
    #[inline]
    fn mut_chunk_iter(self, size: uint) -> MutChunkIter<'self, T> {
        assert!(size != 0);
        let len = self.len();
        MutChunkIter { v: self, len: len, size: size, pos: 0 }
    }
}

#[test]
fn test_mut_chunk_iterator() {
    let mut v = [0u8, 1, 2, 3, 4, 5];

    for (i, chunk) in v.mut_chunk_iter(3).enumerate() {
        chunk[0] = i as u8;
        chunk[1] = i as u8;
        chunk[2] = i as u8;
    }

    let result = [0u8, 0, 0, 1, 1, 1];
    assert_eq!(v, result);
}

#[test]
#[should_fail]
fn test_mut_chunk_iterator_0() {
    let mut v = [1, 2, 3, 4];
    let _it = v.mut_chunk_iter(0);
}
