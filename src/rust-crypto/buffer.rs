// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cmp;
use std::vec;

pub enum BufferResult {
    BufferUnderflow,
    BufferOverflow
}

pub trait ReadBuffer {
    fn is_empty(&self) -> bool;
    fn is_full(&self) -> bool;
    fn remaining(&self) -> uint;
    fn capacity(&self) -> uint;
    fn position(&self) -> uint { self.capacity() - self.remaining() }

    fn rewind(&mut self, distance: uint);
    fn truncate(&mut self, amount: uint);
    fn reset(&mut self);

    fn peek_next<'a>(&'a self, count: uint) -> &'a [u8];
    fn peek_remaining<'a>(&'a self) -> &'a [u8] {
        self.peek_next(self.remaining())
    }

    fn take_next<'a>(&'a mut self, count: uint) -> &'a [u8];
    fn take_remaining<'a>(&'a mut self) -> &'a [u8] {
        let rem = self.remaining();
        self.take_next(rem)
    }

    fn push_to<W: WriteBuffer>(&mut self, output: &mut W) {
        let count = cmp::min(output.remaining(), self.remaining());
        vec::bytes::copy_memory(output.take_next(count), self.take_next(count));
    }
}

pub trait WriteBuffer {
    fn is_empty(&self) -> bool;
    fn is_full(&self) -> bool;
    fn remaining(&self) -> uint;
    fn capacity(&self) -> uint;
    fn position(&self) -> uint { self.capacity() - self.remaining() }

    fn rewind(&mut self, distance: uint);
    fn reset(&mut self);

    // FIXME - Shouldn't need mut self
    fn peek_read_buffer<'a>(&'a mut self) -> RefReadBuffer<'a>;

    fn take_next<'a>(&'a mut self, count: uint) -> &'a mut [u8];
    fn take_remaining<'a>(&'a mut self) -> &'a mut [u8] {
        let rem = self.remaining();
        self.take_next(rem)
    }
    fn take_read_buffer<'a>(&'a mut self) -> RefReadBuffer<'a>;
}

pub struct RefReadBuffer<'a> {
    buff: &'a [u8],
    pos: uint
}

impl <'a> RefReadBuffer<'a> {
    pub fn new<'a>(buff: &'a [u8]) -> RefReadBuffer<'a> {
        RefReadBuffer {
            buff: buff,
            pos: 0
        }
    }
}

impl <'a> ReadBuffer for RefReadBuffer<'a> {
    fn is_empty(&self) -> bool { self.pos == self.buff.len() }
    fn is_full(&self) -> bool { self.pos == 0 }
    fn remaining(&self) -> uint { self.buff.len() - self.pos }
    fn capacity(&self) -> uint { self.buff.len() }

    fn rewind(&mut self, distance: uint) { self.pos -= distance; }
    fn truncate(&mut self, amount: uint) {
        self.buff = self.buff.slice_to(self.buff.len() - amount);
    }
    fn reset(&mut self) { self.pos = 0; }

    fn peek_next<'a>(&'a self, count: uint) -> &'a [u8] { self.buff.slice(self.pos, count) }

    fn take_next<'a>(&'a mut self, count: uint) -> &'a [u8] {
        let r = self.buff.slice(self.pos, self.pos + count);
        self.pos += count;
        r
    }
}

pub struct OwnedReadBuffer {
    buff: ~[u8],
    len: uint,
    pos: uint
}

impl OwnedReadBuffer {
    pub fn new(buff: ~[u8]) -> OwnedReadBuffer {
        let len = buff.len();
        OwnedReadBuffer {
            buff: buff,
            len: len,
            pos: 0
        }
    }
    pub fn new_with_len<'a>(buff: ~[u8], len: uint) -> OwnedReadBuffer {
        OwnedReadBuffer {
            buff: buff,
            len: len,
            pos: 0
        }
    }
    pub fn into_write_buffer(self) -> OwnedWriteBuffer {
        OwnedWriteBuffer::new(self.buff)
    }
    pub fn borrow_write_buffer<'a>(&'a mut self) -> BorrowedWriteBuffer<'a> {
        self.pos = 0;
        self.len = 0;
        BorrowedWriteBuffer::new(self)
    }
}

impl ReadBuffer for OwnedReadBuffer {
    fn is_empty(&self) -> bool { self.pos == self.len }
    fn is_full(&self) -> bool { self.pos == 0 }
    fn remaining(&self) -> uint { self.len - self.pos }
    fn capacity(&self) -> uint { self.len }

    fn rewind(&mut self, distance: uint) { self.pos -= distance; }
    fn truncate(&mut self, amount: uint) { self.len -= amount; }
    fn reset(&mut self) { self.pos = 0; }

    fn peek_next<'a>(&'a self, count: uint) -> &'a [u8] { self.buff.slice(self.pos, count) }

    fn take_next<'a>(&'a mut self, count: uint) -> &'a [u8] {
        let r = self.buff.slice(self.pos, self.pos + count);
        self.pos += count;
        r
    }
}

pub struct RefWriteBuffer<'a> {
    buff: &'a mut [u8],
    len: uint,
    pos: uint
}

impl <'a> RefWriteBuffer<'a> {
    pub fn new<'a>(buff: &'a mut [u8]) -> RefWriteBuffer<'a> {
        let len = buff.len();
        RefWriteBuffer {
            buff: buff,
            len: len,
            pos: 0
        }
    }
}

impl <'a> WriteBuffer for RefWriteBuffer<'a> {
    fn is_empty(&self) -> bool { self.pos == 0 }
    fn is_full(&self) -> bool { self.pos == self.len }
    fn remaining(&self) -> uint { self.len - self.pos }
    fn capacity(&self) -> uint { self.len }

    fn rewind(&mut self, distance: uint) { self.pos -= distance; }
    fn reset(&mut self) { self.pos = 0; }

    fn peek_read_buffer<'a>(&'a mut self) -> RefReadBuffer<'a> {
        RefReadBuffer::new(self.buff.slice_to(self.pos))
    }

    fn take_next<'a>(&'a mut self, count: uint) -> &'a mut [u8] {
        let r = self.buff.mut_slice(self.pos, self.pos + count);
        self.pos += count;
        r
    }
    fn take_read_buffer<'a>(&'a mut self) -> RefReadBuffer<'a> {
        let r = RefReadBuffer::new(self.buff.slice_to(self.pos));
        self.pos = 0;
        r
    }
}

pub struct BorrowedWriteBuffer<'a> {
    parent: &'a mut OwnedReadBuffer,
    pos: uint,
    len: uint
}

impl <'a> BorrowedWriteBuffer<'a> {
    fn new<'a>(parent: &'a mut OwnedReadBuffer) -> BorrowedWriteBuffer<'a> {
        let buff_len = parent.buff.len();
        BorrowedWriteBuffer {
            parent: parent,
            pos: 0,
            len: buff_len
        }
    }
}

impl <'a> WriteBuffer for BorrowedWriteBuffer<'a> {
    fn is_empty(&self) -> bool { self.pos == 0 }
    fn is_full(&self) -> bool { self.pos == self.len }
    fn remaining(&self) -> uint { self.len - self.pos }
    fn capacity(&self) -> uint { self.len }

    fn rewind(&mut self, distance: uint) {
        self.pos -= distance;
        self.parent.len -= distance;
    }
    fn reset(&mut self) {
        self.pos = 0;
        self.parent.len = 0;
    }

    fn peek_read_buffer<'a>(&'a mut self) -> RefReadBuffer<'a> {
        RefReadBuffer::new(self.parent.buff.slice_to(self.pos))
    }

    fn take_next<'a>(&'a mut self, count: uint) -> &'a mut [u8] {
        let r = self.parent.buff.mut_slice(self.pos, self.pos + count);
        self.pos += count;
        self.parent.len += count;
        r
    }
    fn take_read_buffer<'a>(&'a mut self) -> RefReadBuffer<'a> {
        let r = RefReadBuffer::new(self.parent.buff.slice_to(self.pos));
        self.pos = 0;
        self.parent.len = 0;
        r
    }
}

pub struct OwnedWriteBuffer {
    buff: ~[u8],
    len: uint,
    pos: uint
}

impl OwnedWriteBuffer {
    pub fn new(buff: ~[u8]) -> OwnedWriteBuffer {
        let len = buff.len();
        OwnedWriteBuffer {
            buff: buff,
            len: len,
            pos: 0
        }
    }
    pub fn into_read_buffer(self) -> OwnedReadBuffer {
        let pos = self.pos;
        OwnedReadBuffer::new_with_len(self.buff, pos)
    }
}

impl WriteBuffer for OwnedWriteBuffer {
    fn is_empty(&self) -> bool { self.pos == 0 }
    fn is_full(&self) -> bool { self.pos == self.len }
    fn remaining(&self) -> uint { self.len - self.pos }
    fn capacity(&self) -> uint { self.len }

    fn rewind(&mut self, distance: uint) { self.pos -= distance; }
    fn reset(&mut self) { self.pos = 0; }

    fn peek_read_buffer<'a>(&'a mut self) -> RefReadBuffer<'a> {
        RefReadBuffer::new(self.buff.slice_to(self.pos))
    }

    fn take_next<'a>(&'a mut self, count: uint) -> &'a mut [u8] {
        let r = self.buff.mut_slice(self.pos, self.pos + count);
        self.pos += count;
        r
    }
    fn take_read_buffer<'a>(&'a mut self) -> RefReadBuffer<'a> {
        let r = RefReadBuffer::new(self.buff.slice_to(self.pos));
        self.pos = 0;
        r
    }
}
