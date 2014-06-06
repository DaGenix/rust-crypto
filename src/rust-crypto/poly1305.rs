// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// This is a port of Andrew Moons poly1305-donna
// https://github.com/floodyberry/poly1305-donna

use std::cmp::min;

use cryptoutil::{read_u32_le, write_u32_le};
use mac::{Mac, MacResult};

pub struct Poly1305 {
    r        : [u32, ..5],
    h        : [u32, ..5],
    pad      : [u32, ..4],
    leftover : uint,
    buffer   : [u8, ..16],
    final    : bool,
}

impl Poly1305 {
    pub fn new(key: &[u8]) -> Poly1305 {
        assert!(key.len() == 32);
        let mut poly = Poly1305{ r: [0u32, ..5], h: [0u32, ..5], pad: [0u32, ..4], leftover: 0, buffer: [0u8, ..16], final: false };

        // r &= 0xffffffc0ffffffc0ffffffc0fffffff
        poly.r[0] = (read_u32_le(key.slice( 0,  4))     ) & 0x3ffffff;
        poly.r[1] = (read_u32_le(key.slice( 3,  7)) >> 2) & 0x3ffff03;
        poly.r[2] = (read_u32_le(key.slice( 6, 10)) >> 4) & 0x3ffc0ff;
        poly.r[3] = (read_u32_le(key.slice( 9, 13)) >> 6) & 0x3f03fff;
        poly.r[4] = (read_u32_le(key.slice(12, 16)) >> 8) & 0x00fffff;

        poly.pad[0] = read_u32_le(key.slice(16, 20));
        poly.pad[1] = read_u32_le(key.slice(20, 24));
        poly.pad[2] = read_u32_le(key.slice(24, 28));
        poly.pad[3] = read_u32_le(key.slice(28, 32));

        poly
    }

    fn block(&mut self, m: &[u8]) {
        let hibit : u32 = if self.final { 0 } else { 1 << 24 };

        let r0 = self.r[0];
        let r1 = self.r[1];
        let r2 = self.r[2];
        let r3 = self.r[3];
        let r4 = self.r[4];

        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        // h += m
        h0 += (read_u32_le(m.slice( 0,  4))     ) & 0x3ffffff;
        h1 += (read_u32_le(m.slice( 3,  7)) >> 2) & 0x3ffffff;
        h2 += (read_u32_le(m.slice( 6, 10)) >> 4) & 0x3ffffff;
        h3 += (read_u32_le(m.slice( 9, 13)) >> 6) & 0x3ffffff;
        h4 += (read_u32_le(m.slice(12, 16)) >> 8) | hibit;

        // h *= r
        let     d0 = (h0 as u64 * r0 as u64) + (h1 as u64 * s4 as u64) + (h2 as u64 * s3 as u64) + (h3 as u64 * s2 as u64) + (h4 as u64 * s1 as u64);
        let mut d1 = (h0 as u64 * r1 as u64) + (h1 as u64 * r0 as u64) + (h2 as u64 * s4 as u64) + (h3 as u64 * s3 as u64) + (h4 as u64 * s2 as u64);
        let mut d2 = (h0 as u64 * r2 as u64) + (h1 as u64 * r1 as u64) + (h2 as u64 * r0 as u64) + (h3 as u64 * s4 as u64) + (h4 as u64 * s3 as u64);
        let mut d3 = (h0 as u64 * r3 as u64) + (h1 as u64 * r2 as u64) + (h2 as u64 * r1 as u64) + (h3 as u64 * r0 as u64) + (h4 as u64 * s4 as u64);
        let mut d4 = (h0 as u64 * r4 as u64) + (h1 as u64 * r3 as u64) + (h2 as u64 * r2 as u64) + (h3 as u64 * r1 as u64) + (h4 as u64 * r0 as u64);

        // (partial) h %= p
        let mut c : u32;
                        c = (d0 >> 26) as u32; h0 = d0 as u32 & 0x3ffffff;
        d1 += c as u64; c = (d1 >> 26) as u32; h1 = d1 as u32 & 0x3ffffff;
        d2 += c as u64; c = (d2 >> 26) as u32; h2 = d2 as u32 & 0x3ffffff;
        d3 += c as u64; c = (d3 >> 26) as u32; h3 = d3 as u32 & 0x3ffffff;
        d4 += c as u64; c = (d4 >> 26) as u32; h4 = d4 as u32 & 0x3ffffff;
        h0 += c * 5;    c = (h0 >> 26) as u32; h0 = h0 & 0x3ffffff;
        h1 += c;

        self.h[0] = h0;
        self.h[1] = h1;
        self.h[2] = h2;
        self.h[3] = h3;
        self.h[4] = h4;
    }

    fn finish(&mut self) {
        if self.leftover > 0 {
            self.buffer[self.leftover] = 1;
            for i in range(self.leftover+1, 16) {
                self.buffer[i] = 0;
            }
            self.final = true;
            let tmp = self.buffer;
            self.block(tmp);
        }

        // fully carry h
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        let mut c : u32;
                     c = h1 >> 26; h1 = h1 & 0x3ffffff;
        h2 +=     c; c = h2 >> 26; h2 = h2 & 0x3ffffff;
        h3 +=     c; c = h3 >> 26; h3 = h3 & 0x3ffffff;
        h4 +=     c; c = h4 >> 26; h4 = h4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
        h1 +=     c;

        // compute h + -p
        let mut g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
        let mut g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
        let mut g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
        let mut g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
        let mut g4 = h4 + c - (1 << 26);

        // select h if h < p, or h + -p if h >= p
        let mut mask = (g4 >> (32 - 1)) - 1;
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        g4 &= mask;
        mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // h = h % (2^128)
        h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
        h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
        h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
        h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

        // h = mac = (h + pad) % (2^128)
        let mut f : u64;
        f = h0 as u64 + self.pad[0] as u64            ; h0 = f as u32;
        f = h1 as u64 + self.pad[1] as u64 + (f >> 32); h1 = f as u32;
        f = h2 as u64 + self.pad[2] as u64 + (f >> 32); h2 = f as u32;
        f = h3 as u64 + self.pad[3] as u64 + (f >> 32); h3 = f as u32;

        self.h[0] = h0;
        self.h[1] = h1;
        self.h[2] = h2;
        self.h[3] = h3;
    }
}

impl Mac for Poly1305 {
    fn input(&mut self, data: &[u8]) {
        assert!(!self.final);
        let mut m = data;

        if self.leftover > 0 {
            let want = min(16 - self.leftover, m.len());
            for i in range(0, want) {
                self.buffer[self.leftover+i] = m[i];
            }
            m = m.slice_from(want);
            self.leftover += want;

            if self.leftover < 16 {
                return;
            }

            // self.block(self.buffer.as_slice());
            let tmp = self.buffer;
            self.block(tmp);

            self.leftover = 0;
        }

        while m.len() >= 16 {
            self.block(m.slice(0, 16));
            m = m.slice_from(16);
        }

        for i in range(0, m.len()) {
            self.buffer[i] = m[i];
        }
        self.leftover = m.len();
    }

    fn reset(&mut self) {
        self.h = [0u32, ..5];
        self.leftover = 0;
        self.final = false;
    }

    fn result(&mut self) -> MacResult {
        let mut mac = [0u8, ..16];
        self.raw_result(mac.as_mut_slice());
        return MacResult::new(mac.as_slice());
    }

    fn raw_result(&mut self, output: &mut [u8]) {
        assert!(output.len() >= 16);
        if !self.final{
            self.finish();
        }
        write_u32_le(output.mut_slice( 0,  4), self.h[0]);
        write_u32_le(output.mut_slice( 4,  8), self.h[1]);
        write_u32_le(output.mut_slice( 8, 12), self.h[2]);
        write_u32_le(output.mut_slice(12, 16), self.h[3]);
    }

    fn output_bytes(&self) -> uint { 16 }
}
