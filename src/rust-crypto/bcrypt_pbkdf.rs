// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::iter::range_step;
use blowfish::Blowfish;
use cryptoutil::{read_u32v_be, write_u32_be, write_u32_le};
use sha2::Sha512;
use digest::Digest;

fn bcrypt_hash(hpass: &[u8], hsalt: &[u8], output: &mut [u8, ..32]) {
    let mut bf = Blowfish::init_state();
    bf.salted_expand_key(hsalt, hpass);

    for _ in range(0, 64) {
        bf.expand_key(hsalt);
        bf.expand_key(hpass);
    }

    let mut buf = [0u32, ..8];
    read_u32v_be(buf, bytes!("OxychromaticBlowfishSwatDynamite"));

    for i in range_step(0u, 8, 2) {
        for _ in range(0, 64) {
            let (l, r) = bf.encrypt(buf[i], buf[i+1]);
            buf[i] = l;
            buf[i+1] = r;
        }
    }

    for i in range(0u, 8) {
        write_u32_le(output.mut_slice(i*4, (i+1)*4), buf[i]);
    }
}

pub fn bcrypt_pbkdf(password: &[u8], salt: &[u8], rounds: uint, output: &mut [u8])  {
    let mut hpass = [0u8, ..64];

    assert!(password.len() > 0);
    assert!(salt.len() > 0);
    assert!(rounds > 0);
    assert!(output.len() > 0);
    assert!(output.len() <= 1024);

    let nblocks = (output.len() + 31) / 32;

    let mut h = Sha512::new();
    h.input(password);
    h.result(hpass.as_mut_slice());

    for block in range(1u, (nblocks+1)) {
        let mut count = [0u8, ..4];
        let mut hsalt = [0u8, ..64];
        let mut out   = [0u8, ..32];
        write_u32_be(count.as_mut_slice(), block as u32);

        h.reset();
        h.input(salt);
        h.input(count);
        h.result(hsalt);

        bcrypt_hash(hpass, hsalt, &mut out);
        let mut tmp = out;

        for _ in range(1, rounds) {
            h.reset();
            h.input(tmp);
            h.result(hsalt);

            bcrypt_hash(hpass, hsalt, &mut tmp);
            for i in range(0, out.len()) {
                out[i] ^= tmp[i];
            }

            for i in range(0, out.len()) {
                let idx = i * nblocks + (block-1);
                if idx < output.len() {
                    output[idx] = out[i];
                }
            }
        }
    }
}
