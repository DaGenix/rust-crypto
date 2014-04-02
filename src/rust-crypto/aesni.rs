// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use symmetriccipher::{BlockEncryptor, BlockDecryptor};

pub struct AesNi128Encryptor {
    round_keys: [u8, ..16 * (10 + 1)]
}

pub struct AesNi128Decryptor {
    round_keys: [u8, ..16 * (10 + 1)]
}

impl AesNi128Encryptor {
    pub fn new(key: &[u8]) -> AesNi128Encryptor {
        let mut e = AesNi128Encryptor {
            round_keys: ([0u8, ..16 * (10 + 1)])
        };
        setup_working_key_aesni_128(key, Encryption, e.round_keys);
        return e;
    }
}

impl AesNi128Decryptor {
    pub fn new(key: &[u8]) -> AesNi128Decryptor {
        let mut d = AesNi128Decryptor {
            round_keys: ([0u8, ..16 * (10 + 1)])
        };
        setup_working_key_aesni_128(key, Decryption, d.round_keys);
        return d;
    }
}

impl BlockEncryptor for AesNi128Encryptor {
    fn block_size(&self) -> uint { 16 }
    fn encrypt_block(&self, input: &[u8], output: &mut [u8]) {
        encrypt_block_aseni(10, input, self.round_keys, output);
    }
}

impl BlockDecryptor for AesNi128Decryptor {
    fn block_size(&self) -> uint { 16 }
    fn decrypt_block(&self, input: &[u8], output: &mut [u8]) {
        decrypt_block_aseni(10, input, self.round_keys, output);
    }
}

pub struct AesNi192Encryptor {
    round_keys: [u8, ..16 * (12 + 1)]
}

pub struct AesNi192Decryptor {
    round_keys: [u8, ..16 * (12 + 1)]
}

impl AesNi192Encryptor {
    pub fn new(key: &[u8]) -> AesNi192Encryptor {
        let mut e = AesNi192Encryptor {
            round_keys: ([0u8, ..16 * (12 + 1)])
        };
        setup_working_key_aesni_192(key, Encryption, e.round_keys);
        return e;
    }
}

impl AesNi192Decryptor {
    pub fn new(key: &[u8]) -> AesNi192Decryptor {
        let mut d =  AesNi192Decryptor {
            round_keys: ([0u8, ..16 * (12 + 1)])
        };
        setup_working_key_aesni_192(key, Decryption, d.round_keys);
        return d;
    }
}

impl BlockEncryptor for AesNi192Encryptor {
    fn block_size(&self) -> uint { 16 }
    fn encrypt_block(&self, input: &[u8], output: &mut [u8]) {
        encrypt_block_aseni(12, input, self.round_keys, output);
    }
}

impl BlockDecryptor for AesNi192Decryptor {
    fn block_size(&self) -> uint { 16 }
    fn decrypt_block(&self, input: &[u8], output: &mut [u8]) {
        decrypt_block_aseni(12, input, self.round_keys, output);
    }
}

pub struct AesNi256Encryptor {
    round_keys: [u8, ..16 * (14 + 1)]
}

pub struct AesNi256Decryptor {
    round_keys: [u8, ..16 * (14 + 1)]
}

impl AesNi256Encryptor {
    pub fn new(key: &[u8]) -> AesNi256Encryptor {
        let mut e = AesNi256Encryptor {
            round_keys: ([0u8, ..16 * (14 + 1)])
        };
        setup_working_key_aesni_256(key, Encryption, e.round_keys);
        return e;
    }
}

impl AesNi256Decryptor {
    pub fn new(key: &[u8]) -> AesNi256Decryptor {
        let mut d = AesNi256Decryptor {
            round_keys: ([0u8, ..16 * (14 + 1)])
        };
        setup_working_key_aesni_256(key, Decryption, d.round_keys);
        return d;
    }
}

impl BlockEncryptor for AesNi256Encryptor {
    fn block_size(&self) -> uint { 16 }
    fn encrypt_block(&self, input: &[u8], output: &mut [u8]) {
        encrypt_block_aseni(14, input, self.round_keys, output);
    }
}

impl BlockDecryptor for AesNi256Decryptor {
    fn block_size(&self) -> uint { 16 }
    fn decrypt_block(&self, input: &[u8], output: &mut [u8]) {
        decrypt_block_aseni(14, input, self.round_keys, output);
    }
}

enum KeyType {
    Encryption,
    Decryption
}

#[inline(always)]
unsafe fn aesimc(round_keys: *u8) {
    asm!(
    "
        movdqu ($0), %xmm1
        aesimc %xmm1, %xmm1
        movdqu %xmm1, ($0)
    "
    : // outputs
    : "r" (round_keys) // inputs
    : "xmm1", "memory" // clobbers
    : "volatile"
    )
}

#[inline(never)]
#[allow(dead_assignment)]
fn setup_working_key_aesni_128(key: &[u8], key_type: KeyType, round_key: &mut [u8]) {
    unsafe {
        let mut round_keysp: *u8 = round_key.unsafe_ref(0);
        let keyp: *u8 = key.unsafe_ref(0);

        asm!(
        "
            movdqu ($1), %xmm1
            movdqu %xmm1, ($0)
            add $$0x10, $0

            aeskeygenassist $$0x01, %xmm1, %xmm2
            call key_expansion_128
            aeskeygenassist $$0x02, %xmm1, %xmm2
            call key_expansion_128
            aeskeygenassist $$0x04, %xmm1, %xmm2
            call key_expansion_128
            aeskeygenassist $$0x08, %xmm1, %xmm2
            call key_expansion_128
            aeskeygenassist $$0x10, %xmm1, %xmm2
            call key_expansion_128
            aeskeygenassist $$0x20, %xmm1, %xmm2
            call key_expansion_128
            aeskeygenassist $$0x40, %xmm1, %xmm2
            call key_expansion_128
            aeskeygenassist $$0x80, %xmm1, %xmm2
            call key_expansion_128
            aeskeygenassist $$0x1b, %xmm1, %xmm2
            call key_expansion_128
            aeskeygenassist $$0x36, %xmm1, %xmm2
            call key_expansion_128

            jmp end_key_128

            key_expansion_128:
            pshufd $$0xff, %xmm2, %xmm2
            vpslldq $$0x04, %xmm1, %xmm3
            pxor %xmm3, %xmm1
            vpslldq $$0x4, %xmm1, %xmm3
            pxor %xmm3, %xmm1
            vpslldq $$0x04, %xmm1, %xmm3
            pxor %xmm3, %xmm1
            pxor %xmm2, %xmm1
            movdqu %xmm1, ($0)
            add $$0x10, $0
            ret

            end_key_128:
        "
        : "=r" (round_keysp)
        : "r" (keyp), "0" (round_keysp)
        : "xmm1", "xmm2", "xmm3", "memory"
        : "volatile"
        )

        match key_type {
            Decryption => {
                // range of rounds keys from #1 to #9; skip the first and last key
                for i in range(1u, 10) {
                    aesimc(round_key.unsafe_ref(16 * i));
                }
            }
            Encryption => { /* nothing more to do */ }
        }
    }
}

#[inline(never)]
#[allow(dead_assignment)]
fn setup_working_key_aesni_192(key: &[u8], key_type: KeyType, round_key: &mut [u8]) {
    unsafe {
        let mut round_keysp: *u8 = round_key.unsafe_ref(0);
        let keyp: *u8 = key.unsafe_ref(0);

        asm!(
        "
            movdqu ($1), %xmm1
            movdqu 16($1), %xmm3
            movdqu %xmm1, ($0)
            movdqa %xmm3, %xmm5

            aeskeygenassist $$0x1, %xmm3, %xmm2
            call process_key_192
            shufpd $$0, %xmm1, %xmm5
            movdqu %xmm5, 16($0)
            movdqa %xmm1, %xmm6
            shufpd $$1, %xmm3, %xmm6
            movdqu %xmm6, 32($0)

            aeskeygenassist $$0x2, %xmm3, %xmm2
            call process_key_192
            movdqu %xmm1, 48($0)
            movdqa %xmm3, %xmm5

            aeskeygenassist $$0x4, %xmm3, %xmm2
            call process_key_192
            shufpd $$0, %xmm1, %xmm5
            movdqu %xmm5, 64($0)
            movdqa %xmm1, %xmm6
            shufpd $$1, %xmm3, %xmm6
            movdqu %xmm6, 80($0)

            aeskeygenassist $$0x8, %xmm3, %xmm2
            call process_key_192
            movdqu %xmm1, 96($0)
            movdqa %xmm3, %xmm5

            aeskeygenassist $$0x10, %xmm3, %xmm2
            call process_key_192
            shufpd $$0, %xmm1, %xmm5
            movdqu %xmm5, 112($0)
            movdqa %xmm1, %xmm6
            shufpd $$1, %xmm3, %xmm6
            movdqu %xmm6, 128($0)

            aeskeygenassist $$0x20, %xmm3, %xmm2
            call process_key_192
            movdqu %xmm1, 144($0)
            movdqa %xmm3, %xmm5

            aeskeygenassist $$0x40, %xmm3, %xmm2
            call process_key_192
            shufpd $$0, %xmm1, %xmm5
            movdqu %xmm5, 160($0)
            movdqa %xmm1, %xmm6
            shufpd $$1, %xmm3, %xmm6
            movdqu %xmm6, 176($0)

            aeskeygenassist $$0x80, %xmm3, %xmm2
            call process_key_192
            movdqu %xmm1, 192($0)

            jmp end_key_192

            process_key_192:
            pshufd $$0x55, %xmm2, %xmm2
            movdqu %xmm1, %xmm4
            pslldq $$4, %xmm4
            pxor %xmm4, %xmm1
            pslldq $$4, %xmm4
            pxor %xmm4, %xmm1
            pslldq $$4, %xmm4
            pxor %xmm4, %xmm1
            pxor %xmm2, %xmm1
            pshufd $$0xff, %xmm1, %xmm2
            movdqu %xmm3, %xmm4
            pslldq $$4, %xmm4
            pxor %xmm4, %xmm3
            pxor %xmm2, %xmm3
            ret

            end_key_192:
        "
        : "=r" (round_keysp)
        : "r" (keyp), "0" (round_keysp)
        : "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "memory"
        : "volatile"
        )

        match key_type {
            Decryption => {
                // range of rounds keys from #1 to #11; skip the first and last key
                for i in range(1u, 12) {
                    aesimc(round_key.unsafe_ref(16 * i));
                }
            }
            Encryption => { /* nothing more to do */ }
        }
    }
}

#[inline(never)]
#[allow(dead_assignment)]
fn setup_working_key_aesni_256(key: &[u8], key_type: KeyType, round_key: &mut [u8]) {
    unsafe {
        let mut round_keysp: *u8 = round_key.unsafe_ref(0);
        let keyp: *u8 = key.unsafe_ref(0);

        asm!(
        "
            movdqu ($1), %xmm1
            movdqu 16($1), %xmm3
            movdqu %xmm1, ($0)
            movdqu %xmm3, 16($0)

            aeskeygenassist $$0x1, %xmm3, %xmm2
            call make_rk256_a
            movdqu %xmm1, 32($0)

            aeskeygenassist $$0x0, %xmm1, %xmm2
            call make_rk256_b
            movdqu %xmm3, 48($0)

            aeskeygenassist $$0x2, %xmm3, %xmm2
            call make_rk256_a
            movdqu %xmm1, 64($0)

            aeskeygenassist $$0x0, %xmm1, %xmm2
            call make_rk256_b
            movdqu %xmm3, 80($0)

            aeskeygenassist $$0x4, %xmm3, %xmm2
            call make_rk256_a
            movdqu %xmm1, 96($0)

            aeskeygenassist $$0x0, %xmm1, %xmm2
            call make_rk256_b
            movdqu %xmm3, 112($0)

            aeskeygenassist $$0x8, %xmm3, %xmm2
            call make_rk256_a
            movdqu %xmm1, 128($0)

            aeskeygenassist $$0x0, %xmm1, %xmm2
            call make_rk256_b
            movdqu %xmm3, 144($0)

            aeskeygenassist $$0x10, %xmm3, %xmm2
            call make_rk256_a
            movdqu %xmm1, 160($0)

            aeskeygenassist $$0x0, %xmm1, %xmm2
            call make_rk256_b
            movdqu %xmm3, 176($0)

            aeskeygenassist $$0x20, %xmm3, %xmm2
            call make_rk256_a
            movdqu %xmm1, 192($0)

            aeskeygenassist $$0x0, %xmm1, %xmm2
            call make_rk256_b
            movdqu %xmm3, 208($0)

            aeskeygenassist $$0x40, %xmm3, %xmm2
            call make_rk256_a
            movdqu %xmm1, 224($0)

            jmp end_key_256

            make_rk256_a:
            pshufd $$0xff, %xmm2, %xmm2
            movdqa %xmm1, %xmm4
            pslldq $$4, %xmm4
            pxor %xmm4, %xmm1
            pslldq $$4, %xmm4
            pxor %xmm4, %xmm1
            pslldq $$4, %xmm4
            pxor %xmm4, %xmm1
            pxor %xmm2, %xmm1
            ret

            make_rk256_b:
            pshufd $$0xaa, %xmm2, %xmm2
            movdqa %xmm3, %xmm4
            pslldq $$4, %xmm4
            pxor %xmm4, %xmm3
            pslldq $$4, %xmm4
            pxor %xmm4, %xmm3
            pslldq $$4, %xmm4
            pxor %xmm4, %xmm3
            pxor %xmm2, %xmm3
            ret

            end_key_256:
        "
        : "=r" (round_keysp)
        : "r" (keyp), "0" (round_keysp)
        : "xmm1", "xmm2", "xmm3", "xmm4", "memory"
        : "volatile"
        )

        match key_type {
            Decryption => {
                // range of rounds keys from #1 to #13; skip the first and last key
                for i in range(1u, 14) {
                    aesimc(round_key.unsafe_ref(16 * i));
                }
            }
            Encryption => { /* nothing more to do */ }
        }
    }
}

#[inline(never)]
#[allow(dead_assignment)]
fn encrypt_block_aseni(rounds: uint, input: &[u8], round_keys: &[u8], output: &mut [u8]) {
    unsafe {
        let mut rounds = rounds;
        let mut round_keysp: *u8 = round_keys.unsafe_ref(0);
        let outp: *u8 = output.unsafe_ref(0);
        let inp: *u8 = input.unsafe_ref(0);

        asm!(
        "
            /* Copy the data to encrypt to xmm15 */
            movdqu ($2), %xmm15

            /* Perform round 0 - the whitening step */
            movdqu ($1), %xmm0
            add $$0x10, $1
            pxor %xmm0, %xmm15

            /* Perform all remaining rounds (except the final one) */
            enc_round:
            movdqu ($1), %xmm0
            add $$0x10, $1
            aesenc %xmm0, %xmm15
            sub $$0x01, $0
            cmp $$0x01, $0
            jne enc_round

            /* Perform the last round */
            movdqu ($1), %xmm0
            aesenclast %xmm0, %xmm15

            /* Finally, move the result from xmm15 to outp */
            movdqu %xmm15, ($3)
        "
        : "=r" (rounds), "=r" (round_keysp) // outputs
        : "r" (inp), "r" (outp), "0" (rounds), "1" (round_keysp) // inputs
        : "xmm0", "xmm15", "memory", "cc" // clobbers
        : "volatile" // options
        );
    }
}

#[inline(never)]
#[allow(dead_assignment)]
fn decrypt_block_aseni(rounds: uint, input: &[u8], round_keys: &[u8], output: &mut [u8]) {
    unsafe {
        let mut rounds = rounds;
        let mut round_keysp: *u8 = round_keys.unsafe_ref(round_keys.len() - 16);
        let outp: *u8 = output.unsafe_ref(0);
        let inp: *u8 = input.unsafe_ref(0);

        asm!(
        "
            /* Copy the data to decrypt to xmm15 */
            movdqu ($2), %xmm15

            /* Perform round 0 - the whitening step */
            movdqu ($1), %xmm0
            sub $$0x10, $1
            pxor %xmm0, %xmm15

            /* Perform all remaining rounds (except the final one) */
            dec_round:
            movdqu ($1), %xmm0
            sub $$0x10, $1
            aesdec %xmm0, %xmm15
            sub $$0x01, $0
            cmp $$0x01, $0
            jne dec_round

            /* Perform the last round */
            movdqu ($1), %xmm0
            aesdeclast %xmm0, %xmm15

            /* Finally, move the result from xmm15 to outp */
            movdqu %xmm15, ($3)
        "
        : "=r" (rounds), "=r" (round_keysp) // outputs
        : "r" (inp), "r" (outp), "0" (rounds), "1" (round_keysp) // inputs
        : "xmm0", "xmm15", "memory", "cc" // clobbers
        : "volatile" // options
        );
    }
}
