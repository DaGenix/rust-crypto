// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use aes::KeySize;
use aes::KeySize::{KeySize128, KeySize192, KeySize256};
use symmetriccipher::{BlockEncryptor, BlockDecryptor};

#[deriving(Copy)]
pub struct AesNiEncryptor {
    rounds: uint,
    round_keys: [u8, ..240]
}

#[deriving(Copy)]
pub struct AesNiDecryptor {
    rounds: uint,
    round_keys: [u8, ..240]
}

/// The number of rounds as well as a function to setup an appropriately sized key.
type RoundSetupInfo = (uint, fn(&[u8], KeyType, &mut [u8]));

impl AesNiEncryptor {
    pub fn new(key_size: KeySize, key: &[u8]) -> AesNiEncryptor {
        let (rounds, setup_function): RoundSetupInfo = match key_size {
            KeySize128 => (10, setup_working_key_aesni_128),
            KeySize192 => (12, setup_working_key_aesni_192),
            KeySize256 => (14, setup_working_key_aesni_256)
        };
        let mut e = AesNiEncryptor {
            rounds: rounds,
            round_keys: [0u8, ..240]
        };
        setup_function(key, KeyType::Encryption, e.round_keys.slice_mut(0, size(e.rounds)));
        e
    }
}

impl AesNiDecryptor {
    pub fn new(key_size: KeySize, key: &[u8]) -> AesNiDecryptor {
        let (rounds, setup_function): RoundSetupInfo = match key_size {
            KeySize128 => (10, setup_working_key_aesni_128),
            KeySize192 => (12, setup_working_key_aesni_192),
            KeySize256 => (14, setup_working_key_aesni_256)
        };
        let mut d = AesNiDecryptor {
            rounds: rounds,
            round_keys: [0u8, ..240]
        };
        setup_function(key, KeyType::Decryption, d.round_keys.slice_mut(0, size(d.rounds)));
        d
    }

}

impl BlockEncryptor for AesNiEncryptor {
    fn block_size(&self) -> uint { 16 }
    fn encrypt_block(&self, input: &[u8], output: &mut [u8]) {
        encrypt_block_aesni(self.rounds, input, self.round_keys.slice(0, size(self.rounds))[], output);
    }
}

impl BlockDecryptor for AesNiDecryptor {
    fn block_size(&self) -> uint { 16 }
    fn decrypt_block(&self, input: &[u8], output: &mut [u8]) {
        decrypt_block_aesni(self.rounds, input, self.round_keys.slice(0, size(self.rounds))[], output);
    }
}

enum KeyType {
    Encryption,
    Decryption
}

#[inline(always)]
fn size(rounds: uint) -> uint { 16 * (rounds + 1) }

#[inline(always)]
unsafe fn aesimc(round_keys: *mut u8) {
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

#[allow(unused_assignments)]
fn setup_working_key_aesni_128(key: &[u8], key_type: KeyType, round_key: &mut [u8]) {
    unsafe {
        let mut round_keysp: *mut u8 = round_key.unsafe_mut(0);
        let keyp: *const u8 = key.unsafe_get(0);

        asm!(
        "
            movdqu ($1), %xmm1
            movdqu %xmm1, ($0)
            add $$0x10, $0

            aeskeygenassist $$0x01, %xmm1, %xmm2
            call 1f
            aeskeygenassist $$0x02, %xmm1, %xmm2
            call 1f
            aeskeygenassist $$0x04, %xmm1, %xmm2
            call 1f
            aeskeygenassist $$0x08, %xmm1, %xmm2
            call 1f
            aeskeygenassist $$0x10, %xmm1, %xmm2
            call 1f
            aeskeygenassist $$0x20, %xmm1, %xmm2
            call 1f
            aeskeygenassist $$0x40, %xmm1, %xmm2
            call 1f
            aeskeygenassist $$0x80, %xmm1, %xmm2
            call 1f
            aeskeygenassist $$0x1b, %xmm1, %xmm2
            call 1f
            aeskeygenassist $$0x36, %xmm1, %xmm2
            call 1f

            jmp 2f

            1:
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

            2:
        "
        : "=r" (round_keysp)
        : "r" (keyp), "0" (round_keysp)
        : "xmm1", "xmm2", "xmm3", "memory"
        : "volatile"
        );

        match key_type {
            KeyType::Decryption => {
                // range of rounds keys from #1 to #9; skip the first and last key
                for i in range(1u, 10) {
                    aesimc(round_key.unsafe_mut(16 * i));
                }
            }
            KeyType::Encryption => { /* nothing more to do */ }
        }
    }
}

#[allow(unused_assignments)]
fn setup_working_key_aesni_192(key: &[u8], key_type: KeyType, round_key: &mut [u8]) {
    unsafe {
        let mut round_keysp: *mut u8 = round_key.unsafe_mut(0);
        let keyp: *const u8 = key.unsafe_get(0);

        asm!(
        "
            movdqu ($1), %xmm1
            movdqu 16($1), %xmm3
            movdqu %xmm1, ($0)
            movdqa %xmm3, %xmm5

            aeskeygenassist $$0x1, %xmm3, %xmm2
            call 1f
            shufpd $$0, %xmm1, %xmm5
            movdqu %xmm5, 16($0)
            movdqa %xmm1, %xmm6
            shufpd $$1, %xmm3, %xmm6
            movdqu %xmm6, 32($0)

            aeskeygenassist $$0x2, %xmm3, %xmm2
            call 1f
            movdqu %xmm1, 48($0)
            movdqa %xmm3, %xmm5

            aeskeygenassist $$0x4, %xmm3, %xmm2
            call 1f
            shufpd $$0, %xmm1, %xmm5
            movdqu %xmm5, 64($0)
            movdqa %xmm1, %xmm6
            shufpd $$1, %xmm3, %xmm6
            movdqu %xmm6, 80($0)

            aeskeygenassist $$0x8, %xmm3, %xmm2
            call 1f
            movdqu %xmm1, 96($0)
            movdqa %xmm3, %xmm5

            aeskeygenassist $$0x10, %xmm3, %xmm2
            call 1f
            shufpd $$0, %xmm1, %xmm5
            movdqu %xmm5, 112($0)
            movdqa %xmm1, %xmm6
            shufpd $$1, %xmm3, %xmm6
            movdqu %xmm6, 128($0)

            aeskeygenassist $$0x20, %xmm3, %xmm2
            call 1f
            movdqu %xmm1, 144($0)
            movdqa %xmm3, %xmm5

            aeskeygenassist $$0x40, %xmm3, %xmm2
            call 1f
            shufpd $$0, %xmm1, %xmm5
            movdqu %xmm5, 160($0)
            movdqa %xmm1, %xmm6
            shufpd $$1, %xmm3, %xmm6
            movdqu %xmm6, 176($0)

            aeskeygenassist $$0x80, %xmm3, %xmm2
            call 1f
            movdqu %xmm1, 192($0)

            jmp 2f

            1:
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

            2:
        "
        : "=r" (round_keysp)
        : "r" (keyp), "0" (round_keysp)
        : "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "memory"
        : "volatile"
        );

        match key_type {
            KeyType::Decryption => {
                // range of rounds keys from #1 to #11; skip the first and last key
                for i in range(1u, 12) {
                    aesimc(round_key.unsafe_mut(16 * i));
                }
            }
            KeyType::Encryption => { /* nothing more to do */ }
        }
    }
}

#[allow(unused_assignments)]
fn setup_working_key_aesni_256(key: &[u8], key_type: KeyType, round_key: &mut [u8]) {
    unsafe {
        let mut round_keysp: *mut u8 = round_key.unsafe_mut(0);
        let keyp: *const u8 = key.unsafe_get(0);

        asm!(
        "
            movdqu ($1), %xmm1
            movdqu 16($1), %xmm3
            movdqu %xmm1, ($0)
            movdqu %xmm3, 16($0)

            aeskeygenassist $$0x1, %xmm3, %xmm2
            call 1f
            movdqu %xmm1, 32($0)

            aeskeygenassist $$0x0, %xmm1, %xmm2
            call 2f
            movdqu %xmm3, 48($0)

            aeskeygenassist $$0x2, %xmm3, %xmm2
            call 1f
            movdqu %xmm1, 64($0)

            aeskeygenassist $$0x0, %xmm1, %xmm2
            call 2f
            movdqu %xmm3, 80($0)

            aeskeygenassist $$0x4, %xmm3, %xmm2
            call 1f
            movdqu %xmm1, 96($0)

            aeskeygenassist $$0x0, %xmm1, %xmm2
            call 2f
            movdqu %xmm3, 112($0)

            aeskeygenassist $$0x8, %xmm3, %xmm2
            call 1f
            movdqu %xmm1, 128($0)

            aeskeygenassist $$0x0, %xmm1, %xmm2
            call 2f
            movdqu %xmm3, 144($0)

            aeskeygenassist $$0x10, %xmm3, %xmm2
            call 1f
            movdqu %xmm1, 160($0)

            aeskeygenassist $$0x0, %xmm1, %xmm2
            call 2f
            movdqu %xmm3, 176($0)

            aeskeygenassist $$0x20, %xmm3, %xmm2
            call 1f
            movdqu %xmm1, 192($0)

            aeskeygenassist $$0x0, %xmm1, %xmm2
            call 2f
            movdqu %xmm3, 208($0)

            aeskeygenassist $$0x40, %xmm3, %xmm2
            call 1f
            movdqu %xmm1, 224($0)

            jmp 3f

            1:
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

            2:
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

            3:
        "
        : "=r" (round_keysp)
        : "r" (keyp), "0" (round_keysp)
        : "xmm1", "xmm2", "xmm3", "xmm4", "memory"
        : "volatile"
        );

        match key_type {
            KeyType::Decryption => {
                // range of rounds keys from #1 to #13; skip the first and last key
                for i in range(1u, 14) {
                    aesimc(round_key.unsafe_mut(16 * i));
                }
            }
            KeyType::Encryption => { /* nothing more to do */ }
        }
    }
}

#[allow(unused_assignments)]
fn encrypt_block_aesni(rounds: uint, input: &[u8], round_keys: &[u8], output: &mut [u8]) {
    unsafe {
        let mut rounds = rounds;
        let mut round_keysp: *const u8 = round_keys.unsafe_get(0);
        let outp: *mut u8 = output.unsafe_mut(0);
        let inp: *const u8 = input.unsafe_get(0);

        asm!(
        "
            /* Copy the data to encrypt to xmm1 */
            movdqu ($2), %xmm1

            /* Perform round 0 - the whitening step */
            movdqu ($1), %xmm0
            add $$0x10, $1
            pxor %xmm0, %xmm1

            /* Perform all remaining rounds (except the final one) */
            1:
            movdqu ($1), %xmm0
            add $$0x10, $1
            aesenc %xmm0, %xmm1
            sub $$0x01, $0
            cmp $$0x01, $0
            jne 1b

            /* Perform the last round */
            movdqu ($1), %xmm0
            aesenclast %xmm0, %xmm1

            /* Finally, move the result from xmm1 to outp */
            movdqu %xmm1, ($3)
        "
        : "=r" (rounds), "=r" (round_keysp) // outputs
        : "r" (inp), "r" (outp), "0" (rounds), "1" (round_keysp) // inputs
        : "xmm0", "xmm1", "memory", "cc" // clobbers
        : "volatile" // options
        );
    }
}

#[allow(unused_assignments)]
fn decrypt_block_aesni(rounds: uint, input: &[u8], round_keys: &[u8], output: &mut [u8]) {
    unsafe {
        let mut rounds = rounds;
        let mut round_keysp: *const u8 = round_keys.unsafe_get(round_keys.len() - 16);
        let outp: *mut u8 = output.unsafe_mut(0);
        let inp: *const u8 = input.unsafe_get(0);

        asm!(
        "
            /* Copy the data to decrypt to xmm1 */
            movdqu ($2), %xmm1

            /* Perform round 0 - the whitening step */
            movdqu ($1), %xmm0
            sub $$0x10, $1
            pxor %xmm0, %xmm1

            /* Perform all remaining rounds (except the final one) */
            1:
            movdqu ($1), %xmm0
            sub $$0x10, $1
            aesdec %xmm0, %xmm1
            sub $$0x01, $0
            cmp $$0x01, $0
            jne 1b

            /* Perform the last round */
            movdqu ($1), %xmm0
            aesdeclast %xmm0, %xmm1

            /* Finally, move the result from xmm1 to outp */
            movdqu %xmm1, ($3)
        "
        : "=r" (rounds), "=r" (round_keysp) // outputs
        : "r" (inp), "r" (outp), "0" (rounds), "1" (round_keysp) // inputs
        : "xmm0", "xmm1", "memory", "cc" // clobbers
        : "volatile" // options
        );
    }
}
