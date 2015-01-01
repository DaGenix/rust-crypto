// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn supports_aesni() -> bool {
    let mut flags: u32;
    unsafe {
        asm!(
        "
        mov $$1, %eax;
        cpuid;
        mov %ecx, $0;
        "
        : "=r" (flags) // output
        : // input
        : "eax", "ebx", "ecx", "edx" // clobbers
        );
        // No idea why, but on 32-bit targets, the compiler complains
        // about not having enough registers. Adding in this dummy
        // section, however, seems to fix it.
        asm!("");
    }

    (flags & 0x02000000) != 0
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(unused_assignments)]
#[allow(unused_variables)]
unsafe fn fixed_time_eq_asm(mut lhsp: *const u8, mut rhsp: *const u8, mut count: uint) -> bool {
    let mut result: u8 = 0;

    asm!(
        "
            1:

            mov ($1), %cl
            xor ($2), %cl
            or %cl, $0

            inc $1
            inc $2
            dec $3
            jnz 1b
        "
        : "+r" (result), "+r" (lhsp), "+r" (rhsp), "+r" (count) // all input and output
        : // input
        : "cl", "cc" // clobbers
        : "volatile" // flags
    );

    result == 0
}

#[cfg(target_arch = "arm")]
#[allow(unused_assignments)]
unsafe fn fixed_time_eq_asm(mut lhsp: *const u8, mut rhsp: *const u8, mut count: uint) -> bool {
    let mut result: u8 = 0;

    asm!(
        "
            1:

            ldrb r4, [$1]
            ldrb r5, [$2]
            eor r4, r4, r5
            orr $0, $0, r4

            add $1, $1, #1
            add $2, $2, #1
            subs $3, $3, #1
            bne 1b
        "
        : "+r" (result), "+r" (lhsp), "+r" (rhsp), "+r" (count) // all input and output
        : // input
        : "r4", "r5", "cc" // clobbers
        : "volatile" // flags
    );

    result == 0
}

/// Compare two vectors using a fixed number of operations. If the two vectors are not of equal
/// length, the function returns false immediately.
pub fn fixed_time_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() {
        false
    } else if lhs.len() == 0 {
        true
    } else {
        let count = lhs.len();

        unsafe {
            let lhsp = lhs.unsafe_get(0);
            let rhsp = rhs.unsafe_get(0);
            fixed_time_eq_asm(lhsp, rhsp, count)
        }
    }
}

#[cfg(test)]
mod test {
    use util::fixed_time_eq;

    #[test]
    pub fn test_fixed_time_eq() {
        let a = [0, 1, 2];
        let b = [0, 1, 2];
        let c = [0, 1, 9];
        let d = [9, 1, 2];
        let e = [2, 1, 0];
        let f = [2, 2, 2];
        let g = [0, 0, 0];

        assert!(fixed_time_eq(&a, &a));
        assert!(fixed_time_eq(&a, &b));

        assert!(!fixed_time_eq(&a, &c));
        assert!(!fixed_time_eq(&a, &d));
        assert!(!fixed_time_eq(&a, &e));
        assert!(!fixed_time_eq(&a, &f));
        assert!(!fixed_time_eq(&a, &g));
    }
}
