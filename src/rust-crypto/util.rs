// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(target_arch = "x86")]
#[cfg(target_arch = "x86_64")]
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
        )
		// No idea why, but on 32-bit targets, the compiler complains
		// about not having enough registers. Adding in this dummy
		// section, however, seems to fix it.
        asm!("")
    }

    return (flags & 0x02000000) != 0;
}
