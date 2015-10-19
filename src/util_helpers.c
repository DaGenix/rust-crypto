// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__i386__)
uint32_t rust_crypto_util_supports_aesni() {
    uint32_t flags;
    asm(
        "pushl %%ebx; \
         mov $1, %%eax; cpuid; \
         popl %%ebx;"
        : "=c" (flags) // output
        : // input
        : "eax", "edx" // clobbers
    );
    return flags & 0x02000000;
}
#endif

#if defined(__x86_64__)
uint32_t rust_crypto_util_supports_aesni() {
    uint32_t flags;
    asm(
        "mov $1, %%eax; cpuid;"
        : "=c" (flags) // output
        : // input
        : "eax", "ebx", "edx" // clobbers
    );
    return flags & 0x02000000;
}
#endif

uint32_t rust_crypto_util_fixed_time_eq(uint8_t* lhsp, uint8_t* rhsp, size_t count) {
	size_t i;
	uint32_t status = 0;

	for (i=0; i < count; i++)
		status |= lhsp[i] ^ rhsp[i];

	return status;
}

void rust_crypto_util_secure_memset(uint8_t* dst, uint8_t val, size_t count) {
    memset(dst, val, count);
    asm("" : : "g" (dst) : "memory");
}

