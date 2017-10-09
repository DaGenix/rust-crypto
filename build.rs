// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate cc;

use std::env;
use std::path::Path;

fn main() {
    let target = env::var("TARGET").unwrap();
    let host = env::var("HOST").unwrap();
    if target.contains("msvc") && host.contains("windows") {
        let mut build = cc::Build::new();
        build.file("src/util_helpers.asm");
        build.file("src/aesni_helpers.asm");
        if target.contains("x86_64") {
            build.define("X64", None);
        }
        build.compile("lib_rust_crypto_helpers.a");
    }
    else {
        let mut build = cc::Build::new();
        build.file("src/util_helpers.c");
        build.file("src/aesni_helpers.c");
        if env::var_os("CC").is_none() {
            if host.contains("openbsd") {
                // Use clang on openbsd since there have been reports that
                // GCC doesn't like some of the assembly that we use on that
                // platform.
                build.compiler(Path::new("clang"));
            } else if target == host {
                build.compiler(Path::new("cc"));
            }
        }
        build.compile("lib_rust_crypto_helpers.a");
    }
}

