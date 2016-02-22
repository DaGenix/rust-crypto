// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate gcc;

use std::env;
use std::path::Path;

fn main() {
    let target = env::var("TARGET").unwrap();
    let host = env::var("HOST").unwrap();
    if target.contains("msvc") && host.contains("windows") {
        let mut config = gcc::Config::new();
        config.file("src/util_helpers.asm");
        config.file("src/aesni_helpers.asm");
        if target.contains("x86_64") {
            config.define("X64", None);
        }
        config.compile("lib_rust_crypto_helpers.a");
    }
    else {
        let mut cfg = gcc::Config::new();
        cfg.file("src/util_helpers.c");
        cfg.file("src/aesni_helpers.c");
        // gcc can't build this library so, unless the user has explicitly
        // specified a different C compiler, use clang.
        if env::var_os("CC").is_none() {
            cfg.compiler(Path::new("clang"));
        }
        cfg.compile("lib_rust_crypto_helpers.a");
    }
}

