// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate gcc;

use std::env;

fn main() {
    let target = env::var("TARGET").unwrap();
    if target.contains("msvc") {
        let mut config = gcc::Config::new();
        config.file("src/util_helpers.asm");
        config.file("src/aesni_helpers.asm");
        if target.contains("x86_64") {
            config.define("X64", None);
        }
        config.compile("lib_rust_crypto_helpers.a");
    } else {
        gcc::compile_library(
            "lib_rust_crypto_helpers.a",
            &["src/util_helpers.c", "src/aesni_helpers.c"]);
    }
}

