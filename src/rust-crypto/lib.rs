// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[license = "MIT/ASL2"];
#[crate_id = "github.com/DaGenix/rust-crypto#rust-crypto:0.1"];

#[feature(asm)];
#[feature(macro_rules)];

extern mod extra;

mod cryptoutil;
pub mod digest;
pub mod hmac;
pub mod mac;
pub mod md5;
pub mod pbkdf2;
pub mod scrypt;
pub mod sha1;
pub mod sha2;
