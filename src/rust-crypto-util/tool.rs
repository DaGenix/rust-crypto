// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![license = "MIT/ASL2"]
#![crate_id = "github.com/DaGenix/rust-crypto#rust-crypto-util:0.1"]

#![allow(deprecated_owned_vector)]

extern crate getopts;
extern crate rust_crypto = "rust-crypto";

use std::io;
use std::os;
use std::slice;

use getopts::{optopt, optflag, getopts, Matches};

use rust_crypto::scrypt;

fn print_usage() {
    println!("Usage: rust-crypto-util <algorithm> [options]");
    println!("-h, --help\tUsage");
    println!("");
    println!("Algorithms:");
    println!(" * Scrypt (scrypt)");
    println!("");
    println!("Scrypt options:");
    println!("--logn\t\tThe Log N parameter");
    println!("-r\t\tThe R parameter");
    println!("-p\t\tThe P parameter");
    println!("--dklen\t\tThe DkLen parameter");
    println!("--rawsalt\tThe salt parameter is supplied on STDIN");
    println!("--rawpassword\tThe password parameter is supplied on STDIN");
    println!("--rawoutput\tThe resulting value should be output directly to STDOUT");
}

fn run_scrypt(matches: &Matches) {
    if !matches.opt_present("logn") || !matches.opt_present("r") || !matches.opt_present("p") ||
       !matches.opt_present("dklen") {
        print_usage();
        return;
    }
    let logn = from_str::<u8>(matches.opt_str("logn").unwrap()).unwrap();
    let r = from_str::<u32>(matches.opt_str("r").unwrap()).unwrap();
    let p = from_str::<u32>(matches.opt_str("p").unwrap()).unwrap();
    let dklen = from_str::<uint>(matches.opt_str("dklen").unwrap()).unwrap();

    if !matches.opt_present("rawsalt") || !matches.opt_present("rawpassword") ||
       !matches.opt_present("rawoutput") {
        println!("Required options missing.");
        return;
    }

    let salt_len = io::stdio::stdin_raw().read_be_u32().unwrap();
    let salt = io::stdio::stdin_raw().read_exact(salt_len as uint).unwrap();
    let pass_len = io::stdio::stdin_raw().read_be_u32().unwrap();
    let pass = io::stdio::stdin_raw().read_exact(pass_len as uint).unwrap();

    let params = scrypt::ScryptParams::new(logn, r, p);
    let mut output = slice::from_elem(dklen, 0u8);
    scrypt::scrypt(pass, salt, &params, output);

    match io::stdout().write(output) {
        Ok(_) => { },
        Err(_) => fail!("Error writing result")
    }
}

fn main() {
    let args = os::args();

    let opts = ~[
        // General parameters:
        optflag("h", "help", "Print help"),

        // Scrypt parameters:
        optopt("", "logn", "Log-N parameter for Scrypt", ""),
        optopt("r", "", "R parameter for Scrypt", ""),
        optopt("p", "", "P parameter for Scrypt", ""),
        optopt("", "dklen", "Length of the derived key", ""),
        optflag("", "rawsalt", "Use a raw salt value"),
        optflag("", "rawpassword", "Use a raw password value"),
        optflag("", "rawoutput", "Use raw output mode"),
    ];

    let matches = match getopts(args.tail(), opts) {
        Ok(m) => { m }
        Err(f) => { fail!(f.to_err_msg()) }
    };

    if matches.opt_present("h") || matches.opt_present("help") {
        print_usage();
        return;
    }

    if matches.free.is_empty() {
        print_usage();
        return;
    }
    let algorithm_name = matches.free.get(0).as_slice();

    match algorithm_name {
        "scrypt" => run_scrypt(&matches),
        _ => {
            print_usage();
            return;
        }
    }
}
