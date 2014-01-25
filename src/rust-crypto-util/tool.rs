// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern mod extra;
extern mod rust_crypto = "rust-crypto";

use std::io;
use std::os;
use std::vec;

use extra::getopts::{optopt, optflag, getopts, Matches};

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

    let salt_len = io::stdin().read_be_u32();
    let salt = io::stdin().read_bytes(salt_len as uint);
    let pass_len = io::stdin().read_be_u32();
    let pass = io::stdin().read_bytes(pass_len as uint);

    let params = scrypt::ScryptParams::new(logn, r, p);
    let mut output = vec::from_elem(dklen, 0u8);
    scrypt::scrypt(pass, salt, &params, output);

    io::stdout().write(output);
}

fn main() {
    let args = os::args();

    let opts = ~[
        // General parameters:
        optflag("h"),
        optflag("help"),

        // Scrypt parameters:
        optopt("logn"),
        optopt("r"),
        optopt("p"),
        optopt("dklen"),
        optflag("rawsalt"),
        optflag("rawpassword"),
        optflag("rawoutput"),
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
    let algorithm_name: &str = matches.free[0];

    match algorithm_name {
        "scrypt" => run_scrypt(&matches),
        _ => {
            print_usage();
            return;
        }
    }
}
