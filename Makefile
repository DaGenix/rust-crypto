# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

RUSTPKG=rustpkg
MVN=mvn
RUSTFLAGS=-O

all: rust-crypto

rust-crypto:
	$(RUSTPKG) install $(RUSTFLAGS) rust_crypto

crypt-util: rust-crypto
	$(RUSTPKG) install $(RUSTFLAGS) crypt-util

test:
	$(RUSTPKG) test rust_crypto

test-tool: crypt-util
	cd tools/rust-crypto-tester; \
	$(MVN) exec:java -Dexec.mainClass="com.palmercox.rustcryptotester.App" -Dexec.args="--rustexec ../../bin/crypt-util"

clean:
	rm -rf build bin .lib
