# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

include rust.mk

RUSTC ?= rustc
MVN ?= mvn
RUSTFLAGS ?= -O

.PHONY : all
all: rust-crypto

.PHONY : check
check: check-rust-crypto

rust-crypto-util: src/rust-crypto/librust-crypto-78d3c8e4-0.1.so
	$(RUSTC) $(RUSTFLAGS) -L src/rust-crypto/ --dep-info src/rust-crypto-util/main.rs -o rust-crypto-util
	mv main.d src/rust-crypto-util/

-include src/rust-crypto-util/main.d

.PHONY : clean
clean: clean-rust-crypto
	rm -f rust-crypto-util
	rm -f src/rust-crypto-util/main.d

.PHONY : test-tool
test-tool: rust-crypto-util
	cd tools/rust-crypto-tester; \
	$(MVN) exec:java -Dexec.mainClass="com.palmercox.rustcryptotester.App" -Dexec.args="--rustexec ../../rust-crypto-util"

$(eval $(call RUST_CRATE, src/rust-crypto/))

