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

.PHONY : clean
clean: clean-rust-crypto clean-rust-crypto-util

.PHONY : test-tool
test-tool: rust-crypto-util
	@cd tools/rust-crypto-tester; \
	$(MVN) compile exec:java -Dexec.mainClass="com.palmercox.rustcryptotester.App" -Dexec.args="--rustexec ../../rust-crypto-util"

$(eval $(call RUST_CRATE,1,src/rust-crypto/lib.rs,rlib,))
$(eval $(call RUST_CRATE,2,src/rust-crypto-util/tool.rs,bin,-L .))

# RUST_CRATE doesn't know how to express dependancies between targets, so
# just do it manually here.
rust-crypto-util: $(1_rust_crate_out)
