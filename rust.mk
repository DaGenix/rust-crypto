# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

# This file was taken from the rust-geom project with some minor modifications,
# including adding the license header.

RUST_CRATE_PKGID = $(shell sed -ne 's/^\#\[ *pkgid *= *"\(.*\)" *];$$/\1/p' $(firstword $(1)))
RUST_CRATE_PATH = $(shell printf $(1) | sed -ne 's/^\([^\#]*\)\/.*$$/\1/p')
RUST_CRATE_NAME = $(shell printf $(1) | sed -ne 's/^\([^\#]*\/\)\{0,1\}\([^\#]*\).*$$/\2/p')
RUST_CRATE_VERSION = $(shell printf $(1) | sed -ne 's/^[^\#]*\#\(.*\)$$/\1/p')
RUST_CRATE_HASH = $(shell printf $(strip $(1)) | shasum -a 256 | sed -ne 's/^\(.\{8\}\).*$$/\1/p')

ifeq ($(shell uname),Darwin)
RUST_DYLIB_EXT=dylib
else
RUST_DYLIB_EXT=so
endif

define RUST_CRATE

_rust_crate_dir = $(dir $(1))
_rust_crate_lib = $$(_rust_crate_dir)lib.rs
_rust_crate_test = $$(_rust_crate_dir)test.rs

_rust_crate_pkgid = $$(call RUST_CRATE_PKGID, $$(_rust_crate_lib))
_rust_crate_name = $$(call RUST_CRATE_NAME, $$(_rust_crate_pkgid))
_rust_crate_version = $$(call RUST_CRATE_VERSION, $$(_rust_crate_pkgid))
_rust_crate_hash = $$(call RUST_CRATE_HASH, $$(_rust_crate_pkgid))
_rust_crate_dylib = lib$$(_rust_crate_name)-$$(_rust_crate_hash)-$$(_rust_crate_version).$(RUST_DYLIB_EXT)

_rust_lib_d = $$(patsubst %.rs,%.d,$$(_rust_crate_lib))
_rust_test_d = $$(patsubst %.rs,%.d,$$(_rust_crate_test))

.PHONY : $$(_rust_crate_name)
$$(_rust_crate_name) : $$(_rust_crate_dir)$$(_rust_crate_dylib)

$$(_rust_crate_dir)$$(_rust_crate_dylib) : $$(_rust_crate_lib)
	$$(RUSTC) $$(RUSTFLAGS) --dep-info --lib $$<

-include $$(_rust_lib_d)

ifneq ($$(wildcard $$(_rust_crate_test)),"")

.PHONY : check-$$(_rust_crate_name)
check-$$(_rust_crate_name): $$(_rust_crate_name)-test
	./$$(_rust_crate_name)-test

$$(_rust_crate_name)-test : $$(_rust_crate_test)
	$$(RUSTC) $$(RUSTFLAGS) --dep-info --test $$< -o $(_rust_crate_dir)$$@
	mv test.d $$(_rust_crate_dir)

-include $$(_rust_test_d)

.PHONY : clean-$$(_rust_crate_name)
clean-$$(_rust_crate_name):
	rm -f $$(_rust_crate_dir)$$(_rust_crate_dylib)
	rm -f $$(_rust_lib_d)
	rm -f $$(_rust_create_dir)$$(_rust_crate_name)-test
	rm -f $$(_rust_test_d)

endif

endef
