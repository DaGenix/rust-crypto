# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

# This file was taken from the rust-geom project with some major modifications,
# including adding the license header (which corresponds to the licensing of
# the rust-geom project at the time that this file was taken from it).

ifeq ($(shell uname),Darwin)
RUST_DYLIB_EXT=dylib
else
RUST_DYLIB_EXT=so
endif

# param 1 - Some value to make all of the variables defined unique
# param 2 - The path to the main file in the crate
# param 3 - The output type
# param 4 - Any extra parameters to pass to $(RUSTC)

define RUST_CRATE

$(1)_rust_crate_dir = $(dir $(2))
$(1)_rust_crate_main = $(2)
$(1)_rust_crate_test = $$($(1)_rust_crate_dir)test.rs

$(1)_rust_crate_name = $$(shell $$(RUSTC) --crate-name $$($(1)_rust_crate_main))
$(1)_rust_crate_out = $$(shell $$(RUSTC) --crate-file-name --crate-type=$(3) $$($(1)_rust_crate_main))

# If compiling a binary, these two variables will be equal, so it doesn't make
# any sense to create a rule that lists itself as its dependancy.
ifneq ($$($(1)_rust_crate_name),$$($(1)_rust_crate_out))
.PHONY : $$($(1)_rust_crate_name)
$$($(1)_rust_crate_name) : $$($(1)_rust_crate_out)
endif

$$($(1)_rust_crate_out) : $$($(1)_rust_crate_main)
	$$(RUSTC) $$(RUSTFLAGS) $(4) --dep-info $$($(1)_rust_crate_main).d --crate-type=$(3) --out-dir . $$<

-include $$($(1)_rust_crate_main).d

ifneq ($$(wildcard $$($(1)_rust_crate_test)),"")

.PHONY : check-$$($(1)_rust_crate_name)
check-$$($(1)_rust_crate_name): $$($(1)_rust_crate_name)-test
	./$$($(1)_rust_crate_name)-test

$$($(1)_rust_crate_name)-test : $$($(1)_rust_crate_test)
	$$(RUSTC) $$(RUSTFLAGS) $(4) --dep-info $$($(1)_rust_crate_test).d --test $$< -o $$($(1)_rust_crate_name)-test

-include $$($(1)_rust_crate_test).d

.PHONY : clean-$$($(1)_rust_crate_name)
clean-$$($(1)_rust_crate_name):
	@rm -f $$($(1)_rust_crate_out)
	@rm -f $$($(1)_rust_crate_main).d
	@rm -f $$($(1)_rust_crate_name)-test
	@rm -f $$($(1)_rust_crate_test).d
	@rm -f $$($(1)_rust_crate_dir)/*.o
endif

endef

