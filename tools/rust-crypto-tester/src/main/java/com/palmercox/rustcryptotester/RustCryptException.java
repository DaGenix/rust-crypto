// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

package com.palmercox.rustcryptotester;

class RustCryptException extends Exception {
	private static final long serialVersionUID = 1L;

	private final int code;

	public RustCryptException(final int code, final String msg) {
		super(msg);
		this.code = code;
	}

	public int getCode() {
		return code;
	}
}
