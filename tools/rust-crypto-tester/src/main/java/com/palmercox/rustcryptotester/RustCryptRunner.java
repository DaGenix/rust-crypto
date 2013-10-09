// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

package com.palmercox.rustcryptotester;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public final class RustCryptRunner {
	private final File rustExec;
	private final ExecutorService exec;

	public RustCryptRunner(final File rustExec) {
		this.rustExec = rustExec;
		exec = Executors.newCachedThreadPool();
	}

	private static final class OutputReader implements
			Callable<ByteArrayOutputStream> {
		private final InputStream stream;

		public OutputReader(final InputStream stream) {
			this.stream = stream;
		}

		@Override
		public ByteArrayOutputStream call() throws Exception {
			final ByteArrayOutputStream data = new ByteArrayOutputStream();
			final byte[] buff = new byte[4096];
			int cnt = 0;
			while ((cnt = stream.read(buff)) >= 0) {
				data.write(buff, 0, cnt);
			}
			return data;
		}
	}

	private static String getMessage(final byte[] data) throws Exception {
		Charset c = Charset.forName("UTF-8");
		return c.decode(ByteBuffer.wrap(data)).toString();
	}

	public byte[] runRustCrypt(final byte[] data, final Object... parameters)
			throws Exception {
		final List<String> params = new ArrayList<>();

		params.add(rustExec.getAbsolutePath());

		for (final Object p : parameters) {
			params.add(p.toString());
		}

		final ProcessBuilder pb = new ProcessBuilder(params);

		final Process p = pb.start();

		if (data != null) {
			p.getOutputStream().write(data);
		}
		p.getOutputStream().close();

		final Future<ByteArrayOutputStream> in = exec.submit(new OutputReader(p.getInputStream()));
		final Future<ByteArrayOutputStream> err = exec.submit(new OutputReader(p.getErrorStream()));

		final int result = p.waitFor();

		if (err.get().size() > 0) {
			System.out.println("STDERR: " + getMessage(err.get().toByteArray()));
		}

		if (result != 0) {
			throw new RustCryptException(result, getMessage(err.get().toByteArray()));
		}

		return in.get().toByteArray();
	}

	public final void close() {
		exec.shutdown();
	}
}
