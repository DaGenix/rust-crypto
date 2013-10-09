// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

package com.palmercox.rustcryptotester;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

import com.lambdaworks.crypto.SCrypt;

public class ScryptTester extends Tester {
	private final int minLogN;
	private final int maxLogN;
	private final int minR;
	private final int maxR;
	private final int minP;
	private final int maxP;
	private final int count;
	
	public ScryptTester(
			int minLogN,
			int maxLogN,
			int minR,
			int maxR,
			int minP,
			int maxP,
			int count) {
		this.minLogN = minLogN;
		this.maxLogN = maxLogN;
		this.minR = minR;
		this.maxR = maxR;
		this.minP = minP;
		this.maxP = maxP;
		this.count = count;
	}

	private static Object[] getParams(
			final int logN,
			final int r,
			final int p,
			final int dkLen) {
		final ArrayList<Object> arr = new ArrayList<>();
		arr.add("scrypt");
		arr.add("--logn");
		arr.add(logN);
		arr.add("-r");
		arr.add(r);
		arr.add("-p");
		arr.add(p);
		arr.add("--dklen");
		arr.add(dkLen);
		arr.add("--rawsalt");
		arr.add("--rawpassword");
		arr.add("--rawoutput");
		return arr.toArray();
	}
	
	@Override
	public boolean test(
			final RustCryptRunner runner,
			final Random rand) throws Exception {
		for (int i = 0; i < count; i++) {
			final int logN = rand.nextInt(maxLogN - minLogN) + minLogN;
			final int r = rand.nextInt(maxR - minR) + minR;
			final int p = rand.nextInt(maxP - minP) + minP;
			final byte[] salt = new byte[rand.nextInt(64)];
			rand.nextBytes(salt);
			final byte[] password = new byte[rand.nextInt(512)];
			rand.nextBytes(password);
			final int dkLen = rand.nextInt(512);
			
			final ByteArrayOutputStream bos = new ByteArrayOutputStream();
			final DataOutputStream dataStream = new DataOutputStream(bos);
			dataStream.writeInt(salt.length);
			dataStream.write(salt);
			dataStream.writeInt(password.length);
			dataStream.write(password);
			final byte[] data = bos.toByteArray();
			
			final byte[] result = runner.runRustCrypt(data, getParams(logN, r, p, dkLen));
			
			final byte[] expectedResult = SCrypt.scrypt(password, salt, (1 << logN), r, p, dkLen);
			
			if (Arrays.equals(result, expectedResult)) {
				System.out.println("Ok: " + i);
			} else {
				return false;
			}
		}
		
		return true;
	}
}
