// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

package com.palmercox.rustcryptotester;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;

public class App {
	private static List<Tester> getTesters() {
		// TODO - Store name somewhere
		final List<Tester> testers = new ArrayList<>();
		testers.add(new ScryptTester(8, 12, 1, 16, 1, 4, 100));
		return testers;
	}

	private static Options getOptions() {
		final Options options = new Options();
		options.addOption("help", false, "Print out help.");
		options.addOption("rustexec", true,	"Location of the Rust Crypto executable.");
		return options;
	}

	private static void help() {
		final HelpFormatter help = new HelpFormatter();
		help.printHelp("rust-crypto-tester", getOptions());
	}

	public static void main(String[] args) throws Exception {
		final CommandLineParser clp = new GnuParser();
		final CommandLine cl = clp.parse(getOptions(), args);

		if (cl.hasOption("help")) {
			help();
			return;
		}

		final String rustExec;
		if (cl.hasOption("rustexec")) {
			rustExec = cl.getOptionValue("rustexec");
		} else {
			help();
			return;
		}

		System.out.println("Starting Rust Crypto Tests:");

		boolean ok = true;

		final RustCryptRunner runner = new RustCryptRunner(new File(rustExec));
		try {
			for (final Tester t : getTesters()) {
				final Random rand = new Random(0);
				final boolean result = t.test(runner, rand);
				System.out.println("Test passed: " + result);
				ok = ok && result;
			}
		} finally {
			runner.close();
		}

		System.out.println("Done");

		if (!ok) {
			System.exit(1);
		}
	}
}
