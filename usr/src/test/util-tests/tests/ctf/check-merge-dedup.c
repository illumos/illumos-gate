/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2019, Joyent, Inc.
 */

/*
 * This tests that we don't end up with several copies of the same type.
 */

#include "check-common.h"

static check_symbol_t check_syms[] = {
	{ "int", "a" },
	{ "short", "b" },
	{ "const char *", "c" },
	{ "float", "d" },
	{ "double" "e" },
	{ "int", "f" },
	{ "short", "g" },
	{ "const char *", "h" },
	{ "float", "i" },
	{ "double" "j" },
	{ "int", "k" },
	{ "short", "l" },
	{ "const char *", "m" },
	{ "float", "n" },
	{ "double" "o" },
	{ "int", "p" },
	{ "short", "q" },
	{ "const char *", "r" },
	{ "float", "s" },
	{ "double" "t" },
	{ "struct dup" "dupmain" },
	{ "struct dup" "dup1" },
	{ "struct dup" "dup2" },
	{ "struct dup" "dup3" },
	{ NULL }
};


int
main(int argc, char *argv[])
{
	int i, ret = 0;

	if (argc < 2) {
		errx(EXIT_FAILURE, "missing test files");
	}

	for (i = 1; i < argc; i++) {
		ctf_file_t *fp;

		if ((fp = ctf_open(argv[i], &ret)) == NULL) {
			warnx("failed to open %s: %s", argv[i],
			    ctf_errmsg(ret));
			ret = EXIT_FAILURE;
			continue;
		}

		if (!ctftest_check_symbols(fp, check_syms)) {
			ret = EXIT_FAILURE;
		}

		if (!ctftest_duplicates(fp)) {
			ret = EXIT_FAILURE;
		}

		ctf_close(fp);
	}

	return (ret);
}
