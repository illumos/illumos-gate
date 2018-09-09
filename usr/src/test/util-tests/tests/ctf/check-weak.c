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
 * Check that we properly handle weak symbols.
 */

#include "check-common.h"


static check_function_test_t functions[] = {
	{ "mumble", "int", 0, 0, NULL },
	{ "_mumble", "int", 0, 0, NULL },
	{ NULL }
};

static check_symbol_t check_syms[] = {
	{ "strong", "int" },
	{ "_strong", "int" },
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
		uint_t j;

		if ((fp = ctf_open(argv[i], &ret)) == NULL) {
			warnx("failed to open %s: %s", argv[i],
			    ctf_errmsg(ret));
			ret = EXIT_FAILURE;
			continue;
		}

		if (!ctftest_check_symbols(fp, check_syms))
			ret = EXIT_FAILURE;

		for (j = 0; functions[j].cft_name != NULL; j++) {
			if (!ctftest_check_function(functions[j].cft_name, fp,
			    functions[j].cft_rtype, functions[j].cft_nargs,
			    functions[j].cft_flags, functions[j].cft_args)) {
				ret = EXIT_FAILURE;
			}
		}

		ctf_close(fp);
	}

	return (ret);
}
