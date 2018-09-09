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
 * Check that we properly handle functions and function pointers.
 */

#include "check-common.h"

static const char *one_args[] = { "int" };
static const char *two_args[] = { "int", "const char *" };
static const char *three_args[] = { "int", "const char *", "float" };
static const char *argument_args[] = { "uintptr_t" };
static const char *vararg_args[] = { "const char *" };

static check_function_test_t functions[] = {
	{ "simple_func", "void", 0, 0, NULL },
	{ "one", "void", 1, 0, one_args },
	{ "two", "void", 2, 0, two_args },
	{ "three", "void", 3, 0, three_args },
	{ "noarg", "const char *", 0, 0, NULL },
	{ "argument", "const char *", 1, 0, argument_args },
	{ "vararg", "void", 1, CTF_FUNC_VARARG, vararg_args },
	{ "vararg_ret", "uintptr_t", 1, CTF_FUNC_VARARG, vararg_args },
	{ NULL }
};

static const char *strfunc_args[] = { "const char *", "const char *" };

static check_function_test_t fptrs[] = {
	{ "strfunc_t", "int", 2, 0, strfunc_args },
	{ "vararg_t", "void", 1, CTF_FUNC_VARARG, vararg_args },
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

		for (j = 0; functions[j].cft_name != NULL; j++) {
			if (!ctftest_check_function(functions[j].cft_name, fp,
			    functions[j].cft_rtype, functions[j].cft_nargs,
			    functions[j].cft_flags, functions[j].cft_args)) {
				ret = EXIT_FAILURE;
			}
		}

		for (j = 0; fptrs[j].cft_name != NULL; j++) {
			if (!ctftest_check_fptr(fptrs[j].cft_name, fp,
			    fptrs[j].cft_rtype, fptrs[j].cft_nargs,
			    fptrs[j].cft_flags, fptrs[j].cft_args)) {
				ret = EXIT_FAILURE;
			}
		}

		ctf_close(fp);
	}

	return (ret);
}
