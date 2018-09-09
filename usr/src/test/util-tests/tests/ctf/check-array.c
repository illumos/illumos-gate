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
 * Check that we properly generate basic nested arrays.
 */

#include "check-common.h"

static check_number_t check_base[] = {
	{ "char", CTF_K_INTEGER, CTF_INT_SIGNED | CTF_INT_CHAR, 0, 8 },
	{ "int", CTF_K_INTEGER, CTF_INT_SIGNED, 0, 32 },
	{ "double", CTF_K_FLOAT, CTF_FP_DOUBLE, 0, 64 },
	{ NULL }
};

static check_symbol_t check_syms[] = {
	{ "a", "int [3]" },
	{ "b", "double [42]" },
	{ "c", "const char *[2]" },
	{ "d", "int [4][5]" },
	{ "e", "int [4][5][6]" },
	{ "f", "int [4][5][6][7]" },
	{ "g", "int [4][5][6][7][8]" },
	{ "h", "int [4][5][6][7][8][9]" },
	{ "i", "int [4][5][6][7][8][9][10]" },
	{ NULL }
};

static check_descent_t check_array_a[] = {
	{ "int [3]", CTF_K_ARRAY, "int", 3 },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_t check_array_b[] = {
	{ "double [42]", CTF_K_ARRAY, "double", 42 },
	{ "double", CTF_K_FLOAT },
	{ NULL }
};

static check_descent_t check_array_c[] = {
	{ "const char *[2]", CTF_K_ARRAY, "const char *", 2 },
	{ "const char *", CTF_K_POINTER },
	{ "const char", CTF_K_CONST },
	{ "char", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_t check_array_i[] = {
	{ "int [4][5][6][7][8][9][10]", CTF_K_ARRAY,
	    "int [5][6][7][8][9][10]", 4 },
	{ "int [5][6][7][8][9][10]", CTF_K_ARRAY, "int [6][7][8][9][10]", 5 },
	{ "int [6][7][8][9][10]", CTF_K_ARRAY, "int [7][8][9][10]", 6 },
	{ "int [7][8][9][10]", CTF_K_ARRAY, "int [8][9][10]", 7 },
	{ "int [8][9][10]", CTF_K_ARRAY, "int [9][10]", 8 },
	{ "int [9][10]", CTF_K_ARRAY, "int [10]", 9 },
	{ "int [10]", CTF_K_ARRAY, "int", 10 },
	{ "int", CTF_K_INTEGER },
	{ NULL },
};

static check_descent_test_t descents[] = {
	{ "a", check_array_a },
	{ "b", check_array_b },
	{ "c", check_array_c },
	{ "i", check_array_i },
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
		uint_t d;

		if ((fp = ctf_open(argv[i], &ret)) == NULL) {
			warnx("failed to open %s: %s", argv[i],
			    ctf_errmsg(ret));
			ret = EXIT_FAILURE;
			continue;
		}
		if (!ctftest_check_numbers(fp, check_base))
			ret = EXIT_FAILURE;
		if (!ctftest_check_symbols(fp, check_syms))
			ret = EXIT_FAILURE;
		for (d = 0; descents[d].cdt_sym != NULL; d++) {
			if (!ctftest_check_descent(descents[d].cdt_sym, fp,
			    descents[d].cdt_tests)) {
				ret = EXIT_FAILURE;
			}
		}
		ctf_close(fp);
	}

	return (ret);
}
