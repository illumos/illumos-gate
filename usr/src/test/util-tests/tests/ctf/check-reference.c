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
 * Check that we properly understand reference types and can walk through them
 * as well as generate them.
 */

#include "check-common.h"

static check_number_t check_base[] = {
	{ "char", CTF_K_INTEGER, CTF_INT_SIGNED | CTF_INT_CHAR, 0, 8 },
	{ "int", CTF_K_INTEGER, CTF_INT_SIGNED, 0, 32 },
	{ "float", CTF_K_FLOAT, CTF_FP_SINGLE, 0, 32 },
	{ NULL }
};

static check_symbol_t check_syms[] = {
	{ "a", "int" },
	{ "aa", "test_int_t" },
	{ "b", "const short" },
	{ "c", "volatile float" },
	{ "d", "int *" },
	{ "dd", "int **" },
	{ "ddd", "int ***" },
	{ "e", "test_int_t *" },
	{ "ce", "const test_int_t *" },
	{ "ve", "volatile test_int_t *" },
	{ "cve", "const volatile test_int_t *" },
	{ "f", "int *const *" },
	{ "g", "const char *const" },
	{ NULL },
};

static check_descent_t check_descent_aa[] = {
	{ "test_int_t", CTF_K_TYPEDEF },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_t check_descent_b[] = {
	{ "const short", CTF_K_CONST },
	{ "short", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_t check_descent_c[] = {
	{ "volatile float", CTF_K_VOLATILE },
	{ "float", CTF_K_FLOAT },
	{ NULL }
};

static check_descent_t check_descent_d[] = {
	{ "int *", CTF_K_POINTER },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_t check_descent_dd[] = {
	{ "int **", CTF_K_POINTER },
	{ "int *", CTF_K_POINTER },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_t check_descent_ddd[] = {
	{ "int ***", CTF_K_POINTER },
	{ "int **", CTF_K_POINTER },
	{ "int *", CTF_K_POINTER },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_t check_descent_e[] = {
	{ "test_int_t *", CTF_K_POINTER },
	{ "test_int_t", CTF_K_TYPEDEF },
	{ "int", CTF_K_INTEGER },
	{ NULL },
};

static check_descent_t check_descent_ce[] = {
	{ "const test_int_t *", CTF_K_POINTER },
	{ "const test_int_t", CTF_K_CONST },
	{ "test_int_t", CTF_K_TYPEDEF },
	{ "int", CTF_K_INTEGER },
	{ NULL },
};

static check_descent_t check_descent_ve[] = {
	{ "volatile test_int_t *", CTF_K_POINTER},
	{ "volatile test_int_t", CTF_K_VOLATILE },
	{ "test_int_t", CTF_K_TYPEDEF },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_t check_descent_cve[] = {
	{ "const volatile test_int_t *", CTF_K_POINTER },
	{ "const volatile test_int_t", CTF_K_CONST },
	{ "volatile test_int_t", CTF_K_VOLATILE },
	{ "test_int_t", CTF_K_TYPEDEF },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_t check_descent_f[] = {
	{ "int *const *", CTF_K_POINTER },
	{ "int *const", CTF_K_CONST },
	{ "int *", CTF_K_POINTER },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_t check_descent_g[] = {
	{ "const char *const", CTF_K_CONST },
	{ "const char *", CTF_K_POINTER },
	{ "const char", CTF_K_CONST },
	{ "char", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_t check_descent_cvh[] = {
	{ "const volatile foo_t *", CTF_K_POINTER },
	{ "const volatile foo_t", CTF_K_CONST },
	{ "volatile foo_t", CTF_K_VOLATILE },
	{ "foo_t", CTF_K_TYPEDEF },
	{ "int *const *", CTF_K_POINTER },
	{ "int *const", CTF_K_CONST },
	{ "int *", CTF_K_POINTER },
	{ "int", CTF_K_INTEGER },
	{ NULL }
};

static check_descent_test_t descents[] = {
	{ "aa", check_descent_aa },
	{ "b", check_descent_b },
	{ "c", check_descent_c },
	{ "d", check_descent_d },
	{ "dd", check_descent_dd },
	{ "ddd", check_descent_ddd },
	{ "e", check_descent_e },
	{ "ce", check_descent_ce },
	{ "ve", check_descent_ve },
	{ "cve", check_descent_cve },
	{ "f", check_descent_f },
	{ "g", check_descent_g },
	{ "cvh", check_descent_cvh },
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
