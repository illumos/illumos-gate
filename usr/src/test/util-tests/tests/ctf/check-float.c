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
 * Check for basic float types.
 */

#include <stdlib.h>
#include <unistd.h>

#include "check-common.h"

static check_number_t check_floats[] = {
	{ "float", CTF_K_FLOAT, CTF_FP_SINGLE, 0, 32 },
	{ "double", CTF_K_FLOAT, CTF_FP_DOUBLE, 0, 64 },
#ifdef	TARGET_LP64
	{ "long double", CTF_K_FLOAT, CTF_FP_LDOUBLE, 0, 128 },
#else
	{ "long double", CTF_K_FLOAT, CTF_FP_LDOUBLE, 0, 96 },
#endif
	{ "complex float", CTF_K_FLOAT, CTF_FP_CPLX, 0, 64 },
	{ "complex double", CTF_K_FLOAT, CTF_FP_DCPLX, 0, 128 },
#ifdef	TARGET_LP64
	{ "complex long double", CTF_K_FLOAT, CTF_FP_LDCPLX, 0, 256 },
#else
	{ "complex long double", CTF_K_FLOAT, CTF_FP_LDCPLX, 0, 192 },
#endif
	{ NULL }
};

static check_symbol_t check_syms[] = {
	{ "a", "float" },
	{ "b", "double" },
	{ "c", "long double" },
	{ "d", "complex float" },
	{ "e", "complex double" },
	{ "f", "complex long double" },
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

		if (!ctftest_check_numbers(fp, check_floats))
			ret = EXIT_FAILURE;
		if (!ctftest_check_symbols(fp, check_syms))
			ret = EXIT_FAILURE;
		ctf_close(fp);
	}

	return (ret);
}
