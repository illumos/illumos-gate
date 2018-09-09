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
 * Check for basic integer types.
 */

#include <stdlib.h>
#include <unistd.h>

#include "check-common.h"

static check_number_t check_ints[] = {
	{ "char", CTF_K_INTEGER, CTF_INT_SIGNED | CTF_INT_CHAR, 0, 8 },
	{ "short", CTF_K_INTEGER, CTF_INT_SIGNED, 0, 16 },
	{ "int", CTF_K_INTEGER, CTF_INT_SIGNED, 0, 32 },
#ifdef	TARGET_LP64
	{ "long", CTF_K_INTEGER, CTF_INT_SIGNED, 0, 64 },
#else
	{ "long", CTF_K_INTEGER, CTF_INT_SIGNED, 0, 32 },
#endif
	{ "long long", CTF_K_INTEGER, CTF_INT_SIGNED, 0, 64 },
	{ "unsigned char", CTF_K_INTEGER, CTF_INT_CHAR, 0, 8 },
	{ "unsigned short", CTF_K_INTEGER, 0, 0, 16 },
	{ "unsigned int", CTF_K_INTEGER, 0, 0, 32 },
#ifdef	TARGET_LP64
	{ "unsigned long", CTF_K_INTEGER, 0, 0, 64 },
#else
	{ "unsigned long", CTF_K_INTEGER, 0, 0, 32 },
#endif
	{ "unsigned long long", CTF_K_INTEGER, 0, 0, 64 },
	{ NULL }
};

static check_symbol_t check_syms[] = {
	{ "a", "char" },
	{ "b", "unsigned char" },
	{ "d", "short" },
	{ "e", "unsigned short" },
	{ "g", "int" },
	{ "h", "unsigned int" },
	{ "j", "long" },
	{ "k", "unsigned long" },
	{ "m", "long long" },
	{ "n", "unsigned long long" },
	{ NULL },
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

		if (!ctftest_check_numbers(fp, check_ints))
			ret = EXIT_FAILURE;
		if (!ctftest_check_symbols(fp, check_syms))
			ret = EXIT_FAILURE;
		ctf_close(fp);
	}

	return (ret);
}
