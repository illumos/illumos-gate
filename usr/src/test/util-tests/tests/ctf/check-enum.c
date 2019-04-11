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
 * Copyright 2019, Joyent, Inc.
 */

/*
 * Check that we properly handle enums.
 */

#include "check-common.h"

static check_symbol_t check_syms[] = {
	{ "ff6", "enum ff6" },
	{ "ff10", "ff10_t" },
	{ NULL }
};

static check_descent_t check_descent_ff6[] = {
	{ "enum ff6", CTF_K_ENUM },
	{ NULL }
};

static check_descent_t check_descent_ff10[] = {
	{ "ff10_t", CTF_K_TYPEDEF },
	{ "enum ff10", CTF_K_ENUM },
	{ NULL }
};

static check_descent_t check_descent_chrono[] = {
	{ "chrono_t", CTF_K_TYPEDEF },
	{ "enum chrono", CTF_K_ENUM },
	{ NULL }
};

static check_descent_test_t descents[] = {
	{ "ff10", check_descent_ff10 },
	{ "ff6", check_descent_ff6 },
	{ "trigger", check_descent_chrono },
	{ NULL }
};

static check_enum_t check_enum_ff6[] = {
	{ "TERRA", 0 },
	{ "LOCKE", 1 },
	{ "EDGAR", 2 },
	{ "SABIN", 3 },
	{ "CELES", 4 },
	{ "CYAN", 5 },
	{ "SHADOW", 6 },
	{ "GAU", 7 },
	{ "SETZER", 8 },
	{ "STRAGO", 9 },
	{ "RELM", 10 },
	{ "MOG", 11 },
	{ "GOGO", 12 },
	{ "UMARO", 13 },
	{ "LEO", 14 },
	{ "KEFKA", 15 },
	{ NULL }
};

static check_enum_t check_enum_ff10[] = {
	{ "TIDUS", -10 },
	{ "YUNA", 23 },
	{ "AURON", -34 },
	{ "WAKA", 52 },
	{ "LULU", INT32_MAX },
	{ "RIKKU", INT32_MIN },
	{ "KHIMARI", 0 },
	{ NULL }
};

static check_enum_t check_enum_chrono[] = {
	{ "CRONO", 0x1000 },
	{ "LUCCA", 0x2000 },
	{ "MARLE", 0x3000 },
	{ "FROG", 0x4000 },
	{ "ROBO", 0x5000 },
	{ "AYLA", 0x6000 },
	{ "MAGUS", 0x7000 },
	{ "SCHALA", 0x8000 },
	{ "LAVOS", 0x9000 },
	{ "BALTHAZAR", 0xa000 },
	{ NULL }
};

static check_enum_test_t enums[] = {
	{ "enum ff6", check_enum_ff6 },
	{ "enum ff10", check_enum_ff10 },
	{ "enum chrono", check_enum_chrono },
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
		if (!ctftest_check_symbols(fp, check_syms))
			ret = EXIT_FAILURE;
		for (d = 0; descents[d].cdt_sym != NULL; d++) {
			if (!ctftest_check_descent(descents[d].cdt_sym, fp,
			    descents[d].cdt_tests, B_FALSE)) {
				ret = EXIT_FAILURE;
			}
		}

		for (d = 0; enums[d].cet_type != NULL; d++) {
			if (!ctftest_check_enum(enums[d].cet_type, fp,
			    enums[d].cet_tests)) {
				ret = EXIT_FAILURE;
			}
		}
		ctf_close(fp);
	}

	return (ret);

}
