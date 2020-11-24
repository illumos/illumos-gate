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
 * Verify that we can properly handle forward declarations.
 */

#include "check-common.h"

static check_symbol_t check_syms[] = {
	{ "forward", "struct forward" },
	{ "foop", "struct foo *" },
	{ "barp", "union bar *" },
	{ "bazp", "enum baz *" },
	{ NULL }
};

static check_member_t check_member_forward[] = {
#ifdef	TARGET_LP64
	{ "prev", "struct foo *", 0 },
	{ "next", "struct foo *", 8 * NBBY },
	{ "data", "union bar *", 16 * NBBY },
	{ "tag", "enum baz *", 24 * NBBY },
#else
	{ "prev", "struct foo *", 0 },
	{ "next", "struct foo *", 4 * NBBY },
	{ "data", "union bar *", 8 * NBBY },
	{ "tag", "enum baz *", 12 * NBBY },
#endif
	{ NULL }
};


static check_member_test_t members[] = {
#ifdef	TARGET_LP64
	{ "struct forward", CTF_K_STRUCT, 32, check_member_forward },
#else
	{ "struct forward", CTF_K_STRUCT, 16, check_member_forward },
#endif
	{ NULL }
};

static check_descent_t check_descent_foo[] = {
	{ "struct foo *", CTF_K_POINTER },
	{ "struct foo", CTF_K_FORWARD },
	{ NULL }
};

static check_descent_t check_descent_bar[] = {
	{ "union bar *", CTF_K_POINTER },
	{ "union bar", CTF_K_FORWARD },
	{ NULL }
};

static check_descent_t check_descent_baz[] = {
	{ "enum baz *", CTF_K_POINTER },
	{ "enum baz", CTF_K_ENUM },
	{ NULL }
};

static check_descent_test_t descents[] = {
	{ "foop", check_descent_foo },
	{ "barp", check_descent_bar },
	{ "bazp", check_descent_baz },
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

		for (j = 0; descents[j].cdt_sym != NULL; j++) {
			if (!ctftest_check_descent(descents[j].cdt_sym, fp,
			    descents[j].cdt_tests, B_FALSE)) {
				ret = EXIT_FAILURE;
			}
		}


		for (j = 0; members[j].cmt_type != NULL; j++) {
			if (!ctftest_check_members(members[j].cmt_type, fp,
			    members[j].cmt_kind, members[j].cmt_size,
			    members[j].cmt_members)) {
				ret = EXIT_FAILURE;
			}
		}

		ctf_close(fp);
	}

	return (ret);
}
