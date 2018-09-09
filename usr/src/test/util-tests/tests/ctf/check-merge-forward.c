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
 * This tests that a forward declared in one object file that is defined in
 * another doesn't end up in the final one.
 */

#include "check-common.h"

static check_symbol_t check_syms[] = {
	{ "list", "foo_list_t" },
	{ NULL }
};

static check_member_t check_member_foo_list[] = {
	{ "count", "int", 0 },
#ifdef	TARGET_LP64
	{ "head", "struct foo *", 8 * NBBY },
	{ "tail", "struct foo *", 16 * NBBY },
#else
	{ "head", "struct foo *", 4 * NBBY },
	{ "tail", "struct foo *", 8 * NBBY },
#endif
	{ NULL }
};

static check_member_t check_member_foo[] = {
	{ "next", "struct foo *", 0 * NBBY },
#ifdef	TARGET_LP64
	{ "left", "int", 8 * NBBY },
	{ "right", "int", 12 * NBBY },
	{ "count", "int", 16 * NBBY },
#else
	{ "left", "int", 4 * NBBY },
	{ "right", "int", 8 * NBBY },
	{ "count", "int", 12 * NBBY },
#endif
	{ NULL }
};

static check_member_test_t members[] = {
#ifdef	TARGET_LP64
	{ "struct foo_list", CTF_K_STRUCT, 24, check_member_foo_list },
	{ "struct foo", CTF_K_STRUCT, 24, check_member_foo },
#else
	{ "struct foo_list", CTF_K_STRUCT, 12, check_member_foo_list },
	{ "struct foo", CTF_K_STRUCT, 16, check_member_foo },
#endif
	{ NULL }
};

static int
ctf_merge_forward_cb(ctf_id_t id, boolean_t root, void *arg)
{
	ctf_file_t *fp = arg;
	char buf[2048];

	if (ctf_type_kind(fp, id) != CTF_K_FORWARD)
		return (0);

	if (ctf_type_name(fp, id, buf, sizeof (buf)) == NULL) {
		warnx("failed to lookup the name of type %ld: %s", id,
		    ctf_errmsg(ctf_errno(fp)));
		return (1);
	}

	/*
	 * If a forward shows up, that's OK. It's only bad if it's the name of
	 * the one we created.
	 */
	if (strcmp("struct foo", buf) == 0) {
		warnx("encountered forward type for struct foo that "
		    "shouldn't exist");
		return (1);
	}

	return (0);
}

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

		for (j = 0; members[j].cmt_type != NULL; j++) {
			if (!ctftest_check_members(members[j].cmt_type, fp,
			    members[j].cmt_kind, members[j].cmt_size,
			    members[j].cmt_members)) {
				ret = EXIT_FAILURE;
			}
		}

		if (ctf_type_iter(fp, B_TRUE, ctf_merge_forward_cb, fp) != 0) {
			ret = EXIT_FAILURE;
		}

		ctf_close(fp);
	}

	return (ret);
}
