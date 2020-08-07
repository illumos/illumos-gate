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
 * Copyright 2020 Richard Hansen <rhansen@rhansen.org>
 */

#include <errno.h>
#include <libintl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <umem.h>
#include <unistd.h>
#include "test_common.h"

const char *
_umem_debug_init(void)
{
	return ("default");
}

int
main(int argc, char *argv[])
{
	int ret = 0;
	int optc;
	while ((optc = getopt(argc, argv, "df")) != -1) {
		switch (optc) {
		case 'd':
			test_set_debug();
			break;
		case 'f':
			test_set_force();
			break;
		default:
			(void) fprintf(stderr, "Usage: %s [-df]\n", argv[0]);
			exit(1);
		}
	}

	struct {
		const char *name;
		const char *dir;
		bool malloc_fail;
		const char *want;
		int want_errno;
	} test_cases[] = {
		{
			.name = "unbound query",
			.dir = NULL,
			.want = "/usr/lib/locale/",
		},
		{
			.name = "bind malloc fail",
			.dir = "/bounddir1",
			.malloc_fail = true,
			.want = NULL,
			.want_errno = EAGAIN,
		},
		{
			.name = "query after bind malloc fail",
			.dir = NULL,
			.want = "/usr/lib/locale/",
		},
		{
			.name = "normal bind",
			.dir = "/bounddir2",
			.want = "/bounddir2",
		},
		{
			.name = "query after normal bind",
			.dir = NULL,
			.want = "/bounddir2",
		},
		{
			.name = "rebind to same",
			.dir = "/bounddir2",
			.want = "/bounddir2",
		},
		{
			.name = "query after rebind to same",
			.dir = NULL,
			.want = "/bounddir2",
		},
		{
			.name = "rebind to new",
			.dir = "/bounddir3",
			.want = "/bounddir3",
		},
		{
			.name = "query after rebind to new",
			.dir = NULL,
			.want = "/bounddir3",
		},
		{
			.name = "rebind malloc fail",
			.dir = "/bounddir4",
			.malloc_fail = true,
			.want = NULL,
			.want_errno = EAGAIN,
		},
		{
			.name = "query after rebind malloc fail",
			.dir = NULL,
			.want = "/bounddir3",
		},
	}, *tc;

	for (size_t i = 0; i < ARRAY_SIZE(test_cases); ++i) {
		tc = &test_cases[i];
		test_t t = test_start(tc->name);
		umem_setmtbf((uint_t)tc->malloc_fail);
		errno = 0;
		const char *got = bindtextdomain("domain", tc->dir);
		int got_errno = errno;
		umem_setmtbf(0);
		if (((got == NULL) != (tc->want == NULL)) ||
		    ((got != NULL) && strcmp(got, tc->want))) {
			test_failed(t, "returned %s, want %s",
			    got != NULL ? got : "<NULL>",
			    tc->want != NULL ? tc->want : "<NULL>");
			ret = 1;
		}
		if (got_errno != tc->want_errno) {
			test_failed(t, "got errno %d, want %d",
			    got_errno, tc->want_errno);
			ret = 1;
		}
		test_passed(t);
	}
	test_summary();
	return (ret);
}
