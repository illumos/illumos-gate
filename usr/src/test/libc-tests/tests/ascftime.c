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
 * Copyright 2024 Bill Sommerfeld <sommerfeld@hamachi.org>
 */

/*
 * Regression test for illumos bug #16352: verify that strftime behaves
 * properly if the buffer length is overly large.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int status = EXIT_SUCCESS;

static const char expected_buf[] = "2024 04 23";
static int expected_ret = 10;

static void
check_results(const char *name, int ret, const char *buf)
{
	if (ret == 0) {
		fprintf(stderr, "TEST FAILED: %s returned 0\n", name);
		status = EXIT_FAILURE;
	}

	if (ret != 10) {
		fprintf(stderr, "TEST FAILED: %s length %d (expected %d)\n",
		    name, ret, expected_ret);
		status = EXIT_FAILURE;
	}

	if (strcmp(buf, expected_buf) != 0) {
		fprintf(stderr, "TEST FAILED: %s contents [%s]"
		    " (expected [%s])\n", name, buf, expected_buf);
		status = EXIT_FAILURE;
	}
}

int
main(void)
{
	int ret;
	struct tm t;
	char buf[1024];

	memset(&t, 0, sizeof (t));
	t.tm_year = 124;
	t.tm_mon = 3;
	t.tm_mday = 23;

	/*
	 * Test that ascftime() behaves properly; ascftime calls
	 * strftime(buf, LONG_MAX, format, t).  For an unfixed libc,
	 * this will fail if buf lies above the midpoint of the
	 * process address space, as the computation of buf + len
	 * overflows and wraps around.
	 */
	ret = ascftime(buf, "%Y %m %d", &t);
	check_results("ascftime", ret, buf);

	/*
	 * Repeat test with strftime passed the maximum possible length.
	 * This will wrap around as long as buf is not NULL, letting us
	 * exercise the fix even if the user address space is restricted
	 * in some way.
	 */
	ret = strftime(buf, ULONG_MAX, "%Y %m %d", &t);
	check_results("strftime", ret, buf);

	if (status == EXIT_SUCCESS) {
		(void) printf("TEST PASSED: observed expected output\n");
	}
	printf("NOTE: buffer is %p\n", buf);
	return (status);
}
