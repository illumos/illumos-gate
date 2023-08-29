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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * Test the implementation of strtonum() and strtonumx()
 */

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool fail = false;

static void
runtestx(const char *nstr, long long minval, long long maxval,
    int base, long long expval, bool expect_pass)
{
	const char *errstr;
	char key[0x100];
	long long val;

	if (base == -1) {
		val = strtonum(nstr, minval, maxval, &errstr);
		(void) snprintf(key, sizeof (key), "strtonum(%s)", nstr);
	} else {
		val = strtonumx(nstr, minval, maxval, &errstr, base);
		(void) snprintf(key, sizeof (key), "strtonumx(%s, %d)",
		    nstr, base);
	}

	if (expect_pass) {
		if (errstr != NULL) {
			fprintf(stderr, "FAIL %s was rejected: "
			    "%s [%lld,%lld]\n",
			    key, errstr, minval, maxval);
			fail = true;
		} else {
			fprintf(stdout, "PASS %s was accepted: "
			    "[%lld,%lld] = %lld\n",
			    key, minval, maxval, val);
			if (val != expval) {
				fprintf(stderr, "FAIL %s returned wrong value: "
				    "[%lld,%lld] = %lld vs. %lld\n", key,
				    minval, maxval, val, expval);
				fail = true;
			}
		}
	} else {
		if (errstr == NULL) {
			fprintf(stderr, "FAIL %s was accepted: "
			    "[%lld,%lld] = %lld\n",
			    key, minval, maxval, val);
			fail = true;
		} else {
			fprintf(stdout, "PASS %s was rejected: "
			    "%s [%lld,%lld]\n",
			    key, errstr, minval, maxval);
		}
	}
}

static void
runtest(const char *nstr, long long minval, long long maxval, long long expval,
    bool expect_pass)
{
	runtestx(nstr, minval, maxval, -1, expval, expect_pass);
	runtestx(nstr, minval, maxval, 10, expval, expect_pass);
	runtestx(nstr, minval, maxval,  0, expval, expect_pass);
}

int
main(void)
{
	runtest("1", 0, 100, 1, true);
	runtest("0", -3, 7, 0, true);
	runtest("0", 2, 10, 0, false);
	runtest("0", 2, LLONG_MAX, 0, false);
	runtest("-2", 0, LLONG_MAX, 0, false);
	runtest("0", -5, LLONG_MAX, 0, true);
	runtest("-3", -3, LLONG_MAX, -3, true);
	runtest("-2", 10, -1, 0, false);
	runtest("-2", -10, -1, -2, true);
	runtest("-20", -10, -1, 0, false);
	runtest("20", -10, -1, 0, false);

	runtest("-9223372036854775808", LLONG_MIN, LLONG_MAX, LLONG_MIN, true);
	runtest("-9223372036854775809", LLONG_MIN, LLONG_MAX, 0, false);

	runtest("9223372036854775807", LLONG_MIN, LLONG_MAX, LLONG_MAX, true);
	runtest("9223372036854775808", LLONG_MIN, LLONG_MAX, 0, false);

	for (int base = 2; base <= 36; base++)
		runtestx("1", 0, 100, base, 1, true);

	runtestx("1", 0, 100, -2, 0, false);
	runtestx("1", 0, 100, 1, 0, false);
	runtestx("1", 0, 100, 37, 0, false);

	runtestx("0x1234", 0, LLONG_MAX, 16, 0x1234, true);
	runtestx("0x1234", 0, LLONG_MAX, 0, 0x1234, true);
	runtestx("0x1234", 0, LLONG_MAX, 10, 0, false);

	runtestx("AZbc123", 0, LLONG_MAX, 36, 23903176539, true);
	runtestx("AZbc123", 0, LLONG_MAX, 35, 0, false);
	runtestx("AYBC123", 0, LLONG_MAX, 35, 20185422673, true);
	runtestx("AYBC123", 0, LLONG_MAX, 34, 0, false);

	runtestx("01234", 0, LLONG_MAX, 8, 01234, true);
	runtestx("01234", 0, LLONG_MAX, 0, 01234, true);
	runtestx("01234", 0, LLONG_MAX, 10, 1234, true);

	if (fail) {
		printf("\nOverall status: FAIL\n");
		return (EXIT_FAILURE);
	}

	printf("\nOverall status: PASS\n");
	return (EXIT_SUCCESS);
}
