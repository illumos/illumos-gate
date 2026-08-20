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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Test the implementation of strtonum(), strtonumx(), strtounum() and
 * strtounumx()
 */

#include <errno.h>
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
	int n;

	if (base == -1) {
		val = strtonum(nstr, minval, maxval, &errstr);
		n = snprintf(key, sizeof (key), "strtonum(%s)", nstr);
	} else {
		val = strtonumx(nstr, minval, maxval, &errstr, base);
		n = snprintf(key, sizeof (key), "strtonumx(%s, %d)",
		    nstr, base);
	}
	if (n < 0 || (size_t)n >= sizeof (key)) {
		fprintf(stderr, "FAIL could not build key for '%s'\n", nstr);
		fail = true;
		return;
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

static void
runtestux(const char *nstr, unsigned long long minval,
    unsigned long long maxval, int base, unsigned long long expval,
    bool expect_pass, const char *experr)
{
	const char *errstr;
	char key[0x100];
	unsigned long long val;
	int n;

	if (base == -1) {
		val = strtounum(nstr, minval, maxval, &errstr);
		n = snprintf(key, sizeof (key), "strtounum(%s)", nstr);
	} else {
		val = strtounumx(nstr, minval, maxval, &errstr, base);
		n = snprintf(key, sizeof (key), "strtounumx(%s, %d)",
		    nstr, base);
	}
	if (n < 0 || (size_t)n >= sizeof (key)) {
		fprintf(stderr, "FAIL could not build key for '%s'\n", nstr);
		fail = true;
		return;
	}

	if (expect_pass) {
		if (errstr != NULL) {
			fprintf(stderr, "FAIL %s was rejected: "
			    "%s [%llu,%llu]\n",
			    key, errstr, minval, maxval);
			fail = true;
		} else {
			fprintf(stdout, "PASS %s was accepted: "
			    "[%llu,%llu] = %llu\n",
			    key, minval, maxval, val);
			if (val != expval) {
				fprintf(stderr, "FAIL %s returned wrong value: "
				    "[%llu,%llu] = %llu vs. %llu\n", key,
				    minval, maxval, val, expval);
				fail = true;
			}
		}
	} else {
		if (errstr == NULL) {
			fprintf(stderr, "FAIL %s was accepted: "
			    "[%llu,%llu] = %llu\n",
			    key, minval, maxval, val);
			fail = true;
		} else if (experr != NULL && strcmp(errstr, experr) != 0) {
			fprintf(stderr, "FAIL %s wrong error: "
			    "'%s' vs. '%s' [%llu,%llu]\n",
			    key, errstr, experr, minval, maxval);
			fail = true;
		} else {
			fprintf(stdout, "PASS %s was rejected: "
			    "%s [%llu,%llu]\n",
			    key, errstr, minval, maxval);
		}
	}
}

static void
runtestu(const char *nstr, unsigned long long minval,
    unsigned long long maxval, unsigned long long expval, bool expect_pass,
    const char *experr)
{
	runtestux(nstr, minval, maxval, -1, expval, expect_pass, experr);
	runtestux(nstr, minval, maxval, 10, expval, expect_pass, experr);
	runtestux(nstr, minval, maxval,  0, expval, expect_pass, experr);
}

/*
 * The unsigned functions must restore the caller's errno on success and
 * set it appropriately on failure.
 */
static void
runtest_errno(void)
{
	const char *errstr;
	unsigned long long val;

	errno = EDOM;
	val = strtounum("5", 0, 10, &errstr);
	if (errstr != NULL || errno != EDOM || val != 5) {
		fprintf(stderr, "FAIL errno/value wrong on success: "
		    "errno %d vs. %d, value %llu vs. 5\n", errno, EDOM, val);
		fail = true;
	} else {
		fprintf(stdout, "PASS errno preserved on success\n");
	}

	errno = 0;
	val = strtounum("11", 0, 10, &errstr);
	if (errstr == NULL || errno != ERANGE || val != 0) {
		fprintf(stderr, "FAIL errno/value wrong on range error: "
		    "errno %d, value %llu\n", errno, val);
		fail = true;
	} else {
		fprintf(stdout, "PASS errno set to ERANGE on range error\n");
	}

	errno = 0;
	val = strtounum("zebra", 0, 10, &errstr);
	if (errstr == NULL || errno != EINVAL || val != 0) {
		fprintf(stderr, "FAIL errno/value wrong on invalid input: "
		    "errno %d, value %llu\n", errno, val);
		fail = true;
	} else {
		fprintf(stdout, "PASS errno set to EINVAL on invalid input\n");
	}
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

	/* Unsigned variants */
	runtestu("1", 0, 100, 1, true, NULL);
	runtestu("0", 0, 100, 0, true, NULL);
	runtestu("+42", 0, 100, 42, true, NULL);
	runtestu("0", 2, 10, 0, false, "too small");
	runtestu("11", 0, 10, 0, false, "too large");
	runtestu("5", 10, 2, 0, false, "invalid");
	runtestu("", 0, 100, 0, false, "invalid");
	runtestu("zebra", 0, 100, 0, false, "invalid");

	/* Values beyond the signed 64-bit range must work */
	runtestu("9223372036854775808", 0, ULLONG_MAX,
	    9223372036854775808ULL, true, NULL);
	runtestu("18446744073709551615", 0, ULLONG_MAX, ULLONG_MAX, true,
	    NULL);
	runtestu("18446744073709551616", 0, ULLONG_MAX, 0, false,
	    "too large");
	runtestu("18446744073709551615", 0, 100, 0, false, "too large");

	/* Negative input is always rejected, never wrapped */
	runtestu("-1", 0, ULLONG_MAX, 0, false, "too small");
	runtestu("-0", 0, ULLONG_MAX, 0, false, "too small");
	runtestu("  -5", 0, ULLONG_MAX, 0, false, "too small");
	runtestu("-18446744073709551615", 0, ULLONG_MAX, 0, false,
	    "too small");

	/* Malformed minus-prefixed input is invalid, not out of range */
	runtestu("-", 0, ULLONG_MAX, 0, false, "invalid");
	runtestu("  -", 0, ULLONG_MAX, 0, false, "invalid");
	runtestu("-xyz", 0, ULLONG_MAX, 0, false, "invalid");
	runtestu("- 5", 0, ULLONG_MAX, 0, false, "invalid");
	runtestu("--5", 0, ULLONG_MAX, 0, false, "invalid");
	runtestu("-5x", 0, ULLONG_MAX, 0, false, "invalid");

	/* Base handling */
	for (int base = 2; base <= 36; base++)
		runtestux("1", 0, 100, base, 1, true, NULL);

	runtestux("1", 0, 100, -2, 0, false, NULL);
	runtestux("1", 0, 100, 1, 0, false, NULL);
	runtestux("1", 0, 100, 37, 0, false, NULL);

	runtestux("0x20000000", 0, ULLONG_MAX, 0, 0x20000000ULL, true, NULL);
	runtestux("0x20000000", 0, ULLONG_MAX, 16, 0x20000000ULL, true, NULL);
	runtestux("0xffffffffffffffff", 0, ULLONG_MAX, 16, ULLONG_MAX, true,
	    NULL);
	runtestux("0x1234", 0, ULLONG_MAX, 10, 0, false, "invalid");
	runtestux("01234", 0, ULLONG_MAX, 0, 01234, true, NULL);

	runtest_errno();

	if (fail) {
		printf("\nOverall status: FAIL\n");
		return (EXIT_FAILURE);
	}

	printf("\nOverall status: PASS\n");
	return (EXIT_SUCCESS);
}
