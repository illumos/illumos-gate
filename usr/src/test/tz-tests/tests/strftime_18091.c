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
 * Regression test for illumos#18091 where the current time has different time
 * zone names than a past or future time. Prior to this test strftime would
 * report time zone names based on the current time.
 */

#include <err.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <string.h>
#include <sys/sysmacros.h>

typedef struct st_test {
	const char *st_tz;
	long st_time;
	const char *st_exp;
} st_test_t;

const st_test_t st_tests[] = { {
	/*
	 * America/Vancouver moved to MST in tzdata2026b. However, at the time,
	 * the current information would have had it in PST/PDT.
	 */
	.st_tz = "America/Vancouver",
	.st_time = 1798790400,
	.st_exp = "MST"
}, {
	.st_tz = "America/Vancouver",
	.st_time = 1777569072,
	.st_exp = "PDT"
}, {
	/*
	 * The other way this was originally reported.
	 */
	.st_tz = "Europe/Kyiv",
	.st_time = 500000000,
	.st_exp = "MSK"
}, {
	.st_tz = "Europe/Kyiv",
	.st_time = 700000000,
	.st_exp = "EET"
} };

static bool
st_test_one(const st_test_t *test)
{
	struct tm *tm;
	char buf[32];

	(void) setenv("TZ", test->st_tz, 1);
	tm = localtime(&test->st_time);
	if (tm == NULL) {
		warn("TEST FAILED: %s (%ld): failed to convert to struct tm",
		    test->st_tz, test->st_time);
		return (false);
	}

	if (strftime(buf, sizeof (buf), "%Z", tm) == 0) {
		warnx("TEST FAILED: %s (%ld): strftime wrote no data",
		    test->st_tz, test->st_time);
		return (false);
	}

	if (strcmp(buf, test->st_exp) != 0) {
		warnx("TEST FAILED: %s (%ld): tz mismatch: found %s, expected "
		    "%s", test->st_tz, test->st_time, buf, test->st_exp);
		return (false);
	}

	return (true);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(st_tests); i++) {
		if (!st_test_one(&st_tests[i]))
			ret = EXIT_FAILURE;
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully!\n");
	}
	return (ret);
}
