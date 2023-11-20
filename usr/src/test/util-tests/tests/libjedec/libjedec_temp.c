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
 * Basic test of libjedec temperature features.
 */

#include <stdlib.h>
#include <limits.h>
#include <err.h>
#include <sys/sysmacros.h>
#include <libjedec.h>

typedef struct {
	uint32_t ltt_temp;
	boolean_t ltt_res;
	int32_t ltt_min;
	int32_t ltt_max;
	const char *ltt_desc;
} libjedec_temp_test_t;

static const libjedec_temp_test_t temp_tests[] = {
	{ JEDEC_TEMP_CASE_A2T, B_TRUE, -40, 105, "Operating temperature A2T" },
	{ JEDEC_TEMP_CASE_RT, B_TRUE, 0, 45, "Operating temperature RT" },
	{ JEDEC_TEMP_AMB_CT, B_TRUE, 0, 70, "Ambient temperature CT" },
	{ JEDEC_TEMP_AMB_IOT, B_TRUE, -40, 85, "Ambient temperature IOT" },
	{ JEDEC_TEMP_AMB_AO1T, B_TRUE,  -40, 125, "Ambient temperature A01T" },
	{ JEDEC_TEMP_STOR_ST, B_TRUE, -40, 85, "Storage temperature ST" },
	{ 42, B_FALSE, 0, 0, "invalid temperature (42)" },
	{ INT32_MAX, B_FALSE, 0, 0, "invalid temperature (INT32_MAX)" },
	{ UINT32_MAX, B_FALSE, 0, 0, "invalid temperature (UINT32_MAX)" }
};

static boolean_t
libjedec_temp_run_single(const libjedec_temp_test_t *test)
{
	int32_t min = INT32_MIN, max = INT32_MAX;
	boolean_t res;

	res = libjedec_temp_range(test->ltt_temp, &min, &max);
	if (res != test->ltt_res) {
		if (test->ltt_res) {
			warnx("libjedec_temp_range() succeeded, but we "
			    "expected failure!");
		} else {
			warnx("libjedec_temp_range() failed, but we expected "
			    "success!");
		}
		return (B_FALSE);
	}

	if (!res) {
		return (B_TRUE);
	}

	if (min != test->ltt_min) {
		warnx("received incorrect minimum temperature: expected %d, "
		    "found %d\n", test->ltt_min, min);
	}

	if (max != test->ltt_max) {
		warnx("received incorrect maximum temperature: expected %d, "
		    "found %d\n", test->ltt_max, max);
	}

	return (B_TRUE);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(temp_tests); i++) {
		const libjedec_temp_test_t *test = &temp_tests[i];

		if (libjedec_temp_run_single(test)) {
			(void) printf("TEST PASSED: %s\n", test->ltt_desc);
		} else {
			(void) fprintf(stderr, "TEST FAILED: %s\n",
			    test->ltt_desc);
			ret = EXIT_FAILURE;
		}
	}

	return (ret);
}
