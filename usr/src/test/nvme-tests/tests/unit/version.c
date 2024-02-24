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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * Verify the basics of the common NVMe version interfaces.
 */

#include <err.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/sysmacros.h>
#include <stdlib.h>

#include <nvme_common.h>

int vers_exit = EXIT_SUCCESS;

/*
 * Each tests asks is the version nvt_dev >= nvt_targ.
 */
typedef struct nvme_version_test {
	const nvme_version_t *nvt_dev;
	const nvme_version_t *nvt_targ;
	bool nvt_pass;
	const char *nvt_desc;
} nvme_version_test_t;

static const nvme_version_test_t vers_tests[] = {
	{ &nvme_vers_1v0, &nvme_vers_1v0, true, "same version (1.0)" },
	{ &nvme_vers_1v1, &nvme_vers_1v1, true, "same version (1.1)" },
	{ &nvme_vers_1v2, &nvme_vers_1v2, true, "same version (1.2)" },
	{ &nvme_vers_1v3, &nvme_vers_1v3, true, "same version (1.3)" },
	{ &nvme_vers_1v4, &nvme_vers_1v4, true, "same version (1.4)" },
	{ &nvme_vers_2v0, &nvme_vers_2v0, true, "same version (2.0)" },
	{ &nvme_vers_2v0, &nvme_vers_1v0, true, "greater major, same minor" },
	{ &nvme_vers_2v0, &nvme_vers_1v1, true, "greater major, lesser minor" },
	{ &nvme_vers_2v0, &nvme_vers_1v3, true, "greater major, lesser minor" },
	{ &nvme_vers_1v2, &nvme_vers_1v0, true, "same major, greater minor "
	    "(1)" },
	{ &nvme_vers_1v2, &nvme_vers_1v1, true, "same major, greater minor "
	    "(2)" },
	{ &nvme_vers_1v4, &nvme_vers_1v0, true, "same major, greater minor "
	    "(3)" },
	{ &nvme_vers_1v4, &nvme_vers_1v2, true, "same major, greater minor "
	    "(4)" },
	{ &nvme_vers_1v0, &nvme_vers_1v4, false, "same major, lesser minor "
	    "(1)" },
	{ &nvme_vers_1v1, &nvme_vers_1v4, false, "same major, lesser minor "
	    "(2)" },
	{ &nvme_vers_1v3, &nvme_vers_1v4, false, "same major, lesser minor "
	    "(3)" },
	{ &nvme_vers_1v4, &nvme_vers_2v0, false, "lesser major, greater minor "
	    "(1)" },
	{ &nvme_vers_1v3, &nvme_vers_2v0, false, "lesser major, greater minor "
	    "(2)" },
	{ &nvme_vers_1v2, &nvme_vers_2v0, false, "lesser major, greater minor "
	    "(3)" },
	{ &nvme_vers_1v1, &nvme_vers_2v0, false, "lesser major, greater minor "
	    "(4)" },
	{ &nvme_vers_1v0, &nvme_vers_2v0, false, "lesser major, same minor" },
};

static bool
vers_test_one(const nvme_version_test_t *test)
{
	bool res = nvme_vers_atleast(test->nvt_dev, test->nvt_targ);
	if (res != test->nvt_pass) {
		const char *rstr = res ? "passed" : "failed";

		warnx("TEST FAILED: %s (%u.%u >= %u.%u) erroneously %s",
		    test->nvt_desc, test->nvt_dev->v_major,
		    test->nvt_dev->v_minor, test->nvt_targ->v_major,
		    test->nvt_targ->v_minor, rstr);
		return (false);
	} else {
		(void) printf("TEST PASSED: %s\n", test->nvt_desc);
		return (true);
	}
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(vers_tests); i++) {
		if (!vers_test_one(&vers_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully!\n");
	}

	return (ret);
}
