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
 * Copyright 2016 Joyent, Inc.
 * Copyright 2024 Oxide Computer Company
 */

/*
 * Basic tests for aligned_alloc(3C). Note that we test ENOMEM failure by
 * relying on the implementation of the current libc malloc. Specifically we go
 * through and add a mapping so we can't expand the heap and then use it up. If
 * the memory allocator is ever changed, this test will start failing, at which
 * point, it may not be worth the cost of keeping it around.
 */

#include <stdlib.h>
#include <errno.h>
#include <libproc.h>
#include <stdio.h>
#include <stdalign.h>
#include <err.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <sys/debug.h>
#include <stdbool.h>
#include <string.h>

typedef struct {
	size_t at_size;
	size_t at_align;
	int at_errno;
	const char *at_desc;
} alloc_test_t;

static const alloc_test_t alloc_tests[] = {
	{ 0, sizeof (long), EINVAL, "zero alignment fails with EINVAL" },
	{ sizeof (long), 0, EINVAL, "zero size fails with EINVAL" },
	{ 128, 3, EINVAL, "3-byte alignment fails with EINVAL" },
	{ 128, 7777, EINVAL, "7777-byte alignment fails with EINVAL" },
	{ 128, 23, EINVAL, "23-byte alignment fails with EINVAL" },
	{ sizeof (char), alignof (char), 0, "alignof (char), 1 byte" },
	{ 5, alignof (char), 0, "alignof (char), multiple bytes" },
	{ 1, alignof (short), 0, "alignof (short), 1 byte" },
	{ 16, alignof (short), 0, "alignof (short), 16 byte" },
	{ 1, alignof (int), 0, "alignof (int), 1 byte" },
	{ 4, alignof (int), 0, "alignof (int), 4 bytes" },
	{ 22, alignof (int), 0, "alignof (int), 22 bytes" },
	/* We skip long here because it varies between ILP32/LP64 */
	{ 7, alignof (long long), 0, "alignof (long long), 7 bytes" },
	{ 128, alignof (long long), 0, "alignof (long long), 128 bytes" },
	{ 511, alignof (long long), 0, "alignof (long long), 511 bytes" },
	{ 16, 16, 0, "16-byte alignment), 16 bytes" },
	{ 256, 16, 0, "16-byte alignment), 256 bytes" },
	{ 256, 4096, 0, "4096-byte alignment), 256 bytes" },
	{ 4096, 4096, 0, "4096-byte alignment), 4096 bytes" },
};

/*
 * Disable the per-thread caches and enable debugging if launched with umem.
 */
const char *
_umem_debug_init(void)
{
	return ("default,verbose");
}

const char *
_umem_options_init(void)
{
	return ("perthreadcache=0");
}

static bool
alloc_test_one(const alloc_test_t *test)
{
	bool ret = false;
	void *buf = aligned_alloc(test->at_align, test->at_size);

	if (buf == NULL) {
		if (test->at_errno == 0) {
			warnx("TEST FAILED: %s: allocation failed with %s, but "
			    "expected success", test->at_desc,
			    strerrorname_np(errno));
		} else if (errno != test->at_errno) {
			warnx("TEST FAILED: %s: allocation failed with %s, but "
			    "expected errno %s", test->at_desc,
			    strerrorname_np(errno),
			    strerrorname_np(test->at_errno));
		} else {
			(void) printf("TEST PASSED: %s\n", test->at_desc);
			ret = true;
		}
	} else if (test->at_errno != 0) {
		warnx("TEST FAILED: %s: allocation succeeded, but expected "
		    "errno %s", test->at_desc, strerrorname_np(test->at_errno));
	} else {
		(void) printf("TEST PASSED: %s\n", test->at_desc);
		ret = true;
	}

	free(buf);
	return (ret);
}

static bool
alloc_test_enomem(const alloc_test_t *test)
{
	bool ret = false;
	void *buf = aligned_alloc(test->at_align, test->at_size);

	if (buf != NULL) {
		warnx("TEST FAILED: %s (forced ENOMEM/EAGAIN): succeeded, but "
		    "expected ENOMEM", test->at_desc);
	} else if (errno != ENOMEM && errno != EAGAIN) {
		warnx("TEST FAILED: %s (forced ENOMEM/EAGAIN): failed with %s, "
		    "but expected ENOMEM", test->at_desc,
		    strerrordesc_np(errno));
	} else {
		(void) printf("TEST PASSED: %s: ENOMEM/EAGAIN forced\n",
		    test->at_desc);
		ret = true;
	}

	return (ret);
}

static void
libc_enomem(void)
{
	pstatus_t status;

	VERIFY0(proc_get_status(getpid(), &status));
	VERIFY3P(mmap((caddr_t)P2ROUNDUP(status.pr_brkbase +
	    status.pr_brksize, 0x1000), 0x1000,
	    PROT_READ, MAP_ANON | MAP_FIXED | MAP_PRIVATE, -1, 0),
	    !=, (void *)-1);

	for (;;) {
		if (malloc(16) == NULL)
			break;
	}

	for (;;) {
		if (aligned_alloc(sizeof (void *), 16) == NULL)
			break;
	}
}

/*
 * Because this test is leveraging LD_PRELOAD in the test runner to test
 * different malloc libraries, we can't call umem_setmtbf() directly. Instead we
 * ask rtld to find it for us, which is a bit gross, but works.
 */
static void
libumem_enomem(void)
{
	void (*mtbf)(uint32_t) = dlsym(RTLD_DEFAULT, "umem_setmtbf");
	if (mtbf == NULL) {
		errx(EXIT_FAILURE, "failed to find umem_setmtbf: %s",
		    dlerror());
	}

	mtbf(1);
}

int
main(void)
{
	const char *preload;
	int ret = EXIT_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(alloc_tests); i++) {
		if (!alloc_test_one(&alloc_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	/*
	 * To catch failure tests, we need to know what memory allocator we're
	 * using which we expect to be indicated via an LD_PRELOAD environment
	 * variable. If it's not set, assume libc.
	 */
	preload = getenv("LD_PRELOAD");
	if (preload != NULL) {
		if (strstr(preload, "umem") != NULL) {
			libumem_enomem();
		} else {
			warnx("malloc(3C) library %s not supported, skipping "
			    "ENOMEM tests", preload);
			goto skip;
		}
	} else {
		libc_enomem();
	}

	for (size_t i = 0; i < ARRAY_SIZE(alloc_tests); i++) {
		if (alloc_tests[i].at_errno != 0)
			continue;
		if (!alloc_test_enomem(&alloc_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

skip:
	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}

	return (ret);
}
