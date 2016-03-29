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
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <sys/debug.h>

int
main(void)
{
	pstatus_t status;
	void *buf;

	/*
	 * Alignment must be sizeof (void *) (word) aligned.
	 */
	VERIFY3P(aligned_alloc(sizeof (void *) - 1, 16), ==, NULL);
	VERIFY3S(errno, ==, EINVAL);

	VERIFY3P(aligned_alloc(sizeof (void *) + 1, 16), ==, NULL);
	VERIFY3S(errno, ==, EINVAL);


	VERIFY3P(aligned_alloc(23, 16), ==, NULL);
	VERIFY3S(errno, ==, EINVAL);

	buf = aligned_alloc(sizeof (void *), 16);
	VERIFY3P(buf, !=, NULL);
	free(buf);

	/*
	 * Cause ENOMEM
	 */
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

	VERIFY3P(aligned_alloc(sizeof (void *), 16), ==, NULL);
	VERIFY3S(errno, ==, ENOMEM);

	return (0);
}
