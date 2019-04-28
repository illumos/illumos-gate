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
 * Basic tests for posix_memalign(3C). Note that we test ENOMEM failure by
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
	/*
	 * We use a non-NULL value, so we can verify that failure does not
	 * change the value of 'buf'
	 */
	void *sentinel = (void *)0xbad00000;
	void *buf = sentinel;
	int err = 0;

	/*
	 * Alignment must be sizeof (void *) (word) aligned.
	 */
	err = posix_memalign(&buf, sizeof (void *) - 1, 16);
	VERIFY3S(err, ==, EINVAL);
	VERIFY3P(buf, ==, sentinel);

	err = posix_memalign(&buf, sizeof (void *) + 1, 16);
	VERIFY3S(err, ==, EINVAL);
	VERIFY3P(buf, ==, sentinel);

	err = posix_memalign(&buf, 23, 16);
	VERIFY3S(err, ==, EINVAL);
	VERIFY3P(buf, ==, sentinel);

	err = posix_memalign(&buf, sizeof (void *), 16);
	VERIFY3S(err, ==, 0);
	VERIFY3B(IS_P2ALIGNED(buf, sizeof (void *)), ==, B_TRUE);
	VERIFY3P(buf, !=, sentinel);
	VERIFY3P(buf, !=, NULL);
	free(buf);
	buf = sentinel;

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
		if (posix_memalign(&buf, sizeof (void *), 16) == ENOMEM)
			break;
	}

	buf = sentinel;
	err = posix_memalign(&buf, sizeof (void *), 16);
	VERIFY3S(err, ==, ENOMEM);
	VERIFY3P(buf, ==, sentinel);

	return (0);
}
