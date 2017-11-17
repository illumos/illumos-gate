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
 * Copyright (c) 2017, Joyent, Inc.
 */

/*
 * Test various error cases all of which should return EFAULT.
 */

#include <stdio.h>
#include <errno.h>
#include <strings.h>
#include <err.h>
#include <libsff.h>
#include <unistd.h>
#include <sys/mman.h>

int
main(void)
{
	void *addr;
	nvlist_t *nvl;
	size_t len = getpagesize();
	int ret;

	/*
	 * Get an unreadable page
	 */
	if ((addr = mmap(NULL, len, PROT_READ, MAP_PRIVATE | MAP_ANON, -1,
	    0)) == MAP_FAILED) {
		err(1, "TEST FAILED: failed to mmap private page");
	}

	if (mprotect(addr, len, PROT_NONE) != 0) {
		err(1, "TEST FAILED: failed to protect private page");
	}

	if ((ret = libsff_parse(addr, 128, 0xa0, &nvl)) != EFAULT) {
		errx(1, "TEST FAILED: failed to return EFAULT on bad "
		    "data buffer (%s instead)\n", strerror(ret));
	}

	return (0);
}
