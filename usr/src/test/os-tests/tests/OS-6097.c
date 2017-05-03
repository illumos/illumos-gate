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
 * Regression test for OS-6097.
 */

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <libdlpi.h>
#include <sys/debug.h>

int
main(void)
{
	int ret;
	char path[4096];
	uint_t num = 4294967294U;
	dlpi_handle_t dh;

	/*
	 * First, we need to determine a path that doesn't exist to trigger this
	 * bug. We start with the highest possible number and just decrement
	 * until we find something.
	 */

	while (num > 0) {
		struct stat st;

		(void) snprintf(path, sizeof (path), "/dev/net/net%u", num);

		ret = stat(path, &st);
		if (ret == -1 && errno == ENOENT)
			break;
		if (ret == -1) {
			(void) fprintf(stderr, "test failed: unexpected error "
			    "running stat(2) on %s: %s\n", path,
			    strerror(errno));
			return (1);
		}
		num--;
	}

	/*
	 * While technically this is a valid entry that we could try, at this
	 * point we've exhausted so many NICs, there's likely a bug.
	 */
	if (num == 0) {
		(void) fprintf(stderr, "failed to construct a non-existent "
		    "NIC with a name starting with 'net'\n");
		return (1);
	}

	(void) snprintf(path, sizeof (path), "net%u", num);
	ret = dlpi_open(path, &dh, 0);
	VERIFY3U(ret, ==, DLPI_ENOLINK);
	return (0);
}
