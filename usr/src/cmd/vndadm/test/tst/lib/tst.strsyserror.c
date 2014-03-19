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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * Verify that the error message from libvnd's strsyserrno is the same as the
 * underlying strerror function's. It should be. We'll just check an assortment
 * of errnos.
 */

#include <stdio.h>
#include <string.h>
#include <libvnd.h>

int
main(void)
{
	int i;
	const char *vnd, *libc;
	for (i = 0; i < 42; i++) {
		vnd = vnd_strsyserror(i);
		libc = strerror(i);
		if ((vnd != NULL && libc == NULL) ||
		    (vnd == NULL && libc != NULL)) {
			(void) fprintf(stderr, "errno %d, vnd: %p, libc: %p",
			    i, (void *)vnd, (void *)libc);
			return (1);
		}
		if (vnd != NULL && strcmp(vnd, libc) != 0) {
			(void) fprintf(stderr,
			    "errno %d: libc and vnd disagree.\n", i);
			(void) fprintf(stderr, "vnd: %s\n", vnd);
			(void) fprintf(stderr, "libc: %s\n", libc);
			return (1);
		}
	}

	return (0);
}
