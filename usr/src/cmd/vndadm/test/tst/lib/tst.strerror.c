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
 * Verify that all the error strings we care about match what we expect.
 */

#include <stdio.h>
#include <libvnd.h>

int
main(void)
{
	int i;
	for (i = 0; i <= VND_E_UNKNOWN + 1; i++)
		(void) printf("[%s]\n", vnd_strerror(i));
	return (0);
}
