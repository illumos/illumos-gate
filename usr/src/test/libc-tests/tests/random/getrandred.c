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
 * Copyright 2015 Joyent, Inc.
 */

/*
 * Regression test for illumos#5843.
 */

#include <string.h>
#include <stdlib.h>
#include <sys/random.h>

#define	NTRIES 5
#define	NOFF	128
#define	NBYTES	223

int
main(void)
{
	int i;
	char buf[1024];

	(void) memset(buf, 'a', sizeof (buf));

	/*
	 * Try to go ahead and corrupt ourselves NTRIES times.
	 */
	for (i = 0; i < NTRIES; i++) {
		(void) getrandom(buf + NOFF, NBYTES, 0);
	}

	for (i = 0; i < NOFF; i++) {
		if (buf[i] != 'a')
			abort();
	}

	for (i = NBYTES + NOFF; i < sizeof (buf); i++) {
		if (buf[i] != 'a')
			abort();
	}

	return (0);
}
