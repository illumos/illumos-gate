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
 * Copyright (c) 2015, Joyent, Inc.
 */

/*
 * This test is designed to fill a buffer with arc4random_buf and ensure that we
 * rekey ourselves multiple times during this test. We have a 4 Mb buffer and
 * currently we rekey ourselves every ~1.53 Mb. A wrapper script should call
 * this with an appropriate bit of D to verify the rekey.
 */

#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#define	NENTS	(4 * 1024 * 1024)

int
main(void)
{
	uint8_t *buf;

	buf = malloc(NENTS);
	assert(buf != NULL);
	arc4random_buf(buf, NENTS);

	return (0);
}
