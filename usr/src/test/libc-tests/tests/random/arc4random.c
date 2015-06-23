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
 * Basic tests for the arc4random(3C) family of functions. They should always
 * succeed, let's make sure these do.
 */

#include <stdlib.h>
#include <assert.h>
#include <errno.h>

int
main(void)
{
	uint32_t ret;
	uint8_t buf[32];

	(void) arc4random();
	ret = arc4random_uniform(100);
	assert(ret < 100);
	ret = arc4random_uniform(200);
	assert(ret < 200);

	arc4random_buf(buf, sizeof (buf));

	return (0);
}
