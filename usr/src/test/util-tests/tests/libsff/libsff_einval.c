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
 * Test various error cases all of which should return EINVAL.
 */

#include <stdio.h>
#include <errno.h>
#include <strings.h>
#include <err.h>
#include <libsff.h>

#include "sff.h"

int
main(void)
{
	uint8_t buf[256];
	nvlist_t *nvl;
	int ret;

	bzero(buf, sizeof (buf));
	if ((ret = libsff_parse(NULL, sizeof (buf), 0xa0, &nvl)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on NULL buffer");
	}

	if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, NULL)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on NULL nvl "
		    "(%s instead)", strerror(ret));
	}

	if ((ret = libsff_parse(buf, sizeof (buf), 0xa1, &nvl)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on bad page "
		    "(%s instead)", strerror(ret));
	}

	if ((ret = libsff_parse(buf, sizeof (buf), 0, &nvl)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on bad page "
		    "(%s instead)", strerror(ret));
	}

	if ((ret = libsff_parse(buf, sizeof (buf), 0xff, &nvl)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on bad page "
		    "(%s instead)", strerror(ret));
	}

	if ((ret = libsff_parse(buf, 0, 0xa0, &nvl)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on bad 8476 "
		    "size (%s instead)", strerror(ret));
	}

	if ((ret = libsff_parse(buf, 50, 0xa0, &nvl)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on bad 8476 "
		    "size (%s instead)", strerror(ret));
	}

	buf[SFF_8472_IDENTIFIER] = SFF_8024_ID_QSFP;
	if ((ret = libsff_parse(buf, 0, 0xa0, &nvl)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on bad 8476 "
		    "size (%s instead)", strerror(ret));
	}

	if ((ret = libsff_parse(buf, 50, 0xa0, &nvl)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on bad 8476 "
		    "size (%s instead)", strerror(ret));
	}

	if ((ret = libsff_parse(buf, 96, 0xa0, &nvl)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on bad 8635 "
		    "size (%s instead)", strerror(ret));
	}

	if ((ret = libsff_parse(buf, 128, 0xa0, &nvl)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on bad 8635 "
		    "size (%s instead)", strerror(ret));
	}

	return (0);
}
