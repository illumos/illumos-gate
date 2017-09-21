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
	int ret;
	uint8_t buf[256];
	nvlist_t *nvl;

	bzero(buf, sizeof (buf));
	if ((ret = libsff_parse(NULL, sizeof (buf), 0xa0, &nvl)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on NULL buffer");
	}

	if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, NULL)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on NULL nvl");
	}

	if ((ret = libsff_parse(buf, sizeof (buf), 0xa1, &nvl)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on bad page");
	}

	if ((ret = libsff_parse(buf, sizeof (buf), 0, &nvl)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on bad page");
	}

	if ((ret = libsff_parse(buf, sizeof (buf), 0xff, &nvl)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on bad page");
	}

	if ((ret = libsff_parse(buf, 0, 0xa0, &nvl)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on bad 8476 "
		    "size");
	}

	if ((ret = libsff_parse(buf, 50, 0xa0, &nvl)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on bad 8476 "
		    "size");
	}

	buf[SFF_8472_IDENTIFIER] = SFF_8024_ID_QSFP;
	if ((ret = libsff_parse(buf, 0, 0xa0, &nvl)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on bad 8476 "
		    "size");
	}

	if ((ret = libsff_parse(buf, 50, 0xa0, &nvl)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on bad 8476 "
		    "size");
	}

	if ((ret = libsff_parse(buf, 96, 0xa0, &nvl)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on bad 8635 "
		    "size");
	}

	if ((ret = libsff_parse(buf, 128, 0xa0, &nvl)) != EINVAL) {
		errx(1, "TEST FAILED: failed to return EINVAL on bad 8635 "
		    "size");
	}

	return (0);
}
