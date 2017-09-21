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
 * Print all SFF 8636 diagnostic monitoring
 */

#include <stdio.h>
#include <errno.h>
#include <strings.h>
#include <err.h>
#include <libsff.h>

/*
 * Pick up private sff header file with offsets from lib/libsff.
 */
#include "sff.h"

int
main(void)
{
	int ret;
	uint8_t buf[256];
	char **vals;
	uint_t count, i;
	nvlist_t *nvl;

	bzero(buf, sizeof (buf));
	buf[SFF_8472_IDENTIFIER] = SFF_8024_ID_QSFP;
	buf[SFF_8636_DIAG_MONITORING] = 0xff;

	if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, &nvl)) != 0) {
		errx(1, "TEST FAILED: failed to parse QSFP diagnostics: "
		    "%s\n", strerror(errno));
	}

	if ((ret = nvlist_lookup_string_array(nvl, LIBSFF_KEY_DIAG_MONITOR,
	    &vals, &count)) != 0) {
		errx(1, "TEST FAILED: failed to find key %s: %s ",
		    LIBSFF_KEY_EXT_SPEC, strerror(ret));
	}

	for (i = 0; i < count; i++) {
		(void) printf("%d\t%s\n", i, vals[i]);
	}

	nvlist_free(nvl);
	return (0);
}
