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
 * Print SFF 8636 device tech values.
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

static void
lst_print_array(nvlist_t *nvl, const char *key)
{
	int ret;
	uint_t i, count;
	char **vals;

	if ((ret = nvlist_lookup_string_array(nvl, key, &vals, &count)) != 0) {
		errx(1, "TEST FAILED failed to find key %s: %s\n", key,
		    strerror(ret));
	}

	(void) puts(key);
	for (i = 0; i < count; i++) {
		(void) printf("\t%d\t%s\n", i, vals[i]);
	}
}

int
main(void)
{
	uint_t i;
	uint8_t buf[256];

	bzero(buf, sizeof (buf));
	buf[SFF_8472_IDENTIFIER] = SFF_8024_ID_QSFP;

	/*
	 * The upper four bits of this value are used as a 4-bit identifier. The
	 * lower four bits are used as options.
	 */
	for (i = 0; i < 16; i++) {
		int ret;
		nvlist_t *nvl;

		buf[SFF_8636_DEVICE_TECH] = i << 4;
		buf[SFF_8636_DEVICE_TECH] |= (i % 16);

		if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, &nvl)) != 0) {
			errx(1, "TEST FAILED: failed to parse QSFP device tech "
			    "%d: %s\n", i, strerror(errno));
		}

		lst_print_array(nvl, LIBSFF_KEY_TRAN_TECH);
		nvlist_free(nvl);
	}

	return (0);
}
