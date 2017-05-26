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
 * Print and tests SFF options values.
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
lso_print_array(nvlist_t *nvl, const char *key)
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
	int ret;
	uint8_t buf[256];
	nvlist_t *nvl;

	/*
	 * Set every shared bit for options then print them all out. Note we
	 * include reserved bits so that way if someone ends up adding something
	 * to one of the reserved fields, we end up printing it.
	 */
	bzero(buf, sizeof (buf));
	buf[SFF_8472_OPTIONS_HI] = 0xff;
	buf[SFF_8472_OPTIONS_LOW] = 0xff;
	buf[SFF_8472_ENHANCED_OPTIONS] = 0xff;

	if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, &nvl)) != 0) {
		errx(1, "TEST FAILED: failed to parse SFP options "
		    "values: %s\n", strerror(ret));
	}

	lso_print_array(nvl, LIBSFF_KEY_OPTIONS);
	lso_print_array(nvl, LIBSFF_KEY_EXTENDED_OPTIONS);

	nvlist_free(nvl);

	/*
	 * Now for QSFP+
	 */
	(void) puts("\n\nQSFP\n");
	bzero(buf, sizeof (buf));
	buf[SFF_8472_IDENTIFIER] = SFF_8024_ID_QSFP;
	buf[SFF_8636_OPTIONS_HI] = 0xff;
	buf[SFF_8636_OPTIONS_MID] = 0xff;
	buf[SFF_8636_OPTIONS_LOW] = 0xff;
	buf[SFF_8636_ENHANCED_OPTIONS] = 0xff;

	if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, &nvl)) != 0) {
		errx(1, "TEST FAILED: failed to parse QSFP options "
		    "values: %s\n", strerror(ret));
	}

	lso_print_array(nvl, LIBSFF_KEY_OPTIONS);
	lso_print_array(nvl, LIBSFF_KEY_ENHANCED_OPTIONS);

	nvlist_free(nvl);

	return (0);
}
