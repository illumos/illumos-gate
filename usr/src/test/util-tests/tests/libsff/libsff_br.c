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
 * Print and tests SFF BR values.
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
	nvlist_t *nvl;
	char *val;

	/*
	 * SFF 8472 has two different modes of printing the bit rate. It has a
	 * nominal bit rate and then if 0xff is in that field it has a max and
	 * min.
	 */
	bzero(buf, sizeof (buf));
	buf[SFF_8472_BR_NOMINAL] = 0x42;

	if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, &nvl)) != 0) {
		errx(1, "TEST FAILED: failed to parse SFP compliance "
		    "values: %s\n", strerror(ret));
	}

	if ((ret = nvlist_lookup_string(nvl, LIBSFF_KEY_BR_NOMINAL, &val)) !=
	    0) {
		errx(1, "TEST FAILED: failed to find %s: %s when "
		    "parsing key %d: %s\n", LIBSFF_KEY_BR_NOMINAL,
		    strerror(ret));
	}
	(void) printf("nominal: %s\n", val);

	/*
	 * Make sure min, max are missing.
	 */
	if ((ret = nvlist_lookup_string(nvl, LIBSFF_KEY_BR_MIN, &val)) !=
	    ENOENT) {
		errx(1, "TEST FALIED: found unexpected return value for key "
		    "%s: %d\n", LIBSFF_KEY_BR_MIN, ret);
	}

	if ((ret = nvlist_lookup_string(nvl, LIBSFF_KEY_BR_MAX, &val)) !=
	    ENOENT) {
		errx(1, "TEST FALIED: found unexpected return value for key "
		    "%s: %d\n", LIBSFF_KEY_BR_MAX, ret);
	}
	nvlist_free(nvl);

	/*
	 * Now the opposite.
	 */
	buf[SFF_8472_BR_NOMINAL] = 0xff;
	buf[SFF_8472_BR_MAX] = 0x50;
	buf[SFF_8472_BR_MIN] = 0x10;

	if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, &nvl)) != 0) {
		errx(1, "TEST FAILED: failed to parse SFP compliance "
		    "values: %s\n", strerror(ret));
	}

	if ((ret = nvlist_lookup_string(nvl, LIBSFF_KEY_BR_MAX, &val)) != 0) {
		errx(1, "TEST FAILED: failed to find %s: %s when "
		    "parsing key %d: %s\n", LIBSFF_KEY_BR_MAX,
		    strerror(ret));
	}
	(void) printf("max: %s\n", val);

	if ((ret = nvlist_lookup_string(nvl, LIBSFF_KEY_BR_MIN, &val)) != 0) {
		errx(1, "TEST FAILED: failed to find %s: %s when "
		    "parsing key %d: %s\n", LIBSFF_KEY_BR_MIN,
		    strerror(ret));
	}
	(void) printf("min: %s\n", val);

	if ((ret = nvlist_lookup_string(nvl, LIBSFF_KEY_BR_NOMINAL, &val)) !=
	    ENOENT) {
		errx(1, "TEST FALIED: found unexpected return value for key "
		    "%s: %d\n", LIBSFF_KEY_BR_NOMINAL, ret);
	}
	nvlist_free(nvl);

	/*
	 * Now for QSFP+
	 */
	(void) puts("\n\nQSFP\n");
	bzero(buf, sizeof (buf));
	buf[SFF_8472_IDENTIFIER] = SFF_8024_ID_QSFP;
	buf[SFF_8636_BR_NOMINAL] = 0x42;

	if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, &nvl)) != 0) {
		errx(1, "TEST FAILED: failed to parse QSFP BR "
		    "values: %s\n", strerror(ret));
	}

	if ((ret = nvlist_lookup_string(nvl, LIBSFF_KEY_BR_NOMINAL,
	    &val)) != 0) {
		errx(1, "TEST FAILED: failed to find %s: %s when "
		    "parsing key %d: %s\n", LIBSFF_KEY_BR_NOMINAL,
		    strerror(ret));
	}
	(void) printf("nominal: %s\n", val);

	nvlist_free(nvl);

	return (0);
}
