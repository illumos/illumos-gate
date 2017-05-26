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
 * Print and tests SFF length values.
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
	uint_t i;
	const char *lengths_8472[] = { LIBSFF_KEY_LENGTH_SMF_KM,
	    LIBSFF_KEY_LENGTH_SMF, LIBSFF_KEY_LENGTH_OM2, LIBSFF_KEY_LENGTH_OM1,
	    LIBSFF_KEY_LENGTH_COPPER, LIBSFF_KEY_LENGTH_OM3, NULL };
	const char *lengths_8636[] = { LIBSFF_KEY_LENGTH_SMF_KM,
	    LIBSFF_KEY_LENGTH_OM2, LIBSFF_KEY_LENGTH_OM1,
	    LIBSFF_KEY_LENGTH_COPPER, LIBSFF_KEY_LENGTH_OM3, NULL };

	/*
	 * Make sure if lengths are zero that they don't show up.
	 */
	bzero(buf, sizeof (buf));
	if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, &nvl)) != 0) {
		errx(1, "TEST FAILED: failed to parse SFP length "
		    "values: %s\n", strerror(ret));
	}

	for (i = 0; lengths_8472[i] != NULL; i++) {
		if ((ret = nvlist_lookup_string(nvl, lengths_8472[i], &val)) !=
		    ENOENT) {
			errx(1, "TEST FALIED: found unexpected return value "
			    "for key %s: %d\n", lengths_8472[i], ret);
		}
	}

	nvlist_free(nvl);

	buf[SFF_8472_LENGTH_SMF_KM] = 0x23;
	buf[SFF_8472_LENGTH_SMF] = 0x24;
	buf[SFF_8472_LENGTH_50UM] = 0x25;
	buf[SFF_8472_LENGTH_62UM] = 0x26;
	buf[SFF_8472_LENGTH_COPPER] = 0x27;
	buf[SFF_8472_LENGTH_OM3] = 0x28;

	if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, &nvl)) != 0) {
		errx(1, "TEST FAILED: failed to parse SFP length "
		    "values: %s\n", strerror(ret));
	}

	for (i = 0; lengths_8472[i] != NULL; i++) {
		if ((ret = nvlist_lookup_string(nvl, lengths_8472[i], &val)) !=
		    0) {
			errx(1, "TEST FALIED: failed to find length for key "
			    "%s: %d\n", lengths_8472[i], ret);
		}
		(void) printf("%s: %s\n", lengths_8472[i], val);
	}

	nvlist_free(nvl);

	/*
	 * Now for QSFP+
	 */
	(void) puts("\n\nQSFP\n");
	bzero(buf, sizeof (buf));
	buf[SFF_8472_IDENTIFIER] = SFF_8024_ID_QSFP;

	if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, &nvl)) != 0) {
		errx(1, "TEST FAILED: failed to parse QSFP length "
		    "values: %s\n", strerror(ret));
	}

	for (i = 0; lengths_8472[i] != NULL; i++) {
		if ((ret = nvlist_lookup_string(nvl, lengths_8472[i], &val)) !=
		    ENOENT) {
			errx(1, "TEST FALIED: found unexpected return value "
			    "for key %s: %d\n", lengths_8472[i], ret);
		}
	}

	nvlist_free(nvl);

	buf[SFF_8636_LENGTH_SMF] = 0x23;
	buf[SFF_8636_LENGTH_OM3] = 0x24;
	buf[SFF_8636_LENGTH_OM2] = 0x25;
	buf[SFF_8636_LENGTH_OM1] = 0x26;
	buf[SFF_8636_LENGTH_COPPER] = 0x27;

	if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, &nvl)) != 0) {
		errx(1, "TEST FAILED: failed to parse QSFP length "
		    "values: %s\n", strerror(ret));
	}

	for (i = 0; lengths_8636[i] != NULL; i++) {
		if ((ret = nvlist_lookup_string(nvl, lengths_8636[i], &val)) !=
		    0) {
			errx(1, "TEST FALIED: failed to find length for key "
			    "%s: %d\n", lengths_8472[i], ret);
		}
		(void) printf("%s: %s\n", lengths_8636[i], val);
	}

	nvlist_free(nvl);

	return (0);
}
