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
 * Test our ability to parse SFF string values which are space encoded. As this
 * is shared between the SFP and QSFP logic, we end up only testing the SFP
 * based data.
 */

#include <stdio.h>
#include <errno.h>
#include <strings.h>
#include <err.h>
#include <libsff.h>

/*
 * Pick up private sff header file with offsets from lib/libsff. Strings are
 * described as having spaces at the end of them. We mostly want to make sure
 * that if we have strings without spaces that we parse them sanely as well as
 * test what happens with embedded spaces and NUL characters.
 */
#include "sff.h"

typedef struct {
	uint8_t	lss_bytes[16];
	const char *lss_parsed;
} lsfs_string_pair_t;

static const lsfs_string_pair_t lsfs_bad_vals[] = {
	/* All NULs */
	{ { '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
	    '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0' },
	    "" },
	/* Embedded NULs */
	{ { 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
	    '\0', 'a', 'a', 'a', 'a', 'a', 'a', 'a' },
	    "" },
	/* Non-ASCII */
	{ { 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
	    156, 'a', 'a', 'a', 'a', 'a', 'a', 'a' },
	    "" },
	/* All padding */
	{ { ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
	    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ' },
	    "" }
};
#define	NBAD	(sizeof (lsfs_bad_vals) / sizeof (lsfs_string_pair_t))

static const lsfs_string_pair_t lsfs_good_vals[] = {
	/* Basic Name */
	{ { 'f', 'i', 'n', 'g', 'o', 'l', 'f', 'i',
	    'n', ' ', ' ', ' ', ' ', ' ', ' ', ' ' },
	    "fingolfin" },
	/* Non-padding Space */
	{ { 'G', 'l', 'o', 'b', 'e', 'x', ' ', 'C',
	    'o', 'r', 'p', ' ', ' ', ' ', ' ', ' ' },
	    "Globex Corp" },
	/* 1-character name to catch off by one */
	{ { '~', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
	    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ' },
	    "~" },
	/* Use all characters */
	{ { '!', '!', '!', '!', '!', '!', '!', '!',
	    '!', '!', '!', '!', '!', '!', '!', '!' },
	    "!!!!!!!!!!!!!!!!" }
};
#define	NGOOD	(sizeof (lsfs_good_vals) / sizeof (lsfs_string_pair_t))

int
main(void)
{
	int ret, i;
	uint8_t buf[256];
	nvlist_t *nvl;
	char *val;

	for (i = 0; i < NBAD; i++) {
		bzero(buf, sizeof (buf));
		bcopy(lsfs_bad_vals[i].lss_bytes, &buf[SFF_8472_VENDOR],
		    SFF_8472_VENDOR_LEN);


		if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, &nvl)) != 0) {
			errx(1, "TEST FAILED: failed to parse SFP bad string "
			    "case %d: %s\n", i, strerror(ret));
		}

		if ((ret = nvlist_lookup_string(nvl, LIBSFF_KEY_VENDOR,
		    &val)) != ENOENT) {
			errx(1, "TEST FALIED: found unexpected return value "
			    "for %s: %d\n", LIBSFF_KEY_VENDOR, ret);
		}
		nvlist_free(nvl);
	}

	for (i = 0; i < NGOOD; i++) {
		bzero(buf, sizeof (buf));
		bcopy(lsfs_good_vals[i].lss_bytes, &buf[SFF_8472_VENDOR],
		    SFF_8472_VENDOR_LEN);

		if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, &nvl)) != 0) {
			errx(1, "TEST FAILED: failed to parse SFP good string "
			    "case %d: %s\n", i, strerror(ret));
		}

		if ((ret = nvlist_lookup_string(nvl, LIBSFF_KEY_VENDOR,
		    &val)) != 0) {
			errx(1, "TEST FALIED: failed to find expected key "
			    "%s: %d", LIBSFF_KEY_VENDOR, ret);
		}

		if (strcmp(val, lsfs_good_vals[i].lss_parsed) != 0) {
			errx(1, "TEST FAILED: expected string %s, found %s\n",
			    lsfs_good_vals[i].lss_parsed, val);
		}

		nvlist_free(nvl);
	}

	return (0);
}
