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
 * Print and tests SFF compliance values.
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
lsc_print_array(nvlist_t *nvl, const char *key)
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
	 * Set every shared bit for compliance then print them all out. Note we
	 * include reserved bits so that way if someone ends up adding something
	 * to one of the reserved fields, we end up printing it.
	 */
	bzero(buf, sizeof (buf));
	buf[SFF_8472_COMPLIANCE_10GE] = 0xff;
	buf[SFF_8472_COMPLIANCE_SONET_LOW] = 0xff;
	buf[SFF_8472_COMPLIANCE_SONET_HIGH] = 0xff;
	buf[SFF_8472_COMPLIANCE_ETHERNET] = 0xff;
	buf[SFF_8472_COMPLIANCE_FC_LOW] = 0xff;
	buf[SFF_8472_COMPLIANCE_FC_HIGH] = 0xff;
	buf[SFF_8472_COMPLIANCE_FC_MEDIA] = 0xff;
	buf[SFF_8472_COMPLIANCE_FC_SPEED] = 0xff;

	if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, &nvl)) != 0) {
		errx(1, "TEST FAILED: failed to parse SFP compliance "
		    "values: %s\n", strerror(ret));
	}

	lsc_print_array(nvl, LIBSFF_KEY_COMPLIANCE_10GBE);
	lsc_print_array(nvl, LIBSFF_KEY_COMPLIANCE_IB);
	lsc_print_array(nvl, LIBSFF_KEY_COMPLIANCE_ESCON);
	lsc_print_array(nvl, LIBSFF_KEY_COMPLIANCE_SONET);
	lsc_print_array(nvl, LIBSFF_KEY_COMPLIANCE_GBE);
	lsc_print_array(nvl, LIBSFF_KEY_COMPLIANCE_FC_LEN);
	lsc_print_array(nvl, LIBSFF_KEY_COMPLIANCE_FC_TECH);
	lsc_print_array(nvl, LIBSFF_KEY_COMPLIANCE_SFP);
	lsc_print_array(nvl, LIBSFF_KEY_COMPLIANCE_FC_MEDIA);
	lsc_print_array(nvl, LIBSFF_KEY_COMPLIANCE_FC_SPEED);

	nvlist_free(nvl);

	/*
	 * Now for QSFP+
	 */
	(void) puts("\n\nQSFP\n");
	bzero(buf, sizeof (buf));
	buf[SFF_8472_IDENTIFIER] = SFF_8024_ID_QSFP;
	buf[SFF_8636_COMPLIANCE_10GBEP] = 0xff;
	buf[SFF_8636_COMPLIANCE_SONET] = 0xff;
	buf[SFF_8636_COMPLIANCE_SAS] = 0xff;
	buf[SFF_8636_COMPLIANCE_ETHERNET] = 0xff;
	buf[SFF_8636_COMPLIANCE_FCLEN] = 0xff;
	buf[SFF_8636_COMPLIANCE_FC_LOW] = 0xff;
	buf[SFF_8636_COMPLIANCE_FC_HIGH] = 0xff;
	buf[SFF_8636_COMPLIANCE_FC_MEDIA] = 0xff;
	buf[SFF_8636_COMPLIANCE_FC_SPEED] = 0xff;
	buf[SFF_8636_EXTENDED_MODULE] = 0xff;

	if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, &nvl)) != 0) {
		errx(1, "TEST FAILED: failed to parse QSFP compliance "
		    "values: %s\n", strerror(ret));
	}

	lsc_print_array(nvl, LIBSFF_KEY_COMPLIANCE_10GBE);
	lsc_print_array(nvl, LIBSFF_KEY_COMPLIANCE_SONET);
	lsc_print_array(nvl, LIBSFF_KEY_COMPLIANCE_SAS);
	lsc_print_array(nvl, LIBSFF_KEY_COMPLIANCE_GBE);
	lsc_print_array(nvl, LIBSFF_KEY_COMPLIANCE_FC_LEN);
	lsc_print_array(nvl, LIBSFF_KEY_COMPLIANCE_FC_TECH);
	lsc_print_array(nvl, LIBSFF_KEY_COMPLIANCE_FC_MEDIA);
	lsc_print_array(nvl, LIBSFF_KEY_COMPLIANCE_FC_SPEED);
	lsc_print_array(nvl, LIBSFF_KEY_EXT_MOD_CODES);

	nvlist_free(nvl);

	return (0);
}
