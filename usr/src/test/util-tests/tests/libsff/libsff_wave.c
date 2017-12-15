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
 * Print and tests SFF Wavelength values. Note that in both SFF 8472 and SFF
 * 8636 the wavelength values also double for various copper complaince values.
 * We check both forms here. Note that the copper compliance in SFF 8472 is
 * currently tested in libsff_compliance.c. SFF 8636's Copper Attenuation values
 * are tested here.
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
	int ret, i;
	uint8_t buf[256];
	nvlist_t *nvl;
	char *val;
	char *attenuate[] = { LIBSFF_KEY_ATTENUATE_2G, LIBSFF_KEY_ATTENUATE_5G,
	    LIBSFF_KEY_ATTENUATE_7G, LIBSFF_KEY_ATTENUATE_12G, NULL };
	char *wave[] = { LIBSFF_KEY_WAVELENGTH, LIBSFF_KEY_WAVE_TOLERANCE,
	    NULL };

	bzero(buf, sizeof (buf));
	buf[SFF_8472_WAVELENGTH_HI] = 0x12;
	buf[SFF_8472_WAVELENGTH_LOW] = 0x34;

	if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, &nvl)) != 0) {
		errx(1, "TEST FAILED: failed to parse SFP wavelength "
		    "values: %s\n", strerror(ret));
	}

	if ((ret = nvlist_lookup_string(nvl, LIBSFF_KEY_WAVELENGTH, &val)) !=
	    0) {
		errx(1, "TEST FAILED: failed to find %s: %s when "
		    "parsing key %d: %s\n", LIBSFF_KEY_WAVELENGTH,
		    strerror(ret));
	}
	(void) printf("%s: %s\n", LIBSFF_KEY_WAVELENGTH, val);
	nvlist_free(nvl);

	/*
	 * Make sure wavelength is missing if we specify a copper compliance.
	 */
	bzero(buf, sizeof (buf));
	buf[SFF_8472_COMPLIANCE_SFP] = 0x08;
	buf[SFF_8472_WAVELENGTH_HI] = 0x12;
	buf[SFF_8472_WAVELENGTH_LOW] = 0x34;

	if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, &nvl)) != 0) {
		errx(1, "TEST FAILED: failed to parse SFP wavelength "
		    "values: %s\n", strerror(ret));
	}

	if ((ret = nvlist_lookup_string(nvl, LIBSFF_KEY_WAVELENGTH, &val)) !=
	    ENOENT) {
		errx(1, "TEST FALIED: found unexpected return value for key "
		    "%s: %d\n", LIBSFF_KEY_WAVELENGTH, ret);
	}

	nvlist_free(nvl);

	bzero(buf, sizeof (buf));
	buf[SFF_8472_COMPLIANCE_SFP] = 0x04;
	buf[SFF_8472_WAVELENGTH_HI] = 0x12;
	buf[SFF_8472_WAVELENGTH_LOW] = 0x34;

	if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, &nvl)) != 0) {
		errx(1, "TEST FAILED: failed to parse SFP wavelength "
		    "values: %s\n", strerror(ret));
	}

	if ((ret = nvlist_lookup_string(nvl, LIBSFF_KEY_WAVELENGTH, &val)) !=
	    ENOENT) {
		errx(1, "TEST FALIED: found unexpected return value for key "
		    "%s: %d\n", LIBSFF_KEY_WAVELENGTH, ret);
	}

	nvlist_free(nvl);

	/*
	 * Now for QSFP+
	 */
	(void) puts("\n\nQSFP\n");

	/* First copper */
	bzero(buf, sizeof (buf));
	buf[SFF_8472_IDENTIFIER] = SFF_8024_ID_QSFP;
	buf[SFF_8636_DEVICE_TECH] = 0xa0;

	buf[SFF_8636_ATTENUATE_2G] = 0x42;
	buf[SFF_8636_ATTENUATE_5G] = 0x43;
	buf[SFF_8636_ATTENUATE_7G] = 0x44;
	buf[SFF_8636_ATTENUATE_12G] = 0x45;

	if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, &nvl)) != 0) {
		errx(1, "TEST FAILED: failed to parse QSFP BR "
		    "values: %s\n", strerror(ret));
	}

	for (i = 0; attenuate[i] != NULL; i++) {
		if ((ret = nvlist_lookup_string(nvl, attenuate[i], &val)) !=
		    0) {
			errx(1, "TEST FAILED: failed to find %s: %s when "
			    "parsing key %d: %s\n", attenuate[i],
			    strerror(ret));
		}
		(void) printf("%s: %s\n", attenuate[i], val);
	}

	for (i = 0; wave[i] != NULL; i++) {
		if ((ret = nvlist_lookup_string(nvl, wave[i], &val)) !=
		    ENOENT) {
			errx(1, "TEST FALIED: found unexpected return value "
			    "for key %s: %d\n", attenuate[i], ret);
		}

	}
	nvlist_free(nvl);

	/* Now normal wavelengths */
	bzero(buf, sizeof (buf));
	buf[SFF_8472_IDENTIFIER] = SFF_8024_ID_QSFP;

	buf[SFF_8636_WAVELENGTH_NOMINAL_HI] = 0x12;
	buf[SFF_8636_WAVELENGTH_NOMINAL_LOW] = 0x34;
	buf[SFF_8636_WAVELENGTH_TOLERANCE_HI] = 0x56;
	buf[SFF_8636_WAVELENGTH_TOLERANCE_LOW] = 0x78;

	if ((ret = libsff_parse(buf, sizeof (buf), 0xa0, &nvl)) != 0) {
		errx(1, "TEST FAILED: failed to parse QSFP Wavelength "
		    "values: %s\n", strerror(ret));
	}

	for (i = 0; wave[i] != NULL; i++) {
		if ((ret = nvlist_lookup_string(nvl, wave[i], &val)) != 0) {
			errx(1, "TEST FAILED: failed to find %s: %s when "
			    "parsing key %d: %s\n", wave[i], strerror(ret));
		}
		(void) printf("%s: %s\n", wave[i], val);
	}

	for (i = 0; attenuate[i] != NULL; i++) {
		if ((ret = nvlist_lookup_string(nvl, attenuate[i], &val)) !=
		    ENOENT) {
			errx(1, "TEST FALIED: found unexpected return value "
			    "for key %s: %d\n", attenuate[i], ret);
		}

	}
	nvlist_free(nvl);

	return (0);
}
