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
 * Copyright (c) 2018, Joyent, Inc.
 * Copyright 2024 Oxide Computer Company
 */

/*
 * Test basic vendor lookup functionality.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <libjedec.h>
#include <stdio.h>
#include <strings.h>

/*
 * Table of various values and expected vendors.
 */
typedef struct {
	uint_t		ljtt_cont;
	uint_t		ljtt_vendor;
	const char	*ljtt_exp;
} libjedec_test_t;

static const libjedec_test_t libjedec_expects[] = {
	{ 0x00, 0x01, "AMD" },
	{ 0x00, 0x19, "Xicor" },
	{ 0x00, 0x89, "Intel" },
	{ 0x00, 0xFE, "Numonyx Corporation" },
	{ 0x01, 0x15, "Hughes Aircraft" },
	{ 0x01, 0xF2, "Yamaha Corporation" },
	{ 0x02, 0x9E, "Corsair" },
	{ 0x02, 0x3E, "West Bay Semiconductor" },
	{ 0x02, 0xF8, "Galaxy Power" },
	{ 0x03, 0x26, "BOPS" },
	{ 0x03, 0x6B, "NVIDIA" },
	{ 0x03, 0x7A, "Astec International" },
	{ 0x04, 0x07, "Dotcast" },
	{ 0x04, 0x40, "Bandspeed" },
	{ 0x04, 0x6D, "Supreme Top Technology Ltd." },
	{ 0x05, 0x2A, "Atrua Technologies, Inc." },
	{ 0x05, 0x52, "New Japan Radio Co. Ltd." },
	{ 0x05, 0xEF, "MetaRAM" },
	{ 0x06, 0x0B, "Netxen" },
	{ 0x06, 0xF2, "Muscle Power" },
	{ 0x07, 0x9E, "Teikon" },
	{ 0x07, 0xCE, "Mustang" },
	{ 0x08, 0x1F, "Shenzhen City Gcai Electronics" },
	{ 0x08, 0xF1, "Asgard" },
	{ 0x09, 0x13, "Raspberry Pi Trading Ltd." },
	{ 0x09, 0xFE, "ALLFLASH Technology Limited" },
	{ 0x0a, 0x2C, "Diamond" },
	{ 0x0a, 0x6B, "Acer" },
	{ 0x0b, 0xE6, "NUVIA Inc" },
	{ 0x0c, 0xC4, "uFound" },
	{ 0x0d, 0x8A, "Aerospace Science Memory Shenzhen" },
	{ 0x0f, 0xD0, "PIRATEMAN" },
	/* Various Failure cases */
	{ 0x00, 0x05, NULL },
	{ 0x0d, 0xFF, NULL },
	{ 0x20, 0x01, NULL }
};

int
main(void)
{
	uint_t i, errs = 0;

	for (i = 0; i < ARRAY_SIZE(libjedec_expects); i++) {
		const char *out;

		out = libjedec_vendor_string(libjedec_expects[i].ljtt_cont,
		    libjedec_expects[i].ljtt_vendor);
		if (out == NULL) {
			if (libjedec_expects[i].ljtt_exp != NULL) {
				errs++;
				(void) fprintf(stderr, "test %u failed, "
				    "expected %s, but lookup failed\n", i,
				    libjedec_expects[i].ljtt_exp);
			}
		} else {
			if (libjedec_expects[i].ljtt_exp == NULL) {
				errs++;
				(void) fprintf(stderr, "test %u failed, "
				    "expected lookup failure, but it succeeded "
				    "with %s\n", i, out);
			} else if (strcmp(out, libjedec_expects[i].ljtt_exp) !=
			    0) {
				errs++;
				(void) fprintf(stderr, "test %u failed, "
				    "expected %s, found %s\n", i,
				    libjedec_expects[i].ljtt_exp, out);
			}
		}
	}

	if (errs == 0) {
		(void) printf("All tests completed successfully\n");
	}

	return (errs);
}
