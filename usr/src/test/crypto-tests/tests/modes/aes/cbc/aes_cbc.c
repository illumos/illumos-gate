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
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

#include <aes/aes_impl.h>
#include <stdio.h>

#include "cryptotest.h"
#include "aes_cbc.h"

int
main(void)
{
	int errs = 0;
	int i;
	uint8_t N[1024];
	cryptotest_t args;

	args.out = N;

	args.outlen = sizeof (N);
	args.plen = AES_BLOCK_LEN;

	args.mechname = SUN_CKM_AES_CBC;
	args.updatelen = 1;


	for (i = 0; i < sizeof (RES) / sizeof (RES[0]); i++) {
		args.in = DATA[i];
		args.key = KEY[i];
		args.param = IV[i];

		args.inlen = DATALEN[i];
		args.keylen = KEYLEN[i];

		errs += run_test(&args, RES[i], RESLEN[i], ENCR_FG);
		(void) fprintf(stderr, "----------\n");
	}

	(void) fprintf(stderr, "\t\t\t=== decrypt ===\n----------\n\n");

	for (i = 0; i < sizeof (RES) / sizeof (RES[0]); i++) {
		args.in = RES[i];
		args.key = KEY[i];
		args.param = IV[i];

		args.inlen = RESLEN[i];
		args.keylen = KEYLEN[i];

		errs += run_test(&args, DATA[i], DATALEN[i], DECR_FG);
		(void) fprintf(stderr, "----------\n");
	}

	if (errs != 0)
		(void) fprintf(stderr, "%d tests failed\n", errs);

	return (errs);
}
