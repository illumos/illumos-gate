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
 * Copyright 2019 Joyent, Inc.
 */

#include <aes/aes_impl.h>
#include <strings.h>
#include <stdio.h>
#include "cryptotest.h"
#include "aes_gcm.h"

static size_t updatelens[] = {
	1, AES_BLOCK_LEN, AES_BLOCK_LEN + 1, 2*AES_BLOCK_LEN,
	CTEST_UPDATELEN_WHOLE, CTEST_UPDATELEN_END
};

const size_t GCM_SPEC_TAG_LEN = 16;

int
main(void)
{
	int errs = 0;
	int i;
	uint8_t N[1024];
	size_t taglen = GCM_SPEC_TAG_LEN;

	/*
	 * For the PKCS build this is actually CK_GCM_PARAMS
	 * but thankfully the layout is the same.
	 */
	CK_AES_GCM_PARAMS param = {
		.ulTagBits = taglen * 8
	};
	cryptotest_t args = {
		.out = N,
		.outlen = sizeof (N),
		.param = &param,
		.plen = sizeof (param),
		.mechname = SUN_CKM_AES_GCM,
		.updatelens = updatelens
	};

	for (i = 0; i < sizeof (DATA) / sizeof (DATA[0]); i++) {
		args.in = DATA[i];
		args.key = KEY[i];

		args.inlen = DATALEN[i];
		args.keylen = KEYLEN[i];

		param.pIv = IV[i];
		param.ulIvLen = IVLEN[i];
		param.ulIvBits = IVLEN[i]*8;
		param.pAAD = AUTH[i];
		param.ulAADLen = AUTHLEN[i];


		errs += run_test(&args, RES[i], RESLEN[i], ENCR_FG);
		(void) fprintf(stderr, "----------\n");
	}

	(void) fprintf(stderr, "\t\t\t=== decrypt ===\n----------\n\n");

	for (i = 0; i < sizeof (DATA) / sizeof (DATA[0]); i++) {
		args.in = RES[i];
		args.key = KEY[i];

		args.inlen = RESLEN[i];
		args.keylen = KEYLEN[i];

		param.pIv = IV[i];
		param.ulIvLen = IVLEN[i];
		param.ulIvBits = IVLEN[i]*8;
		param.pAAD = AUTH[i];
		param.ulAADLen = AUTHLEN[i];


		errs += run_test(&args, DATA[i], DATALEN[i], DECR_FG);
		(void) fprintf(stderr, "----------\n");
	}

	if (errs != 0)
		(void) fprintf(stderr, "%d tests failed\n", errs);

	return (errs);
}
