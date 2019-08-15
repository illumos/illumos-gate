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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2019 Joyent, Inc.
 */

#include <aes/aes_impl.h>
#include <strings.h>
#include <stdio.h>
#include <sys/debug.h>
#include "cryptotest.h"
#include "aes_ccm.h"

/*
 * Size of param (in 8-byte chunks for alignment) large enough for both
 * CK_CCM_PARAMS and CK_AES_CCM_PARAMS.
 */
#define	PARAM_SIZE_64 8

static size_t updatelens[] = {
	1, AES_BLOCK_LEN, AES_BLOCK_LEN + 1, 2*AES_BLOCK_LEN,
	CTEST_UPDATELEN_WHOLE, CTEST_UPDATELEN_END
};

int
main(void)
{
	int errs = 0;
	int i;
	uint8_t N[1024];
	uint64_t param[PARAM_SIZE_64];

	cryptotest_t args = {
		.out = N,
		.outlen = sizeof (N),
		.mechname = SUN_CKM_AES_CCM,
		.updatelens = updatelens
	};

	args.key = CCM_KEY1;
	args.keylen = sizeof (CCM_KEY1);
	for (i = 0; i < 12; i++) {
		bzero(param, sizeof (param));
		ccm_init_params(param, DATALEN[i] - AUTHLEN[i], NONCE[i],
		    NONCELEN[i], CCM_DATA1, AUTHLEN[i], MACLEN[i]);

		args.param = param;
		args.plen = ccm_param_len();

		VERIFY3U(args.plen, <=, sizeof (param));

		args.in = CCM_DATA1 + AUTHLEN[i];
		args.inlen = DATALEN[i] - AUTHLEN[i];

		errs += run_test(&args, RES[i] + AUTHLEN[i],
		    RESLEN[i] - AUTHLEN[i], ENCR_FG);
		(void) fprintf(stderr, "----------\n");
	}

	args.key = CCM_KEY2;
	args.keylen = sizeof (CCM_KEY2);
	for (i = 12; i < 24; i++) {
		bzero(param, sizeof (param));
		ccm_init_params(param, DATALEN[i] - AUTHLEN[i], NONCE[i],
		    NONCELEN[i], DATA_2[i-12], AUTHLEN[i], MACLEN[i]);

		args.param = param;
		args.plen = ccm_param_len();

		VERIFY3U(args.plen, <=, sizeof (param));

		args.in = DATA_2[i-12] + AUTHLEN[i];
		args.inlen = DATALEN[i] - AUTHLEN[i];

		errs += run_test(&args, RES[i] + AUTHLEN[i],
		    RESLEN[i] - AUTHLEN[i], ENCR_FG);
		(void) fprintf(stderr, "----------\n");
	}

	(void) fprintf(stderr, "\t\t\t=== decrypt ===\n----------\n\n");

	args.key = CCM_KEY1;
	args.keylen = sizeof (CCM_KEY1);
	for (i = 0; i < 12; i++) {
		bzero(param, sizeof (param));
		ccm_init_params(param, RESLEN[i] - AUTHLEN[i], NONCE[i],
		    NONCELEN[i], CCM_DATA1, AUTHLEN[i], MACLEN[i]);

		args.param = param;
		args.plen = ccm_param_len();

		VERIFY3U(args.plen, <=, sizeof (param));

		args.in = RES[i] + AUTHLEN[i];
		args.inlen = RESLEN[i] - AUTHLEN[i];

		errs += run_test(&args, CCM_DATA1 + AUTHLEN[i],
		    DATALEN[i] - AUTHLEN[i], DECR_FG);
		(void) fprintf(stderr, "----------\n");
	}

	args.key = CCM_KEY2;
	args.keylen = sizeof (CCM_KEY2);
	for (i = 12; i < 24; i++) {
		bzero(param, sizeof (param));
		ccm_init_params(param, RESLEN[i] - AUTHLEN[i], NONCE[i],
		    NONCELEN[i], DATA_2[i-12], AUTHLEN[i], MACLEN[i]);

		args.param = param;
		args.plen = ccm_param_len();

		VERIFY3U(args.plen, <=, sizeof (param));

		args.in = RES[i] + AUTHLEN[i];
		args.inlen = RESLEN[i] - AUTHLEN[i];

		errs += run_test(&args, DATA_2[i-12] + AUTHLEN[i],
		    DATALEN[i] - AUTHLEN[i], ENCR_FG);
		(void) fprintf(stderr, "----------\n");
	}

	if (errs != 0)
		(void) fprintf(stderr, "%d tests failed\n", errs);

	return (errs);
}
