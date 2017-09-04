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

#include <strings.h>
#include <stdio.h>
/* used for CK_*_PARAMS */
#include <security/cryptoki.h>

#include "cryptotest.h"
#include "aes_ctr.h"

int
main(void)
{
	int errs = 0;
	int i;
	uint8_t N[1024];
	CK_AES_CTR_PARAMS param;
	cryptotest_t args;
	size_t cblen = sizeof (CTR_CB0);

	bzero(&param, sizeof (param));
	param.ulCounterBits = 128 - cblen*8;
	param.cb[15] = 0x01;

	args.out = N;
	args.param = &param;

	args.outlen = sizeof (N);
	args.plen = sizeof (param);

	/*
	 * CTR is a stream cipher, and it runs ctr_mode_final every time
	 * it has a remainder, so the result is different
	 * if len == 0 mod block_size vs len != 0 mod block_size
	 */

	args.mechname = SUN_CKM_AES_CTR;
	args.updatelen = 16;

	for (i = 0; i < sizeof (DATA) / sizeof (DATA[0]); i++) {
		bcopy(CB[i], param.cb, cblen);

		args.in = DATA[i];
		args.key = KEY[i];

		args.inlen = DATALEN[i];
		args.keylen = KEYLEN[i];

		errs += run_test(&args, RES[i], RESLEN[i], ENCR_FG);
		(void) fprintf(stderr, "----------\n");
	}

	(void) fprintf(stderr, "\t\t\t=== decrypt ===\n----------\n\n");

	for (i = 0; i < sizeof (DATA) / sizeof (DATA[0]); i++) {
		bcopy(CB[i], param.cb, cblen);

		args.in = RES[i];
		args.key = KEY[i];

		args.inlen = RESLEN[i];
		args.keylen = KEYLEN[i];

		errs += run_test(&args, DATA[i], DATALEN[i], ENCR_FG);
		(void) fprintf(stderr, "----------\n");
	}

	if (errs != 0)
		(void) fprintf(stderr, "%d tests failed\n", errs);

	return (errs);
}
