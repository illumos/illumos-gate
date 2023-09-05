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
 * Copyright 2023-2026 RackTop Systems, Inc.
 */

/*
 * Verify correct hash computations using the MAC function group.
 * See MAC_FG in cryptotest.h, cryptotest_mac_fg in testfuncs.c
 *
 * See also aes_gmac_enc.c which uses ENCR_FG in place of MAC_FG
 */

#include <aes/aes_impl.h>
#include <strings.h>
#include <stdio.h>
#include "cryptotest.h"
#include "aes_gmac.h"

static size_t updatelens[] = {
	1, AES_BLOCK_LEN, AES_BLOCK_LEN + 1, 2*AES_BLOCK_LEN,
	CTEST_UPDATELEN_WHOLE, CTEST_UPDATELEN_END
};

/* Settable (eg. set to 1 for debugging) */
int ndata = sizeof (DATA) / sizeof (DATA[0]);

int
main(void)
{
	int errs = 0;
	int i;
	uint8_t N[1024];
	CK_AES_GMAC_PARAMS param = {0};
	cryptotest_t args = {
		.out = N,
		.outlen = sizeof (N),
		.param = &param,
		.plen = sizeof (param),
		.mechname = SUN_CKM_AES_GMAC,
		.updatelens = updatelens
	};

	(void) fprintf(stderr, "\t\t\t=== all input ===\n----------\n\n");
	for (i = 0; i < ndata; i++) {
		args.in = DATA[i];
		args.key = KEY[i];

		args.inlen = DATALEN[i];
		args.keylen = KEYLEN[i];

		param.pIv = IV[i];
		param.pAAD = NULL;
		param.ulAADLen = 0;


		errs += run_test(&args, RES[i], RESLEN[i], MAC_FG);
		(void) fprintf(stderr, "----------\n");
	}

	(void) fprintf(stderr, "\t\t\t=== all AAD ===\n----------\n\n");
	for (i = 0; i < ndata; i++) {
		args.in = NULL;
		args.key = KEY[i];

		args.inlen = 0;
		args.keylen = KEYLEN[i];

		param.pIv = IV[i];
		param.pAAD = DATA[i];
		param.ulAADLen = DATALEN[i];


		errs += run_test(&args, RES[i], RESLEN[i], MAC_FG);
		(void) fprintf(stderr, "----------\n");
	}

	(void) fprintf(stderr, "\t\t\t=== half AAD ===\n----------\n\n");
	for (i = 0; i < ndata; i++) {
		args.in = &DATA[i][DATALEN[i] / 2];
		args.key = KEY[i];

		args.inlen = DATALEN[i] - DATALEN[i] / 2;
		args.keylen = KEYLEN[i];

		param.pIv = IV[i];
		param.pAAD = DATA[i];
		param.ulAADLen = DATALEN[i] / 2;


		errs += run_test(&args, RES[i], RESLEN[i], MAC_FG);
		(void) fprintf(stderr, "----------\n");
	}

	(void) fprintf(stderr, "\t\t\t=== 16-byte AAD ===\n----------\n\n");
	for (i = 0; i < ndata; i++) {
		if (DATALEN[i] <= 16) {
			(void) fprintf(stderr, "len < 16; skip\n----------\n");
			continue;
		}

		args.in = &DATA[i][16];
		args.key = KEY[i];

		args.inlen = DATALEN[i] - 16;
		args.keylen = KEYLEN[i];

		param.pIv = IV[i];
		param.pAAD = DATA[i];
		param.ulAADLen = 16;


		errs += run_test(&args, RES[i], RESLEN[i], MAC_FG);
		(void) fprintf(stderr, "----------\n");
	}

	if (errs != 0) {
		(void) fprintf(stderr, "%d tests failed\n", errs);
		return (1);
	}

	return (0);
}
