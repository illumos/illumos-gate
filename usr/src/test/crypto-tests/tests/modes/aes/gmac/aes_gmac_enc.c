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
 * Verify correct hash computations using the ENCR function group.
 * See ENCR_FG in cryptotest.h, cryptotest_mac_fg in testfuncs.c
 * (and a DECR_FG test case)
 *
 * CKM_AES_GMAC supports both MAC and encrypt/decrypt functions.
 * This is similar to aes_gmac.c with ENCR_FG in place of MAC_FG
 * to tests AES_GMAC with C_EncryptInit, C_Encrypt, etc.
 */

#include <aes/aes_impl.h>
#include <strings.h>
#include <stdio.h>
#include "cryptotest.h"
#include "aes_gmac.h"

/*
 * Size of param (in 8-byte chunks for alignment) large enough for both
 * CK_GCM_PARAMS and CK_AES_GMAC_PARAMS.
 */
#define	PARAM_SIZE_64 8

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
	int i, j;
	uint8_t N[1024];
	uint64_t param[PARAM_SIZE_64];

	cryptotest_t args = {
		.out = N,
		.outlen = sizeof (N),
		.mechname = SUN_CKM_AES_GMAC,
		.updatelens = updatelens
	};

	(void) fprintf(stderr, "\t\t\t=== encrypt ===\n----------\n\n");

	(void) fprintf(stderr, "\t\t\t=== all input ===\n----------\n\n");
	for (i = 0; i < ndata; i++) {
		args.in = DATA[i];
		args.key = KEY[i];

		args.inlen = DATALEN[i];
		args.keylen = KEYLEN[i];

		bzero(param, sizeof (param));
		args.param = param;
		args.plen = gmac_param_len();
		gmac_init_params(param, IV[i], NULL, 0);

		errs += run_test(&args, RES[i], RESLEN[i], ENCR_FG);
		(void) fprintf(stderr, "----------\n");
	}

	(void) fprintf(stderr, "\t\t\t=== all AAD ===\n----------\n\n");
	if (cryptotest_pkcs) {
		/* PKCS does not support passing AAD */
		(void) fprintf(stderr, "(skip on PKCS)\n");
		j = 0;
	} else {
		j = ndata;
	}
	for (i = 0; i < j; i++) {
		args.in = NULL;
		args.key = KEY[i];

		args.inlen = 0;
		args.keylen = KEYLEN[i];

		bzero(param, sizeof (param));
		args.param = param;
		args.plen = gmac_param_len();
		gmac_init_params(param, IV[i], DATA[i], DATALEN[i]);

		errs += run_test(&args, RES[i], RESLEN[i], ENCR_FG);
		(void) fprintf(stderr, "----------\n");
	}

	(void) fprintf(stderr, "\t\t\t=== half AAD ===\n----------\n\n");
	if (cryptotest_pkcs) {
		(void) fprintf(stderr, "(skip on PKCS)\n");
		j = 0;
	} else {
		j = ndata;
	}
	for (i = 0; i < j; i++) {
		args.in = &DATA[i][DATALEN[i] / 2];
		args.key = KEY[i];

		args.inlen = DATALEN[i] - DATALEN[i] / 2;
		args.keylen = KEYLEN[i];

		bzero(param, sizeof (param));
		args.param = param;
		args.plen = gmac_param_len();
		gmac_init_params(param, IV[i], DATA[i], DATALEN[i] / 2);

		errs += run_test(&args, RES[i], RESLEN[i], ENCR_FG);
		(void) fprintf(stderr, "----------\n");
	}

	(void) fprintf(stderr, "\t\t\t=== 16-byte AAD ===\n----------\n\n");
	if (cryptotest_pkcs) {
		(void) fprintf(stderr, "(skip on PKCS)\n");
		j = 0;
	} else {
		j = ndata;
	}
	for (i = 0; i < j; i++) {
		if (DATALEN[i] <= 16) {
			(void) fprintf(stderr, "len < 16; skip\n----------\n");
			continue;
		}

		args.in = &DATA[i][16];
		args.key = KEY[i];

		args.inlen = DATALEN[i] - 16;
		args.keylen = KEYLEN[i];

		bzero(param, sizeof (param));
		args.param = param;
		args.plen = gmac_param_len();
		gmac_init_params(param, IV[i], DATA[i], 16);

		errs += run_test(&args, RES[i], RESLEN[i], ENCR_FG);
		(void) fprintf(stderr, "----------\n");
	}

	(void) fprintf(stderr, "\t\t\t=== decrypt ===\n----------\n\n");

	if (cryptotest_pkcs) {
		(void) fprintf(stderr, "(skip on PKCS)\n");
		j = 0;
	} else {
		j = ndata;
	}
	for (i = 0; i < j; i++) {
		args.in = RES[i];
		args.key = KEY[i];

		args.inlen = RESLEN[i];
		args.keylen = KEYLEN[i];

		bzero(param, sizeof (param));
		args.param = param;
		args.plen = gmac_param_len();
		gmac_init_params(param, IV[i], DATA[i], DATALEN[i]);

		errs += run_test(&args, NULL, 0, DECR_FG);
		(void) fprintf(stderr, "----------\n");
	}

	if (errs != 0) {
		(void) fprintf(stderr, "%d tests failed\n", errs);
		return (1);
	}
	(void) fprintf(stderr, "all tests pass\n");

	return (0);
}
