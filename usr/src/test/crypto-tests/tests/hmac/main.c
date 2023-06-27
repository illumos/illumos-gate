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
 * Copyright 2023 RackTop Systems, Inc.
 */

#include <stdio.h>
#include <strings.h>

#include "cryptotest.h"

/*
 * These are all supplied by the specific test.  See;
 * hmac_sha1.c hmac_sha1_gen.c ...
 */
extern char *mechname;
extern uint8_t *KEY[];
extern size_t KEYLEN[];
extern uint8_t *DATA[];
extern size_t DATALEN[];
extern uint8_t *HMAC[];
extern size_t hmac_len;
extern size_t msgcount;

static size_t updatelens[] = {
	1, 8, 33, 67, CTEST_UPDATELEN_WHOLE, CTEST_UPDATELEN_END
};

int
main(void)
{
	int errs = 0;
	int i;
	ulong_t param_len = hmac_len;
	uint8_t N[1024];
	cryptotest_t args = {
		.out = N,
		.outlen = sizeof (N),
		.plen = 0,
		.mechname = mechname,
		.updatelens = updatelens
	};

	/*
	 * When running eg. SUN_CKM_SHA1_HMAC_GENERAL
	 * we need to provide a parameter that speifies
	 * the length of the hash result, which may be
	 * shorter than what the mech. can compute.
	 */
	if (strstr(mechname, "GENERAL") != NULL) {
		args.param = &param_len;
		args.plen = sizeof (param_len);
	}
	for (i = 0; i < msgcount; i++) {
		args.key = KEY[i];
		args.keylen = KEYLEN[i];

		args.in = DATA[i];
		args.inlen = DATALEN[i];

		errs += run_test(&args, HMAC[i], hmac_len, MAC_FG);
		(void) fprintf(stderr, "----------\n");
	}
	if (errs != 0)
		(void) fprintf(stderr, "%d tests failed\n", errs);

	return (errs);
}
