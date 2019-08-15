/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License (), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <stdio.h>
#include <sys/types.h>
#include "cryptotest.h"

extern size_t msgcount;
extern uint8_t *MSG[];
extern size_t MSGLEN[];
extern uint8_t *MD[];
extern size_t mdlen;
extern char *mechname;

static size_t updatelens[] = {
	1, 8, 33, 67, CTEST_UPDATELEN_WHOLE, CTEST_UPDATELEN_END
};

int
main(void)
{
	int i, errs = 0;
	uint8_t N[1024];
	cryptotest_t args = {
		.out = N,
		.outlen = sizeof (N),
		.mechname = mechname,
		.updatelens = updatelens
	};

	for (i = 0; i < msgcount; i++) {
		args.in = MSG[i];
		args.inlen = MSGLEN[i];

		errs += run_test(&args, MD[i], mdlen, DIGEST_FG);
	}

	if (errs != 0)
		(void) fprintf(stderr, "%d tests failed\n", errs);

	return (errs);
}
