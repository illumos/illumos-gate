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
 * Copyright 2020 Oxide Computer Company
 */

#include <stdio.h>
#include <sys/types.h>

#include "cryptotest.h"
#include "parser_runner.h"

int
main(void)
{
	int errs = digest_runner(SUN_CKM_MD5, "MD5Msg.rsp", 16);
	if (errs != 0)
		(void) fprintf(stderr, "%d tests failed\n", errs);

	return (errs);
}
