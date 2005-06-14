/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  sha1_test.c
 *
 *  Description:
 *      This file will exercise the SHA-1 code performing the three
 *      tests documented in FIPS PUB 180-1 plus one which calls
 *      SHA1Input with an exact multiple of 512 bits, plus a few
 *      error test checks.
 *
 *  Portability Issues:
 *      None.
 *
 */

#include <stdio.h>
#include <strings.h>

#include <sys/sha1.h>
#include "sha1_test.h"
#include "cmn_test.h"

/*
 *  Define patterns for testing
 */
#define	TEST1	"abc"
#define	TEST2a	"abcdbcdecdefdefgefghfghighijhi"
#define	TEST2b	"jkijkljklmklmnlmnomnopnopq"
#define	TEST2	TEST2a TEST2b
#define	TEST3	"a"
#define	TEST4a	"01234567012345670123456701234567"
#define	TEST4b	"01234567012345670123456701234567"

/* an exact multiple of 512 bits */
#define	TEST4	TEST4a TEST4b

static char *testarray[4] = {
	TEST1,
	TEST2,
	TEST3,
	TEST4
};

static int repeatcount[4] = { 1, 1, 1000000, 10 };

static char *resultarray[4] = {
	"A9993E364706816ABA3E25717850C26C9CD0D89D",
	"84983E441C3BD26EBAAE4AA1F95129E5E54670F1",
	"34AA973CD4C4DAA4F61EEB2BDBAD27316534016F",
	"DEA356A2CDDD90C7A7ECEDC5EBB563934F460452"
};

int
sha1test(void)
{
	SHA1_CTX sha;
	int fail;
	int i;
	int j;
	uint8_t digest[20];
	uint8_t rdigest[20];

	/*
	 * Perform SHA-1 tests
	 */
	for (j = 0; j < 4; ++j) {
		fail = 0;
		(void) printf("Test #%d ", j+1);

		SHA1Init(&sha);

		for (i = 0; i < repeatcount[j]; ++i) {
			SHA1Update(&sha, (unsigned char *)testarray[j],
			    strlen(testarray[j]));
		}

		SHA1Final(digest, &sha);

		getxdata(rdigest, resultarray[j], 20);
		if (bcmp(digest, rdigest, 20) != 0) {
			(void) printf("FAILED\n");
			fail++;
		} else {
			(void) printf("PASSED\n");
		}
	}

	return (fail);
}
