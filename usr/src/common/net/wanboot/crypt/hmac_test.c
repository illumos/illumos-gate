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
 * HMAC SHA-1 test cases as defined by RFC 2202.
 *
 * The test uses predefined keys, data and digests. The data and keys
 * are used by the HMAC SHA-1 implemention to produce a hash digest and
 * the the result is compared against the expected digest.
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "hmac_sha1.h"
#include "hmac_test.h"
#include "cmn_test.h"

typedef struct test_data {
	unsigned char key[80];
	int keylen;
	unsigned char data[80];
	int datalen;
	unsigned char digest[20];
} test_data_t;

int
hmactest(void)
{
	test_data_t td[7];
	SHA1_CTX sha;
	uchar_t digest[20];
	int fail;
	int num;
	int i;

	td[0].keylen = 20;
	getxdata(td[0].key, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
	    td[0].keylen);
	td[0].datalen = 8;
	(void) strcpy((char *)td[0].data, "Hi There");
	getxdata(td[0].digest, "b617318655057264e28bc0b6fb378c8ef146be00", 20);

	td[1].keylen = 4;
	(void) strcpy((char *)td[1].key, "Jefe");
	td[1].datalen =  28;
	(void) strcpy((char *)td[1].data, "what do ya want for nothing?");
	getxdata(td[1].digest, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", 20);

	td[2].keylen = 20;
	getxdata(td[2].key, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	    td[2].keylen);
	td[2].datalen = 50;
	getxdata(td[2].data, "ddddddddddddddddddddddddddddddddddddddddddddd"
	    "ddddddddddddddddddddddddddddddddddddddddddddddddddddddd", 50);
	getxdata(td[2].digest, "125d7342b9ac11cd91a39af48aa17b4f63f175d3", 20);

	td[3].keylen = 25;
	getxdata(td[3].key, "0102030405060708090a0b0c0d0e0f1011121314151617"
	    "1819", td[3].keylen);
	td[3].datalen = 50;
	getxdata(td[3].data, "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	    "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
	    td[3].datalen);
	getxdata(td[3].digest, "4c9007f4026250c6bc8414f9bf50c86c2d7235da", 20);

	td[4].keylen = 20;
	getxdata(td[4].key, "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
	    td[4].keylen);
	td[4].datalen = 20;
	(void) strcpy((char *)td[4].data, "Test With Truncation");
	getxdata(td[4].digest, "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04", 20);

	td[5].keylen = 80;
	getxdata(td[5].key, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	    td[5].keylen);
	td[5].datalen = 54;
	(void) strcpy((char *)td[5].data,
	    "Test Using Larger Than Block-Size Key - Hash Key First");
	getxdata(td[5].digest, "aa4ae5e15272d00e95705637ce8a3b55ed402112", 20);

	td[6].keylen = 80;
	getxdata(td[6].key, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	    td[6].keylen);
	td[6].datalen = 73;
	(void) strcpy((char *)td[6].data,
	    "Test Using Larger Than Block-Size Key and Larger Than One "
	    "Block-Size Data");
	getxdata(td[6].digest, "e8e99d0f45237d786d6bbaa7965c7808bbff1a91", 20);

	num = sizeof (td) / sizeof (test_data_t);
	for (i = 0; i < num; i++) {
		fail = 0;

		(void) printf("Test #%d ", i);
		HMACInit(&sha, td[i].key, td[i].keylen);
		HMACUpdate(&sha, td[i].data, td[i].datalen);
		HMACFinal(&sha, td[i].key, td[i].keylen, digest);

		if (bcmp(digest, td[i].digest, 20) != 0) {
			(void) printf("FAILED\n");
			fail++;
		} else {
			(void) printf("PASSED\n");
		}
	}
	return (fail);
}
