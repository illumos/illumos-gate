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
 * AES tests as defined by FIPS 197.
 *
 * Encrypts plain text with the defined key and verifies that the result
 * is the expected cipher. Then decrypts the cipher and verifies that the
 * result is the original plain text. One test is run for each AES128,
 * AES192 and AES256.
 */

#include <stdio.h>
#include <strings.h>

#include "aes.h"
#include "cmn_test.h"
#include "aes_test.h"

typedef struct test_data {
	char key[AES_256_KEY_SIZE * 2];
	char plain[AES_BLOCK_SIZE * 2];
	char cipher[AES_BLOCK_SIZE * 2];
	uint32_t keysize;
} test_data_t;

static test_data_t td[] = {
	{ "000102030405060708090a0b0c0d0e0f",
	    "00112233445566778899aabbccddeeff",
	    "69c4e0d86a7b0430d8cdb78070b4c55a", AES_128_KEY_SIZE },
	{ "000102030405060708090a0b0c0d0e0f1011121314151617",
	    "00112233445566778899aabbccddeeff",
	    "dda97ca4864cdfe06eaf70a0ec0d7191", AES_192_KEY_SIZE },
	{ "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	    "00112233445566778899aabbccddeeff",
	    "8ea2b7ca516745bfeafc49904b496089", AES_256_KEY_SIZE }
};

int
aestest(void)
{
	void *ah;

	unsigned char key[AES_256_KEY_SIZE];
	unsigned char plain[AES_BLOCK_SIZE];
	unsigned char cipher[AES_BLOCK_SIZE];
	unsigned char work[AES_BLOCK_SIZE];

	int fail;
	int num;
	int i;

	if (aes_init(&ah) != 0) {
		(void) printf("Error initializing AES\n");
		return (-1);
	}

	num = sizeof (td) / sizeof (test_data_t);
	for (i = 0; i < num; i++) {
		fail = 0;

		(void) printf("Test #%d [AES%d] ", i, td[i].keysize * 8);
		getxdata(key, td[i].key, td[i].keysize);
		aes_key(ah, key, td[i].keysize);

		getxdata(plain, td[i].plain, AES_BLOCK_SIZE);

		getxdata(cipher, td[i].cipher, AES_BLOCK_SIZE);

		bcopy(plain, work, AES_BLOCK_SIZE);
		aes_encrypt(ah, work);

		if (bcmp(work, cipher, AES_BLOCK_SIZE) != 0) {
			(void) printf("FAILED [Encrypt]");
			fail++;
		}
		aes_decrypt(ah, work);
		if (bcmp(work, plain, AES_BLOCK_SIZE) != 0) {
			(void) printf("FAILED [Decrypt]");
			fail++;
		}
		if (fail == 0)
			(void) printf("PASSED");
		(void) printf("\n");
	}

	aes_fini(ah);

	return (fail);
}
