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
 * Assertion based test of the CBC implementation.
 *
 * This test can be used to the CBC implementation using either
 * 3DES, AES128, AES192 or AES256. The test string above is encrypted
 * and then decrypted using one of the algorithms and keys below. The test
 * passes if the decrypted string is the same as the original. Note,
 * that this test should not be used to test the underlying algorithms
 * and relies on the correctness of those algorithms.
 */

#include <stdio.h>
#include <strings.h>

#include "cbc.h"
#include "des3.h"
#include "aes.h"
#include "cbc_test.h"

#define	CBC_MAX_KEY_SIZE	AES_256_KEY_SIZE
#define	CBC_MAX_BLOCK_SIZE	AES_BLOCK_SIZE
#define	CBC_MIN_BLOCK_SIZE	DES3_BLOCK_SIZE
#define	CBC_MAX_IV_SIZE		AES_IV_SIZE

#define	DES3_KEY	"01234567"
#define	AES_128_KEY	"0123456789ABCDEF"
#define	AES_192_KEY	"0123456789ABCDEFHIJKLMNO"
#define	AES_256_KEY	"0123456789ABCDEFHIJKLMNOPQRSTUVW"

#define	TEST_BLOCK_SIZE	(CBC_MAX_BLOCK_SIZE * 2)
#define	TEST_SIZE	(TEST_BLOCK_SIZE * 2)
#define	TEST "This test is successful if this string has a period at the end."

int
cbctest(int type)
{
	unsigned char test_string[TEST_SIZE];
	char iv[CBC_MAX_IV_SIZE];

	cbc_handle_t ch;
	void *eh;
	int ret;
	int i;

	switch (type) {
	case CBC_DES3_TYPE:
		ret = des3_init(&eh);
		break;
	case CBC_AES_128_TYPE:
		ret = aes_init(&eh);
		break;
	case CBC_AES_192_TYPE:
		ret = aes_init(&eh);
		break;
	case CBC_AES_256_TYPE:
		ret = aes_init(&eh);
		break;
	default:
		(void) printf("Illegal encryption type\n");
		return (-1);
	}

	if (ret != 0) {
		(void) printf("Error initializing encryption algorithm\n");
		return (-1);
	}

	bzero(iv, CBC_MAX_IV_SIZE);

	switch (type) {
	case CBC_DES3_TYPE:
		des3_key(eh, (uint8_t *)DES3_KEY);
		cbc_makehandle(&ch, eh, DES3_KEY_SIZE, DES3_BLOCK_SIZE,
		    DES3_IV_SIZE, des3_encrypt, des3_decrypt);
		break;
	case CBC_AES_128_TYPE:
		aes_key(eh, (uint8_t *)AES_128_KEY, AES_128_KEY_SIZE);
		cbc_makehandle(&ch, eh, AES_128_KEY_SIZE, AES_BLOCK_SIZE,
		    AES_IV_SIZE, aes_encrypt, aes_decrypt);
		break;
	case CBC_AES_192_TYPE:
		aes_key(eh, (uint8_t *)AES_192_KEY, AES_192_KEY_SIZE);
		cbc_makehandle(&ch, eh, AES_192_KEY_SIZE, AES_BLOCK_SIZE,
		    AES_IV_SIZE, aes_encrypt, aes_decrypt);
		break;
	case CBC_AES_256_TYPE:
		aes_key(eh, (uint8_t *)AES_256_KEY, AES_256_KEY_SIZE);
		cbc_makehandle(&ch, eh, AES_256_KEY_SIZE, AES_BLOCK_SIZE,
		    AES_IV_SIZE, aes_encrypt, aes_decrypt);
		break;
	default:
		/* Should not happen */
		(void) printf("Illegal encryption type\n");
		return (-1);
	}

	(void) strcpy((char *)test_string, TEST);

	for (i = 0; i < TEST_SIZE; i += TEST_BLOCK_SIZE) {
		(void) cbc_encrypt(&ch, (uint8_t *)&test_string[i],
		    TEST_BLOCK_SIZE, (uint8_t *)iv);
	}

	if (strcmp((char *)test_string, TEST) == 0) {
		(void) printf("FAILED [Encryption]\n");
		goto out;
	}

	bzero(iv, CBC_MAX_IV_SIZE);

	for (i = 0; i < TEST_SIZE; i += TEST_BLOCK_SIZE) {
		(void) cbc_decrypt(&ch, (uint8_t *)&test_string[i],
		    TEST_BLOCK_SIZE, (uint8_t *)iv);
	}

	if (strcmp((char *)test_string, TEST) == 0) {
		(void) printf("PASSED\n");
	} else {
		(void) printf("FAILED [Decryption]\n");
	}

out:
	switch (type) {
	case CBC_DES3_TYPE:
		des3_fini(eh);
		break;
	case CBC_AES_128_TYPE:
	case CBC_AES_192_TYPE:
	case CBC_AES_256_TYPE:
		aes_fini(eh);
		break;
	default:
		/* Should not happen */
		(void) printf("Illegal encryption type\n");
		return (-1);
	}

	return (0);
}
