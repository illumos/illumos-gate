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
 * NIST tests for 3DES certification.
 *
 * Using the values for td[], encrypts plain text using the provided
 * key and verifies the result against the cipher value. Then decrypts
 * the cipher and compares the result against the plain value.
 *
 * Also, gk[] and bk[] are used to test the 3DES keycheck algorithm.
 * Each key in gk[] should pass the keycheck and every key in bk[] should
 * fail the keycheck.
 */

#include <stdio.h>
#include <strings.h>

#include "des3.h"
#include "des.h"
#include "des3_test.h"
#include "cmn_test.h"

typedef struct test_data {
	char key[DES_KEY_SIZE * 2];
	char plain[DES3_BLOCK_SIZE * 2];
	char cipher[DES3_BLOCK_SIZE * 2];
} test_data_t;

static test_data_t td[] = {
	{ "0000000000000000", "0000000000000000", "8CA64DE9C1B123A7" },
	{ "FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "7359B2163E4EDC58" },
	{ "3000000000000000", "1000000000000001", "958E6E627A05557B" },
	{ "1111111111111111", "1111111111111111", "F40379AB9E0EC533" },
	{ "0123456789ABCDEF", "1111111111111111", "17668DFC7292532D" },
	{ "1111111111111111", "0123456789ABCDEF", "8A5AE1F81AB8F2DD" },
	{ "0000000000000000", "0000000000000000", "8CA64DE9C1B123A7" },
	{ "FEDCBA9876543210", "0123456789ABCDEF", "ED39D950FA74BCC4" },
	{ "7CA110454A1A6E57", "01A1D6D039776742", "690F5B0D9A26939B" },
	{ "0131D9619DC1376E", "5CD54CA83DEF57DA", "7A389D10354BD271" },
	{ "07A1133E4A0B2686", "0248D43806F67172", "868EBB51CAB4599A" },
	{ "3849674C2602319E", "51454B582DDF440A", "7178876E01F19B2A" },
	{ "04B915BA43FEB5B6", "42FD443059577FA2", "AF37FB421F8C4095" },
	{ "0113B970FD34F2CE", "059B5E0851CF143A", "86A560F10EC6D85B" },
	{ "0170F175468FB5E6", "0756D8E0774761D2", "0CD3DA020021DC09" },
	{ "43297FAD38E373FE", "762514B829BF486A", "EA676B2CB7DB2B7A" },
	{ "07A7137045DA2A16", "3BDD119049372802", "DFD64A815CAF1A0F" },
	{ "04689104C2FD3B2F", "26955F6835AF609A", "5C513C9C4886C088" },
	{ "37D06BB516CB7546", "164D5E404F275232", "0A2AEEAE3FF4AB77" },
	{ "1F08260D1AC2465E", "6B056E18759F5CCA", "EF1BF03E5DFA575A" },
	{ "584023641ABA6176", "004BD6EF09176062", "88BF0DB6D70DEE56" },
	{ "025816164629B007", "480D39006EE762F2", "A1F9915541020B56" },
	{ "49793EBC79B3258F", "437540C8698F3CFA", "6FBF1CAFCFFD0556" },
	{ "4FB05E1515AB73A7", "072D43A077075292", "2F22E49BAB7CA1AC" },
	{ "49E95D6D4CA229BF", "02FE55778117F12A", "5A6B612CC26CCE4A" },
	{ "018310DC409B26D6", "1D9D5C5018F728C2", "5F4C038ED12B2E41" },
	{ "1C587F1C13924FEF", "305532286D6F295A", "63FAC0D034D9F793" },
	{ "0101010101010101", "0123456789ABCDEF", "617B3A0CE8F07100" },
	{ "1F1F1F1F0E0E0E0E", "0123456789ABCDEF", "DB958605F8C8C606" },
	{ "E0FEE0FEF1FEF1FE", "0123456789ABCDEF", "EDBFD1C66C29CCC7" },
	{ "0000000000000000", "FFFFFFFFFFFFFFFF", "355550B2150E2451" },
	{ "FFFFFFFFFFFFFFFF", "0000000000000000", "CAAAAF4DEAF1DBAE" },
	{ "0123456789ABCDEF", "0000000000000000", "D5D44FF720683D0D" },
	{ "FEDCBA9876543210", "FFFFFFFFFFFFFFFF", "2A2BB008DF97C2F2" }
};

typedef struct test_keys {
	char key1[DES_KEY_SIZE * 2];
	char key2[DES_KEY_SIZE * 2];
	char key3[DES_KEY_SIZE * 2];
} test_keys_t;

static test_keys_t gk[] = {
	{ "A0CB0D98FE752301", "105237EFCBA00DFE", "8CA64DE9C1B123A7" }
};

static test_keys_t bk[] = {
	{ "A0CB0D98FE752301", "A0CB0D98FE752301", "8CA64DE9C1B123A7" },
	{ "FFFFFFFFFFFFFFFF", "0101010101010101", "E0E0E0E0F1F1F1F1" }
};

int
des3test(void)
{
	void *d3h;

	unsigned char key[DES3_KEY_SIZE];
	unsigned char plain[DES3_BLOCK_SIZE];
	unsigned char cipher[DES3_BLOCK_SIZE];
	unsigned char work[DES3_BLOCK_SIZE];

	int fail;
	int num;
	int i;

	if (des3_init(&d3h) != 0) {
		(void) printf("Error initializing DES3\n");
		return (-1);
	}

	num = sizeof (td) / sizeof (test_data_t);
	for (i = 0; i < num; i++) {
		fail = 0;

		(void) printf("NIST Test #%d ", i+1);
		getxdata(key, td[i].key, DES_KEY_SIZE);
		bcopy(key, &key[8], DES_KEY_SIZE); /* K1=K2=K3 for test */
		bcopy(key, &key[16], DES_KEY_SIZE);
		des3_key(d3h, key);

		getxdata(plain, td[i].plain, DES3_BLOCK_SIZE);

		getxdata(cipher, td[i].cipher, DES3_BLOCK_SIZE);

		bcopy(plain, work, DES3_BLOCK_SIZE);
		des3_encrypt(d3h, work);

		if (bcmp(work, cipher, DES3_BLOCK_SIZE) != 0) {
			(void) printf("FAILED [Encrypt]");
			(void) printf(" c: ");
			putxdata(work, DES3_BLOCK_SIZE);
			fail++;
		}
		des3_decrypt(d3h, work);
		if (bcmp(work, plain, DES3_BLOCK_SIZE) != 0) {
			(void) printf("FAILED [Decrypt]");
			(void) printf(" p: ");
			putxdata(work, DES3_BLOCK_SIZE);
			fail++;
		}
		if (fail == 0)
			(void) printf("PASSED");
		(void) printf("\n");
	}

	des3_fini(d3h);

	return (fail);
}

int
des3_keytest(void)
{
	unsigned char key[DES_KEY_SIZE * 3];
	int num;
	int testnum = 0;
	int fail = 0;
	int i;

	num = sizeof (gk) / sizeof (test_keys_t);
	for (i = 0; i < num; i++) {
		getxdata(key, gk[i].key1, DES_KEY_SIZE);
		getxdata(&key[8], gk[i].key2, DES_KEY_SIZE);
		getxdata(&key[16], gk[i].key3, DES_KEY_SIZE);
		(void) printf("Keycheck Test #%d ", testnum);
		if (des3_keycheck(key)) {
			(void) printf("PASSED\n", testnum);
		} else {
			fail++;
			(void) printf("FAILED\n", testnum);
		}
		testnum++;
	}

	num = sizeof (bk) / sizeof (test_keys_t);
	for (i = 0; i < num; i++) {
		getxdata(key, bk[i].key1, DES_KEY_SIZE);
		getxdata(&key[8], bk[i].key2, DES_KEY_SIZE);
		getxdata(&key[16], bk[i].key3, DES_KEY_SIZE);
		(void) printf("Keycheck Test #%d ", testnum);
		if (!des3_keycheck(key)) {
			(void) printf("PASSED\n", testnum);
		} else {
			fail++;
			(void) printf("FAILED\n", testnum);
		}
		testnum++;
	}

	return (fail);
}
