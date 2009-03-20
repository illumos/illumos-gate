/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include <bignum.h>
#include <cryptoutil.h>
#include "softGlobal.h"
#include "softRandom.h"
#include "softCrypt.h"

CK_RV
soft_random_generator(CK_BYTE *ran_out, CK_ULONG ran_len, boolean_t token)
{
	/*
	 * When random-number generator is called by asymmetric token
	 * (persistent) key generation, use /dev/random. Otherwise,
	 * use /dev/urandom.
	 */
	if (token) {
		if (pkcs11_get_random(ran_out, ran_len) < 0)
			return (CKR_DEVICE_ERROR);
	} else {
		if (pkcs11_get_urandom(ran_out, ran_len) < 0)
			return (CKR_DEVICE_ERROR);
	}
	return (CKR_OK);
}


/*
 * Generate random number in BIGNUM format. length is in bits
 */
BIG_ERR_CODE
random_bignum(BIGNUM *r, int length, boolean_t token_obj)
{
	size_t len1;
	CK_RV rv = CKR_OK;

	/* Convert length of bits to length of word to hold valid data. */
	r->len = (length-1) / BIG_CHUNK_SIZE + 1;

	/* len1 is the byte count. */
	len1 = r->len * sizeof (BIG_CHUNK_TYPE);

	/* Generate len1 bytes of data and store in memory pointed by value. */
	rv = soft_random_generator((CK_BYTE *)(r->value), len1, token_obj);

	if (rv != CKR_OK) {
		return (convert_brv(rv));
	}

	r->value[r->len - 1] |= BIG_CHUNK_HIGHBIT;

	/*
	 * If the bit length is not on word boundary, shift the existing
	 * bits in last word to right adjusted.
	 */
	if ((length % BIG_CHUNK_SIZE) != 0)
		r->value[r->len - 1] =
		    r->value[r->len - 1] >>
		    (BIG_CHUNK_SIZE - (length % BIG_CHUNK_SIZE));
	r->sign = 1;

	return (BIG_OK);
}
