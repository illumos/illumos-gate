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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include "softGlobal.h"
#include "softRandom.h"
#include "softCrypt.h"

CK_RV
soft_random_generator(CK_BYTE *ran_out, CK_ULONG ran_len, boolean_t token)
{

	long	nread;

	/*
	 * When random-number generator is called by asymmetric token
	 * (persistent) key generation, use /dev/random. Otherwise,
	 * use /dev/urandom.
	 */
	if (token) {
		if (soft_random_fd < 0) {
			(void) pthread_mutex_lock(&soft_giant_mutex);
			/* Check again holding the mutex */
			if (soft_random_fd < 0) {
				while ((soft_random_fd = open(DEV_RANDOM,
				    O_RDONLY)) < 0) {
					if (errno != EINTR)
						break;
				}
				if (soft_random_fd < 0) {
					(void) pthread_mutex_unlock(
					    &soft_giant_mutex);
					return (CKR_DEVICE_ERROR);
				}
				(void) fcntl(soft_random_fd, F_SETFD,
				    FD_CLOEXEC);
			}
			(void) pthread_mutex_unlock(&soft_giant_mutex);
		}
	} else {
		if (soft_urandom_fd < 0) {
			(void) pthread_mutex_lock(&soft_giant_mutex);
			/* Check again holding the mutex */
			if (soft_urandom_fd < 0) {
				while ((soft_urandom_fd = open(DEV_URANDOM,
				    O_RDONLY)) < 0) {
					if (errno != EINTR)
						break;
				}
				if (soft_urandom_fd < 0) {
					(void) pthread_mutex_unlock(
					    &soft_giant_mutex);
					return (CKR_DEVICE_ERROR);
				}
				(void) fcntl(soft_urandom_fd, F_SETFD,
				    FD_CLOEXEC);
			}
			(void) pthread_mutex_unlock(&soft_giant_mutex);
		}
	}

	if (token)
		nread = looping_read(soft_random_fd, ran_out, ran_len);
	else
		nread = looping_read(soft_urandom_fd, ran_out, ran_len);

	if (nread <= 0) {
		return (CKR_DEVICE_ERROR);
	}
	return (CKR_OK);

}


/*
 * This function guarantees to return non-zero random numbers.
 */
CK_RV
soft_nzero_random_generator(CK_BYTE *ran_out, CK_ULONG ran_len)
{

	CK_RV rv = CKR_OK;
	size_t ebc = 0; /* count of extra bytes in extrarand */
	size_t i = 0;
	char extrarand[32];
	size_t extrarand_len;

	/*
	 * soft_random_generator() may return zeros.
	 */
	if ((rv = soft_random_generator(ran_out, ran_len, B_FALSE)) != CKR_OK) {
		return (rv);
	}

	/*
	 * Walk through the returned random numbers pointed by ran_out,
	 * and look for any random number which is zero.
	 * If we find zero, call soft_random_generator() to generate
	 * another 32 random numbers pool. Replace any zeros in ran_out[]
	 * from the random number in pool.
	 */
	while (i < ran_len) {
		if (((char *)ran_out)[i] != 0) {
			i++;
			continue;
		}

		if (ebc == 0) {
			/* refresh extrarand */
			extrarand_len = sizeof (extrarand);
			if ((rv = soft_random_generator((CK_BYTE *)extrarand,
			    extrarand_len, B_FALSE)) != CKR_OK) {
				return (rv);
			}

			ebc = extrarand_len;
		}
		-- ebc;

		/*
		 * The new random byte zero/non-zero will be checked in
		 * the next pass through the loop.
		 */
		((char *)ran_out)[i] = extrarand[ebc];
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
