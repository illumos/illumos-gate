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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/sha1.h>
#include <sys/crypto/common.h>
#include <sys/cmn_err.h>
#ifndef _KERNEL
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <security/cryptoki.h>
#include <cryptoutil.h>
#include "softMAC.h"
#endif
#include <rng/fips_random.h>


int
fips_rng_post(void)
{
	static uint8_t XKeyValue[] = {
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00
	};

	static uint8_t XSeed[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00
	};

	static uint8_t rng_known_GENX[] = {
		0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
		0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
		0xaf, 0xd8, 0x07, 0x09
	};

	uint8_t GENX[SHA1_HASH_SIZE];
	uint8_t XKey[SHA1_HASH_SIZE];

	(void) memcpy(XKey, XKeyValue, SHA1_HASH_SIZE);

	/* Generate X with a known seed. */
	fips_random_inner(
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)
	    XKey,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)
	    GENX,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)
	    XSeed);

	/* Verify GENX to perform the RNG integrity check */
	if ((memcmp(GENX, rng_known_GENX, (SHA1_HASH_SIZE)) != 0))
		return (CKR_DEVICE_ERROR);
	else
		return (CKR_OK);
}
