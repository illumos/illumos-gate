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

/*
 * Random Number Generation Functions
 * (as defined in PKCS#11 spec section 11.15)
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "metaGlobal.h"

/*
 * meta_SeedRandom
 *
 * Unlike most other metaslot functions, meta_SeedRandom does not distribute
 * the call to a specific provider. Rather, we assume that the /dev/urandom
 * implementation is a kCF consumer, and is pulling randomness from everywhere
 * it can. Thus, by seeding /dev/urandom we let kCF potentially do all the
 * work.
 *
 * NOTES:
 * 1) /dev/urandom vs. /dev/random... Unfortunately P11 does not allow app
 *    to request a "quality", so we'll just assume urandom is good enough.
 *    Concerned apps can pull hardcore randomness from specific places they
 *    trust (eg by checking for CKF_HW?)..
 *
 */
CK_RV
meta_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
    CK_ULONG ulSeedLen)
{
	CK_RV rv;
	meta_session_t *session;

	if (pSeed == NULL || ulSeedLen == 0)
		return (CKR_ARGUMENTS_BAD);

	/* Just check handle for validity, we don't need it for anything. */
	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);
	REFRELEASE(session);

	if (pkcs11_seed_urandom(pSeed, ulSeedLen) < 0) {
		if (errno == EACCES)
			return (CKR_RANDOM_SEED_NOT_SUPPORTED);
		return (CKR_DEVICE_ERROR);
	}
	return (CKR_OK);
}

/*
 * meta_GenerateRandom
 *
 * Unlike most other metaslot functions, meta_GenerateRandom does not distribute
 * the call to a specific provider. Rather, we assume that the /dev/urandom
 * implementation is a kCF consumer, and is pulling randomness from everywhere
 * it can. Thus, by reading /dev/urandom we let kCF potentially do all the
 * work.
 *
 */
CK_RV
meta_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData,
    CK_ULONG ulRandomLen)
{
	CK_RV rv;
	meta_session_t *session;

	if (pRandomData == NULL || ulRandomLen < 1)
		return (CKR_ARGUMENTS_BAD);

	/* Just check handle for validity, we don't need it for anything. */
	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);
	REFRELEASE(session);

	if (pkcs11_get_urandom(pRandomData, ulRandomLen) < 0) {
		return (CKR_DEVICE_ERROR);
	}
	return (CKR_OK);
}
