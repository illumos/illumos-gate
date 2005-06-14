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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "kernelGlobal.h"
#include <errno.h>
#include <security/cryptoki.h>
#include <sys/crypto/common.h>
#include <sys/crypto/ioctl.h>

CK_RV
C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	kernel_session_t *session_p;
	crypto_seed_random_t seed_random;
	boolean_t ses_lock_held = B_FALSE;
	CK_RV rv;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if ((pSeed == NULL) || (ulSeedLen == 0)) {
		REFRELE(session_p, ses_lock_held);
		return (CKR_ARGUMENTS_BAD);
	}

	seed_random.sr_session = session_p->k_session;
	seed_random.sr_seedbuf = (caddr_t)pSeed;
	seed_random.sr_seedlen = ulSeedLen;

	while ((r = ioctl(kernel_fd, CRYPTO_SEED_RANDOM, &seed_random)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		if (seed_random.sr_return_value != CRYPTO_SUCCESS) {
			rv = crypto2pkcs11_error_number(
			    seed_random.sr_return_value);
		} else {
			rv = CKR_OK;
		}
	}

	REFRELE(session_p, ses_lock_held);
	return (rv);
}

CK_RV
C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData,
    CK_ULONG ulRandomLen)
{
	kernel_session_t *session_p;
	crypto_generate_random_t generate_random;
	boolean_t ses_lock_held = B_FALSE;
	CK_RV rv;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if ((pRandomData == NULL) || (ulRandomLen == 0)) {
		REFRELE(session_p, ses_lock_held);
		return (CKR_ARGUMENTS_BAD);
	}

	generate_random.gr_session = session_p->k_session;
	generate_random.gr_buf = (caddr_t)pRandomData;
	generate_random.gr_buflen = ulRandomLen;

	while ((r = ioctl(kernel_fd, CRYPTO_GENERATE_RANDOM,
	    &generate_random)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		if (generate_random.gr_return_value != CRYPTO_SUCCESS) {
			rv = crypto2pkcs11_error_number(
			    generate_random.gr_return_value);
		} else {
			rv = CKR_OK;
		}
	}

	REFRELE(session_p, ses_lock_held);
	return (rv);
}
