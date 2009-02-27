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

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include <cryptoutil.h>
#include "softGlobal.h"
#include "softRandom.h"
#include "softSession.h"

CK_RV
C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{

	CK_RV	rv;
	soft_session_t	*session_p;
	boolean_t	lock_held = B_FALSE;
	long		nwrite;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer just for validity check. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	SES_REFRELE(session_p, lock_held);

	if ((pSeed == NULL) || (ulSeedLen == 0)) {
		return (CKR_ARGUMENTS_BAD);
	}

	if (soft_urandom_seed_fd < 0) {
		(void) pthread_mutex_lock(&soft_giant_mutex);
		/* Check again holding the mutex */
		if (soft_urandom_seed_fd < 0) {
			soft_urandom_seed_fd = open_nointr(DEV_URANDOM,
			    O_WRONLY);
			if (soft_urandom_seed_fd < 0) {
				(void) pthread_mutex_unlock(&soft_giant_mutex);
				if (errno == EACCES)
					return (CKR_RANDOM_SEED_NOT_SUPPORTED);
				return (CKR_DEVICE_ERROR);
			}
		}
		(void) pthread_mutex_unlock(&soft_giant_mutex);
	}

	nwrite = writen_nointr(soft_urandom_seed_fd, pSeed, ulSeedLen);
	if (nwrite <= 0) {
		return (CKR_DEVICE_ERROR);
	}

	return (CKR_OK);

}

CK_RV
C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData,
    CK_ULONG ulRandomLen)
{

	CK_RV	rv;
	soft_session_t	*session_p;
	boolean_t	lock_held = B_FALSE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Obtain the session pointer just for validity check. */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	SES_REFRELE(session_p, lock_held);

	if ((pRandomData == NULL) || (ulRandomLen == 0)) {
		return (CKR_ARGUMENTS_BAD);
	}

	return (soft_random_generator(pRandomData, ulRandomLen, B_FALSE));

}
