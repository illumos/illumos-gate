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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <security/cryptoki.h>
#include "pkcs11Global.h"
#include "pkcs11Session.h"
#include "pkcs11Slot.h"

/*
 * C_SeedRandom will verify that the session handle is valid within
 * the framework, that random numbers are not disabled for the slot
 * associated with this session, and then redirect to the underlying
 * provider.
 */
CK_RV
C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;
	CK_SLOT_ID slotid;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		/* Check if random number functions are allowed */
		if (policyfastpath &&
		    slottable->st_slots[fast_slot]->sl_norandom) {
			return (CKR_FUNCTION_FAILED);
		}
		return (fast_funcs->C_SeedRandom(hSession, pSeed, ulSeedLen));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	slotid = sessp->se_slotid;

	/* Check if random number functions are allowed */
	if (slottable->st_slots[slotid]->sl_norandom)
		return (CKR_FUNCTION_FAILED);

	/* Pass data to the provider */
	rv = FUNCLIST(slotid)->C_SeedRandom(sessp->se_handle, pSeed,
	    ulSeedLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_GenerateRandom will verify that the session handle is valid within
 * the framework, that random numbers are not disabled for the slot
 * associated with this session, and then redirect to the underlying
 * provider.
 */
CK_RV
C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData,
    CK_ULONG ulRandomLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;
	CK_SLOT_ID slotid;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		/* Check if random number functions are allowed */
		if (policyfastpath &&
		    slottable->st_slots[fast_slot]->sl_norandom) {
			return (CKR_FUNCTION_FAILED);
		}
		return (fast_funcs->C_GenerateRandom(hSession, pRandomData,
			    ulRandomLen));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	slotid = sessp->se_slotid;

	/* Check if random number functions are allowed */
	if (slottable->st_slots[slotid]->sl_norandom)
		return (CKR_FUNCTION_FAILED);

	/* Pass data to the provider */
	rv = FUNCLIST(sessp->se_slotid)->C_GenerateRandom(sessp->se_handle,
	    pRandomData, ulRandomLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}
