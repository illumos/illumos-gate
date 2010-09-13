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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Slot and Token Management functions
 * (as defined in PKCS#11 spec section 11.5)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "metaGlobal.h"

extern CK_ULONG num_meta_sessions;
extern CK_ULONG num_rw_meta_sessions;

/*
 * meta_GetSlotList
 *
 * For the metaslot, this is a trivial function. The metaslot module,
 * by defination, provides exactly one slot. The token is always present.
 *
 * This function is actually not called.
 */
/* ARGSUSED */
CK_RV
meta_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
    CK_ULONG_PTR pulCount)
{
	CK_RV rv;

	if (pulCount == NULL)
		return (CKR_ARGUMENTS_BAD);

	if (pSlotList == NULL) {
		*pulCount = 1;
		return (CKR_OK);
	}

	if (*pulCount < 1) {
		rv = CKR_BUFFER_TOO_SMALL;
	} else {
		pSlotList[0] = METASLOT_SLOTID;
		rv = CKR_OK;
	}
	*pulCount = 1;

	return (rv);
}


/*
 * meta_GetSlotInfo
 *
 * Returns basic information about the metaslot.
 *
 * The slotID argument is ignored.
 */
/*ARGSUSED*/
CK_RV
meta_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	CK_SLOT_INFO slotinfo;
	CK_SLOT_ID true_id;
	CK_RV rv;

	if (!metaslot_enabled) {
		return (CKR_SLOT_ID_INVALID);
	}

	if (pInfo == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	/* Provide information about the slot in the provided buffer */
	(void) memcpy(pInfo->slotDescription, METASLOT_SLOT_DESCRIPTION, 64);
	(void) memcpy(pInfo->manufacturerID, METASLOT_MANUFACTURER_ID, 32);
	pInfo->hardwareVersion.major = METASLOT_HARDWARE_VERSION_MAJOR;
	pInfo->hardwareVersion.minor = METASLOT_HARDWARE_VERSION_MINOR;
	pInfo->firmwareVersion.major = METASLOT_FIRMWARE_VERSION_MAJOR;
	pInfo->firmwareVersion.minor = METASLOT_FIRMWARE_VERSION_MINOR;

	/* Find out token is present in the underlying keystore */
	true_id = TRUEID(metaslot_keystore_slotid);

	rv = FUNCLIST(metaslot_keystore_slotid)->C_GetSlotInfo(true_id,
	    &slotinfo);
	if ((rv == CKR_OK) && (slotinfo.flags & CKF_TOKEN_PRESENT)) {
		/*
		 * store the token present flag if it is successfully
		 * received from the keystore slot.
		 * If not, this flag will not be set.
		 */
		pInfo->flags = CKF_TOKEN_PRESENT;
	}

	return (CKR_OK);
}


/*
 * meta_GetTokenInfo
 *
 * Returns basic information about the metaslot "token."
 *
 * The slotID argument is ignored.
 *
 */
/*ARGSUSED*/
CK_RV
meta_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	CK_RV rv;
	CK_TOKEN_INFO metainfo;
	CK_SLOT_ID true_id;

	if (!metaslot_enabled) {
		return (CKR_SLOT_ID_INVALID);
	}

	if (pInfo == NULL)
		return (CKR_ARGUMENTS_BAD);

	true_id = TRUEID(metaslot_keystore_slotid);

	rv = FUNCLIST(metaslot_keystore_slotid)->C_GetTokenInfo(true_id,
	    &metainfo);

	/*
	 * If we could not get information about the object token, use
	 * default values. This allows metaslot to be used even if there
	 * are problems with the object token (eg, it's not present).
	 */
	if (rv != CKR_OK) {
		metainfo.ulTotalPublicMemory	= CK_UNAVAILABLE_INFORMATION;
		metainfo.ulFreePublicMemory	= CK_UNAVAILABLE_INFORMATION;
		metainfo.ulTotalPrivateMemory	= CK_UNAVAILABLE_INFORMATION;
		metainfo.ulFreePrivateMemory	= CK_UNAVAILABLE_INFORMATION;

		metainfo.flags = CKF_WRITE_PROTECTED;

		metainfo.ulMaxPinLen = 0;
		metainfo.ulMinPinLen = 0;
		metainfo.hardwareVersion.major =
		    METASLOT_HARDWARE_VERSION_MAJOR;
		metainfo.hardwareVersion.minor =
		    METASLOT_HARDWARE_VERSION_MINOR;
		metainfo.firmwareVersion.major =
		    METASLOT_FIRMWARE_VERSION_MAJOR;
		metainfo.firmwareVersion.minor =
		    METASLOT_FIRMWARE_VERSION_MINOR;
	}

	/*
	 * Override some values that the object token may have set. They
	 * can be inappropriate/misleading when used in the context of
	 * metaslot.
	 */
	(void) memcpy(metainfo.label, METASLOT_TOKEN_LABEL, 32);
	(void) memcpy(metainfo.manufacturerID,
	    METASLOT_MANUFACTURER_ID, 32);
	(void) memcpy(metainfo.model, METASLOT_TOKEN_MODEL, 16);
	(void) memset(metainfo.serialNumber, ' ', 16);

	metainfo.ulMaxSessionCount	= CK_EFFECTIVELY_INFINITE;
	metainfo.ulSessionCount		= num_meta_sessions;
	metainfo.ulMaxRwSessionCount	= CK_EFFECTIVELY_INFINITE;
	metainfo.ulRwSessionCount	= num_rw_meta_sessions;

	metainfo.flags |= CKF_RNG;
	metainfo.flags &= ~CKF_RESTORE_KEY_NOT_NEEDED;
	metainfo.flags |= CKF_TOKEN_INITIALIZED;
	metainfo.flags &= ~CKF_SECONDARY_AUTHENTICATION;

	/* Clear the time field if the token does not have a clock. */
	if (!(metainfo.flags & CKF_CLOCK_ON_TOKEN))
		(void) memset(metainfo.utcTime, ' ', 16);

	*pInfo = metainfo;

	return (CKR_OK);
}


/*
 * meta_WaitForSlotEvent
 *
 * The metaslot never generates events, so this function doesn't do anything
 * useful. We do not pass on provider events because we want to hide details
 * of the providers.
 *
 * If CKF_DONT_BLOCK flag is turned on, CKR_NO_EVENT will be return.
 * Otherwise, return CKR_FUNCTION_FAILED.
 *
 */
/* ARGSUSED */
CK_RV
meta_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
    CK_VOID_PTR pReserved)
{
	if (flags & CKF_DONT_BLOCK) {
		return (CKR_NO_EVENT);
	} else {
		return (CKR_FUNCTION_FAILED);
	}
}


/*
 * meta_GetMechanismList
 *
 * The slotID argument is not used.
 *
 */
/*ARGSUSED*/
CK_RV
meta_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList,
    CK_ULONG_PTR pulCount)
{
	CK_RV rv;

	if (!metaslot_enabled) {
		return (CKR_SLOT_ID_INVALID);
	}

	if (pulCount == NULL)
		return (CKR_ARGUMENTS_BAD);

	rv = meta_mechManager_get_mechs(pMechanismList, pulCount);

	if ((rv == CKR_BUFFER_TOO_SMALL) && (pMechanismList == NULL)) {
		/*
		 * if pMechanismList is not provided, just need to
		 * return count
		 */
		rv = CKR_OK;
	}
	return (rv);
}


/*
 * meta_GetMechanismInfo
 *
 * The slotID argument is not used.
 */
/*ARGSUSED*/
CK_RV
meta_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
    CK_MECHANISM_INFO_PTR pInfo)
{
	CK_RV rv;
	mechinfo_t **slots = NULL;
	unsigned long i, slotCount = 0;
	mech_support_info_t  mech_support_info;

	if (!metaslot_enabled) {
		return (CKR_SLOT_ID_INVALID);
	}

	if (pInfo == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	mech_support_info.supporting_slots =
	    malloc(meta_slotManager_get_slotcount() * sizeof (mechinfo_t *));
	if (mech_support_info.supporting_slots == NULL) {
		return (CKR_HOST_MEMORY);
	}

	mech_support_info.mech = type;

	rv = meta_mechManager_get_slots(&mech_support_info, TRUE, NULL);
	if (rv != CKR_OK) {
		free(mech_support_info.supporting_slots);
		return (rv);
	}

	slotCount = mech_support_info.num_supporting_slots;
	slots = mech_support_info.supporting_slots;

	/* Merge mechanism info from all slots. */
	(void) memcpy(pInfo, &(slots[0]->mechanism_info),
	    sizeof (CK_MECHANISM_INFO));

	/* no need to look at index 0, since that's what we started with */
	for (i = 1; i < slotCount; i++) {
		CK_ULONG thisValue;

		/* MinKeySize should be smallest of all slots. */
		thisValue = slots[i]->mechanism_info.ulMinKeySize;
		if (thisValue < pInfo->ulMinKeySize) {
			pInfo->ulMinKeySize = thisValue;
		}

		/* MaxKeySize should be largest of all slots. */
		thisValue = slots[i]->mechanism_info.ulMaxKeySize;
		if (thisValue > pInfo->ulMaxKeySize) {
			pInfo->ulMaxKeySize = thisValue;
		}

		pInfo->flags |= slots[i]->mechanism_info.flags;
	}

	/* Clear the CKF_HW flag. We might select a software provider later. */
	pInfo->flags &= ~CKF_HW;

	/* Clear the extenstion flag. Spec says is should never even be set. */
	pInfo->flags &= ~CKF_EXTENSION;

	free(mech_support_info.supporting_slots);

	return (CKR_OK);
}


/*
 * meta_InitToken
 *
 * Not supported. The metaslot "token" is always initialized. The token object
 * token must already be initialized. Other vendors don't seem to support
 * this anyway.
 */
/* ARGSUSED */
CK_RV
meta_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
    CK_UTF8CHAR_PTR pLabel)
{
	return (CKR_FUNCTION_NOT_SUPPORTED);
}


/*
 * meta_InitPIN
 *
 * Not supported. Same reason as C_InitToken.
 */
/* ARGSUSED */
CK_RV
meta_InitPIN(CK_SESSION_HANDLE hSession,
    CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	return (CKR_FUNCTION_NOT_SUPPORTED);
}


/*
 * meta_SetPIN
 *
 * This is basically just a pass-thru to the object token. No need to
 * even check the arguments, since we don't use them.
 */
CK_RV
meta_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
    CK_ULONG ulOldPinLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewPinLen)
{
	CK_RV rv;
	meta_session_t *session;
	slot_session_t *slot_session;

	rv = meta_handle2session(hSession, &session);
	if (rv != CKR_OK)
		return (rv);

	if (IS_READ_ONLY_SESSION(session->session_flags)) {
		REFRELEASE(session);
		return (CKR_SESSION_READ_ONLY);
	}

	rv = meta_get_slot_session(get_keystore_slotnum(), &slot_session,
	    session->session_flags);
	if (rv != CKR_OK) {
		REFRELEASE(session);
		return (rv);
	}

	rv = FUNCLIST(slot_session->fw_st_id)->C_SetPIN(slot_session->hSession,
	    pOldPin, ulOldPinLen, pNewPin, ulNewPinLen);

	meta_release_slot_session(slot_session);

	REFRELEASE(session);
	return (rv);
}
