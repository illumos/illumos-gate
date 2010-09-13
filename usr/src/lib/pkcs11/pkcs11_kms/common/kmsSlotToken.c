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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */


#include <stdlib.h>
#include <strings.h>
#include <security/cryptoki.h>
#include <cryptoutil.h>
#include <errno.h>
#include <aes_impl.h>

#include "kmsGlobal.h"
#include "kmsSlot.h"
#include "kmsKeystoreUtil.h"

/*
 * Just basic AES mechanisms (for now...)
 */
static CK_MECHANISM_TYPE kms_mechanisms[] = {
	CKM_AES_KEY_GEN,
	CKM_AES_CBC,
	CKM_AES_CBC_PAD
};

/*
 * KMS only supports 256 bit keys, so the range below is MAX-MAX
 * instead of MIN-MAX.
 */
static CK_MECHANISM_INFO kms_mechanism_info[] = {
	{AES_MAX_KEY_BYTES, AES_MAX_KEY_BYTES, CKF_GENERATE},
	{AES_MAX_KEY_BYTES, AES_MAX_KEY_BYTES, CKF_ENCRYPT|CKF_DECRYPT|
		CKF_WRAP|CKF_UNWRAP},		/* CKM_AES_CBC */
	{AES_MAX_KEY_BYTES, AES_MAX_KEY_BYTES, CKF_ENCRYPT|CKF_DECRYPT|
		CKF_WRAP|CKF_UNWRAP}		/* CKM_AES_CBC_PAD */
};

/* ARGSUSED */
CK_RV
C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
    CK_ULONG_PTR pulCount)
{
	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pulCount == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	/*
	 * If KMS is not available or initialized, return 0 slots
	 * but CKR_OK status.
	 */
	if (!kms_is_initialized()) {
		*pulCount = 0;
		return (CKR_OK);
	}

	if (pSlotList == NULL) {
		*pulCount = KMS_SLOTS;
		return (CKR_OK);
	}

	if (*pulCount < KMS_SLOTS) {
		*pulCount = KMS_SLOTS;
		return (CKR_BUFFER_TOO_SMALL);
	}

	*pulCount = 1;
	pSlotList[0] = KMS_TOKEN_SLOTID;

	return (CKR_OK);
}

CK_RV
C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (slotID != KMS_TOKEN_SLOTID ||
	    !kms_is_initialized()) {
		return (CKR_SLOT_ID_INVALID);
	}

	if (pInfo == NULL)
		return (CKR_ARGUMENTS_BAD);

	/* Provide information about the slot in the provided buffer */
	(void) strncpy((char *)pInfo->slotDescription, SLOT_DESCRIPTION,
	    64);
	(void) strncpy((char *)pInfo->manufacturerID, MANUFACTURER_ID, 32);
	pInfo->flags = CKF_TOKEN_PRESENT;
	pInfo->hardwareVersion.major = HARDWARE_VERSION_MAJOR;
	pInfo->hardwareVersion.minor = HARDWARE_VERSION_MINOR;
	pInfo->firmwareVersion.major = FIRMWARE_VERSION_MAJOR;
	pInfo->firmwareVersion.minor = FIRMWARE_VERSION_MINOR;

	return (CKR_OK);
}

CK_RV
C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	kms_cfg_info_t kmscfg;
	KMSAGENT_PROFILE_FLAGS kmsflags = 0;

	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (slotID != KMS_TOKEN_SLOTID ||
	    !kms_is_initialized())
		return (CKR_SLOT_ID_INVALID);

	if (pInfo == NULL)
		return (CKR_ARGUMENTS_BAD);

	/* Provide information about a token in the provided buffer */
	(void) strncpy((char *)pInfo->label, KMS_TOKEN_LABEL, 32);
	(void) strncpy((char *)pInfo->manufacturerID, MANUFACTURER_ID, 32);
	(void) strncpy((char *)pInfo->model, KMS_TOKEN_MODEL, 16);
	(void) strncpy((char *)pInfo->serialNumber, KMS_TOKEN_SERIAL, 16);

	pInfo->flags = KMS_TOKEN_FLAGS;
	pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulSessionCount = kms_session_cnt;
	pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulRwSessionCount = kms_session_rw_cnt;
	pInfo->ulMaxPinLen = MAX_PIN_LEN;
	pInfo->ulMinPinLen = MIN_PIN_LEN;
	pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->hardwareVersion.major = HARDWARE_VERSION_MAJOR;
	pInfo->hardwareVersion.minor = HARDWARE_VERSION_MINOR;
	pInfo->firmwareVersion.major = FIRMWARE_VERSION_MAJOR;
	pInfo->firmwareVersion.minor = FIRMWARE_VERSION_MINOR;
	(void) memset(pInfo->utcTime, ' ', 16);

	if (KMS_GetConfigInfo(&kmscfg) == CKR_OK &&
	    KMSAgent_GetProfileStatus(kmscfg.name, &kmsflags) ==
	    KMS_AGENT_STATUS_OK) {

		if ((kmsflags & KMSAGENT_PROFILE_EXISTS_FLAG) &&
		    (kmsflags & KMSAGENT_CLIENTKEY_EXISTS_FLAG))
			pInfo->flags |= CKF_TOKEN_INITIALIZED;
		else
			pInfo->flags &= ~CKF_TOKEN_INITIALIZED;
	}
	return (CKR_OK);
}

/*ARGSUSED*/
CK_RV
C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}


CK_RV
C_GetMechanismList(CK_SLOT_ID slotID,
	CK_MECHANISM_TYPE_PTR pMechanismList,
	CK_ULONG_PTR pulCount)
{
	int i;
	ulong_t mechnum;

	/*
	 * Just check to see if the library has been
	 * properly initialized.
	 */
	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * This is different from above check, this verifies that
	 * the KMS token is actually configured.
	 */
	if (slotID != KMS_TOKEN_SLOTID ||
	    !kms_is_initialized())
		return (CKR_SLOT_ID_INVALID);

	mechnum = sizeof (kms_mechanisms) / sizeof (CK_MECHANISM_TYPE);
	if (pMechanismList == NULL) {
		*pulCount = mechnum;
		return (CKR_OK);
	}
	if (*pulCount < mechnum) {
		*pulCount = mechnum;
		return (CKR_BUFFER_TOO_SMALL);
	}
	for (i = 0; i < mechnum; i++)
		pMechanismList[i] = kms_mechanisms[i];

	*pulCount = mechnum;

	return (CKR_OK);
}

CK_RV
C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
    CK_MECHANISM_INFO_PTR pInfo)
{
	CK_ULONG mechnum, i;

	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (slotID != KMS_TOKEN_SLOTID ||
	    !kms_is_initialized())
		return (CKR_SLOT_ID_INVALID);

	if (pInfo == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	mechnum = sizeof (kms_mechanisms) / sizeof (CK_MECHANISM_TYPE);
	for (i = 0; i < mechnum; i++) {
		if (kms_mechanisms[i] == type)
			break;
	}

	if (i == mechnum)
		/* unsupported mechanism */
		return (CKR_MECHANISM_INVALID);

	pInfo->ulMinKeySize = kms_mechanism_info[i].ulMinKeySize;
	pInfo->ulMaxKeySize = kms_mechanism_info[i].ulMaxKeySize;
	pInfo->flags = kms_mechanism_info[i].flags;

	return (CKR_OK);
}

/*ARGSUSED*/
CK_RV
C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
    CK_UTF8CHAR_PTR pLabel)
{
	CK_RV rv = CKR_FUNCTION_FAILED;
	kms_cfg_info_t kmscfg;
	KMSAGENT_PROFILE_FLAGS kmsflags;

	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (slotID != KMS_TOKEN_SLOTID ||
	    !kms_is_initialized())
		return (CKR_SLOT_ID_INVALID);

	if (KMS_GetConfigInfo(&kmscfg) != CKR_OK ||
	    KMSAgent_GetProfileStatus(kmscfg.name, &kmsflags) !=
	    KMS_AGENT_STATUS_OK)
		return (CKR_FUNCTION_FAILED);

	if (!(kmsflags & KMSAGENT_PROFILE_EXISTS_FLAG) ||
	    !(kmsflags & KMSAGENT_CLIENTKEY_EXISTS_FLAG)) {
		KMSClientProfile kmsProfile;
		/*
		 * Attempt to enroll and load a KMS profile.
		 * This will force the KMSAgent library to fetch
		 * the profile, the CA certificate, and the
		 * client private key and store them locally so that
		 * the KMS agent API can be used later.
		 */
		rv = KMS_LoadProfile(
		    &kmsProfile,
		    &kmscfg,
		    (const char *)pPin,
		    (size_t)ulPinLen);

		if (rv == CKR_OK)
			KMS_UnloadProfile(&kmsProfile);
	}
	return (rv);
}

/*ARGSUSED*/
CK_RV
C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Could be supported once the agent library supports
	 * storing the client certificate in a PKCS#12 file.
	 */
	return (CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV
C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
    CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	CK_RV	rv = CKR_OK;
	kms_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;

	if (!kms_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Make sure it is a RW session. */
	if (session_p->ses_RO) {
		rv = CKR_SESSION_READ_ONLY;
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

	/*
	 * If the token is not yet initialized, we cannot set the pin.
	 */
	if (!kms_is_initialized()) {
		REFRELE(session_p, ses_lock_held);
		return (CKR_FUNCTION_FAILED);
	}

	if (pOldPin == NULL || ulOldLen == 0 ||
	    pNewPin == NULL || ulNewLen == 0) {
		REFRELE(session_p, ses_lock_held);
		return (CKR_ARGUMENTS_BAD);
	}

	if (!kms_is_pin_set()) {
		/*
		 * We don't yet support this mode since
		 * the KMS private key file will automatically
		 * be generated using the KMS Agent passphrase
		 * which is initialized out-of-band.
		 */
		rv = CKR_FUNCTION_NOT_SUPPORTED;

	} else {
		/*
		 * Login to KMS by attempting to load the profile using
		 * the given password.
		 */
		rv = KMS_LoadProfile(&session_p->kmsProfile,
		    &session_p->configInfo,
		    (const char *)pOldPin,
		    (size_t)ulOldLen);
		if (rv == CKR_USER_ANOTHER_ALREADY_LOGGED_IN)
			rv = CKR_OK;

		if (rv == CKR_OK)
			rv = KMS_ChangeLocalPWD(session_p,
			    (const char *)pOldPin,
			    (const char *)pNewPin);
	}

	REFRELE(session_p, ses_lock_held);
	return (rv);
}
