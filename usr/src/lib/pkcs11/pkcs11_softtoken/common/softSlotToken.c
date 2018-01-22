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
 * Copyright 2018, Joyent, Inc.
 */

#include <strings.h>
#include <cryptoutil.h>
#include <security/cryptoki.h>
#include <sys/crypto/common.h>
#include <arcfour.h>
#include "softGlobal.h"
#include "softSession.h"
#include <aes_impl.h>
#include <blowfish_impl.h>
#include <des_impl.h>
#include <ecc_impl.h>
#include "softDH.h"
#include "softObject.h"
#include "softKeystore.h"
#include "softKeystoreUtil.h"


static CK_MECHANISM_TYPE soft_mechanisms[] = {
	CKM_DES_CBC,
	CKM_DES_CBC_PAD,
	CKM_DES_ECB,
	CKM_DES_KEY_GEN,
	CKM_DES_MAC_GENERAL,
	CKM_DES_MAC,
	CKM_DES3_CBC,
	CKM_DES3_CBC_PAD,
	CKM_DES3_ECB,
	CKM_DES2_KEY_GEN,
	CKM_DES3_KEY_GEN,
	CKM_AES_CBC,
	CKM_AES_CBC_PAD,
	CKM_AES_CTR,
	CKM_AES_CMAC_GENERAL,
	CKM_AES_CMAC,
	CKM_AES_ECB,
	CKM_AES_KEY_GEN,
	CKM_BLOWFISH_CBC,
	CKM_BLOWFISH_KEY_GEN,
	CKM_SHA_1,
	CKM_SHA_1_HMAC,
	CKM_SHA_1_HMAC_GENERAL,
	CKM_SHA256,
	CKM_SHA256_HMAC,
	CKM_SHA256_HMAC_GENERAL,
	CKM_SHA384,
	CKM_SHA384_HMAC,
	CKM_SHA384_HMAC_GENERAL,
	CKM_SHA512,
	CKM_SHA512_HMAC,
	CKM_SHA512_HMAC_GENERAL,
	CKM_SSL3_SHA1_MAC,
	CKM_MD5,
	CKM_MD5_HMAC,
	CKM_MD5_HMAC_GENERAL,
	CKM_SSL3_MD5_MAC,
	CKM_RC4,
	CKM_RC4_KEY_GEN,
	CKM_DSA,
	CKM_DSA_SHA1,
	CKM_DSA_KEY_PAIR_GEN,
	CKM_RSA_PKCS,
	CKM_RSA_PKCS_KEY_PAIR_GEN,
	CKM_RSA_X_509,
	CKM_MD5_RSA_PKCS,
	CKM_SHA1_RSA_PKCS,
	CKM_SHA256_RSA_PKCS,
	CKM_SHA384_RSA_PKCS,
	CKM_SHA512_RSA_PKCS,
	CKM_DH_PKCS_KEY_PAIR_GEN,
	CKM_DH_PKCS_DERIVE,
	CKM_MD5_KEY_DERIVATION,
	CKM_SHA1_KEY_DERIVATION,
	CKM_SHA256_KEY_DERIVATION,
	CKM_SHA384_KEY_DERIVATION,
	CKM_SHA512_KEY_DERIVATION,
	CKM_PBE_SHA1_RC4_128,
	CKM_PKCS5_PBKD2,
	CKM_SSL3_PRE_MASTER_KEY_GEN,
	CKM_TLS_PRE_MASTER_KEY_GEN,
	CKM_SSL3_MASTER_KEY_DERIVE,
	CKM_TLS_MASTER_KEY_DERIVE,
	CKM_SSL3_MASTER_KEY_DERIVE_DH,
	CKM_TLS_MASTER_KEY_DERIVE_DH,
	CKM_SSL3_KEY_AND_MAC_DERIVE,
	CKM_TLS_KEY_AND_MAC_DERIVE,
	CKM_TLS_PRF,
	CKM_EC_KEY_PAIR_GEN,
	CKM_ECDSA,
	CKM_ECDSA_SHA1,
	CKM_ECDH1_DERIVE
};

/*
 * This is the table of CK_MECHANISM_INFO structs for the supported mechanisms.
 * The index for this table is the same as the one above for the same
 * mechanism.
 * The minimum and maximum sizes of the key for the mechanism can be measured
 * in bits or in bytes (i.e. mechanism-dependent). This table specifies the
 * supported range of key sizes in bytes; unless noted as in bits.
 */
static CK_MECHANISM_INFO soft_mechanism_info[] = {
	{DES_MINBYTES, DES_MAXBYTES,
		CKF_ENCRYPT|CKF_DECRYPT|
		CKF_WRAP|CKF_UNWRAP},		/* CKM_DES_CBC */
	{DES_MINBYTES, DES_MAXBYTES,
		CKF_ENCRYPT|CKF_DECRYPT|
		CKF_WRAP|CKF_UNWRAP},		/* CKM_DES_CBC_PAD */
	{DES_MINBYTES, DES_MAXBYTES,
		CKF_ENCRYPT|CKF_DECRYPT|
		CKF_WRAP|CKF_UNWRAP},		/* CKM_DES_ECB */
	{DES_MINBYTES, DES_MAXBYTES,
		CKF_GENERATE},			/* CKM_DES_KEY_GEN */
	{DES_MINBYTES, DES_MAXBYTES,
		CKF_SIGN|CKF_VERIFY},		/* CKM_DES_MAC_GENERAL */
	{DES_MINBYTES, DES_MAXBYTES,
		CKF_SIGN|CKF_VERIFY},		/* CKM_DES_MAC */
	{DES3_MINBYTES, DES3_MAXBYTES,
		CKF_ENCRYPT|CKF_DECRYPT|
		CKF_WRAP|CKF_UNWRAP},		/* CKM_DES3_CBC */
	{DES3_MINBYTES, DES3_MAXBYTES,
		CKF_ENCRYPT|CKF_DECRYPT|
		CKF_WRAP|CKF_UNWRAP},		/* CKM_DES3_CBC_PAD */
	{DES3_MINBYTES, DES3_MAXBYTES,
		CKF_ENCRYPT|CKF_DECRYPT|
		CKF_WRAP|CKF_UNWRAP},		/* CKM_DES3_ECB */
	{DES2_MAXBYTES, DES2_MAXBYTES,
		CKF_GENERATE},			/* CKM_DES2_KEY_GEN */
	{DES3_MAXBYTES, DES3_MAXBYTES,		/* CKK_DES3 only */
		CKF_GENERATE},			/* CKM_DES3_KEY_GEN */
	{AES_MINBYTES, AES_MAXBYTES,
		CKF_ENCRYPT|CKF_DECRYPT|
		CKF_WRAP|CKF_UNWRAP},		/* CKM_AES_CBC */
	{AES_MINBYTES, AES_MAXBYTES,
		CKF_ENCRYPT|CKF_DECRYPT|
		CKF_WRAP|CKF_UNWRAP},		/* CKM_AES_CBC_PAD */
	{AES_MINBYTES, AES_MAXBYTES,
		CKF_ENCRYPT|CKF_DECRYPT|
		CKF_WRAP|CKF_UNWRAP},		/* CKM_AES_CTR */
	{AES_MINBYTES, AES_MAXBYTES,
		CKF_SIGN|CKF_VERIFY},		/* CKM_AES_CMAC_GENERAL */
	{AES_MINBYTES, AES_MAXBYTES,
		CKF_SIGN|CKF_VERIFY},		/* CKM_AES_CMAC */
	{AES_MINBYTES, AES_MAXBYTES,
		CKF_ENCRYPT|CKF_DECRYPT|
		CKF_WRAP|CKF_UNWRAP},		/* CKM_AES_ECB */
	{AES_MINBYTES, AES_MAXBYTES,
		CKF_GENERATE},			/* CKM_AES_KEY_GEN */
	{BLOWFISH_MINBYTES, BLOWFISH_MAXBYTES,
		CKF_ENCRYPT|CKF_DECRYPT|
		CKF_WRAP|CKF_UNWRAP},		/* CKM_BLOWFISH_ECB */
	{BLOWFISH_MINBYTES, BLOWFISH_MAXBYTES,
		CKF_GENERATE},			/* CKM_BLOWFISH_KEY_GEN */
	{0, 0, CKF_DIGEST},			/* CKM_SHA_1 */
	{1, 64, CKF_SIGN|CKF_VERIFY},		/* CKM_SHA_1_HMAC */
	{1, 64, CKF_SIGN|CKF_VERIFY},		/* CKM_SHA_1_HMAC_GENERAL */
	{0, 0, CKF_DIGEST},			/* CKM_SHA256 */
	{1, 64, CKF_SIGN|CKF_VERIFY},		/* CKM_SHA256_HMAC */
	{1, 64, CKF_SIGN|CKF_VERIFY},		/* CKM_SHA256_HMAC_GENERAL */
	{0, 0, CKF_DIGEST},			/* CKM_SHA384 */
	{1, 128, CKF_SIGN|CKF_VERIFY},		/* CKM_SHA384_HMAC */
	{1, 128, CKF_SIGN|CKF_VERIFY},		/* CKM_SHA384_HMAC_GENERAL */
	{0, 0, CKF_DIGEST},			/* CKM_SHA512 */
	{1, 128, CKF_SIGN|CKF_VERIFY},		/* CKM_SHA512_HMAC */
	{1, 128, CKF_SIGN|CKF_VERIFY},		/* CKM_SHA512_HMAC_GENERAL */
	{1, 512, CKF_SIGN|CKF_VERIFY},		/* CKM_SSL3_SHA1_MAC */
	{0, 0, CKF_DIGEST},			/* CKM_MD5 */
	{1, 64, CKF_SIGN|CKF_VERIFY},		/* CKM_MD5_HMAC */
	{1, 64, CKF_SIGN|CKF_VERIFY},		/* CKM_MD5_HMAC_GENERAL */
	{1, 512, CKF_SIGN|CKF_VERIFY},		/* CKM_SSL3_MD5_MAC */
	{8, ARCFOUR_MAX_KEY_BITS, CKF_ENCRYPT|CKF_DECRYPT}, /* CKM_RC4; */
							    /* in bits  */
	{8, ARCFOUR_MAX_KEY_BITS, CKF_GENERATE }, /* CKM_RC4_KEY_GEN; in bits */
	{512, 1024, CKF_SIGN|CKF_VERIFY},	/* CKM_DSA; in bits */
	{512, 1024, CKF_SIGN|CKF_VERIFY},	/* CKM_DSA_SHA1; in bits */
	{512, 1024, CKF_GENERATE_KEY_PAIR},	/* CKM_DSA_KEY_PAIR_GEN; */
						/* in bits */
	{256, 4096, CKF_ENCRYPT|CKF_DECRYPT|
		CKF_SIGN|CKF_SIGN_RECOVER|
		CKF_WRAP|CKF_UNWRAP|
		CKF_VERIFY|CKF_VERIFY_RECOVER},	/* CKM_RSA_PKCS; in bits */
	{256, 4096, CKF_GENERATE_KEY_PAIR},	/* CKM_RSA_PKCS_KEY_PAIR_GEN; */
						/* in bits */
	{256, 4096, CKF_ENCRYPT|CKF_DECRYPT|
		CKF_SIGN|CKF_SIGN_RECOVER|
		CKF_WRAP|CKF_UNWRAP|
		CKF_VERIFY|CKF_VERIFY_RECOVER},	/* CKM_RSA_X_509 in bits */
	{256, 4096, CKF_SIGN|CKF_VERIFY},	/* CKM_MD5_RSA_PKCS in bits */
	{256, 4096, CKF_SIGN|CKF_VERIFY},	/* CKM_SHA1_RSA_PKCS in bits */
	{256, 4096, CKF_SIGN|CKF_VERIFY}, /* CKM_SHA256_RSA_PKCS in bits */
	{256, 4096, CKF_SIGN|CKF_VERIFY}, /* CKM_SHA384_RSA_PKCS in bits */
	{256, 4096, CKF_SIGN|CKF_VERIFY}, /* CKM_SHA512_RSA_PKCS in bits */
	{DH_MIN_KEY_LEN, DH_MAX_KEY_LEN, CKF_GENERATE_KEY_PAIR},
						/* CKM_DH_PKCS_KEY_PAIR_GEN */
						/* in bits */
	{DH_MIN_KEY_LEN, DH_MAX_KEY_LEN, CKF_DERIVE},
						/* CKM_DH_PKCS_DERIVE; */
						/* in bits */
	{1, 16, CKF_DERIVE},			/* CKM_MD5_KEY_DERIVATION */
	{1, 20, CKF_DERIVE},			/* CKM_SHA1_KEY_DERIVATION */
	{1, 32, CKF_DERIVE},			/* CKM_SHA256_KEY_DERIVATION */
	{1, 48, CKF_DERIVE},			/* CKM_SHA384_KEY_DERIVATION */
	{1, 64, CKF_DERIVE},			/* CKM_SHA512_KEY_DERIVATION */
	{0, 0, CKF_GENERATE},			/* CKM_PBE_SHA1_RC4_128 */
	{0, 0, CKF_GENERATE},			/* CKM_PKCS5_PBKD2 */
	{48, 48, CKF_GENERATE},		/* CKM_SSL3_PRE_MASTER_KEY_GEN */
	{48, 48, CKF_GENERATE},		/* CKM_TLS_PRE_MASTER_KEY_GEN */
	{48, 48, CKF_DERIVE},		/* CKM_SSL3_MASTER_KEY_DERIVE */
	{48, 48, CKF_DERIVE},		/* CKM_TLS_MASTER_KEY_DERIVE */
	{48, 48, CKF_DERIVE},		/* CKM_SSL3_MASTER_KEY_DERIVE_DH */
	{48, 48, CKF_DERIVE},		/* CKM_TLS_MASTER_KEY_DERIVE_DH */
	{0, 0, CKF_DERIVE},		/* CKM_SSL3_KEY_AND_MAC_DERIVE */
	{0, 0, CKF_DERIVE},		/* CKM_TLS_KEY_AND_MAC_DERIVE */
	{0, 0, CKF_DERIVE},		/* CKM_TLS_PRF */
	{EC_MIN_KEY_LEN, EC_MAX_KEY_LEN, CKF_GENERATE_KEY_PAIR},
	{EC_MIN_KEY_LEN, EC_MAX_KEY_LEN, CKF_SIGN|CKF_VERIFY},
	{EC_MIN_KEY_LEN, EC_MAX_KEY_LEN, CKF_SIGN|CKF_VERIFY},
	{EC_MIN_KEY_LEN, EC_MAX_KEY_LEN, CKF_DERIVE}
};

/*
 * Slot ID for softtoken is always 1. tokenPresent is ignored.
 * Also, only one slot is used.
 */
/*ARGSUSED*/
CK_RV
C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
    CK_ULONG_PTR pulCount)
{

	CK_RV rv;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pulCount == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	if (pSlotList == NULL) {
		/*
		 * Application only wants to know the number of slots.
		 */
		*pulCount = 1;
		return (CKR_OK);
	}

	if ((*pulCount < 1) && (pSlotList != NULL)) {
		rv = CKR_BUFFER_TOO_SMALL;
	} else {
		pSlotList[0] = SOFTTOKEN_SLOTID;
		rv = CKR_OK;
	}

	*pulCount = 1;
	return (rv);
}


CK_RV
C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pInfo == NULL)
		return (CKR_ARGUMENTS_BAD);

	/* Make sure the slot ID is valid */
	if (slotID != SOFTTOKEN_SLOTID)
		return (CKR_SLOT_ID_INVALID);

	/* Provide information about the slot in the provided buffer */
	(void) strncpy((char *)pInfo->slotDescription, SOFT_SLOT_DESCRIPTION,
	    64);
	(void) strncpy((char *)pInfo->manufacturerID, SOFT_MANUFACTURER_ID, 32);
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
	boolean_t pin_initialized = B_FALSE;
	char	*ks_cryptpin = NULL;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/* Make sure the slot ID is valid */
	if (slotID != SOFTTOKEN_SLOTID)
		return (CKR_SLOT_ID_INVALID);

	if (pInfo == NULL)
		return (CKR_ARGUMENTS_BAD);

	/*
	 * It is intentional that we don't forward the error code
	 * returned from soft_keystore_pin_initialized() to the caller
	 */
	pInfo->flags = SOFT_TOKEN_FLAGS;
	if (soft_slot.keystore_load_status == KEYSTORE_UNAVAILABLE) {
		pInfo->flags |= CKF_WRITE_PROTECTED;
	} else {
		if ((soft_keystore_pin_initialized(&pin_initialized,
		    &ks_cryptpin, B_FALSE) == CKR_OK) && !pin_initialized)
			pInfo->flags |= CKF_USER_PIN_TO_BE_CHANGED;
	}

	if (ks_cryptpin != NULL) {
		size_t cplen = strlen(ks_cryptpin) + 1;

		freezero(ks_cryptpin, cplen);
	}

	/* Provide information about a token in the provided buffer */
	(void) strncpy((char *)pInfo->label, SOFT_TOKEN_LABEL, 32);
	(void) strncpy((char *)pInfo->manufacturerID, SOFT_MANUFACTURER_ID, 32);
	(void) strncpy((char *)pInfo->model, TOKEN_MODEL, 16);
	(void) strncpy((char *)pInfo->serialNumber, SOFT_TOKEN_SERIAL, 16);

	pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulSessionCount = soft_session_cnt;
	pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulRwSessionCount = soft_session_rw_cnt;
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

	return (CKR_OK);
}

/*ARGSUSED*/
CK_RV
C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * This is currently not implemented, however we could cause this
	 * to wait for the token files to appear if soft_token_present is
	 * false.
	 * However there is currently no polite and portable way to do that
	 * because we might not even be able to get to an fd to the
	 * parent directory, so instead we don't support any slot events.
	 */
	return (CKR_FUNCTION_NOT_SUPPORTED);
}


CK_RV
C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList,
    CK_ULONG_PTR pulCount)
{

	ulong_t i;
	ulong_t mechnum;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (slotID != SOFTTOKEN_SLOTID)
		return (CKR_SLOT_ID_INVALID);

	mechnum = sizeof (soft_mechanisms) / sizeof (CK_MECHANISM_TYPE);

	if (pMechanismList == NULL) {
		/*
		 * Application only wants to know the number of
		 * supported mechanism types.
		 */
		*pulCount = mechnum;
		return (CKR_OK);
	}

	if (*pulCount < mechnum) {
		*pulCount = mechnum;
		return (CKR_BUFFER_TOO_SMALL);
	}

	for (i = 0; i < mechnum; i++) {
		pMechanismList[i] = soft_mechanisms[i];
	}

	*pulCount = mechnum;

	return (CKR_OK);
}


CK_RV
C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
    CK_MECHANISM_INFO_PTR pInfo)
{

	ulong_t i;
	ulong_t mechnum;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (slotID != SOFTTOKEN_SLOTID)
		return (CKR_SLOT_ID_INVALID);

	if (pInfo == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	mechnum = sizeof (soft_mechanisms) / sizeof (CK_MECHANISM_TYPE);
	for (i = 0; i < mechnum; i++) {
		if (soft_mechanisms[i] == type)
			break;
	}

	if (i == mechnum)
		/* unsupported mechanism */
		return (CKR_MECHANISM_INVALID);

	pInfo->ulMinKeySize = soft_mechanism_info[i].ulMinKeySize;
	pInfo->ulMaxKeySize = soft_mechanism_info[i].ulMaxKeySize;
	pInfo->flags = soft_mechanism_info[i].flags;

	return (CKR_OK);
}


/*ARGSUSED*/
CK_RV
C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
    CK_UTF8CHAR_PTR pLabel)
{
	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (create_keystore() != 0)
		return (CKR_FUNCTION_FAILED);

	return (CKR_OK);
}

/*ARGSUSED*/
CK_RV
C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}


CK_RV
C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
    CK_ULONG ulOldPinLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewPinLen)
{

	soft_session_t *session_p;
	CK_RV rv;
	boolean_t lock_held = B_FALSE;

	if (!softtoken_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	if (!soft_keystore_status(KEYSTORE_LOAD)) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_DEVICE_REMOVED);
	}

	if ((ulOldPinLen < MIN_PIN_LEN) || (ulOldPinLen > MAX_PIN_LEN) ||
	    (ulNewPinLen < MIN_PIN_LEN) ||(ulNewPinLen > MAX_PIN_LEN)) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_PIN_LEN_RANGE);
	}

	if ((pOldPin == NULL_PTR) || (pNewPin == NULL_PTR)) {
		/*
		 * We don't support CKF_PROTECTED_AUTHENTICATION_PATH
		 */
		SES_REFRELE(session_p, lock_held);
		return (CKR_ARGUMENTS_BAD);
	}

	/* check the state of the session */
	if ((session_p->state != CKS_RW_PUBLIC_SESSION) &&
	    (session_p->state != CKS_RW_USER_FUNCTIONS)) {
		SES_REFRELE(session_p, lock_held);
		return (CKR_SESSION_READ_ONLY);
	}

	rv = soft_setpin(pOldPin, ulOldPinLen, pNewPin, ulNewPinLen);

	SES_REFRELE(session_p, lock_held);
	return (rv);
}
