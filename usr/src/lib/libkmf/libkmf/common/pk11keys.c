/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1995-2000 Intel Corporation. All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <kmfapiP.h>
#include <sha1.h>
#include <security/cryptoki.h>

#include <algorithm.h>
#include <ber_der.h>

#define	MAX_PUBLIC_KEY_TEMPLATES    (20)
#define	MAX_PRIVATE_KEY_TEMPLATES   (24)
#define	MAX_SECRET_KEY_TEMPLATES    (24)

static KMF_RETURN
create_pk11_session(CK_SESSION_HANDLE *sessionp, CK_MECHANISM_TYPE wanted_mech,
	CK_FLAGS wanted_flags)
{
	CK_RV rv;
	KMF_RETURN ret;
	KMF_RETURN kmf_rv = KMF_OK;
	CK_SLOT_ID_PTR pSlotList;
	CK_ULONG pulCount;
	CK_MECHANISM_INFO info;
	int i;

	ret = init_pk11();

	if (ret != KMF_OK)
		return (ret);

	rv = C_GetSlotList(0, NULL, &pulCount);
	if (rv != CKR_OK) {
		kmf_rv = KMF_ERR_UNINITIALIZED;
		goto out;
	}

	pSlotList = (CK_SLOT_ID_PTR) malloc(pulCount * sizeof (CK_SLOT_ID));
	if (pSlotList == NULL) {
		kmf_rv = KMF_ERR_MEMORY;
		goto out;
	}

	rv = C_GetSlotList(0, pSlotList, &pulCount);
	if (rv != CKR_OK) {
		kmf_rv = KMF_ERR_UNINITIALIZED;
		goto out;
	}

	for (i = 0; i < pulCount; i++) {
		rv = C_GetMechanismInfo(pSlotList[i], wanted_mech, &info);
		if (rv == CKR_OK && (info.flags & wanted_flags))
			break;
	}
	if (i < pulCount) {
		rv = C_OpenSession(pSlotList[i], CKF_SERIAL_SESSION,
		    NULL, NULL, sessionp);

		if (rv != CKR_OK) {
			kmf_rv = KMF_ERR_UNINITIALIZED;
		}
	} else {
		kmf_rv = KMF_ERR_UNINITIALIZED;
	}

out:
	if (pSlotList != NULL)
		free(pSlotList);
	return (kmf_rv);

}

/*
 * Name: PKCS_AddTemplate
 *
 * Description:
 *  Adds a CK_ATTRIBUTE value to an existing array of CK_ATTRIBUTES. Will
 *  not expand the array beyond the maximum specified size.
 *
 * Returns:
 *  TRUE - Attribute value succesfully added.
 *  FALSE - Maximum array size would be exceded.
 */
static int
PKCS_AddTemplate(CK_ATTRIBUTE *pTemplate,
	CK_ULONG *ckNumTemplates,
	CK_ULONG ckMaxTemplates,
	CK_ATTRIBUTE_TYPE ckAttribCode,
	CK_BYTE * pckBuffer,
	CK_ULONG ckBufferLen)
{
	if (*ckNumTemplates >= ckMaxTemplates) {
		return (FALSE);
	}

	pTemplate[*ckNumTemplates].type = ckAttribCode;
	pTemplate[*ckNumTemplates].pValue = pckBuffer;
	pTemplate[*ckNumTemplates].ulValueLen = ckBufferLen;
	(*ckNumTemplates)++;

	return (TRUE);
}

/*
 * Convert an SPKI data record to PKCS#11
 * public key object.
 */
static KMF_RETURN
PKCS_CreatePublicKey(
	const KMF_X509_SPKI *pKey,
	CK_SESSION_HANDLE ckSession,
	CK_OBJECT_HANDLE *pckPublicKey)
{
	KMF_RETURN mrReturn = KMF_OK;
	CK_RV ckRv;

	CK_ATTRIBUTE ckTemplate[MAX_PUBLIC_KEY_TEMPLATES];
	CK_ULONG ckNumTemplates = 0;

	/* Common object attributes */
	CK_OBJECT_CLASS ckObjClass = CKO_PUBLIC_KEY;
	CK_BBOOL ckToken = 0;
	CK_BBOOL ckPrivate = 0;

	/* Common key attributes */
	CK_KEY_TYPE ckKeyType;
	CK_BBOOL ckDerive = CK_FALSE;

	/* Common public key attributes */
	CK_BBOOL ckEncrypt = 1;
	CK_BBOOL ckVerify = 1;

	CK_BBOOL ckVerifyRecover = CK_FALSE;
	CK_BBOOL ckWrap = CK_FALSE;

	/* Key part array */
	KMF_DATA KeyParts[KMF_MAX_PUBLIC_KEY_PARTS];
	uint32_t i, uNumKeyParts = KMF_MAX_PUBLIC_KEY_PARTS;
	KMF_ALGORITHM_INDEX AlgorithmId;

	/* Parse the keyblob */
	(void) memset(KeyParts, 0, sizeof (KeyParts));

	AlgorithmId = x509_algoid_to_algid(
	    (KMF_OID *)&pKey->algorithm.algorithm);
	if (AlgorithmId == KMF_ALGID_NONE)
		return (KMF_ERR_BAD_ALGORITHM);

	mrReturn = ExtractSPKIData(pKey, AlgorithmId, KeyParts, &uNumKeyParts);

	if (mrReturn != KMF_OK)
		return (mrReturn);

	/* Fill in the common object attributes */
	if (!PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
	    MAX_PUBLIC_KEY_TEMPLATES, CKA_CLASS, (CK_BYTE *)&ckObjClass,
	    sizeof (ckObjClass)) ||
	    !PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
	    MAX_PUBLIC_KEY_TEMPLATES, CKA_TOKEN, (CK_BYTE *)&ckToken,
	    sizeof (ckToken)) ||
	    !PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
	    MAX_PUBLIC_KEY_TEMPLATES, CKA_PRIVATE, (CK_BYTE *)&ckPrivate,
	    sizeof (ckPrivate))) {
		mrReturn = KMF_ERR_INTERNAL;
		goto cleanup;
	}

	/* Fill in the common key attributes */
	if (!pkcs_algid_to_keytype(AlgorithmId,	&ckKeyType)) {
		goto cleanup;
	}
	if (!PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
	    MAX_PUBLIC_KEY_TEMPLATES, CKA_KEY_TYPE, (CK_BYTE *)&ckKeyType,
	    sizeof (ckKeyType)) ||
	    !PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
	    MAX_PUBLIC_KEY_TEMPLATES, CKA_DERIVE, (CK_BYTE *)&ckDerive,
	    sizeof (ckDerive))) {
		mrReturn = KMF_ERR_INTERNAL;
		goto cleanup;
	}

	/* Add common public key attributes */
	if (!PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
	    MAX_PUBLIC_KEY_TEMPLATES, CKA_ENCRYPT, (CK_BYTE *)&ckEncrypt,
	    sizeof (ckEncrypt)) ||
	    !PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
	    MAX_PUBLIC_KEY_TEMPLATES, CKA_VERIFY, (CK_BYTE *)&ckVerify,
	    sizeof (ckVerify)) ||
	    !PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
	    MAX_PUBLIC_KEY_TEMPLATES, CKA_VERIFY_RECOVER,
	    (CK_BYTE *)&ckVerifyRecover, sizeof (ckVerifyRecover)) ||
	    !PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
	    MAX_PUBLIC_KEY_TEMPLATES, CKA_WRAP, (CK_BYTE *)&ckWrap,
	    sizeof (ckWrap))) {
		mrReturn = KMF_ERR_INTERNAL;
		goto cleanup;
	}

	/* Add algorithm specific attributes */
	switch (ckKeyType) {
	case CKK_RSA:
		if (!PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
		    MAX_PUBLIC_KEY_TEMPLATES, CKA_MODULUS,
		    (CK_BYTE *)KeyParts[KMF_RSA_MODULUS].Data,
		    (CK_ULONG)KeyParts[KMF_RSA_MODULUS].Length) ||
		    !PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
		    MAX_PUBLIC_KEY_TEMPLATES, CKA_PUBLIC_EXPONENT,
		    (CK_BYTE *)KeyParts[KMF_RSA_PUBLIC_EXPONENT].Data,
		    (CK_ULONG)KeyParts[KMF_RSA_PUBLIC_EXPONENT].Length)) {
			mrReturn = KMF_ERR_INTERNAL;
			goto cleanup;
		}
		break;
	case CKK_DSA:
		if (!PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
		    MAX_PUBLIC_KEY_TEMPLATES, CKA_PRIME,
		    (CK_BYTE *)KeyParts[KMF_DSA_PRIME].Data,
		    (CK_ULONG)KeyParts[KMF_DSA_PRIME].Length) ||
		    !PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
		    MAX_PUBLIC_KEY_TEMPLATES, CKA_SUBPRIME,
		    (CK_BYTE *)KeyParts[KMF_DSA_SUB_PRIME].Data,
		    (CK_ULONG)KeyParts[KMF_DSA_SUB_PRIME].Length) ||
		    !PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
		    MAX_PUBLIC_KEY_TEMPLATES, CKA_BASE,
		    (CK_BYTE *)KeyParts[KMF_DSA_BASE].Data,
		    (CK_ULONG)KeyParts[KMF_DSA_BASE].Length) ||
		    !PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
		    MAX_PUBLIC_KEY_TEMPLATES, CKA_VALUE,
		    (CK_BYTE *)KeyParts[KMF_DSA_PUBLIC_VALUE].Data,
		    (CK_ULONG)KeyParts[KMF_DSA_PUBLIC_VALUE].Length)) {
		mrReturn = KMF_ERR_INTERNAL;
		goto cleanup;
		}
		break;
	default:
		mrReturn = KMF_ERR_BAD_PARAMETER;
	}

	if (mrReturn == KMF_OK) {
		/* Instantiate the object */
		ckRv = C_CreateObject(ckSession, ckTemplate,
		    ckNumTemplates, pckPublicKey);
		if (ckRv != CKR_OK)
			mrReturn = KMF_ERR_INTERNAL;
	}

cleanup:
	for (i = 0; i < uNumKeyParts; i++) {
		kmf_free_data(&KeyParts[i]);
	}

	return (mrReturn);
}

/*
 * PKCS_AcquirePublicKeyHandle
 *
 *   Given an assymetric key keyblob, attempts to find the appropriate
 *    public key.
 *
 *  Methods of finding the public key:
 *  - Public Key with data present:
 *    Parses the key and creates a temporary session object.
 *  - Public Key with handle:
 *    The handle is type converted and returned. Validity of the handle is
 *    not checked.
 *  - Public Key with label:
 *    Attempts to find a public key with the corresponding label.
 */
KMF_RETURN
PKCS_AcquirePublicKeyHandle(CK_SESSION_HANDLE ckSession,
	const KMF_X509_SPKI *pKey,
	CK_KEY_TYPE ckRequestedKeyType,
	CK_OBJECT_HANDLE *pckKeyHandle,
	KMF_BOOL *pbTemporary)
{
	KMF_RETURN mrReturn = KMF_OK;


	/* Key searching variables */
	CK_OBJECT_HANDLE ckKeyHandle;
	CK_OBJECT_CLASS ckObjClass;
	CK_KEY_TYPE ckKeyType;
	CK_ATTRIBUTE ckTemplate[3];
	CK_ULONG ckNumTemplates;
	static const CK_ULONG ckMaxTemplates = (sizeof (ckTemplate) /
	    sizeof (CK_ATTRIBUTE));
	CK_RV ckRv;

	/* Extract the data from the SPKI into individual fields */
	mrReturn = PKCS_CreatePublicKey(pKey, ckSession, &ckKeyHandle);
	if (mrReturn != KMF_OK)
		return (mrReturn);

	*pbTemporary = KMF_TRUE;

	/* Fetch the key class and algorithm from the object */
	ckNumTemplates = 0;
	if (!PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
	    ckMaxTemplates, CKA_CLASS, (CK_BYTE *)&ckObjClass,
	    sizeof (ckObjClass)) ||
	    !PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
	    ckMaxTemplates, CKA_KEY_TYPE, (CK_BYTE *)&ckKeyType,
	    sizeof (ckKeyType))) {
		return (KMF_ERR_INTERNAL);
	}
	ckRv = C_GetAttributeValue(ckSession, ckKeyHandle,
	    ckTemplate,	ckNumTemplates);
	if (ckRv != CKR_OK) {
		return (ckRv);
	}

	/* Make sure the results match the expected values */
	if ((ckKeyType != ckRequestedKeyType) ||
	    (ckObjClass != CKO_PUBLIC_KEY)) {
		if (*pbTemporary == KMF_TRUE) {
			(void) C_DestroyObject(ckSession, ckKeyHandle);
		}

		return (KMF_ERR_BAD_KEY_FORMAT);
	}

	/* Set the return values */
	*pckKeyHandle = ckKeyHandle;

	return (KMF_OK);
}

KMF_SIGNATURE_MODE
PKCS_GetDefaultSignatureMode(KMF_ALGORITHM_INDEX AlgId)
{
	KMF_SIGNATURE_MODE AlgMode;

	switch (AlgId) {
		case KMF_ALGID_RSA:
		case KMF_ALGID_MD5WithRSA:
		case KMF_ALGID_MD2WithRSA:
		case KMF_ALGID_SHA1WithRSA:
			AlgMode = KMF_ALGMODE_PKCS1_EMSA_V15;
			break;
		default:
			AlgMode = KMF_ALGMODE_NONE;
			break;
	}

	return (AlgMode);
}

KMF_RETURN
PKCS_VerifyData(KMF_HANDLE_T kmfh,
		KMF_ALGORITHM_INDEX AlgorithmId,
		KMF_X509_SPKI *keyp,
		KMF_DATA *data,
		KMF_DATA *signed_data)
{
	KMF_RETURN rv = KMF_OK;
	PKCS_ALGORITHM_MAP *pAlgMap = NULL;
	CK_RV ckRv;
	CK_MECHANISM ckMechanism;
	CK_OBJECT_HANDLE ckKeyHandle;
	KMF_BOOL	bTempKey;
	CK_SESSION_HANDLE ckSession = 0;

	if (AlgorithmId == KMF_ALGID_NONE)
		return (KMF_ERR_BAD_ALGORITHM);

	pAlgMap = pkcs_get_alg_map(KMF_ALGCLASS_SIGNATURE,
	    AlgorithmId, PKCS_GetDefaultSignatureMode(AlgorithmId));

	if (!pAlgMap)
		return (KMF_ERR_BAD_ALGORITHM);

	rv = create_pk11_session(&ckSession, pAlgMap->pkcs_mechanism,
	    CKF_VERIFY);

	if (rv != KMF_OK)
		return (rv);

	/* Fetch the verifying key */
	rv = PKCS_AcquirePublicKeyHandle(ckSession, keyp,
	    pAlgMap->key_type, &ckKeyHandle, &bTempKey);

	if (rv != KMF_OK) {
		(void) C_CloseSession(ckSession);
		return (rv);
	}

	ckMechanism.mechanism = pAlgMap->pkcs_mechanism;
	ckMechanism.pParameter = NULL;
	ckMechanism.ulParameterLen = 0;

	ckRv = C_VerifyInit(ckSession, &ckMechanism, ckKeyHandle);
	if (ckRv != CKR_OK) {
		if (bTempKey)
			(void) C_DestroyObject(ckSession, ckKeyHandle);
		kmfh->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN;
		kmfh->lasterr.errcode = ckRv;
		(void) C_CloseSession(ckSession);
		return (KMF_ERR_INTERNAL);
	}

	ckRv = C_Verify(ckSession, (CK_BYTE *)data->Data,
	    (CK_ULONG)data->Length,
	    (CK_BYTE *)signed_data->Data,
	    (CK_ULONG)signed_data->Length);

	if (ckRv != CKR_OK) {
		kmfh->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN;
		kmfh->lasterr.errcode = ckRv;
		rv = KMF_ERR_INTERNAL;
	}
	if (bTempKey)
		(void) C_DestroyObject(ckSession, ckKeyHandle);

	(void) C_CloseSession(ckSession);
	return (rv);

}

KMF_RETURN
PKCS_EncryptData(KMF_HANDLE_T kmfh,
		KMF_ALGORITHM_INDEX AlgorithmId,
		KMF_X509_SPKI *keyp,
		KMF_DATA *plaintext,
		KMF_DATA *ciphertext)
{
	KMF_RETURN rv = KMF_OK;
	PKCS_ALGORITHM_MAP *pAlgMap = NULL;
	CK_RV ckRv;
	CK_MECHANISM ckMechanism;
	CK_OBJECT_HANDLE ckKeyHandle;
	KMF_BOOL bTempKey;
	CK_SESSION_HANDLE ckSession = NULL;
	CK_ULONG out_len = 0, in_len = 0, total_encrypted = 0;
	uint8_t *in_data, *out_data;
	int i, blocks, block_size;
	CK_ATTRIBUTE ckTemplate[2];
	CK_ULONG ckNumTemplates;
	CK_ULONG ckMaxTemplates = (sizeof (ckTemplate) /
	    sizeof (CK_ATTRIBUTE));

	pAlgMap = pkcs_get_alg_map(KMF_ALGCLASS_SIGNATURE,
	    AlgorithmId, PKCS_GetDefaultSignatureMode(AlgorithmId));

	if (!pAlgMap)
		return (KMF_ERR_BAD_ALGORITHM);

	rv = create_pk11_session(&ckSession, pAlgMap->pkcs_mechanism,
	    CKF_ENCRYPT);

	if (rv != KMF_OK)
		return (rv);

	/* Get the public key used in encryption */
	rv = PKCS_AcquirePublicKeyHandle(ckSession, keyp,
	    pAlgMap->key_type, &ckKeyHandle, &bTempKey);

	if (rv != KMF_OK) {
		(void) C_CloseSession(ckSession);
		return (rv);
	}

	/* Get the modulus length */
	ckNumTemplates = 0;
	if (!PKCS_AddTemplate(ckTemplate, &ckNumTemplates, ckMaxTemplates,
	    CKA_MODULUS, (CK_BYTE *)NULL, sizeof (CK_ULONG))) {
		if (bTempKey)
			(void) C_DestroyObject(ckSession, ckKeyHandle);
		(void) C_CloseSession(ckSession);
		return (KMF_ERR_INTERNAL);
	}

	ckRv = C_GetAttributeValue(ckSession, ckKeyHandle,
	    ckTemplate, ckNumTemplates);

	if (ckRv != CKR_OK) {
		if (bTempKey)
			(void) C_DestroyObject(ckSession, ckKeyHandle);
		kmfh->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN;
		kmfh->lasterr.errcode = ckRv;
		(void) C_CloseSession(ckSession);
		return (KMF_ERR_INTERNAL);
	}
	out_len = ckTemplate[0].ulValueLen;

	if (out_len > ciphertext->Length) {
		if (bTempKey)
			(void) C_DestroyObject(ckSession, ckKeyHandle);
		(void) C_CloseSession(ckSession);
		return (KMF_ERR_BUFFER_SIZE);
	}

	ckMechanism.mechanism = pAlgMap->pkcs_mechanism;
	ckMechanism.pParameter = NULL_PTR;
	ckMechanism.ulParameterLen = 0;

	/* Compute the fixed input data length for single-part encryption */
	block_size = out_len - 11;

	in_data = plaintext->Data;
	out_data = ciphertext->Data;

	blocks = plaintext->Length/block_size;

	for (i = 0; i < blocks; i++) {
		ckRv = C_EncryptInit(ckSession, &ckMechanism, ckKeyHandle);
		if (ckRv != CKR_OK) {
			if (bTempKey)
				(void) C_DestroyObject(ckSession, ckKeyHandle);
			kmfh->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN;
			kmfh->lasterr.errcode = ckRv;
			(void) C_CloseSession(ckSession);
			return (KMF_ERR_INTERNAL);
		}
		ckRv = C_Encrypt(ckSession, (CK_BYTE_PTR)in_data, block_size,
		    (CK_BYTE_PTR)out_data, &out_len);

		if (ckRv != CKR_OK) {
			if (bTempKey)
				(void) C_DestroyObject(ckSession, ckKeyHandle);
			kmfh->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN;
			kmfh->lasterr.errcode = ckRv;
			(void) C_CloseSession(ckSession);
			return (KMF_ERR_INTERNAL);
		}

		out_data += out_len;
		total_encrypted += out_len;
		in_data += block_size;
	}

	if (plaintext->Length % block_size) {
		/* Encrypt the remaining data */
		ckRv = C_EncryptInit(ckSession, &ckMechanism, ckKeyHandle);
		if (ckRv != CKR_OK) {
			if (bTempKey)
				(void) C_DestroyObject(ckSession, ckKeyHandle);
			kmfh->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN;
			kmfh->lasterr.errcode = ckRv;
			(void) C_CloseSession(ckSession);
			return (KMF_ERR_INTERNAL);
		}

		in_len = plaintext->Length % block_size;
		ckRv = C_Encrypt(ckSession, (CK_BYTE_PTR)in_data, in_len,
		    (CK_BYTE_PTR)out_data, &out_len);

		if (ckRv != CKR_OK) {
			if (bTempKey)
				(void) C_DestroyObject(ckSession, ckKeyHandle);
			kmfh->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN;
			kmfh->lasterr.errcode = ckRv;
			(void) C_CloseSession(ckSession);
			return (KMF_ERR_INTERNAL);
		}

		out_data += out_len;
		total_encrypted += out_len;
		in_data += in_len;
	}

	ciphertext->Length = total_encrypted;

	if (bTempKey)
		(void) C_DestroyObject(ckSession, ckKeyHandle);

	(void) C_CloseSession(ckSession);
	return (rv);

}

static void
DigestData(KMF_DATA *IDInput, KMF_DATA *IDOutput)
{
	SHA1_CTX ctx;

	SHA1Init(&ctx);
	SHA1Update(&ctx, IDInput->Data, IDInput->Length);
	SHA1Final(IDOutput->Data, &ctx);

	IDOutput->Length = SHA1_DIGEST_LENGTH;
}

KMF_RETURN
GetIDFromSPKI(KMF_X509_SPKI *spki, KMF_DATA *ID)
{
	KMF_RETURN rv = KMF_OK;
	KMF_DATA KeyParts[KMF_MAX_PUBLIC_KEY_PARTS];
	uint32_t uNumKeyParts = KMF_MAX_PUBLIC_KEY_PARTS;
	KMF_ALGORITHM_INDEX algId;
	int i;

	if (ID == NULL || spki == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	ID->Data = (uchar_t *)malloc(SHA1_HASH_LENGTH);
	if (ID->Data == NULL)
		return (KMF_ERR_MEMORY);

	ID->Length = SHA1_HASH_LENGTH;

	algId = x509_algoid_to_algid(&spki->algorithm.algorithm);
	if (algId == KMF_ALGID_NONE)
		return (KMF_ERR_BAD_ALGORITHM);

	rv = ExtractSPKIData(spki, algId, KeyParts, &uNumKeyParts);
	if (rv != KMF_OK)
		return (rv);

	/* Check the KEY algorithm */
	if (algId == KMF_ALGID_RSA) {
		DigestData(&KeyParts[KMF_RSA_MODULUS], ID);
	} else if (algId == KMF_ALGID_DSA) {
		DigestData(&KeyParts[KMF_DSA_PUBLIC_VALUE], ID);
	} else {
		/* We only support RSA and DSA keys for now */
		rv = KMF_ERR_BAD_ALGORITHM;
	}

	for (i = 0; i < uNumKeyParts; i++) {
		if (KeyParts[i].Data != NULL)
			free(KeyParts[i].Data);
	}

	if (rv != KMF_OK && ID->Data != NULL) {
		free(ID->Data);
		ID->Data = NULL;
		ID->Length = 0;
	}

	return (rv);
}
