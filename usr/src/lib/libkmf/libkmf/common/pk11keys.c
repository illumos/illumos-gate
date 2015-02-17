/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1995-2000 Intel Corporation. All rights reserved.
 */

#include <kmfapiP.h>
#include <sha1.h>
#include <security/cryptoki.h>

#include <ber_der.h>

#define	MAX_PUBLIC_KEY_TEMPLATES    (20)
#define	MAX_PRIVATE_KEY_TEMPLATES   (24)
#define	MAX_SECRET_KEY_TEMPLATES    (24)

typedef struct
{
	KMF_ALGORITHM_INDEX kmfAlgorithmId;
	CK_KEY_TYPE ckKeyType;
	CK_MECHANISM_TYPE signmech;
	CK_MECHANISM_TYPE vfymech;
	CK_MECHANISM_TYPE hashmech;
} ALG_INFO;

static const ALG_INFO alg_info_map[] = {
	{ KMF_ALGID_RSA, CKK_RSA, CKM_RSA_PKCS, CKM_RSA_PKCS, NULL},
	{ KMF_ALGID_DSA, CKK_DSA, CKM_DSA, CKM_DSA, CKM_SHA_1 },
	{ KMF_ALGID_ECDSA, CKK_EC, CKM_ECDSA, CKM_ECDSA, CKM_SHA_1 },
	{ KMF_ALGID_SHA1WithDSA, CKK_DSA, CKM_DSA, CKM_DSA, CKM_SHA_1 },
	{ KMF_ALGID_SHA256WithDSA, CKK_DSA, CKM_DSA, CKM_DSA, CKM_SHA256 },

	/*
	 * For RSA, the verify can be done using a single mechanism,
	 * but signing must be done separately because not all hardware
	 * tokens support the combined hash+key operations.
	 */
	{ KMF_ALGID_MD5WithRSA, CKK_RSA, CKM_RSA_PKCS,
	    CKM_MD5_RSA_PKCS, CKM_MD5},
	{ KMF_ALGID_SHA1WithRSA, CKK_RSA, CKM_RSA_PKCS,
	    CKM_SHA1_RSA_PKCS, CKM_SHA_1},
	{ KMF_ALGID_SHA256WithRSA, CKK_RSA, CKM_RSA_PKCS,
	    CKM_SHA256_RSA_PKCS, CKM_SHA256},
	{ KMF_ALGID_SHA384WithRSA, CKK_RSA, CKM_RSA_PKCS,
	    CKM_SHA384_RSA_PKCS, CKM_SHA384},
	{ KMF_ALGID_SHA512WithRSA, CKK_RSA, CKM_RSA_PKCS,
	    CKM_SHA512_RSA_PKCS, CKM_SHA512},
	{ KMF_ALGID_SHA1WithECDSA, CKK_EC, CKM_ECDSA,
	    CKM_ECDSA, CKM_SHA_1},
	{ KMF_ALGID_SHA256WithECDSA, CKK_EC, CKM_ECDSA,
	    CKM_ECDSA, CKM_SHA256},
	{ KMF_ALGID_SHA384WithECDSA, CKK_EC, CKM_ECDSA,
	    CKM_ECDSA, CKM_SHA384},
	{ KMF_ALGID_SHA512WithECDSA, CKK_EC, CKM_ECDSA,
	    CKM_ECDSA, CKM_SHA512}
};

KMF_RETURN
get_pk11_data(KMF_ALGORITHM_INDEX AlgId,
	CK_KEY_TYPE *keytype, CK_MECHANISM_TYPE *signmech,
	CK_MECHANISM_TYPE *hashmech, boolean_t vfy)
{
	uint32_t uIndex;
	uint32_t uMapSize =
	    sizeof (alg_info_map) / sizeof (ALG_INFO);

	for (uIndex = 0; uIndex < uMapSize; uIndex++) {
		if (alg_info_map[uIndex].kmfAlgorithmId == AlgId) {
			if (keytype)
				*keytype = alg_info_map[uIndex].ckKeyType;
			if (hashmech)
				*hashmech = alg_info_map[uIndex].hashmech;
			if (signmech)
				*signmech =
				    (vfy ? alg_info_map[uIndex].vfymech :
				    alg_info_map[uIndex].signmech);
			return (KMF_OK);
		}
	}
	/* no match */
	return (KMF_ERR_BAD_ALGORITHM);
}

KMF_RETURN
kmf_create_pk11_session(CK_SESSION_HANDLE *sessionp,
	CK_MECHANISM_TYPE wanted_mech,
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
		if (rv == CKR_OK &&
		    (info.flags & wanted_flags) == wanted_flags)
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
	if (get_pk11_data(AlgorithmId, &ckKeyType, NULL, NULL, 0)) {
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
	case CKK_EC:
		if (!PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
		    MAX_PUBLIC_KEY_TEMPLATES, CKA_EC_POINT,
		    (CK_BYTE *)KeyParts[KMF_ECDSA_POINT].Data,
		    (CK_ULONG)KeyParts[KMF_ECDSA_POINT].Length) ||

		    !PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
		    MAX_PUBLIC_KEY_TEMPLATES, CKA_EC_PARAMS,
		    (CK_BYTE *)KeyParts[KMF_ECDSA_PARAMS].Data,
		    (CK_ULONG)KeyParts[KMF_ECDSA_PARAMS].Length)) {
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
static KMF_RETURN
PKCS_AcquirePublicKeyHandle(CK_SESSION_HANDLE ckSession,
	const KMF_X509_SPKI *pKey,
	CK_KEY_TYPE ckRequestedKeyType,
	CK_OBJECT_HANDLE *pckKeyHandle)
{
	KMF_RETURN mrReturn = KMF_OK;

	/* Key searching variables */
	CK_OBJECT_HANDLE ckKeyHandle = 0;
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

	/* Fetch the key class and algorithm from the object */
	ckNumTemplates = 0;
	if (!PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
	    ckMaxTemplates, CKA_CLASS, (CK_BYTE *)&ckObjClass,
	    sizeof (ckObjClass)) ||
	    !PKCS_AddTemplate(ckTemplate, &ckNumTemplates,
	    ckMaxTemplates, CKA_KEY_TYPE, (CK_BYTE *)&ckKeyType,
	    sizeof (ckKeyType))) {
		(void) C_DestroyObject(ckSession, ckKeyHandle);
		return (KMF_ERR_INTERNAL);
	}
	ckRv = C_GetAttributeValue(ckSession, ckKeyHandle,
	    ckTemplate,	ckNumTemplates);
	if (ckRv != CKR_OK) {
		(void) C_DestroyObject(ckSession, ckKeyHandle);
		return (ckRv);
	}

	/* Make sure the results match the expected values */
	if ((ckKeyType != ckRequestedKeyType) ||
	    (ckObjClass != CKO_PUBLIC_KEY)) {
		(void) C_DestroyObject(ckSession, ckKeyHandle);
		return (KMF_ERR_BAD_KEY_FORMAT);
	}

	/* Set the return values */
	*pckKeyHandle = ckKeyHandle;

	return (KMF_OK);
}

/*
 * Utility routine for verifying generic data using
 * the cryptographic framework (PKCS#11).
 * There are situations where we want to force this
 * operation to happen in a specific keystore.
 * For example:
 * libelfsign.so.1 verifies signatures on crypto libraries.
 * We must use pkcs11 functions to verify the pkcs11
 * plugins in order to keep the validation within the
 * Cryptographic Framework's FIPS-140 boundary. To avoid
 * a circular dependency, pksc11_softtoken.so.1 is
 * interposed by libkcfd.so.1 via kcfd, which prevents
 * libpkcs11.so.1's interfaces from being used when libkmf.so.1
 * is called from kcfd.
 *
 * This also saves code and time because verify operations
 * only use public keys and do not need acccess to any
 * keystore specific functions.
 */
KMF_RETURN
PKCS_VerifyData(KMF_HANDLE_T handle,
		KMF_ALGORITHM_INDEX AlgorithmId,
		KMF_X509_SPKI *keyp,
		KMF_DATA *data,
		KMF_DATA *signature)
{
	KMF_RETURN	rv = KMF_OK;
	CK_RV		ckRv;
	KMF_HANDLE	*kmfh = (KMF_HANDLE *)handle;
	CK_MECHANISM	ckMechanism;
	CK_MECHANISM_TYPE mechtype, hashmech;
	CK_OBJECT_HANDLE ckKeyHandle = 0;
	CK_KEY_TYPE	pk11keytype;
	CK_SESSION_HANDLE ckSession = 0;
	CK_ATTRIBUTE	subprime = { CKA_SUBPRIME, NULL, 0 };
	CK_BYTE		*dataptr;
	CK_ULONG	datalen;
	KMF_DATA	hashData = { 0, NULL };
	uchar_t		digest[1024];

	if (AlgorithmId == KMF_ALGID_NONE)
		return (KMF_ERR_BAD_ALGORITHM);

	if (get_pk11_data(AlgorithmId, &pk11keytype, &mechtype, &hashmech, 1))
		return (KMF_ERR_BAD_ALGORITHM);

	/*
	 * Verify in metaslot/softtoken since only the public key is needed
	 * and not all hardware tokens support the combined [hash]-RSA/DSA/EC
	 * mechanisms.
	 */
	rv = kmf_create_pk11_session(&ckSession, mechtype, 0);
	if (rv != KMF_OK)
		return (rv);

	/* Fetch the verifying key */
	rv = PKCS_AcquirePublicKeyHandle(ckSession, keyp,
	    pk11keytype, &ckKeyHandle);

	if (rv != KMF_OK) {
		(void) C_CloseSession(ckSession);
		return (rv);
	}
	dataptr = data->Data;
	datalen = data->Length;
	/*
	 * For some mechanisms, we must compute the hash separately
	 * and then do the verify.
	 */
	if (hashmech != 0 &&
	    (mechtype == CKM_ECDSA ||
	    mechtype == CKM_DSA ||
	    mechtype == CKM_RSA_PKCS)) {
		hashData.Data = digest;
		hashData.Length = sizeof (digest);

		rv = PKCS_DigestData(handle, ckSession,
		    hashmech, data, &hashData,
		    (mechtype == CKM_RSA_PKCS));
		if (rv)
			goto cleanup;

		dataptr = hashData.Data;
		datalen = hashData.Length;
	}
	if (mechtype == CKM_DSA &&
	    hashmech == CKM_SHA256) {
		/*
		 * FIPS 186-3 says that when using DSA
		 * the hash must be truncated to the size of the
		 * subprime.
		 */
		ckRv = C_GetAttributeValue(ckSession,
		    ckKeyHandle, &subprime, 1);
		if (ckRv != CKR_OK)  {
			kmfh->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN;
			kmfh->lasterr.errcode = ckRv;
			rv = KMF_ERR_INTERNAL;
			goto cleanup;
		}
		datalen = subprime.ulValueLen;
	}

	ckMechanism.mechanism = mechtype;
	ckMechanism.pParameter = NULL;
	ckMechanism.ulParameterLen = 0;

	ckRv = C_VerifyInit(ckSession, &ckMechanism, ckKeyHandle);
	if (ckRv != CKR_OK) {
		kmfh->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN;
		kmfh->lasterr.errcode = ckRv;
		rv = KMF_ERR_INTERNAL;
		goto cleanup;
	}
	ckRv = C_Verify(ckSession,
	    dataptr, datalen,
	    (CK_BYTE *)signature->Data,
	    (CK_ULONG)signature->Length);

	if (ckRv != CKR_OK) {
		kmfh->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN;
		kmfh->lasterr.errcode = ckRv;
		rv = KMF_ERR_INTERNAL;
	}

cleanup:
	if (ckKeyHandle != 0)
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
	CK_RV ckRv;
	CK_MECHANISM ckMechanism;
	CK_MECHANISM_TYPE mechtype;
	CK_KEY_TYPE keytype;
	CK_OBJECT_HANDLE ckKeyHandle = 0;
	CK_SESSION_HANDLE ckSession = NULL;
	CK_ULONG out_len = 0, in_len = 0, total_encrypted = 0;
	uint8_t *in_data, *out_data;
	int i, blocks, block_size;
	CK_ATTRIBUTE ckTemplate[2];
	CK_ULONG ckNumTemplates;
	CK_ULONG ckMaxTemplates = (sizeof (ckTemplate) /
	    sizeof (CK_ATTRIBUTE));

	if (get_pk11_data(AlgorithmId, &keytype, &mechtype, NULL, 0))
		return (KMF_ERR_BAD_ALGORITHM);

	rv = kmf_create_pk11_session(&ckSession, mechtype, CKF_ENCRYPT);
	if (rv != KMF_OK)
		return (rv);

	/* Get the public key used in encryption */
	rv = PKCS_AcquirePublicKeyHandle(ckSession, keyp,
	    keytype, &ckKeyHandle);

	if (rv != KMF_OK) {
		(void) C_CloseSession(ckSession);
		return (rv);
	}

	/* Get the modulus length */
	ckNumTemplates = 0;
	if (!PKCS_AddTemplate(ckTemplate, &ckNumTemplates, ckMaxTemplates,
	    CKA_MODULUS, (CK_BYTE *)NULL, sizeof (CK_ULONG))) {
		if (ckKeyHandle != 0)
			(void) C_DestroyObject(ckSession, ckKeyHandle);
		(void) C_CloseSession(ckSession);
		return (KMF_ERR_INTERNAL);
	}

	ckRv = C_GetAttributeValue(ckSession, ckKeyHandle,
	    ckTemplate, ckNumTemplates);

	if (ckRv != CKR_OK) {
		if (ckKeyHandle != 0)
			(void) C_DestroyObject(ckSession, ckKeyHandle);
		kmfh->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN;
		kmfh->lasterr.errcode = ckRv;
		(void) C_CloseSession(ckSession);
		return (KMF_ERR_INTERNAL);
	}
	out_len = ckTemplate[0].ulValueLen;

	if (out_len > ciphertext->Length) {
		if (ckKeyHandle != 0)
			(void) C_DestroyObject(ckSession, ckKeyHandle);
		(void) C_CloseSession(ckSession);
		return (KMF_ERR_BUFFER_SIZE);
	}

	ckMechanism.mechanism = mechtype;
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
			if (ckKeyHandle != 0)
				(void) C_DestroyObject(ckSession, ckKeyHandle);
			kmfh->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN;
			kmfh->lasterr.errcode = ckRv;
			(void) C_CloseSession(ckSession);
			return (KMF_ERR_INTERNAL);
		}
		ckRv = C_Encrypt(ckSession, (CK_BYTE_PTR)in_data, block_size,
		    (CK_BYTE_PTR)out_data, &out_len);

		if (ckRv != CKR_OK) {
			if (ckKeyHandle != 0)
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
			if (ckKeyHandle != 0)
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
			if (ckKeyHandle != 0)
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

	if (ckKeyHandle != 0)
		(void) C_DestroyObject(ckSession, ckKeyHandle);

	(void) C_CloseSession(ckSession);
	return (rv);

}

static void
create_id_hash(KMF_DATA *IDInput, KMF_DATA *IDOutput)
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
		create_id_hash(&KeyParts[KMF_RSA_MODULUS], ID);
	} else if (algId == KMF_ALGID_DSA) {
		create_id_hash(&KeyParts[KMF_DSA_PUBLIC_VALUE], ID);
	} else if (algId == KMF_ALGID_SHA1WithECDSA ||
	    algId == KMF_ALGID_ECDSA) {
		create_id_hash(&KeyParts[KMF_ECDSA_POINT], ID);
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

/*
 * For PKCS1 encoding (necessary for RSA signatures), we
 * must prepend the following prefixes before computing
 * the digest.
 */
static uchar_t SHA1_DER_PREFIX[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
	0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};
static uchar_t MD5_DER_PREFIX[] = {
	0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,
	0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00,
	0x04, 0x10
};
static uchar_t SHA256_DER_PREFIX[] = {0x30, 0x31, 0x30, 0x0d,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20};

static uchar_t SHA384_DER_PREFIX[] = {0x30, 0x41, 0x30, 0x0d,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30};

static uchar_t SHA512_DER_PREFIX[] = {0x30, 0x51, 0x30, 0x0d,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40};

#define	MAX_SHA2_DIGEST_LENGTH 64
/*
 * Compute hashes using metaslot (or softtoken).
 * Not all hardware tokens support the combined HASH + RSA/EC
 * Signing operations so it is safer to separate the hashing
 * from the signing.  This function generates a hash using a
 * separate session.  The resulting digest can be signed later.
 */
KMF_RETURN
PKCS_DigestData(KMF_HANDLE_T handle,
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_TYPE mechtype,
    KMF_DATA *tobesigned, KMF_DATA *output,
    boolean_t pkcs1_encoding)
{
	KMF_RETURN	rv = KMF_OK;
	CK_RV		ckrv;
	CK_MECHANISM	mechanism;
	KMF_HANDLE	*kmfh = (KMF_HANDLE *)handle;
	CK_BYTE		outbuf[MAX_SHA2_DIGEST_LENGTH +
	    sizeof (SHA512_DER_PREFIX)];
	CK_ULONG	outlen = sizeof (outbuf);

	mechanism.mechanism = mechtype;
	mechanism.pParameter = NULL;
	mechanism.ulParameterLen = 0;

	ckrv = C_DigestInit(hSession, &mechanism);
	if (ckrv != CKR_OK) {
		kmfh->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN;
		kmfh->lasterr.errcode = ckrv;
		rv = KMF_ERR_INTERNAL;
		goto end;
	}

	ckrv = C_Digest(hSession, tobesigned->Data,
	    tobesigned->Length, outbuf, &outlen);
	if (ckrv != CKR_OK) {
		kmfh->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN;
		kmfh->lasterr.errcode = ckrv;
		rv = KMF_ERR_INTERNAL;
	}

	if (pkcs1_encoding) {
		uchar_t *pfx;
		int pfxlen;
		switch (mechtype) {
			case CKM_MD5:
				pfx = MD5_DER_PREFIX;
				pfxlen = sizeof (MD5_DER_PREFIX);
				break;
			case CKM_SHA_1:
				pfx = SHA1_DER_PREFIX;
				pfxlen = sizeof (SHA1_DER_PREFIX);
				break;
			case CKM_SHA256:
				pfx = SHA256_DER_PREFIX;
				pfxlen = sizeof (SHA256_DER_PREFIX);
				break;
			case CKM_SHA384:
				pfx = SHA384_DER_PREFIX;
				pfxlen = sizeof (SHA384_DER_PREFIX);
				break;
			case CKM_SHA512:
				pfx = SHA512_DER_PREFIX;
				pfxlen = sizeof (SHA512_DER_PREFIX);
				break;
			default:
				rv = KMF_ERR_BAD_ALGORITHM;
				goto end;
		}
		(void) memcpy(output->Data, pfx, pfxlen);
		(void) memcpy(output->Data + pfxlen, outbuf, outlen);
		output->Length = outlen + pfxlen;
	} else {
		(void) memcpy(output->Data, outbuf, outlen);
		output->Length = outlen;
	}

end:
	return (rv);
}
