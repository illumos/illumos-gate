/*
 * Copyright (c) 1995-2000 Intel Corporation. All rights reserved.
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <kmfapiP.h>
#include <algorithm.h>
#include <security/cryptoki.h>

typedef struct _pkcs_key_type_map
{
	KMF_ALGORITHM_INDEX kmfAlgorithmId;
	CK_KEY_TYPE ckKeyType;
}
PKCS_KEY_TYPE_MAP;

static const PKCS_KEY_TYPE_MAP _PKCS2KMFKeyTypeMap[] = {
	{ KMF_ALGID_RSA, CKK_RSA },
	{ KMF_ALGID_DSA, CKK_DSA }
};

#define	SUP(_ckmech_, _kmfalg_, _kmfcls_, _kmfmode_, _multi_, \
	_fixkelen_, _keylen_, _fixblksz_, _blksz_, _reqiv_, _ivlen_,\
	_regalgflg_, _keytype_, _desc_) \
	{ _ckmech_, _kmfalg_, _kmfcls_, _kmfmode_, _multi_, _fixkelen_,\
	_keylen_, _fixblksz_, _blksz_, _reqiv_, _ivlen_, _regalgflg_,\
	_keytype_, _desc_ },

static const PKCS_ALGORITHM_MAP _PKCS2KMFMap[] = {
/*
 * PKCS #11 Mechanism,
 * Alg. ID
 * Alg. Class
 * Alg. Mode
 * Milti-Part
 * Fix Key Length
 * Key Length
 * Fix Block Size
 * Block Size
 * Needs IV
 * IV Length
 * Alg. Flags
 * Type
 * Description
 */
SUP(CKM_RSA_PKCS_KEY_PAIR_GEN, KMF_ALGID_RSA, KMF_ALGCLASS_KEYGEN,\
	KMF_ALGMODE_NONE, 0, 0, 0,\
	0, 0, 0, 0, CKF_GENERATE_KEY_PAIR,\
	CKK_RSA, "RSA PKCS #1 Key Pair Generation")
SUP(CKM_RSA_X_509, KMF_ALGID_RSA, KMF_ALGCLASS_ASYMMETRIC, KMF_ALGMODE_NONE,
	0, 0, 0, 0, 0, 0, 0, CKF_ENCRYPT,
	CKK_RSA, "RSA RAW Encryption")
SUP(CKM_RSA_X_509, KMF_ALGID_RSA, KMF_ALGCLASS_ASYMMETRIC, KMF_ALGMODE_NONE,
	0, 0, 0, 0, 0, 0, 0, CKF_SIGN_RECOVER,
	CKK_RSA, "RSA RAW Private Key Encryption")
SUP(CKM_RSA_X_509, KMF_ALGID_RSA, KMF_ALGCLASS_SIGNATURE, KMF_ALGMODE_NONE,
	0, 0, 0, 0, 0, 0, 0, CKF_SIGN,
	CKK_RSA, "RSA RAW Signature")
SUP(CKM_RSA_PKCS, KMF_ALGID_RSA, KMF_ALGCLASS_SIGNATURE,
	KMF_ALGMODE_PKCS1_EMSA_V15,
	0, 0, 0, 0, 0, 0, 0, CKF_SIGN, CKK_RSA,
	"RSA PKCS #1 Signature")
SUP(CKM_MD2_RSA_PKCS, KMF_ALGID_MD2WithRSA, KMF_ALGCLASS_SIGNATURE,
	KMF_ALGMODE_PKCS1_EMSA_V15, 1, 0, 0, 0, 0,
	0, 0, CKF_SIGN, CKK_RSA, "MD2 w/RSA Signature")
SUP(CKM_MD5_RSA_PKCS, KMF_ALGID_MD5WithRSA, KMF_ALGCLASS_SIGNATURE,
	KMF_ALGMODE_PKCS1_EMSA_V15, 1, 0, 0, 0, 0,
	0, 0, CKF_SIGN, CKK_RSA, "MD5 w/RSA Signature")
SUP(CKM_SHA1_RSA_PKCS, KMF_ALGID_SHA1WithRSA, KMF_ALGCLASS_SIGNATURE,
	KMF_ALGMODE_PKCS1_EMSA_V15, 1, 0, 0, 0, 0,
	0, 0, CKF_SIGN, CKK_RSA, "SHA-1 w/RSA Signature")

SUP(CKM_DSA_KEY_PAIR_GEN, KMF_ALGID_DSA, KMF_ALGCLASS_KEYGEN, KMF_ALGMODE_NONE,
	0, 0, 0, 0, 0, 0, 0,
	CKF_GENERATE_KEY_PAIR, CKK_DSA, "DSA Key Pair Generation")

SUP(CKM_DSA, KMF_ALGID_DSA, KMF_ALGCLASS_SIGNATURE, KMF_ALGMODE_NONE,
	0, 0, 0, 0, 0, 0, 0, CKF_SIGN,
	CKK_DSA, "DSA Signature")

SUP(CKM_DSA_SHA1, KMF_ALGID_SHA1WithDSA, KMF_ALGCLASS_SIGNATURE,
	KMF_ALGMODE_NONE, 1, 0, 0, 0, 0, 0,
	0, CKF_SIGN, CKK_DSA, "SHA-1 w/DSA Signature")

SUP(CKM_SHA_1, KMF_ALGID_SHA1, KMF_ALGCLASS_DIGEST, KMF_ALGMODE_NONE,
	1, 1, 20, 0, 0, 0, 0, CKF_DIGEST, (CK_KEY_TYPE)-1, "SHA-1")
};

/* Undefine the macro definitions */
#undef SUP

/* Number of items in the algorithm map table */
#define	_PKCS2KMFMapCount (\
	sizeof (_PKCS2KMFMap) / sizeof (_PKCS2KMFMap[0]))

/* Indicator that the algorithm was not found */
#define	PKCS_ALGORITHM_NOT_FOUND    ((uint32_t)(~0))

/*
 * Name: pkcs_get_alg_map
 *
 * Description:
 *  Searches the _PKCS2KMFMap table for a matching set of alg.
 *  description parameters.
 *
 * Parameters:
 *  algType (input) - KMF_ALGCLASS_* identifier to match.
 *  algID (input) - KMF_ALGID_* identifier to match.
 *  mode (input) - KMF_ALGMODE_* identifier to match. Use
 *      KMF_ALGMODE_NONE if a mode does not apply.
 *
 * Returns:
 *  Pointer to the lookup table entry that matches requested parameters.
 *  Ptr->keylength will equal PKCS11CONVERT_NOT_FOUND if no match is found.
 */
PKCS_ALGORITHM_MAP *
pkcs_get_alg_map(KMF_ALGCLASS algType, uint32_t algID, uint32_t mode)
{
	uint32_t i = 0;

	for (i = 0; i < _PKCS2KMFMapCount; i++) {
		if ((_PKCS2KMFMap[i].context_type == algType) &&
		    (_PKCS2KMFMap[i].algorithm == algID) &&
		    (_PKCS2KMFMap[i].enc_mode == mode)) {
		return ((PKCS_ALGORITHM_MAP *)&(_PKCS2KMFMap[i]));
		}
	}

	return (NULL);
}

KMF_BOOL
pkcs_algid_to_keytype(KMF_ALGORITHM_INDEX AlgId,
	CK_KEY_TYPE *pckKeyType)
{
	uint32_t uIndex;
	uint32_t uMapSize =
	    sizeof (_PKCS2KMFKeyTypeMap) / sizeof (PKCS_KEY_TYPE_MAP);

	for (uIndex = 0; uIndex < uMapSize; uIndex++) {
		if (_PKCS2KMFKeyTypeMap[uIndex].kmfAlgorithmId == AlgId) {
			*pckKeyType = _PKCS2KMFKeyTypeMap[uIndex].ckKeyType;
			return (1);
		}
	}

	return (0);
}
