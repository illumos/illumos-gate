/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <etypes.h>
#include <security/cryptoki.h>
#include <security/pkcs11.h>

/*
 * get_algo
 *
 * This routine provides a mapping from Kerberos encryption
 * and hash types to PKCS#11 encryption and hash types.
 */
CK_RV
get_algo(krb5_enctype etype, KRB5_MECH_TO_PKCS *algos)
{
	switch (etype) {
		case ENCTYPE_DES_CBC_CRC:
			algos->enc_algo = CKM_DES_CBC;
			algos->hash_algo = 0;
			algos->str2key_algo = 0;
			algos->flags = USE_ENCR;
			return (CKR_OK);
		case ENCTYPE_DES_CBC_MD5:
			algos->enc_algo = CKM_DES_CBC;
			algos->hash_algo = CKM_MD5;
			algos->str2key_algo = 0;
			algos->flags = USE_ENCR | USE_HASH;
			return (CKR_OK);
		case ENCTYPE_DES_CBC_RAW:
			algos->enc_algo = CKM_DES_CBC;
			algos->hash_algo = 0;
			algos->str2key_algo = 0;
			algos->flags = USE_ENCR;
			return (CKR_OK);
		case ENCTYPE_DES_HMAC_SHA1:
			algos->enc_algo = CKM_DES_CBC;
			algos->hash_algo = CKM_SHA_1_HMAC;
			algos->str2key_algo = 0;
			algos->flags = USE_ENCR | USE_HASH;
			return (CKR_OK);
		case ENCTYPE_DES3_CBC_SHA1:
			algos->enc_algo = CKM_DES3_CBC;
			algos->hash_algo = CKM_SHA_1_HMAC;
			algos->str2key_algo = 0;
			algos->flags = USE_ENCR | USE_HASH;
			return (CKR_OK);
		case ENCTYPE_DES3_CBC_RAW:
			algos->enc_algo = CKM_DES3_CBC;
			algos->hash_algo = 0;
			algos->str2key_algo = 0;
			algos->flags = USE_ENCR;
			return (CKR_OK);
		case ENCTYPE_ARCFOUR_HMAC:
		case ENCTYPE_ARCFOUR_HMAC_EXP:
			algos->enc_algo = CKM_RC4;
			algos->hash_algo = CKM_MD5_HMAC;
			algos->str2key_algo = 0;
			algos->flags = USE_ENCR;
			return (CKR_OK);
		case ENCTYPE_AES128_CTS_HMAC_SHA1_96:
		case ENCTYPE_AES256_CTS_HMAC_SHA1_96:
			algos->enc_algo = CKM_AES_CBC;
			algos->hash_algo = CKM_SHA_1_HMAC;
			algos->str2key_algo = CKM_PKCS5_PBKD2;
			algos->flags = USE_ENCR;
			return (CKR_OK);
	}
	return (CKR_MECHANISM_INVALID);
}

/*
 * get_key_type
 *
 * map Kerberos key types to PKCS#11 key type values.
 */
CK_RV
get_key_type(krb5_enctype etype, CK_KEY_TYPE *keyType)
{
	switch (etype) {
		case ENCTYPE_DES_CBC_CRC:
		case ENCTYPE_DES_CBC_MD5:
		case ENCTYPE_DES_CBC_RAW:
		case ENCTYPE_DES_HMAC_SHA1:
			*keyType = CKK_DES;
			return (CKR_OK);
		case ENCTYPE_DES3_CBC_SHA1:
		case ENCTYPE_DES3_CBC_RAW:
			*keyType = CKK_DES3;
			return (CKR_OK);
		case ENCTYPE_AES128_CTS_HMAC_SHA1_96:
		case ENCTYPE_AES256_CTS_HMAC_SHA1_96:
			*keyType = CKK_AES;
			return (CKR_OK);
		case ENCTYPE_ARCFOUR_HMAC:
		case ENCTYPE_ARCFOUR_HMAC_EXP:
			*keyType = CKK_RC4;
			return (CKR_OK);
	}

	/* There's no appropriate error.  Just return the general one */
	return (CKR_GENERAL_ERROR);
}

/*
 * slot_supports_krb5
 *
 * Determine whether the PKCS#11 "slot" supports the necessary
 * crypto needed for Kerberos functionality.
 *
 * Return values:
 * TRUE = The given slot is OK for Kerberos
 * FALSE = Not ok, try something else.
 */
krb5_error_code
slot_supports_krb5(CK_SLOT_ID_PTR slotid)
{
	int i;
	CK_MECHANISM_INFO info;
	CK_RV rv;
	int enctypes_found = 0;
	KRB5_MECH_TO_PKCS algos;
	krb5_enctype tempenctype;

	for (i = 0; i < krb5_enctypes_length; i++) {
		tempenctype = krb5_enctypes_list[i].etype;
		if ((rv = get_algo(tempenctype, &algos)) != CKR_OK) {
			KRB5_LOG0(KRB5_ERR, "Failed to get algorithm.");
			/*
			 * If the algorithm is not available, disable
			 * this enctype so kerberos doesn't try to use it
			 * again.
			 */
			krb5_enctypes_list[i].etype = -1;
			krb5_enctypes_list[i].in_string = "<unsupported>";
			krb5_enctypes_list[i].out_string = "<unsupported>";
			continue;
		}
		if (ENC_DEFINED(algos)) {
			size_t keysize, keylength;
			rv = C_GetMechanismInfo(*slotid, algos.enc_algo, &info);
			if (rv != CKR_OK) {
				KRB5_LOG1(KRB5_ERR, "C_GetMechanismInfo failed "
				    "for encr algorith %s: 0x%x\n",
				    krb5_enctypes_list[i].in_string,
				    rv);
				return (FALSE);
			}
			/*
			 * If the encryption algorithm is supported,
			 * make sure it supports the correct key sizes.
			 * If not, disable this enctype and continue.
			 */
			keysize = krb5_enctypes_list[i].enc->keybytes;
			keylength = krb5_enctypes_list[i].enc->keylength;

			if (keylength > info.ulMaxKeySize) {
				krb5_enctypes_list[i].etype = -1;
				krb5_enctypes_list[i].in_string =
					"<unsupported>";
				krb5_enctypes_list[i].out_string =
					"<unsupported>";
				continue;
			}
			if (!(info.flags & (CKF_ENCRYPT|CKF_RNG)))
				return (FALSE);
		}
		if (HASH_DEFINED(algos)) {
			rv = C_GetMechanismInfo(*slotid, algos.hash_algo,
			    &info);
			if (rv != CKR_OK) {
				KRB5_LOG1(KRB5_ERR, "C_GetMechanismInfo failed "
				    "for hash algorithm %s: 0x%x\n",
				    krb5_enctypes_list[i].in_string,
				    rv);
				return (FALSE);
			}
			if (!(info.flags & (CKF_DIGEST|CKF_SIGN|CKF_RNG)))
				return (FALSE);
		}
		if (algos.str2key_algo != 0) {
			rv = C_GetMechanismInfo(*slotid, algos.str2key_algo,
			    &info);
			if (rv != CKR_OK) {
				KRB5_LOG(KRB5_ERR, "C_GetMechanismInfo failed "
				    "for str2key algorithm: 0x%x\n", rv);
				return (FALSE);
			}
		}
		enctypes_found++;
	}
	/*
	 * If NO enctypes were found to be supported, return FALSE.
	 */
	if (!enctypes_found) {
		KRB5_LOG0(KRB5_ERR,
			"No crypto support available from PKCS#11.");
		return (FALSE);
	}
	return (TRUE);
}
