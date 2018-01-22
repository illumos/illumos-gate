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
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include <sys/crypto/common.h>
#include <aes_impl.h>
#include <blowfish_impl.h>
#include <des_impl.h>
#include <arcfour.h>
#include <cryptoutil.h>
#include "softGlobal.h"
#include "softSession.h"
#include "softObject.h"
#include "softDSA.h"
#include "softRSA.h"
#include "softDH.h"
#include "softEC.h"
#include "softMAC.h"
#include "softOps.h"
#include "softKeys.h"
#include "softKeystore.h"
#include "softSSL.h"
#include "softASN1.h"


#define	local_min(a, b)	((a) < (b) ? (a) : (b))

static CK_RV
soft_pkcs12_pbe(soft_session_t *, CK_MECHANISM_PTR, soft_object_t *);

/*
 * Create a temporary key object struct by filling up its template attributes.
 */
CK_RV
soft_gen_keyobject(CK_ATTRIBUTE_PTR pTemplate,  CK_ULONG ulCount,
    CK_ULONG *objecthandle_p, soft_session_t *sp,
    CK_OBJECT_CLASS class, CK_KEY_TYPE key_type, CK_ULONG keylen, CK_ULONG mode,
    boolean_t internal)
{

	CK_RV rv;
	soft_object_t *new_objp = NULL;

	new_objp = calloc(1, sizeof (soft_object_t));
	if (new_objp == NULL) {
		return (CKR_HOST_MEMORY);
	}

	new_objp->extra_attrlistp = NULL;

	/*
	 * Validate attribute template and fill in the attributes
	 * in the soft_object_t.
	 */
	rv = soft_build_key(pTemplate, ulCount, new_objp, class, key_type,
	    keylen, mode);
	if (rv != CKR_OK) {
		goto fail_cleanup1;
	}

	/*
	 * If generating a key is an internal request (i.e. not a C_XXX
	 * API request), then skip the following checks.
	 */
	if (!internal) {
		rv = soft_pin_expired_check(new_objp);
		if (rv != CKR_OK) {
			goto fail_cleanup2;
		}

		rv = soft_object_write_access_check(sp, new_objp);
		if (rv != CKR_OK) {
			goto fail_cleanup2;
		}
	}

	/* Initialize the rest of stuffs in soft_object_t. */
	(void) pthread_mutex_init(&new_objp->object_mutex, NULL);
	new_objp->magic_marker = SOFTTOKEN_OBJECT_MAGIC;

	/* Write the new token object to the keystore */
	if (IS_TOKEN_OBJECT(new_objp)) {
		new_objp->version = 1;
		new_objp->session_handle = (CK_SESSION_HANDLE)NULL;
		soft_add_token_object_to_slot(new_objp);
		/*
		 * Type casting the address of an object struct to
		 * an object handle.
		 */
		*objecthandle_p = (CK_ULONG)new_objp;

		return (CKR_OK);
	}

	new_objp->session_handle = (CK_SESSION_HANDLE)sp;

	/* Add the new object to the session's object list. */
	soft_add_object_to_session(new_objp, sp);

	/* Type casting the address of an object struct to an object handle. */
	*objecthandle_p =  (CK_ULONG)new_objp;

	return (CKR_OK);

fail_cleanup2:
	/*
	 * When any error occurs after soft_build_key(), we will need to
	 * clean up the memory allocated by the soft_build_key().
	 */
	soft_cleanup_object(new_objp);

fail_cleanup1:
	if (new_objp) {
		/*
		 * The storage allocated inside of this object should have
		 * been cleaned up by the soft_build_key() if it failed.
		 * Therefore, we can safely free the object.
		 */
		free(new_objp);
	}

	return (rv);
}

CK_RV
soft_genkey(soft_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{

	CK_RV rv = CKR_OK;
	soft_object_t *secret_key;
	CK_KEY_TYPE key_type;
	CK_ULONG keylen = 0;
	CK_ULONG i;
	int des_strength = 0;
	int retry = 0;
	int keyfound = 0;
	boolean_t is_ssl_mech = B_FALSE;

	switch (pMechanism->mechanism) {
	case CKM_DES_KEY_GEN:
		key_type = CKK_DES;
		break;

	case CKM_DES2_KEY_GEN:
		key_type = CKK_DES2;
		break;

	case CKM_DES3_KEY_GEN:
		key_type = CKK_DES3;
		break;

	case CKM_AES_KEY_GEN:
		key_type = CKK_AES;
		break;

	case CKM_BLOWFISH_KEY_GEN:
		key_type = CKK_BLOWFISH;
		break;

	case CKM_RC4_KEY_GEN:
		key_type = CKK_RC4;
		break;

	case CKM_SSL3_PRE_MASTER_KEY_GEN:
	case CKM_TLS_PRE_MASTER_KEY_GEN:
		if (pMechanism->pParameter == NULL ||
		    pMechanism->ulParameterLen != sizeof (CK_VERSION))
			return (CKR_TEMPLATE_INCOMPLETE);
		is_ssl_mech = B_TRUE;
		key_type = CKK_GENERIC_SECRET;
		keylen = 48;
		break;

	case CKM_PKCS5_PBKD2:
		keyfound = 0;
		for (i = 0; i < ulCount && !keyfound; i++) {
			if (pTemplate[i].type == CKA_KEY_TYPE &&
			    pTemplate[i].pValue != NULL) {
				key_type = *((CK_KEY_TYPE*)pTemplate[i].pValue);
				keyfound = 1;
			}
		}
		if (!keyfound)
			return (CKR_TEMPLATE_INCOMPLETE);
		/*
		 * Make sure that parameters were given for this
		 * mechanism.
		 */
		if (pMechanism->pParameter == NULL ||
		    pMechanism->ulParameterLen !=
		    sizeof (CK_PKCS5_PBKD2_PARAMS))
			return (CKR_TEMPLATE_INCOMPLETE);
		break;

	case CKM_PBE_SHA1_RC4_128:
		keyfound = 0;
		for (i = 0; i < ulCount; i++) {
			if (pTemplate[i].type == CKA_KEY_TYPE &&
			    pTemplate[i].pValue != NULL) {
				key_type = *((CK_KEY_TYPE*)pTemplate[i].pValue);
				keyfound = 1;
			}
			if (pTemplate[i].type == CKA_VALUE_LEN &&
			    pTemplate[i].pValue != NULL) {
				keylen = *((CK_ULONG*)pTemplate[i].pValue);
			}
		}
		/* If a keytype was specified, it had better be CKK_RC4 */
		if (keyfound && key_type != CKK_RC4)
			return (CKR_TEMPLATE_INCONSISTENT);
		else if (!keyfound)
			key_type = CKK_RC4;

		/* If key length was specified, it better be 16 bytes */
		if (keylen != 0 && keylen != 16)
			return (CKR_TEMPLATE_INCONSISTENT);

		/*
		 * Make sure that parameters were given for this
		 * mechanism.
		 */
		if (pMechanism->pParameter == NULL ||
		    pMechanism->ulParameterLen !=
		    sizeof (CK_PBE_PARAMS))
			return (CKR_TEMPLATE_INCOMPLETE);
		break;
	default:
		return (CKR_MECHANISM_INVALID);
	}

	/* Create a new object for secret key. */
	rv = soft_gen_keyobject(pTemplate, ulCount, phKey, session_p,
	    CKO_SECRET_KEY, key_type, keylen, SOFT_GEN_KEY, B_FALSE);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Obtain the secret object pointer. */
	secret_key = (soft_object_t *)*phKey;

	switch (pMechanism->mechanism) {
	case CKM_DES_KEY_GEN:
		/*
		 * Set up key value len since it is not a required
		 * attribute for C_GenerateKey.
		 */
		keylen = OBJ_SEC_VALUE_LEN(secret_key) = DES_KEYSIZE;
		des_strength = DES;
		break;

	case CKM_DES2_KEY_GEN:
		/*
		 * Set up key value len since it is not a required
		 * attribute for C_GenerateKey.
		 */
		keylen = OBJ_SEC_VALUE_LEN(secret_key) = DES2_KEYSIZE;
		des_strength = DES2;
		break;

	case CKM_DES3_KEY_GEN:
		/*
		 * Set up key value len since it is not a required
		 * attribute for C_GenerateKey.
		 */
		keylen = OBJ_SEC_VALUE_LEN(secret_key) = DES3_KEYSIZE;
		des_strength = DES3;
		break;

	case CKM_SSL3_PRE_MASTER_KEY_GEN:
	case CKM_TLS_PRE_MASTER_KEY_GEN:
		secret_key->bool_attr_mask |= DERIVE_BOOL_ON;
	/* FALLTHRU */

	case CKM_AES_KEY_GEN:
	case CKM_BLOWFISH_KEY_GEN:
	case CKM_PBE_SHA1_RC4_128:
	case CKM_RC4_KEY_GEN:
		keylen = OBJ_SEC_VALUE_LEN(secret_key);
		break;

	case CKM_PKCS5_PBKD2:
		/*
		 * PKCS#11 does not allow one to specify key
		 * sizes for DES and 3DES, so we must set it here
		 * when using PBKD2 algorithms.
		 */
		if (key_type == CKK_DES) {
			OBJ_SEC_VALUE_LEN(secret_key) = DES_KEYSIZE;
			des_strength = DES;
		} else if (key_type == CKK_DES3) {
			OBJ_SEC_VALUE_LEN(secret_key) = DES3_KEYSIZE;
			des_strength = DES3;
		}

		keylen = OBJ_SEC_VALUE_LEN(secret_key);
		break;
	}

	if ((OBJ_SEC_VALUE(secret_key) = malloc(keylen)) == NULL) {
		if (IS_TOKEN_OBJECT(secret_key))
			soft_delete_token_object(secret_key, B_FALSE, B_FALSE);
		else
			soft_delete_object(session_p, secret_key,
			    B_FALSE, B_FALSE);

		return (CKR_HOST_MEMORY);
	}
	switch (pMechanism->mechanism) {
	case CKM_PBE_SHA1_RC4_128:
		/*
		 * Use the PBE algorithm described in PKCS#11 section
		 * 12.33 to derive the key.
		 */
		rv = soft_pkcs12_pbe(session_p, pMechanism, secret_key);
		break;
	case CKM_PKCS5_PBKD2:
		/* Generate keys using PKCS#5 PBKD2 algorithm */
		rv = soft_generate_pkcs5_pbkdf2_key(session_p, pMechanism,
		    secret_key);
		if (rv == CKR_OK && des_strength > 0) {
			/* Perform weak key checking for DES and DES3. */
			if (des_keycheck(OBJ_SEC_VALUE(secret_key),
			    des_strength, OBJ_SEC_VALUE(secret_key)) ==
			    B_FALSE) {
				/* We got a weak secret key. */
				rv = CKR_FUNCTION_FAILED;
			}
		}
		break;
	default:
		do {
			/* If this fails, bail out */
			rv = CKR_OK;
			if (pkcs11_get_urandom(
			    OBJ_SEC_VALUE(secret_key), keylen) < 0) {
				rv = CKR_DEVICE_ERROR;
				break;
			}

			/* Perform weak key checking for DES and DES3. */
			if (des_strength > 0) {
				rv = CKR_OK;
				if (des_keycheck(OBJ_SEC_VALUE(secret_key),
				    des_strength, OBJ_SEC_VALUE(secret_key)) ==
				    B_FALSE) {
					/* We got a weak key, retry! */
					retry++;
					rv = CKR_FUNCTION_FAILED;
				}
			}
			/*
			 * Copy over the SSL client version For SSL mechs
			 * The first two bytes of the key is the version
			 */
			if (is_ssl_mech)
				bcopy(pMechanism->pParameter,
				    OBJ_SEC_VALUE(secret_key),
				    sizeof (CK_VERSION));

		} while (rv != CKR_OK && retry < KEYGEN_RETRY);
		if (retry == KEYGEN_RETRY)
			rv = CKR_FUNCTION_FAILED;
		break;
	}

	if (rv != CKR_OK)
		if (IS_TOKEN_OBJECT(secret_key))
			soft_delete_token_object(secret_key, B_FALSE, B_FALSE);
		else
			soft_delete_object(session_p, secret_key,
			    B_FALSE, B_FALSE);

	if (IS_TOKEN_OBJECT(secret_key)) {
		/*
		 * All the info has been filled, so we can write to
		 * keystore now.
		 */
		rv = soft_put_object_to_keystore(secret_key);
		if (rv != CKR_OK)
			soft_delete_token_object(secret_key, B_FALSE, B_FALSE);
	}

	return (rv);
}

CK_RV
soft_genkey_pair(soft_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicAttrCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateAttrCount,
    CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{

	CK_RV rv;
	soft_object_t *public_key, *private_key;
	CK_KEY_TYPE key_type;

	switch (pMechanism->mechanism) {

	case CKM_RSA_PKCS_KEY_PAIR_GEN:
		key_type = CKK_RSA;
		break;

	case CKM_DSA_KEY_PAIR_GEN:
		key_type = CKK_DSA;
		break;

	case CKM_DH_PKCS_KEY_PAIR_GEN:
		key_type = CKK_DH;
		break;

	case CKM_EC_KEY_PAIR_GEN:
		key_type = CKK_EC;
		break;

	default:
		return (CKR_MECHANISM_INVALID);
	}

	/* Create a new object for public key. */
	rv = soft_gen_keyobject(pPublicKeyTemplate, ulPublicAttrCount,
	    phPublicKey, session_p, CKO_PUBLIC_KEY, key_type, 0,
	    SOFT_GEN_KEY, B_FALSE);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Obtain the public object pointer. */
	public_key = (soft_object_t *)*phPublicKey;

	/* Create a new object for private key. */
	rv = soft_gen_keyobject(pPrivateKeyTemplate, ulPrivateAttrCount,
	    phPrivateKey, session_p, CKO_PRIVATE_KEY, key_type, 0,
	    SOFT_GEN_KEY, B_FALSE);

	if (rv != CKR_OK) {
		/*
		 * Both public key and private key must be successful.
		 */
		if (IS_TOKEN_OBJECT(public_key))
			soft_delete_token_object(public_key, B_FALSE, B_FALSE);
		else
			soft_delete_object(session_p, public_key,
			    B_FALSE, B_FALSE);
		return (rv);
	}

	/* Obtain the private object pointer. */
	private_key = (soft_object_t *)*phPrivateKey;

	/*
	 * At this point, both public key and private key objects
	 * are settled with the application specified attributes.
	 * We are ready to generate the rest of key attributes based
	 * on the existing attributes.
	 */

	switch (key_type) {
	case CKK_RSA:
		rv = soft_rsa_genkey_pair(public_key, private_key);
		break;

	case CKK_DSA:
		rv = soft_dsa_genkey_pair(public_key, private_key);
		break;

	case CKK_DH:
		rv = soft_dh_genkey_pair(public_key, private_key);
		private_key->bool_attr_mask |= DERIVE_BOOL_ON;
		break;
	case CKK_EC:
		rv = soft_ec_genkey_pair(public_key, private_key);
		private_key->bool_attr_mask |= DERIVE_BOOL_ON;
		break;
	}

	if (rv != CKR_OK) {
		if (IS_TOKEN_OBJECT(public_key)) {
			soft_delete_token_object(public_key, B_FALSE, B_FALSE);
			soft_delete_token_object(private_key, B_FALSE, B_FALSE);
		} else {
			soft_delete_object(session_p, public_key,
			    B_FALSE, B_FALSE);
			soft_delete_object(session_p, private_key,
			    B_FALSE, B_FALSE);
		}
		return (rv);
	}

	if (IS_TOKEN_OBJECT(public_key)) {
		/*
		 * All the info has been filled, so we can write to
		 * keystore now.
		 */
		rv = soft_put_object_to_keystore(public_key);
		if (rv != CKR_OK) {
			soft_delete_token_object(public_key, B_FALSE, B_FALSE);
			soft_delete_token_object(private_key, B_FALSE, B_FALSE);
			return (rv);
		}
	}

	if (IS_TOKEN_OBJECT(private_key)) {
		rv = soft_put_object_to_keystore(private_key);
		if (rv != CKR_OK) {
			/*
			 * We also need to delete the public token object
			 * from keystore.
			 */
			soft_delete_token_object(public_key, B_TRUE, B_FALSE);
			soft_delete_token_object(private_key, B_FALSE, B_FALSE);
		}
	}

	return (rv);
}


CK_RV
soft_key_derive_check_length(soft_object_t *secret_key, CK_ULONG max_keylen)
{

	switch (secret_key->key_type) {
	case CKK_GENERIC_SECRET:
		if (OBJ_SEC_VALUE_LEN(secret_key) == 0) {
			OBJ_SEC_VALUE_LEN(secret_key) = max_keylen;
			return (CKR_OK);
		} else if (OBJ_SEC_VALUE_LEN(secret_key) > max_keylen) {
			return (CKR_ATTRIBUTE_VALUE_INVALID);
		}
		break;
	case CKK_RC4:
	case CKK_AES:
	case CKK_BLOWFISH:
		if ((OBJ_SEC_VALUE_LEN(secret_key) == 0) ||
		    (OBJ_SEC_VALUE_LEN(secret_key) > max_keylen)) {
			/* RC4 and AES has variable key length */
			return (CKR_ATTRIBUTE_VALUE_INVALID);
		}
		break;
	case CKK_DES:
		if (OBJ_SEC_VALUE_LEN(secret_key) == 0) {
			/* DES has a well-defined length */
			OBJ_SEC_VALUE_LEN(secret_key) = DES_KEYSIZE;
			return (CKR_OK);
		} else if (OBJ_SEC_VALUE_LEN(secret_key) != DES_KEYSIZE) {
			return (CKR_ATTRIBUTE_VALUE_INVALID);
		}
		break;
	case CKK_DES2:
		if (OBJ_SEC_VALUE_LEN(secret_key) == 0) {
			/* DES2 has a well-defined length */
			OBJ_SEC_VALUE_LEN(secret_key) = DES2_KEYSIZE;
			return (CKR_OK);
		} else if (OBJ_SEC_VALUE_LEN(secret_key) != DES2_KEYSIZE) {
			return (CKR_ATTRIBUTE_VALUE_INVALID);
		}
		break;

	default:
		return (CKR_MECHANISM_INVALID);
	}

	return (CKR_OK);
}

/*
 * PKCS#11 (12.33) says that v = 512 bits (64 bytes) for SHA1
 * PBE methods.
 */
#define	PKCS12_BUFFER_SIZE 64
/*
 * PKCS#12 defines 3 different ID bytes to be used for
 * deriving keys for different operations.
 */
#define	PBE_ID_ENCRYPT	1
#define	PBE_ID_IV	2
#define	PBE_ID_MAC	3
#define	PBE_CEIL(a, b)	(((a)/(b)) + (((a)%(b)) > 0))

static CK_RV
soft_pkcs12_pbe(soft_session_t *session_p,
    CK_MECHANISM_PTR pMechanism, soft_object_t *derived_key)
{
	CK_RV rv = CKR_OK;
	CK_PBE_PARAMS *params = pMechanism->pParameter;
	CK_ULONG c, i, j, k;
	CK_ULONG hashSize;
	CK_ULONG buffSize;
	/*
	 * Terse variable names are used to make following
	 * the PKCS#12 spec easier.
	 */
	CK_BYTE *A = NULL;
	CK_BYTE *Ai = NULL;
	CK_BYTE *B = NULL;
	CK_BYTE *D = NULL;
	CK_BYTE *I = NULL, *S, *P;
	CK_BYTE *keybuf = NULL;
	CK_ULONG Alen, Ilen, Slen, Plen, AiLen, Blen, Dlen;
	CK_ULONG keysize = OBJ_SEC_VALUE_LEN(derived_key);
	CK_MECHANISM digest_mech;

	/* U = hash function output bits */
	if (pMechanism->mechanism == CKM_PBE_SHA1_RC4_128) {
		hashSize = SHA1_HASH_SIZE;
		buffSize = PKCS12_BUFFER_SIZE;
		digest_mech.mechanism = CKM_SHA_1;
		digest_mech.pParameter = NULL;
		digest_mech.ulParameterLen = 0;
	} else {
		/* we only support 1 PBE mech for now */
		return (CKR_MECHANISM_INVALID);
	}
	keybuf = OBJ_SEC_VALUE(derived_key);

	Blen = Dlen = buffSize;
	D = (CK_BYTE *)malloc(Dlen);
	if (D == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanup;
	}

	B = (CK_BYTE *)malloc(Blen);
	if (B == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanup;
	}

	/*
	 * Initialize some values and create some buffers
	 * that we need later.
	 *
	 * Slen = buffSize * CEIL(SaltLength/buffSize)
	 */
	Slen = buffSize * PBE_CEIL(params->ulSaltLen, buffSize);

	/*
	 * Plen = buffSize * CEIL(PasswordLength/buffSize)
	 */
	Plen = buffSize * PBE_CEIL(params->ulPasswordLen, buffSize);

	/*
	 * From step 4: I = S + P, so: Ilen = Slen + Plen
	 */
	Ilen = Slen + Plen;
	I = (CK_BYTE *)malloc(Ilen);
	if (I == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanup;
	}

	S = I;
	P = I + Slen;

	/*
	 * Step 1.
	 * We are only interested in deriving keys for encrypt/decrypt
	 * for now, so construct the "D"iversifier accordingly.
	 */
	(void) memset(D, PBE_ID_ENCRYPT, Dlen);

	/*
	 * Step 2.
	 * Concatenate copies of the salt together to make S.
	 */
	for (i = 0; i < Slen; i += params->ulSaltLen) {
		(void) memcpy(S+i, params->pSalt,
		    ((Slen - i) > params->ulSaltLen ?
		    params->ulSaltLen : (Slen - i)));
	}

	/*
	 * Step 3.
	 * Concatenate copies of the password together to make
	 * a string P.
	 */
	for (i = 0; i < Plen; i += params->ulPasswordLen) {
		(void) memcpy(P+i, params->pPassword,
		    ((Plen - i) > params->ulPasswordLen ?
		    params->ulPasswordLen : (Plen - i)));
	}

	/*
	 * Step 4.
	 * I = S+P - this is now done because S and P are
	 * pointers into I.
	 *
	 * Step 5.
	 * c= CEIL[n/u]
	 * where n = pseudorandom bits of output desired.
	 */
	c = PBE_CEIL(keysize, hashSize);

	/*
	 * Step 6.
	 */
	Alen = c * hashSize;
	A = (CK_BYTE *)malloc(Alen);
	if (A == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanup;
	}
	AiLen = hashSize;
	Ai = (CK_BYTE *)malloc(AiLen);
	if (Ai == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanup;
	}

	/*
	 * Step 6a.
	 * Ai = Hr(D+I)
	 */
	for (i = 0; i < c; i++) {
		(void) pthread_mutex_lock(&session_p->session_mutex);

		if (session_p->sign.flags & CRYPTO_OPERATION_ACTIVE) {
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			rv = CKR_OPERATION_ACTIVE;
			goto cleanup;
		}
		session_p->sign.flags |= CRYPTO_OPERATION_ACTIVE;
		(void) pthread_mutex_unlock(&session_p->session_mutex);

		for (j = 0; j < params->ulIteration; j++) {
			rv = soft_digest_init(session_p, &digest_mech);
			if (rv != CKR_OK)
				goto digest_done;

			if (j == 0) {
				rv = soft_digest_update(session_p, D, Dlen);
				if (rv != CKR_OK)
					goto digest_done;

				rv = soft_digest_update(session_p, I, Ilen);
			} else {
				rv = soft_digest_update(session_p, Ai, AiLen);
			}
			if (rv != CKR_OK)
				goto digest_done;

			rv = soft_digest_final(session_p, Ai, &AiLen);
			if (rv != CKR_OK)
				goto digest_done;
		}
digest_done:
		(void) pthread_mutex_lock(&session_p->session_mutex);
		session_p->sign.flags &= ~CRYPTO_OPERATION_ACTIVE;
		(void) pthread_mutex_unlock(&session_p->session_mutex);

		if (rv != CKR_OK)
			goto cleanup;
		/*
		 * Step 6b.
		 * Concatenate Ai to make B
		 */
		for (j = 0; j < Blen; j += hashSize) {
			(void) memcpy(B+j, Ai, ((Blen - j > hashSize) ?
			    hashSize : Blen - j));
		}

		/*
		 * Step 6c.
		 */
		k = Ilen / Blen;
		for (j = 0; j < k; j++) {
			uchar_t idx;
			CK_ULONG m, q = 1, cbit = 0;

			for (m = Blen - 1; m >= (CK_ULONG)0; m--, q = 0) {
				idx = m + j*Blen;

				q += (CK_ULONG)I[idx] + (CK_ULONG)B[m];
				q += cbit;
				I[idx] = (CK_BYTE)(q & 0xff);
				cbit = (q > 0xff);
			}
		}

		/*
		 * Step 7.
		 *  A += Ai
		 */
		(void) memcpy(A + i*hashSize, Ai, AiLen);
	}

	/*
	 * Step 8.
	 * The final output of this process is the A buffer
	 */
	(void) memcpy(keybuf, A, keysize);

cleanup:
	freezero(A, Alen);
	freezero(Ai, AiLen);
	freezero(B, Blen);
	freezero(D, Dlen);
	freezero(I, Ilen);
	return (rv);
}

CK_RV
soft_derivekey(soft_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    soft_object_t *basekey_p, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{

	CK_RV rv = CKR_OK;
	soft_object_t *secret_key;
	CK_MECHANISM digest_mech;
	CK_BYTE hash[SHA512_DIGEST_LENGTH]; /* space enough for all mechs */
	CK_ULONG hash_len = SHA512_DIGEST_LENGTH;
	CK_ULONG secret_key_len;
	CK_ULONG hash_size;

	switch (pMechanism->mechanism) {
	case CKM_DH_PKCS_DERIVE:
		/*
		 * Create a new object for secret key. The key type should
		 * be provided in the template.
		 */
		rv = soft_gen_keyobject(pTemplate, ulAttributeCount,
		    phKey, session_p, CKO_SECRET_KEY, (CK_KEY_TYPE)~0UL, 0,
		    SOFT_DERIVE_KEY_DH, B_FALSE);

		if (rv != CKR_OK) {
			return (rv);
		}

		/* Obtain the secret object pointer. */
		secret_key = (soft_object_t *)*phKey;

		rv = soft_dh_key_derive(basekey_p, secret_key,
		    (CK_BYTE *)pMechanism->pParameter,
		    pMechanism->ulParameterLen);

		if (rv != CKR_OK) {
			if (IS_TOKEN_OBJECT(secret_key))
				soft_delete_token_object(secret_key, B_FALSE,
				    B_FALSE);
			else
				soft_delete_object(session_p, secret_key,
				    B_FALSE, B_FALSE);
			return (rv);
		}

		break;

	case CKM_ECDH1_DERIVE:
		/*
		 * Create a new object for secret key. The key type should
		 * be provided in the template.
		 */
		rv = soft_gen_keyobject(pTemplate, ulAttributeCount,
		    phKey, session_p, CKO_SECRET_KEY, (CK_KEY_TYPE)~0UL, 0,
		    SOFT_DERIVE_KEY_DH, B_FALSE);

		if (rv != CKR_OK) {
			return (rv);
		}

		/* Obtain the secret object pointer. */
		secret_key = (soft_object_t *)*phKey;

		rv = soft_ec_key_derive(basekey_p, secret_key,
		    (CK_BYTE *)pMechanism->pParameter,
		    pMechanism->ulParameterLen);

		if (rv != CKR_OK) {
			if (IS_TOKEN_OBJECT(secret_key))
				soft_delete_token_object(secret_key, B_FALSE,
				    B_FALSE);
			else
				soft_delete_object(session_p, secret_key,
				    B_FALSE, B_FALSE);
			return (rv);
		}

		break;

	case CKM_SHA1_KEY_DERIVATION:
		hash_size = SHA1_HASH_SIZE;
		digest_mech.mechanism = CKM_SHA_1;
		goto common;

	case CKM_MD5_KEY_DERIVATION:
		hash_size = MD5_HASH_SIZE;
		digest_mech.mechanism = CKM_MD5;
		goto common;

	case CKM_SHA256_KEY_DERIVATION:
		hash_size = SHA256_DIGEST_LENGTH;
		digest_mech.mechanism = CKM_SHA256;
		goto common;

	case CKM_SHA384_KEY_DERIVATION:
		hash_size = SHA384_DIGEST_LENGTH;
		digest_mech.mechanism = CKM_SHA384;
		goto common;

	case CKM_SHA512_KEY_DERIVATION:
		hash_size = SHA512_DIGEST_LENGTH;
		digest_mech.mechanism = CKM_SHA512;
		goto common;

common:
		/*
		 * Create a new object for secret key. The key type is optional
		 * to be provided in the template. If it is not specified in
		 * the template, the default is CKK_GENERIC_SECRET.
		 */
		rv = soft_gen_keyobject(pTemplate, ulAttributeCount,
		    phKey, session_p, CKO_SECRET_KEY,
		    (CK_KEY_TYPE)CKK_GENERIC_SECRET, 0,
		    SOFT_DERIVE_KEY_OTHER, B_FALSE);

		if (rv != CKR_OK) {
			return (rv);
		}

		/* Obtain the secret object pointer. */
		secret_key = (soft_object_t *)*phKey;

		/* Validate the key type and key length */
		rv = soft_key_derive_check_length(secret_key, hash_size);
		if (rv != CKR_OK) {
			if (IS_TOKEN_OBJECT(secret_key))
				soft_delete_token_object(secret_key, B_FALSE,
				    B_FALSE);
			else
				soft_delete_object(session_p, secret_key,
				    B_FALSE, B_FALSE);
			return (rv);
		}

		/*
		 * Derive the secret key by digesting the value of another
		 * secret key (base key) with SHA-1 or MD5.
		 */
		rv = soft_digest_init_internal(session_p, &digest_mech);
		if (rv != CKR_OK) {
			if (IS_TOKEN_OBJECT(secret_key))
				soft_delete_token_object(secret_key, B_FALSE,
				    B_FALSE);
			else
				soft_delete_object(session_p, secret_key,
				    B_FALSE, B_FALSE);
			return (rv);
		}

		rv = soft_digest(session_p, OBJ_SEC_VALUE(basekey_p),
		    OBJ_SEC_VALUE_LEN(basekey_p), hash, &hash_len);

		(void) pthread_mutex_lock(&session_p->session_mutex);
		/* soft_digest_common() has freed the digest context */
		session_p->digest.flags = 0;
		(void) pthread_mutex_unlock(&session_p->session_mutex);

		if (rv != CKR_OK) {
			if (IS_TOKEN_OBJECT(secret_key))
				soft_delete_token_object(secret_key, B_FALSE,
				    B_FALSE);
			else
				soft_delete_object(session_p, secret_key,
				    B_FALSE, B_FALSE);
			return (rv);
		}

		secret_key_len = OBJ_SEC_VALUE_LEN(secret_key);

		if ((OBJ_SEC_VALUE(secret_key) = malloc(secret_key_len)) ==
		    NULL) {
			if (IS_TOKEN_OBJECT(secret_key))
				soft_delete_token_object(secret_key, B_FALSE,
				    B_FALSE);
			else
				soft_delete_object(session_p, secret_key,
				    B_FALSE, B_FALSE);
			return (CKR_HOST_MEMORY);
		}

		/*
		 * The key produced by this mechanism will be of the
		 * specified type and length.
		 * The truncation removes extra bytes from the leading
		 * of the digested key value.
		 */
		(void) memcpy(OBJ_SEC_VALUE(secret_key),
		    (hash + hash_len - secret_key_len),
		    secret_key_len);

		break;

	/*
	 * The key sensitivity and extractability rules for the generated
	 * keys will be enforced inside soft_ssl_master_key_derive() and
	 * soft_ssl_key_and_mac_derive()
	 */
	case CKM_SSL3_MASTER_KEY_DERIVE:
	case CKM_SSL3_MASTER_KEY_DERIVE_DH:
	case CKM_TLS_MASTER_KEY_DERIVE:
	case CKM_TLS_MASTER_KEY_DERIVE_DH:
		if (phKey == NULL_PTR)
			return (CKR_ARGUMENTS_BAD);
		return (soft_ssl_master_key_derive(session_p, pMechanism,
		    basekey_p, pTemplate, ulAttributeCount, phKey));

	case CKM_SSL3_KEY_AND_MAC_DERIVE:
	case CKM_TLS_KEY_AND_MAC_DERIVE:
		return (soft_ssl_key_and_mac_derive(session_p, pMechanism,
		    basekey_p, pTemplate, ulAttributeCount));

	case CKM_TLS_PRF:
		if (pMechanism->pParameter == NULL ||
		    pMechanism->ulParameterLen != sizeof (CK_TLS_PRF_PARAMS) ||
		    phKey != NULL)
			return (CKR_ARGUMENTS_BAD);

		if (pTemplate != NULL)
			return (CKR_TEMPLATE_INCONSISTENT);

		return (derive_tls_prf(
		    (CK_TLS_PRF_PARAMS_PTR)pMechanism->pParameter, basekey_p));

	default:
		return (CKR_MECHANISM_INVALID);
	}

	soft_derive_enforce_flags(basekey_p, secret_key);

	if (IS_TOKEN_OBJECT(secret_key)) {
		/*
		 * All the info has been filled, so we can write to
		 * keystore now.
		 */
		rv = soft_put_object_to_keystore(secret_key);
		if (rv != CKR_OK)
			soft_delete_token_object(secret_key, B_FALSE, B_FALSE);
	}

	return (rv);
}


/*
 * Perform key derivation rules on key's sensitivity and extractability.
 */
void
soft_derive_enforce_flags(soft_object_t *basekey, soft_object_t *newkey)
{

	boolean_t new_sensitive = B_FALSE;
	boolean_t new_extractable = B_FALSE;

	/*
	 * The sensitive and extractable bits have been set when
	 * the newkey was built.
	 */
	if (newkey->bool_attr_mask & SENSITIVE_BOOL_ON) {
		new_sensitive = B_TRUE;
	}

	if (newkey->bool_attr_mask & EXTRACTABLE_BOOL_ON) {
		new_extractable = B_TRUE;
	}

	/* Derive the CKA_ALWAYS_SENSITIVE flag */
	if (!basekey->bool_attr_mask & ALWAYS_SENSITIVE_BOOL_ON) {
		/*
		 * If the base key has its CKA_ALWAYS_SENSITIVE set to
		 * FALSE, then the derived key will as well.
		 */
		newkey->bool_attr_mask &= ~ALWAYS_SENSITIVE_BOOL_ON;
	} else {
		/*
		 * If the base key has its CKA_ALWAYS_SENSITIVE set to TRUE,
		 * then the derived key has the CKA_ALWAYS_SENSITIVE set to
		 * the same value as its CKA_SENSITIVE;
		 */
		if (new_sensitive) {
			newkey->bool_attr_mask |= ALWAYS_SENSITIVE_BOOL_ON;
		} else {
			newkey->bool_attr_mask &= ~ALWAYS_SENSITIVE_BOOL_ON;
		}
	}

	/* Derive the CKA_NEVER_EXTRACTABLE flag */
	if (!basekey->bool_attr_mask & NEVER_EXTRACTABLE_BOOL_ON) {
		/*
		 * If the base key has its CKA_NEVER_EXTRACTABLE set to
		 * FALSE, then the derived key will as well.
		 */
		newkey->bool_attr_mask &= ~NEVER_EXTRACTABLE_BOOL_ON;
	} else {
		/*
		 * If the base key has its CKA_NEVER_EXTRACTABLE set to TRUE,
		 * then the derived key has the CKA_NEVER_EXTRACTABLE set to
		 * the opposite value from its CKA_EXTRACTABLE;
		 */
		if (new_extractable) {
			newkey->bool_attr_mask &= ~NEVER_EXTRACTABLE_BOOL_ON;
		} else {
			newkey->bool_attr_mask |= NEVER_EXTRACTABLE_BOOL_ON;
		}
	}

	/* Set the CKA_LOCAL flag to false */
	newkey->bool_attr_mask &= ~LOCAL_BOOL_ON;
}


/*
 * do_prf
 *
 * This routine implements Step 3. of the PBKDF2 function
 * defined in PKCS#5 for generating derived keys from a
 * password.
 *
 * Currently, PRF is always SHA_1_HMAC.
 */
static CK_RV
do_prf(soft_session_t *session_p, CK_PKCS5_PBKD2_PARAMS_PTR params,
    soft_object_t *hmac_key, CK_BYTE *newsalt, CK_ULONG saltlen,
    CK_BYTE *blockdata, CK_ULONG blocklen)
{
	CK_RV rv = CKR_OK;
	CK_MECHANISM digest_mech = {CKM_SHA_1_HMAC, NULL, 0};
	CK_BYTE buffer[2][SHA1_HASH_SIZE];
	CK_ULONG hmac_outlen = SHA1_HASH_SIZE;
	CK_ULONG inlen;
	CK_BYTE *input, *output;
	CK_ULONG i, j;

	input = newsalt;
	inlen = saltlen;

	output = buffer[1];
	(void) pthread_mutex_lock(&session_p->session_mutex);

	if (session_p->sign.flags & CRYPTO_OPERATION_ACTIVE) {
		(void) pthread_mutex_unlock(&session_p->session_mutex);
		return (CKR_OPERATION_ACTIVE);
	}
	session_p->sign.flags |= CRYPTO_OPERATION_ACTIVE;
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	for (i = 0; i < params->iterations; i++) {
		/*
		 * The key doesn't change, its always the
		 * password iniitally given.
		 */
		rv = soft_sign_init(session_p, &digest_mech, hmac_key);

		if (rv != CKR_OK) {
			goto cleanup;
		}

		/* Call PRF function (SHA1_HMAC for now). */
		rv = soft_sign(session_p, input, inlen, output, &hmac_outlen);

		if (rv != CKR_OK) {
			goto cleanup;
		}
		/*
		 * The first time, initialize the output buffer
		 * with the HMAC signature.
		 */
		if (i == 0) {
			(void) memcpy(blockdata, output,
			    local_min(blocklen, hmac_outlen));
		} else {
			/*
			 * XOR the existing data with output from PRF.
			 *
			 * Only XOR up to the length of the blockdata,
			 * it may be less than a full hmac buffer when
			 * the final block is being computed.
			 */
			for (j = 0; j < hmac_outlen && j < blocklen; j++)
				blockdata[j] ^= output[j];
		}
		/* Output from previous PRF is input for next round */
		input = output;
		inlen = hmac_outlen;

		/*
		 * Switch buffers to avoid overuse of memcpy.
		 * Initially we used buffer[1], so after the end of
		 * the first iteration (i==0), we switch to buffer[0]
		 * and continue swapping with each iteration.
		 */
		output = buffer[i%2];
	}
cleanup:
	(void) pthread_mutex_lock(&session_p->session_mutex);
	session_p->sign.flags &= ~CRYPTO_OPERATION_ACTIVE;
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (rv);
}

static CK_RV
soft_create_hmac_key(soft_session_t *session_p,  CK_BYTE *passwd,
    CK_ULONG passwd_len, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv = CKR_OK;
	CK_OBJECT_CLASS keyclass = CKO_SECRET_KEY;
	CK_KEY_TYPE keytype = CKK_GENERIC_SECRET;
	CK_BBOOL True = TRUE;
	CK_ATTRIBUTE keytemplate[4];
	/*
	 * We must initialize each template member individually
	 * because at the time of initial coding for ON10, the
	 * compiler was using the "-xc99=%none" option
	 * which prevents us from being able to declare the whole
	 * template in place as usual.
	 */
	keytemplate[0].type = CKA_CLASS;
	keytemplate[0].pValue = &keyclass;
	keytemplate[0].ulValueLen =  sizeof (keyclass);

	keytemplate[1].type = CKA_KEY_TYPE;
	keytemplate[1].pValue = &keytype;
	keytemplate[1].ulValueLen =  sizeof (keytype);

	keytemplate[2].type = CKA_SIGN;
	keytemplate[2].pValue = &True;
	keytemplate[2].ulValueLen =  sizeof (True);

	keytemplate[3].type = CKA_VALUE;
	keytemplate[3].pValue = passwd;
	keytemplate[3].ulValueLen = passwd_len;
	/*
	 * Create a generic key object to be used for HMAC operations.
	 * The "value" for this key is the password from the
	 * mechanism parameter structure.
	 */
	rv = soft_gen_keyobject(keytemplate,
	    sizeof (keytemplate)/sizeof (CK_ATTRIBUTE), phKey, session_p,
	    CKO_SECRET_KEY, (CK_KEY_TYPE)CKK_GENERIC_SECRET, 0,
	    SOFT_CREATE_OBJ, B_TRUE);

	return (rv);
}

CK_RV
soft_generate_pkcs5_pbkdf2_key(soft_session_t *session_p,
    CK_MECHANISM_PTR pMechanism, soft_object_t *secret_key)
{
	CK_RV rv = CKR_OK;
	CK_PKCS5_PBKD2_PARAMS	*params =
	    (CK_PKCS5_PBKD2_PARAMS *)pMechanism->pParameter;
	CK_ULONG hLen = SHA1_HASH_SIZE;
	CK_ULONG dkLen, i;
	CK_ULONG blocks, remainder;
	CK_OBJECT_HANDLE phKey = 0;
	soft_object_t *hmac_key = NULL;
	CK_BYTE *salt = NULL;
	CK_BYTE *keydata = NULL;

	params = (CK_PKCS5_PBKD2_PARAMS_PTR) pMechanism->pParameter;

	if (params->prf != CKP_PKCS5_PBKD2_HMAC_SHA1)
		return (CKR_MECHANISM_PARAM_INVALID);

	if (params->pPrfData != NULL || params->ulPrfDataLen != 0)
		return (CKR_DATA_INVALID);

	if (params->saltSource != CKZ_SALT_SPECIFIED ||
	    params->iterations == 0)
		return (CKR_MECHANISM_PARAM_INVALID);

	/*
	 * Create a key object to use for HMAC operations.
	 */
	rv = soft_create_hmac_key(session_p, params->pPassword,
	    *params->ulPasswordLen, &phKey);

	if (rv != CKR_OK)
		return (rv);

	hmac_key = (soft_object_t *)phKey;

	/* Step 1. */
	dkLen = OBJ_SEC_VALUE_LEN(secret_key);  /* length of desired key */

	if (dkLen > ((((u_longlong_t)1)<<32)-1)*hLen) {
		(void) soft_delete_object(session_p, hmac_key, B_FALSE,
		    B_FALSE);
		return (CKR_KEY_SIZE_RANGE);
	}

	/* Step 2. */
	blocks = dkLen / hLen;

	/* crude "Ceiling" function to adjust the number of blocks to use */
	if (blocks * hLen != dkLen)
		blocks++;

	remainder = dkLen - ((blocks - 1) * hLen);

	/* Step 3 */
	salt = (CK_BYTE *)malloc(params->ulSaltSourceDataLen + 4);
	if (salt == NULL) {
		(void) soft_delete_object(session_p, hmac_key, B_FALSE,
		    B_FALSE);
		return (CKR_HOST_MEMORY);
	}
	/*
	 * Nothing in PKCS#5 says you cannot pass an empty
	 * salt, so we will allow for this and not return error
	 * if the salt is not specified.
	 */
	if (params->pSaltSourceData != NULL && params->ulSaltSourceDataLen > 0)
		(void) memcpy(salt, params->pSaltSourceData,
		    params->ulSaltSourceDataLen);

	/*
	 * Get pointer to the data section of the key,
	 * this will be used below as output from the
	 * PRF iteration/concatenations so that when the
	 * blocks are all iterated, the secret_key will
	 * have the resulting derived key value.
	 */
	keydata = (CK_BYTE *)OBJ_SEC_VALUE(secret_key);

	/* Step 4. */
	for (i = 0; i < blocks && (rv == CKR_OK); i++) {
		CK_BYTE *s;

		s = salt + params->ulSaltSourceDataLen;

		/*
		 * Append the block index to the salt as input
		 * to the PRF.  Block index should start at 1
		 * not 0.
		 */
		*s++ = ((i+1) >> 24) & 0xff;
		*s++ = ((i+1) >> 16) & 0xff;
		*s++ = ((i+1) >> 8) & 0xff;
		*s   = ((i+1)) & 0xff;

		/*
		 * Adjust the key pointer so we always append the
		 * PRF output to the current key.
		 */
		rv = do_prf(session_p, params, hmac_key,
		    salt, params->ulSaltSourceDataLen + 4, keydata,
		    ((i + 1) == blocks ? remainder : hLen));

		keydata += hLen;
	}
	(void) soft_delete_object(session_p, hmac_key, B_FALSE, B_FALSE);
	freezero(salt, params->ulSaltSourceDataLen);

	return (rv);
}

CK_RV
soft_wrapkey(soft_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    soft_object_t *wrappingKey_p, soft_object_t *hkey_p,
    CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	CK_RV		rv = CKR_OK;
	CK_ULONG	plain_len = 0;
	CK_BYTE_PTR	plain_data = NULL;
	CK_ULONG	padded_len = 0;
	CK_BYTE_PTR	padded_data = NULL;
	CK_ULONG	wkey_blksz = 1;		/* so modulo will work right */

	/* Check if the mechanism is supported. */
	switch (pMechanism->mechanism) {
	case CKM_DES_CBC_PAD:
	case CKM_DES3_CBC_PAD:
	case CKM_AES_CBC_PAD:
		/*
		 * Secret key mechs with padding can be used to wrap secret
		 * keys and private keys only.  See PKCS#11, * sec 11.14,
		 * C_WrapKey and secs 12.* for each mechanism's wrapping/
		 * unwrapping constraints.
		 */
		if (hkey_p->class != CKO_SECRET_KEY && hkey_p->class !=
		    CKO_PRIVATE_KEY)
			return (CKR_MECHANISM_INVALID);
		break;
	case CKM_RSA_PKCS:
	case CKM_RSA_X_509:
	case CKM_DES_ECB:
	case CKM_DES3_ECB:
	case CKM_AES_ECB:
	case CKM_DES_CBC:
	case CKM_DES3_CBC:
	case CKM_AES_CBC:
	case CKM_AES_CTR:
	case CKM_BLOWFISH_CBC:
		/*
		 * Unpadded secret key mechs and private key mechs are only
		 * defined for wrapping secret keys.  See PKCS#11 refs above.
		 */
		if (hkey_p->class != CKO_SECRET_KEY)
			return (CKR_MECHANISM_INVALID);
		break;
	default:
		return (CKR_MECHANISM_INVALID);
	}

	if (hkey_p->class == CKO_SECRET_KEY) {
		plain_data = OBJ_SEC_VALUE(hkey_p);
		plain_len = OBJ_SEC_VALUE_LEN(hkey_p);
	} else {
		/*
		 * BER-encode the object to be wrapped:  call first with
		 * plain_data = NULL to get the size needed, allocate that
		 * much space, call again to fill space with actual data.
		 */
		rv = soft_object_to_asn1(hkey_p, NULL, &plain_len);
		if (rv != CKR_OK)
			return (rv);
		if ((plain_data = malloc(plain_len)) == NULL)
			return (CKR_HOST_MEMORY);
		(void) memset(plain_data, 0x0, plain_len);
		rv = soft_object_to_asn1(hkey_p, plain_data, &plain_len);
		if (rv != CKR_OK)
			goto cleanup_wrap;
	}

	/*
	 * For unpadded ECB and CBC mechanisms, the object needs to be
	 * padded to the wrapping key's blocksize prior to the encryption.
	 */
	padded_len = plain_len;
	padded_data = plain_data;

	switch (pMechanism->mechanism) {
	case CKM_DES_ECB:
	case CKM_DES3_ECB:
	case CKM_AES_ECB:
	case CKM_DES_CBC:
	case CKM_DES3_CBC:
	case CKM_AES_CBC:
	case CKM_BLOWFISH_CBC:
		/* Find the block size of the wrapping key. */
		if (wrappingKey_p->class == CKO_SECRET_KEY) {
			switch (wrappingKey_p->key_type) {
			case CKK_DES:
			case CKK_DES2:
			case CKK_DES3:
				wkey_blksz = DES_BLOCK_LEN;
				break;
			case CKK_AES:
				wkey_blksz = AES_BLOCK_LEN;
				break;
			case CKK_BLOWFISH:
				wkey_blksz = BLOWFISH_BLOCK_LEN;
				break;
			default:
				break;
			}
		} else {
			rv = CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
			goto cleanup_wrap;
		}

		/* Extend the plain text data to block size boundary.  */
		if ((padded_len % wkey_blksz) != 0) {
			padded_len += (wkey_blksz - (plain_len % wkey_blksz));
			if ((padded_data = malloc(padded_len)) == NULL) {
				rv = CKR_HOST_MEMORY;
				goto cleanup_wrap;
			}
			(void) memset(padded_data, 0x0, padded_len);
			(void) memcpy(padded_data, plain_data, plain_len);
		}
		break;
	default:
		break;
	}

	rv = soft_encrypt_init(session_p, pMechanism, wrappingKey_p);
	if (rv != CKR_OK)
		goto cleanup_wrap;

	rv = soft_encrypt(session_p, padded_data, padded_len,
	    pWrappedKey, pulWrappedKeyLen);

cleanup_wrap:
	if (padded_data != NULL && padded_len != plain_len) {
		/* Clear buffer before returning to memory pool. */
		freezero(padded_data, padded_len);
	}

	if ((hkey_p->class != CKO_SECRET_KEY) && (plain_data != NULL)) {
		/* Clear buffer before returning to memory pool. */
		freezero(plain_data, plain_len);
	}

	return (rv);
}

/*
 * Quick check for whether unwrapped key length is appropriate for key type
 * and whether it needs to be truncated (in case the wrapping function had
 * to pad the key prior to wrapping).
 */
static CK_RV
soft_unwrap_secret_len_check(CK_KEY_TYPE keytype, CK_MECHANISM_TYPE mechtype,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount)
{
	CK_ULONG	i;
	boolean_t	isValueLen = B_FALSE;

	/*
	 * Based on the key type and the mech used to unwrap, need to
	 * determine if CKA_VALUE_LEN should or should not be specified.
	 * PKCS#11 v2.11 restricts CKA_VALUE_LEN from being specified
	 * for C_UnwrapKey for all mechs and key types, but v2.20 loosens
	 * that restriction, perhaps because it makes it impossible to
	 * determine the original length of unwrapped variable-length secret
	 * keys, such as RC4, AES, and GENERIC_SECRET.  These variable-length
	 * secret keys would have been padded with trailing null-bytes so
	 * that they could be successfully wrapped with *_ECB and *_CBC
	 * mechanisms.  Hence for unwrapping with these mechs, CKA_VALUE_LEN
	 * must be specified.  For unwrapping with other mechs, such as
	 * *_CBC_PAD, the CKA_VALUE_LEN is not needed.
	 */

	/* Find out if template has CKA_VALUE_LEN. */
	for (i = 0; i < ulAttributeCount; i++) {
		if (pTemplate[i].type == CKA_VALUE_LEN &&
		    pTemplate[i].pValue != NULL) {
			isValueLen = B_TRUE;
			break;
		}
	}

	/* Does its presence  conflict with the mech type and key type? */
	switch (mechtype) {
	case CKM_DES_ECB:
	case CKM_DES3_ECB:
	case CKM_AES_ECB:
	case CKM_DES_CBC:
	case CKM_DES3_CBC:
	case CKM_AES_CBC:
	case CKM_BLOWFISH_CBC:
		/*
		 * CKA_VALUE_LEN must be specified
		 * if keytype is CKK_RC4, CKK_AES and CKK_GENERIC_SECRET
		 * and must not be specified otherwise
		 */
		switch (keytype) {
		case CKK_DES:
		case CKK_DES2:
		case CKK_DES3:
			if (isValueLen)
				return (CKR_TEMPLATE_INCONSISTENT);
			break;
		case CKK_GENERIC_SECRET:
		case CKK_RC4:
		case CKK_AES:
		case CKK_BLOWFISH:
			if (!isValueLen)
				return (CKR_TEMPLATE_INCOMPLETE);
			break;
		default:
			return (CKR_FUNCTION_NOT_SUPPORTED);
		}
		break;
	default:
		/* CKA_VALUE_LEN must not be specified */
		if (isValueLen)
			return (CKR_TEMPLATE_INCONSISTENT);
		break;
	}

	return (CKR_OK);
}

CK_RV
soft_unwrapkey(soft_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    soft_object_t *unwrappingkey_p, CK_BYTE_PTR pWrappedKey,
    CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV			rv = CKR_OK;
	CK_OBJECT_CLASS		new_obj_class = ~0UL;
	int			i = 0;
	soft_object_t		*new_objp = NULL;
	boolean_t		persistent = B_FALSE;
	CK_BYTE_PTR		plain_data = NULL;
	CK_ULONG		plain_len = 0;
	secret_key_obj_t	*sck = NULL;

	/* Scan the attribute template for the object class. */
	if (pTemplate != NULL && ulAttributeCount != 0) {
		for (i = 0; i < ulAttributeCount; i++) {
			if (pTemplate[i].type == CKA_CLASS) {
				new_obj_class =
				    *((CK_OBJECT_CLASS *)pTemplate[i].pValue);
				break;
			}
		}
		if (new_obj_class == ~0UL)
			return (CKR_TEMPLATE_INCOMPLETE);
	}

	/*
	 * Check if the mechanism is supported, and now that the new
	 * object's class is known, the mechanism selected should be
	 * capable of doing the unwrap.
	 */
	switch (pMechanism->mechanism) {
	case CKM_RSA_PKCS:
	case CKM_RSA_X_509:
	case CKM_DES_ECB:
	case CKM_DES3_ECB:
	case CKM_AES_ECB:
	case CKM_DES_CBC:
	case CKM_DES3_CBC:
	case CKM_AES_CBC:
	case CKM_BLOWFISH_CBC:
		if (new_obj_class != CKO_SECRET_KEY)
			return (CKR_MECHANISM_INVALID);
		break;
	case CKM_DES_CBC_PAD:
	case CKM_DES3_CBC_PAD:
	case CKM_AES_CBC_PAD:
		if (new_obj_class != CKO_SECRET_KEY && new_obj_class !=
		    CKO_PRIVATE_KEY)
			return (CKR_MECHANISM_INVALID);
		break;
	default:
		return (CKR_MECHANISM_INVALID);
	}

	/* Create a new object based on the attribute template. */
	rv = soft_gen_keyobject(pTemplate, ulAttributeCount,
	    (CK_ULONG *)&new_objp, session_p, (CK_OBJECT_CLASS)~0UL,
	    (CK_KEY_TYPE)~0UL, 0, SOFT_UNWRAP_KEY, B_FALSE);
	if (rv != CKR_OK)
		return (rv);

	/*
	 * New key will have CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE
	 * both set to FALSE.  CKA_EXTRACTABLE will be set _by_default_ to
	 * true -- leaving the possibility that it may be set FALSE by the
	 * supplied attribute template.  If the precise template cannot be
	 * supported, unwrap fails.  PKCS#11 spec, Sec. 11.14, C_UnwrapKey.
	 *
	 * Therefore, check the new object's NEVER_EXTRACTABLE_BOOL_ON and
	 * ALWAYS_SENSITVE_BOOL_ON; if they are TRUE, the template must
	 * have supplied them and therefore we cannot honor the unwrap.
	 */
	if ((new_objp->bool_attr_mask & NEVER_EXTRACTABLE_BOOL_ON) ||
	    (new_objp->bool_attr_mask & ALWAYS_SENSITIVE_BOOL_ON)) {
		rv = CKR_TEMPLATE_INCONSISTENT;
		goto cleanup_unwrap;
	}

	rv = soft_decrypt_init(session_p, pMechanism, unwrappingkey_p);
	if (rv != CKR_OK)
		goto cleanup_unwrap;

	/* First get the length of the plain data */
	rv = soft_decrypt(session_p, pWrappedKey, ulWrappedKeyLen, NULL,
	    &plain_len);
	if (rv != CKR_OK)
		goto cleanup_unwrap;

	/* Allocate space for the unwrapped data */
	if ((plain_data = malloc(plain_len)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanup_unwrap;
	}
	(void) memset(plain_data, 0x0, plain_len);

	/* Perform actual decryption into the allocated space. */
	rv = soft_decrypt(session_p, pWrappedKey, ulWrappedKeyLen, plain_data,
	    &plain_len);
	if (rv != CKR_OK)
		goto cleanup_unwrap;

	if (new_objp->class == CKO_SECRET_KEY) {
		/*
		 * Since no ASN.1 encoding is done for secret keys, check for
		 * appropriateness and copy decrypted buffer to the key object.
		 */

		/* Check keytype and mechtype don't conflict with valuelen */
		rv = soft_unwrap_secret_len_check(new_objp->key_type,
		    pMechanism->mechanism, pTemplate, ulAttributeCount);
		if (rv != CKR_OK)
			goto cleanup_unwrap;

		/*
		 * Allocate the secret key structure if not already there;
		 * it will exist for variable length keys since CKA_VALUE_LEN
		 * is specified and saved, but not for fixed length keys.
		 */
		if (OBJ_SEC(new_objp) == NULL) {
			if ((sck = calloc(1, sizeof (secret_key_obj_t))) ==
			    NULL) {
				rv = CKR_HOST_MEMORY;
				goto cleanup_unwrap;
			}
			OBJ_SEC(new_objp) = sck;
		}

		switch (new_objp->key_type) {
		/* Fixed length secret keys don't have CKA_VALUE_LEN */
		case CKK_DES:
			OBJ_SEC_VALUE_LEN(new_objp) = DES_KEYSIZE;
			break;
		case CKK_DES2:
			OBJ_SEC_VALUE_LEN(new_objp) = DES2_KEYSIZE;
			break;
		case CKK_DES3:
			OBJ_SEC_VALUE_LEN(new_objp) = DES3_KEYSIZE;
			break;

		/*
		 * Variable length secret keys.  CKA_VALUE_LEN must be
		 * provided by the template when mech is *_ECB or *_CBC, and
		 * should already have been set during soft_gen_keyobject().
		 * Otherwise we don't need CKA_VALUE_LEN.
		 */
		case CKK_GENERIC_SECRET:
		case CKK_RC4:
		case CKK_AES:
		case CKK_BLOWFISH:
			break;
		default:
			rv = CKR_WRAPPED_KEY_INVALID;
			goto cleanup_unwrap;
		};

		if (OBJ_SEC_VALUE_LEN(new_objp) == 0) {
			/* No CKA_VALUE_LEN set so set it now and save data */
			OBJ_SEC_VALUE_LEN(new_objp) = plain_len;
			OBJ_SEC_VALUE(new_objp) = plain_data;
		} else if (OBJ_SEC_VALUE_LEN(new_objp) == plain_len) {
			/* No need to truncate, just save the data */
			OBJ_SEC_VALUE(new_objp) = plain_data;
		} else if (OBJ_SEC_VALUE_LEN(new_objp) > plain_len) {
			/* Length can't be bigger than what was decrypted */
			rv = CKR_WRAPPED_KEY_LEN_RANGE;
			goto cleanup_unwrap;
		} else {	/* betw 0 and plain_len, hence padded */
			/* Truncate the data before saving. */
			OBJ_SEC_VALUE(new_objp) = realloc(plain_data,
			    OBJ_SEC_VALUE_LEN(new_objp));
			if (OBJ_SEC_VALUE(new_objp) == NULL) {
				rv = CKR_HOST_MEMORY;
				goto cleanup_unwrap;
			}
		}
	} else {
		/* BER-decode the object to be unwrapped. */
		rv = soft_asn1_to_object(new_objp, plain_data, plain_len);
		if (rv != CKR_OK)
			goto cleanup_unwrap;
	}

	/* If it needs to be persistent, write it to the keystore */
	if (IS_TOKEN_OBJECT(new_objp)) {
		persistent = B_TRUE;
		rv = soft_put_object_to_keystore(new_objp);
		if (rv != CKR_OK)
			goto cleanup_unwrap;
	}

	if (new_objp->class != CKO_SECRET_KEY) {
		/* Clear buffer before returning to memory pool. */
		freezero(plain_data, plain_len);
	}

	*phKey = (CK_OBJECT_HANDLE)new_objp;

	return (CKR_OK);

cleanup_unwrap:
	/* The decrypted private key buffer must be freed explicitly. */
	if ((new_objp->class != CKO_SECRET_KEY) && (plain_data != NULL)) {
		/* Clear buffer before returning to memory pool. */
		freezero(plain_data, plain_len);
	}

	/* sck and new_objp are indirectly free()d inside these functions */
	if (IS_TOKEN_OBJECT(new_objp))
		soft_delete_token_object(new_objp, persistent, B_FALSE);
	else
		soft_delete_object(session_p, new_objp, B_FALSE, B_FALSE);

	return (rv);
}
