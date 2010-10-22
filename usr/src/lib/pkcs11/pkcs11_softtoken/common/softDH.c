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
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include <sys/crypto/common.h>
#include <des_impl.h>
#include <cryptoutil.h>
#include "softGlobal.h"
#include "softSession.h"
#include "softObject.h"
#include "softDH.h"
#include "softCrypt.h"


/*
 * This function takes a converted big integer of the specified attribute
 * as an octet string and stores it in the corresponding key object.
 */
static CK_RV
soft_genDHkey_set_attribute(soft_object_t *key, CK_ATTRIBUTE_TYPE type,
    uchar_t *buf, uint32_t buflen, boolean_t public)
{

	CK_RV rv = CKR_OK;
	biginteger_t *dst = NULL;
	biginteger_t src;

	switch (type) {

	case CKA_VALUE:
		if (public)
			dst = OBJ_PUB_DH_VALUE(key);
		else
			dst = OBJ_PRI_DH_VALUE(key);
		break;

	case CKA_PRIME:
		dst = OBJ_PRI_DH_PRIME(key);
		break;

	case CKA_BASE:
		dst = OBJ_PRI_DH_BASE(key);
		break;
	}

	if ((rv = dup_bigint_attr(&src, buf, buflen)) != CKR_OK)
		goto cleanexit;

	/* Copy the attribute in the key object. */
	copy_bigint_attr(&src, dst);

cleanexit:
	/* No need to free big_value because dst holds it now after copy. */
	return (rv);

}

/*
 * This function covers the DH Key agreement.
 */
CK_RV
soft_dh_genkey_pair(soft_object_t *pubkey, soft_object_t *prikey)
{
	CK_RV		rv;
	CK_ATTRIBUTE 	template;
	uchar_t		prime[MAX_KEY_ATTR_BUFLEN];
	uint32_t	prime_len = sizeof (prime);
	uchar_t		base[MAX_KEY_ATTR_BUFLEN];
	uint32_t	base_len = sizeof (base);
	uint32_t	value_bits;
	uchar_t		private_x[MAX_KEY_ATTR_BUFLEN];
	uchar_t		public_y[MAX_KEY_ATTR_BUFLEN];
	DHbytekey	k;

	if ((pubkey->class != CKO_PUBLIC_KEY) ||
	    (pubkey->key_type != CKK_DH)) {
		return (CKR_KEY_TYPE_INCONSISTENT);
	}

	if ((prikey->class != CKO_PRIVATE_KEY) ||
	    (prikey->key_type != CKK_DH)) {
		return (CKR_KEY_TYPE_INCONSISTENT);
	}

	/* Get private-value length in bits */
	template.pValue = malloc(sizeof (CK_ULONG));
	if (template.pValue == NULL) {
		return (CKR_HOST_MEMORY);
	}
	template.ulValueLen = sizeof (CK_ULONG);
	rv = get_ulong_attr_from_object(OBJ_PRI_DH_VAL_BITS(prikey),
	    &template);
	if (rv != CKR_OK) {
		free(template.pValue);
		return (rv);
	}

#ifdef	__sparcv9
	/* LINTED */
	value_bits = (uint32_t)(*((CK_ULONG *)(template.pValue)));
#else	/* !__sparcv9 */
	value_bits = *((CK_ULONG *)(template.pValue));
#endif	/* __sparcv9 */

	free(template.pValue);

	/*
	 * The input to the first phase shall be the Diffie-Hellman
	 * parameters, which include prime, base, and private-value length.
	 */
	rv = soft_get_public_value(pubkey, CKA_PRIME, prime, &prime_len);
	if (rv != CKR_OK) {
		return (rv);
	}

	rv = soft_get_public_value(pubkey, CKA_BASE, base, &base_len);
	if (rv != CKR_OK) {
		goto ret;
	}

	/* Inputs to DH key pair generation. */
	k.prime = prime;
	k.prime_bits = CRYPTO_BYTES2BITS(prime_len);
	k.base = base;
	k.base_bytes = base_len;
	k.value_bits = value_bits;
	k.rfunc = (IS_TOKEN_OBJECT(pubkey) || IS_TOKEN_OBJECT(prikey)) ?
	    pkcs11_get_random : pkcs11_get_urandom;

	/* Outputs from DH key pair generation. */
	k.private_x = private_x;
	k.public_y = public_y;

	/* If value_bits is 0, it will return as same size as prime */
	if ((rv = dh_genkey_pair(&k)) != CKR_OK) {
		goto ret;
	}

	/*
	 * The integer public value y shall be converted to an octet
	 * string PV of length k, the public value.
	 */
	if ((rv = soft_genDHkey_set_attribute(pubkey, CKA_VALUE, public_y,
	    prime_len, B_TRUE)) != CKR_OK) {
		goto ret;
	}

	/* Convert the big integer private value to an octet string. */
	if ((rv = soft_genDHkey_set_attribute(prikey, CKA_VALUE, private_x,
	    CRYPTO_BITS2BYTES(k.value_bits), B_FALSE)) != CKR_OK) {
		goto ret;
	}

	/* Convert the big integer prime to an octet string. */
	if ((rv = soft_genDHkey_set_attribute(prikey, CKA_PRIME, prime,
	    CRYPTO_BITS2BYTES(k.prime_bits), B_FALSE)) != CKR_OK) {
		goto ret;
	}

	/* Convert the big integer base to an octet string. */
	if ((rv = soft_genDHkey_set_attribute(prikey, CKA_BASE, base,
	    k.base_bytes, B_FALSE)) != CKR_OK) {
		goto ret;
	}

	/* Update private-value length in bits; could have been 0 before */
	OBJ_PRI_DH_VAL_BITS(prikey) = k.value_bits;

ret:
	return (rv);
}

/* ARGSUSED3 */
CK_RV
soft_dh_key_derive(soft_object_t *basekey, soft_object_t *secretkey,
    void *publicvalue, size_t publicvaluelen)
{
	CK_RV		rv;
	uchar_t		privatevalue[MAX_KEY_ATTR_BUFLEN];
	uint32_t	privatevaluelen = sizeof (privatevalue);
	uchar_t		privateprime[MAX_KEY_ATTR_BUFLEN];
	uint32_t	privateprimelen = sizeof (privateprime);
	uchar_t		key[MAX_KEY_ATTR_BUFLEN];
	uint32_t	keylen;
	DHbytekey	k;

	rv = soft_get_private_value(basekey, CKA_VALUE, privatevalue,
	    &privatevaluelen);
	if (rv != CKR_OK) {
		return (rv);
	}

	rv = soft_get_private_value(basekey, CKA_PRIME, privateprime,
	    &privateprimelen);
	if (rv != CKR_OK) {
		goto ret;
	}

	/* keylen may be 0 if CKA_VALUE_LEN did not specify */
	keylen = OBJ_SEC_VALUE_LEN(secretkey);
	if (keylen > sizeof (key)) {		/* check for overflow */
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto ret;
	}

	k.prime = privateprime;
	k.prime_bits = CRYPTO_BYTES2BITS(privateprimelen);
	k.value_bits = CRYPTO_BYTES2BITS(privatevaluelen);
	k.private_x = privatevalue;
	k.public_y = publicvalue;
	k.rfunc = NULL;

	/* keylen may be modified if it was 0 or conflicts with key type */
	rv = dh_key_derive(&k, secretkey->key_type, key, &keylen, 0);

	if (rv != CKR_OK) {
		goto ret;
	}

	if ((OBJ_SEC_VALUE(secretkey) = malloc(keylen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto ret;
	}

	OBJ_SEC_VALUE_LEN(secretkey) = keylen;
	(void) memcpy(OBJ_SEC_VALUE(secretkey), key, keylen);

ret:
	return (rv);
}
