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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include <sys/crypto/common.h>
#include <bignum.h>
#include <des_impl.h>
#include "softGlobal.h"
#include "softSession.h"
#include "softObject.h"
#include "softDH.h"
#include "softRandom.h"
#include "softCrypt.h"


/*
 * This function converts the big integer of the specified attribute
 * to an octet string and store it in the corresponding key object.
 */
CK_RV
soft_genDHkey_set_attribute(soft_object_t *key, BIGNUM *bn,
    CK_ATTRIBUTE_TYPE type, uint32_t prime_len, boolean_t public)
{

	uchar_t	*buf;
	uint32_t buflen;
	CK_RV rv = CKR_OK;
	biginteger_t *dst = NULL;
	biginteger_t src;

	/*
	 * Allocate the buffer used to store the value of key fields
	 * for bignum2bytestring. Since bignum only deals with a buffer
	 * whose size is multiple of 4, prime_len is rounded up to be
	 * multiple of 4.
	 */
	if ((buf = malloc((prime_len + sizeof (BIG_CHUNK_TYPE) - 1) &
	    ~(sizeof (BIG_CHUNK_TYPE) - 1))) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanexit;
	}

	buflen = bn->len * (int)sizeof (BIG_CHUNK_TYPE);
	bignum2bytestring(buf, bn, buflen);

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

	src.big_value_len = buflen;

	if ((src.big_value = malloc(buflen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanexit;
	}
	(void) memcpy(src.big_value, buf, buflen);

	/* Copy the attribute in the key object. */
	copy_bigint_attr(&src, dst);

cleanexit:
	free(buf);
	return (rv);

}

/*
 * This function covers the DH Key agreement.
 */
CK_RV
soft_dh_genkey_pair(soft_object_t *pubkey, soft_object_t *prikey)
{
	CK_RV		rv;
	BIG_ERR_CODE	brv;
	uchar_t		prime[MAX_KEY_ATTR_BUFLEN];
	uint32_t	prime_len = sizeof (prime);
	uint32_t	primebit_len;
	uint32_t	value_bits;
	uchar_t		base[MAX_KEY_ATTR_BUFLEN];
	uint32_t	base_len = sizeof (base);
	BIGNUM		bnprime;
	BIGNUM		bnbase;
	BIGNUM		bnprival;
	BIGNUM		bnpubval;
	CK_ATTRIBUTE 	template;

	if ((pubkey->class != CKO_PUBLIC_KEY) ||
	    (pubkey->key_type != CKK_DH)) {
		return (CKR_KEY_TYPE_INCONSISTENT);
	}

	if ((prikey->class != CKO_PRIVATE_KEY) ||
	    (prikey->key_type != CKK_DH)) {
		return (CKR_KEY_TYPE_INCONSISTENT);
	}

	/*
	 * The input to the first phase shall be the Diffie-Hellman
	 * parameters, which include prime, base, and private-value length.
	 */
	rv = soft_get_public_value(pubkey, CKA_PRIME, prime, &prime_len);

	if (rv != CKR_OK) {
		return (rv);
	}

	if ((prime_len < (MIN_DH_KEYLENGTH / 8)) ||
	    (prime_len > (MAX_DH_KEYLENGTH / 8))) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto ret0;
	}

	if ((brv = big_init(&bnprime, CHARLEN2BIGNUMLEN(prime_len))) !=
	    BIG_OK) {
		rv = convert_rv(brv);
		goto ret0;
	}

	/* Convert the prime octet string to big integer format. */
	bytestring2bignum(&bnprime, prime, prime_len);

	rv = soft_get_public_value(pubkey, CKA_BASE, base, &base_len);

	if (rv != CKR_OK) {
		goto ret1;
	}

	if ((brv = big_init(&bnbase, CHARLEN2BIGNUMLEN(base_len))) != BIG_OK) {
		rv = convert_rv(brv);
		goto ret1;
	}

	/* Convert the base octet string to big integer format. */
	bytestring2bignum(&bnbase, base, base_len);

	if (big_cmp_abs(&bnbase, &bnprime) >= 0) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto ret2;
	}

	primebit_len = big_bitlength(&bnprime);

	template.pValue = malloc(sizeof (CK_ULONG));

	if (template.pValue == NULL) {
		rv = CKR_HOST_MEMORY;
		goto ret2;
	}

	template.ulValueLen = sizeof (CK_ULONG);

	rv = get_ulong_attr_from_object(OBJ_PRI_DH_VAL_BITS(prikey),
	    &template);

	if (rv != CKR_OK) {
		goto ret2;
	}

	/*
	 * The intention of selecting a private-value length is to reduce
	 * the computation time for key agreement, while maintaining a
	 * given level of security.
	 */

#ifdef	__sparcv9
	/* LINTED */
	value_bits = (uint32_t)(*((CK_ULONG *)(template.pValue)));
#else	/* !__sparcv9 */
	value_bits = *((CK_ULONG *)(template.pValue));
#endif	/* __sparcv9 */

	if (value_bits > primebit_len) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto ret3;
	}

	/* Generate DH key pair private and public values. */
	if ((brv = big_init(&bnprival, CHARLEN2BIGNUMLEN(prime_len)))
	    != BIG_OK) {
		rv = convert_rv(brv);
		goto ret3;
	}

	if ((brv = big_init(&bnpubval, CHARLEN2BIGNUMLEN(prime_len)))
	    != BIG_OK) {
		rv = convert_rv(brv);
		goto ret4;
	}

	/*
	 * The big integer of the private value shall be generated privately
	 * and randomly.
	 */
	if ((brv = random_bignum(&bnprival, (value_bits == 0) ?
	    primebit_len : value_bits, (IS_TOKEN_OBJECT(pubkey) ||
	    IS_TOKEN_OBJECT(prikey)))) != BIG_OK) {
		rv = convert_rv(brv);
		goto ret5;
	}

	/*
	 * The base g shall be raised to the private value x modulo p to
	 * give an integer y, the integer public value.
	 */
	if ((brv = big_modexp(&bnpubval,
	    &bnbase, &bnprival, &bnprime, NULL)) != BIG_OK) {
		rv = convert_rv(brv);
		goto ret5;
	}

	/*
	 * The integer public value y shall be converted to an octet
	 * string PV of length k, the public value.
	 */
	if ((rv = soft_genDHkey_set_attribute(pubkey, &bnpubval,
	    CKA_VALUE, prime_len, B_TRUE)) != CKR_OK) {
		goto ret5;
	}

	/* Convert the big integer private value to an octet string. */
	if ((rv = soft_genDHkey_set_attribute(prikey, &bnprival,
	    CKA_VALUE, prime_len, B_FALSE)) != CKR_OK) {
		goto ret5;
	}

	/* Convert the big integer prime to an octet string. */
	if ((rv = soft_genDHkey_set_attribute(prikey, &bnprime,
	    CKA_PRIME, prime_len, B_FALSE)) != CKR_OK) {
		goto ret5;
	}

	/* Convert the big integer base to an octet string. */
	if ((rv = soft_genDHkey_set_attribute(prikey, &bnbase,
	    CKA_BASE, prime_len, B_FALSE)) != CKR_OK) {
		goto ret5;
	}

	if (value_bits == 0) {
		OBJ_PRI_DH_VAL_BITS(prikey) = primebit_len;
	}


ret5:
	big_finish(&bnpubval);
ret4:
	big_finish(&bnprival);
ret3:
	free(template.pValue);
ret2:
	big_finish(&bnbase);
ret1:
	big_finish(&bnprime);
ret0:
	return (rv);
}

CK_RV
soft_dh_key_derive(soft_object_t *basekey, soft_object_t *secretkey,
    void *publicvalue, size_t publicvaluelen)
{
	uchar_t		privatevalue[MAX_KEY_ATTR_BUFLEN];
	uint32_t	privatevaluelen = sizeof (privatevalue);
	uchar_t		privateprime[MAX_KEY_ATTR_BUFLEN];
	uint32_t	privateprimelen = sizeof (privateprime);
	uchar_t		*value;
	uint32_t	valuelen;
	uint32_t	keylen;
	uchar_t		*buf = NULL;
	CK_RV		rv;
	BIG_ERR_CODE	brv;
	BIGNUM		bnprime;
	BIGNUM		bnpublic;
	BIGNUM		bnprivate;
	BIGNUM		bnsecret;

	rv = soft_get_private_value(basekey, CKA_VALUE, privatevalue,
	    &privatevaluelen);
	if (rv != CKR_OK) {
		return (rv);
	}

	rv = soft_get_private_value(basekey, CKA_PRIME, privateprime,
	    &privateprimelen);
	if (rv != CKR_OK) {
		goto ret0;
	}

	if ((brv = big_init(&bnprime, CHARLEN2BIGNUMLEN(privateprimelen))) !=
	    BIG_OK) {
		rv = convert_rv(brv);
		goto ret0;
	}

	bytestring2bignum(&bnprime, privateprime, privateprimelen);

	if ((brv = big_init(&bnprivate, CHARLEN2BIGNUMLEN(privatevaluelen))) !=
	    BIG_OK) {
		rv = convert_rv(brv);
		goto ret1;
	}

	bytestring2bignum(&bnprivate, privatevalue, privatevaluelen);

#ifdef	__sparcv9
	if ((brv = big_init(&bnpublic,
	    (int)CHARLEN2BIGNUMLEN(publicvaluelen))) != BIG_OK) {
#else	/* !__sparcv9 */
	if ((brv = big_init(&bnpublic,
	    CHARLEN2BIGNUMLEN(publicvaluelen))) != BIG_OK) {
#endif	/* __sparcv9 */
		rv = convert_rv(brv);
		goto ret2;
	}

	bytestring2bignum(&bnpublic, (uchar_t *)publicvalue, publicvaluelen);

	if ((brv = big_init(&bnsecret,
	    CHARLEN2BIGNUMLEN(privateprimelen))) != BIG_OK) {
		rv = convert_rv(brv);
		goto ret3;
	}

	if ((brv = big_modexp(&bnsecret, &bnpublic, &bnprivate, &bnprime,
	    NULL)) != BIG_OK) {
		rv = convert_rv(brv);
		goto ret4;
	}

	if ((buf = malloc((privateprimelen + sizeof (BIG_CHUNK_TYPE) - 1) &
	    ~(sizeof (BIG_CHUNK_TYPE) - 1))) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto ret4;
	}

	value = buf;
	valuelen = bnsecret.len * (int)sizeof (BIG_CHUNK_TYPE);
	bignum2bytestring(value, &bnsecret, valuelen);

	switch (secretkey->key_type) {

	case CKK_DES:
		keylen = DES_KEYSIZE;
		break;
	case CKK_DES2:
		keylen = DES2_KEYSIZE;
		break;
	case CKK_DES3:
		keylen = DES3_KEYSIZE;
		break;
	case CKK_RC4:
	case CKK_AES:
	case CKK_GENERIC_SECRET:
#ifdef	__sparcv9
		/* LINTED */
		keylen = (uint32_t)OBJ_SEC_VALUE_LEN(secretkey);
#else	/* !__sparcv9 */
		keylen = OBJ_SEC_VALUE_LEN(secretkey);
#endif	/* __sparcv9 */
		break;
	}

	if (keylen == 0) {
		/*
		 * keylen == 0 only if CKA_VALUE_LEN did not specify.
		 */
		keylen = valuelen;
	}
	/*
	 * Note: No need to have "default:" case here since invalid key type
	 * if any has been detected at function soft_build_secret_key_object()
	 * before it gets here.
	 */

	if (keylen > valuelen) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto ret5;
	}

	if ((OBJ_SEC_VALUE(secretkey) = malloc(keylen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto ret5;
	}
	OBJ_SEC_VALUE_LEN(secretkey) = keylen;

	/*
	 * The truncation removes bytes from the leading end of the
	 * secret value.
	 */
	(void) memcpy(OBJ_SEC_VALUE(secretkey), (value + valuelen - keylen),
	    keylen);

ret5:
	free(buf);
ret4:
	big_finish(&bnsecret);
ret3:
	big_finish(&bnpublic);
ret2:
	big_finish(&bnprivate);
ret1:
	big_finish(&bnprime);
ret0:
	return (rv);
}
