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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright (c) 2018, Joyent. Inc.
 */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <lber.h>
#include <security/cryptoki.h>
#include "softDSA.h"
#include "softDH.h"
#include "softRSA.h"
#include "softObject.h"
#include "softASN1.h"

#define	OID_TAG			0x06

#define	MAX_DH_KEY	MAX_DH_KEYLENGTH_IN_BYTES	/* bytes in DH key */
static uchar_t	DH_OID[] = {
	/* DH key agreement OID:  1 . 2 . 840 . 113549 . 1 . 3 . 1 */
	0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x03, 0x01
};

#define	MAX_DH942_KEY	MAX_DH_KEYLENGTH_IN_BYTES /* bytes in DH X9.42 key */
static uchar_t	DH942_OID[] = {
	/* DH X9.42 OID:  1 . 2 . 840 . 10046 . 1  */
	0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x01
};

#define	MAX_DSA_KEY	MAX_DSA_KEY_LEN		/* bytes in DSA key */
static uchar_t	DSA_OID[] = {
	/* DSA algorithm OID:  1 . 2 . 840 . 10040 . 4 . 1  */
	0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01
};

#define	MAX_RSA_KEY	MAX_RSA_KEYLENGTH_IN_BYTES	/* bytes in RSA key */
static uchar_t	RSA_OID[] = {
	/* RSA algorithm OID:  1 . 2 . 840 . 113549 . 1 . 1 . 1 */
	0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01
};


/*
 * If the first bit of big integer is non-zero (i.e, first byte is
 * 0x80 or greater), it may be interpreted as an ASN.1 negative number.
 * Add one leading byte of zero-padding only in these cases to ensure
 * it is treated as an unsigned integer.
 */
static CK_RV
pad_bigint_attr(biginteger_t *src, biginteger_t *dst)
{
	int	padding;

	/* Src and dst must already by previously allocated. */
	if (src == NULL || dst == NULL)
		return (CKR_HOST_MEMORY);

	if (src->big_value_len == 0) {
		dst->big_value = NULL;
		dst->big_value_len = 0;
		return (CKR_OK);
	}
	/*
	 * Realloc() may free() or shrink previous memory location, so
	 * clear out potentially sensitive data before that happens.
	 */
	if (dst->big_value != NULL)
		explicit_bzero(dst->big_value, dst->big_value_len);

	padding = (src->big_value[0] < 0x80) ? 0 : 1;
	dst->big_value_len = src->big_value_len + padding;

	dst->big_value = realloc(dst->big_value, dst->big_value_len);
	if (dst->big_value == NULL)
		return (CKR_HOST_MEMORY);

	/* Set zero-pad at first byte, then append actual big_value. */
	dst->big_value[0] = 0x0;
	(void) memcpy(&(dst->big_value[padding]), src->big_value,
	    src->big_value_len);
	return (CKR_OK);
}

/*
 * Sometimes there is one bytes of zero-padding, if a big integer may
 * be interpreted as an ASN.1 negative number (i.e, the first bit is
 * non-zero, the first byte is 0x80 or greater).  Remove first byte
 * of zero-padding in those cases from the decoded octet strings.
 */
static CK_RV
unpad_bigint_attr(biginteger_t src, biginteger_t *dst)
{
	int	offset;

	if (dst == NULL)
		return (CKR_HOST_MEMORY);

	if (src.big_value_len == 0) {
		dst->big_value = NULL;
		dst->big_value_len = 0;
		return (CKR_OK);
	}

	offset = (src.big_value[0] == 0x00) ? 1 : 0;
	dst->big_value_len = src.big_value_len - offset;

	/*
	 * Must allocate memory here because subsequent calls to
	 * copy_bigint_attr() just redirect pointer; it doesn't
	 * really copy the bigint like the function name implies.
	 */
	dst->big_value = malloc(dst->big_value_len);
	if (dst->big_value == NULL)
		return (CKR_HOST_MEMORY);

	(void) memcpy(dst->big_value, &(src.big_value[offset]),
	    dst->big_value_len);
	return (CKR_OK);
}


/* Encode RSA private key in ASN.1 BER syntax. */
static CK_RV
rsa_pri_to_asn1(soft_object_t *objp, uchar_t *buf, ulong_t *buf_len)
{
	CK_RV		rv = CKR_OK;
	BerElement	*key_asn = NULLBER, *p8obj_asn = NULLBER;
	BerValue	*key_octs = NULL, *p8obj_octs = NULL;
	int		version = SOFT_ASN_VERSION;
	biginteger_t	tmp_pad = { NULL, 0 };

	/*
	 * The ASN.1 syntax for an RSA private key is:
	 *
	 * PKCS#8	\* PrivateKeyInfo *\
	 * ---------------------------------
	 * Sequence {
	 *	version		INTEGER;
	 *	Sequence {	\* PrivateKeyAlgorithm *\
	 *		OID	0x06,	\* RSA algorithm OID *\
	 *		param(NULL)
	 *	}
	 *	RSAPrivateKey	OCTETSTRING =
	 *		PKCS#1	\* RSAPrivateKey *\
	 *		---------------------------
	 *		Sequence {
	 *			version		INTEGER,
	 *			modulus		INTEGER,
	 *			publicExponent	INTEGER,
	 *			privateExponent	INTEGER,
	 *			prime1		INTEGER,
	 *			prime2		INTEGER,
	 *			exponent1	INTEGER,
	 *			exponent2	INTEGER,
	 *			coefficient	INTEGER
	 *		}
	 * }
	 *
	 * The code below starts building the innermost octets
	 * RSAPrivateKey, and then builds the PrivateKeyInfo
	 * sequence around that octet string.  The BER syntax
	 * used in this function is (others may be possible):
	 *	{ i { to n } { i to  to  to  to  to  to  to  to } }
	 * where "i" is for integers with fixed size
	 * where "to" is for integers that vary in size (length + value)
	 * where "n" is for nulls
	 * where "{}" delimit sequences
	 */

	/* RSAPrivateKey ... */
	if ((key_asn = ber_alloc()) == NULLBER)
		return (CKR_HOST_MEMORY);

	/* ... begin-sequence { version, */
	if (ber_printf(key_asn, "{i", version) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_rsapri2asn;
	}

	/* ... modulus, */
	if ((rv = pad_bigint_attr(OBJ_PRI_RSA_MOD(objp), &tmp_pad)) != CKR_OK)
		goto cleanup_rsapri2asn;
	if (ber_printf(key_asn, "to", LBER_INTEGER,
	    tmp_pad.big_value, tmp_pad.big_value_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_rsapri2asn;
	}

	/* ... public exponent, */
	if ((rv = pad_bigint_attr(OBJ_PRI_RSA_PUBEXPO(objp), &tmp_pad)) !=
	    CKR_OK)
		goto cleanup_rsapri2asn;

	else if (ber_printf(key_asn, "to", LBER_INTEGER, tmp_pad.big_value,
	    tmp_pad.big_value_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_rsapri2asn;
	}

	/* ... private exponent, */
	if ((rv = pad_bigint_attr(OBJ_PRI_RSA_PRIEXPO(objp), &tmp_pad)) !=
	    CKR_OK)
		goto cleanup_rsapri2asn;
	if (ber_printf(key_asn, "to", LBER_INTEGER,
	    tmp_pad.big_value, tmp_pad.big_value_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_rsapri2asn;
	}

	/* ... prime 1, */
	if ((rv = pad_bigint_attr(OBJ_PRI_RSA_PRIME1(objp), &tmp_pad)) !=
	    CKR_OK)
		goto cleanup_rsapri2asn;
	else if (ber_printf(key_asn, "to", LBER_INTEGER,
	    tmp_pad.big_value, tmp_pad.big_value_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_rsapri2asn;
	}

	/* ... prime 2, */
	if ((rv = pad_bigint_attr(OBJ_PRI_RSA_PRIME2(objp), &tmp_pad)) !=
	    CKR_OK)
		goto cleanup_rsapri2asn;
	else if (ber_printf(key_asn, "to", LBER_INTEGER,
	    tmp_pad.big_value, tmp_pad.big_value_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_rsapri2asn;
	}

	/* ... exponent 1, */
	if ((rv = pad_bigint_attr(OBJ_PRI_RSA_EXPO1(objp), &tmp_pad)) != CKR_OK)
		goto cleanup_rsapri2asn;
	else if (ber_printf(key_asn, "to", LBER_INTEGER,
	    tmp_pad.big_value, tmp_pad.big_value_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_rsapri2asn;
	}

	/* ... exponent 2, */
	if ((rv = pad_bigint_attr(OBJ_PRI_RSA_EXPO2(objp), &tmp_pad)) != CKR_OK)
		goto cleanup_rsapri2asn;
	else if (ber_printf(key_asn, "to", LBER_INTEGER,
	    tmp_pad.big_value, tmp_pad.big_value_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_rsapri2asn;
	}

	/* ... coefficient } end-sequence */
	if ((rv = pad_bigint_attr(OBJ_PRI_RSA_COEF(objp), &tmp_pad)) != CKR_OK)
		goto cleanup_rsapri2asn;
	else if (ber_printf(key_asn, "to}", LBER_INTEGER,
	    tmp_pad.big_value, tmp_pad.big_value_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_rsapri2asn;
	}

	/* Convert key ASN.1 to octet string. */
	if (ber_flatten(key_asn, &key_octs) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_rsapri2asn;
	}

	/* PKCS#8 PrivateKeyInfo ... */
	if ((p8obj_asn = ber_alloc()) == NULLBER) {
		rv = CKR_HOST_MEMORY;
		goto cleanup_rsapri2asn;
	}

	/*
	 * Embed key octet string into PKCS#8 object ASN.1:
	 * begin-sequence {
	 *	version
	 *	begin-sequence {
	 *		OID,
	 *		NULL
	 *	} end-sequence
	 *	RSAPrivateKey
	 * } end-sequence
	 */
	if (ber_printf(p8obj_asn, "{i{ton}o}", version,
	    OID_TAG, RSA_OID, sizeof (RSA_OID), /* NULL parameter, */
	    key_octs->bv_val, key_octs->bv_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_rsapri2asn;
	}

	/* Convert PKCS#8 object ASN.1 to octet string. */
	if (ber_flatten(p8obj_asn, &p8obj_octs) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_rsapri2asn;
	}

	/* Ship out the PKCS#8 object ASN.1 octet string, if possible. */
	/*
	 * If the user passes in a null buf, then buf_len is set.
	 * If the user passes in a value with buf_len, then it can
	 * be checked to see if the accompanying buf is big enough.
	 * If it is, the octet string is copied into a pre-malloc'd
	 * buf; otherwise the user must resize buf and call again.
	 * In either case, buf_len is reset to the corrected size.
	 * See PKCS#11 section 11.2.
	 */
#ifdef _LP64
	/* LINTED E_CAST_INT_TO_SMALL_INT */
	if ((buf == NULL) || ((ber_len_t)(*buf_len) < p8obj_octs->bv_len)) {
#else
	if ((buf == NULL) || ((ber_len_t)(*buf_len) < p8obj_octs->bv_len)) {
#endif
		*buf_len = p8obj_octs->bv_len;
		rv = (buf == NULL) ? CKR_OK : CKR_BUFFER_TOO_SMALL;
		goto cleanup_rsapri2asn;
	}

	*buf_len = p8obj_octs->bv_len;
	(void) memcpy(buf, p8obj_octs->bv_val, *buf_len);

cleanup_rsapri2asn:

	freezero(tmp_pad.big_value, tmp_pad.big_value_len);

	if (key_asn != NULLBER)
		ber_free(key_asn, 1);

	if (key_octs != NULL)
		ber_bvfree(key_octs);

	if (p8obj_asn != NULLBER)
		ber_free(p8obj_asn, 1);

	if (p8obj_octs != NULL)
		ber_bvfree(p8obj_octs);

	return (rv);
}

/* Encode DSA private key in ASN.1 BER syntax. */
static CK_RV
dsa_pri_to_asn1(soft_object_t *objp, uchar_t *buf, ulong_t *buf_len)
{
	CK_RV		rv = CKR_OK;
	BerElement	*key_asn = NULLBER, *p8obj_asn = NULLBER;
	BerValue	*key_octs = NULL, *p8obj_octs = NULL;
	int		version = SOFT_ASN_VERSION;
	biginteger_t	tmp_pad = { NULL, 0 };

	/*
	 * The ASN.1 syntax for a DSA private key is:
	 *
	 * PKCS#8	\* PrivateKeyInfo *\
	 * ---------------------------------
	 * Sequence {
	 *	version		INTEGER;
	 *	Sequence {	\* PrivateKeyAlgorithm *\
	 *		OID	0x06,	\* DSA algorithm OID *\
	 *		param(DSS-params)	OCTETSTRING =
	 *			PKCS#?	\* DSSParameter *\
	 *			----------------------------------
	 *			Sequence {
	 *				prime	INTEGER,
	 *				subprime INTEGER,
	 *				base	INTEGER,
	 *		}
	 *	}
	 *	DSAPrivateKey	OCTETSTRING =
	 *		PKCS#1	\* DSAPrivateKey *\
	 *		---------------------------
	 *		value		INTEGER
	 * }
	 *
	 * The code below starts building the innermost octets
	 * DSAPrivateKey, and then builds the PrivateKeyInfo
	 * sequence around that octet string.  The BER syntax
	 * used in this function is (others may be possible):
	 *	{ i { to { to to to } } to }
	 * where "i" is for integers with fixed size
	 * where "to" is for integers that vary in size (length + value)
	 * where "{}" delimit sequences
	 */

	/* DSAPrivateKey ... */
	if ((key_asn = ber_alloc()) == NULLBER)
		return (CKR_HOST_MEMORY);

	/* ... value */
	if ((rv = pad_bigint_attr(OBJ_PRI_DSA_VALUE(objp), &tmp_pad)) != CKR_OK)
		goto cleanup_dsapri2asn;
	if (ber_printf(key_asn, "to", LBER_INTEGER,
	    tmp_pad.big_value, tmp_pad.big_value_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_dsapri2asn;
	}

	/* Convert key ASN.1 to octet string. */
	if (ber_flatten(key_asn, &key_octs) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_dsapri2asn;
	}

	/* PKCS#8 PrivateKeyInfo ... */
	if ((p8obj_asn = ber_alloc()) == NULLBER) {
		rv = CKR_HOST_MEMORY;
		goto cleanup_dsapri2asn;
	}

	/*
	 * Start off the PKCS#8 object ASN.1:
	 * begin-sequence {
	 *	version
	 *	begin-sequence {
	 *		OID,
	 * ...
	 */
	if (ber_printf(p8obj_asn, "{i{to", version,
	    OID_TAG, DSA_OID, sizeof (DSA_OID)) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_dsapri2asn;
	}

	/*
	 * Add DSS parameters:
	 * ...
	 *		begin-sequence {
	 *			prime,
	 * ...
	 */
	if ((rv = pad_bigint_attr(OBJ_PRI_DSA_PRIME(objp), &tmp_pad)) != CKR_OK)
		goto cleanup_dsapri2asn;
	if (ber_printf(p8obj_asn, "{to", LBER_INTEGER,
	    tmp_pad.big_value, tmp_pad.big_value_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_dsapri2asn;
	}

	/*
	 * ...
	 *			subprime,
	 * ...
	 */
	if ((rv = pad_bigint_attr(OBJ_PRI_DSA_SUBPRIME(objp), &tmp_pad)) !=
	    CKR_OK)
		goto cleanup_dsapri2asn;
	if (ber_printf(p8obj_asn, "to", LBER_INTEGER,
	    tmp_pad.big_value, tmp_pad.big_value_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_dsapri2asn;
	}

	/*
	 * ...
	 *			base
	 *		} end-sequence
	 */
	if ((rv = pad_bigint_attr(OBJ_PRI_DSA_BASE(objp), &tmp_pad)) != CKR_OK)
		goto cleanup_dsapri2asn;
	if (ber_printf(p8obj_asn, "to}", LBER_INTEGER,
	    tmp_pad.big_value, tmp_pad.big_value_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_dsapri2asn;
	}

	/*
	 * Add the key octet string:
	 *	} end-sequence
	 *	DSAPrivateKey
	 * } end-sequence
	 */
	if (ber_printf(p8obj_asn, "}o}",
	    key_octs->bv_val, key_octs->bv_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_dsapri2asn;
	}

	/* Convert PKCS#8 object ASN.1 to octet string. */
	if (ber_flatten(p8obj_asn, &p8obj_octs) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_dsapri2asn;
	}

	/* Ship out the PKCS#8 object ASN.1 octet string, if possible. */
	/*
	 * If the user passes in a null buf, then buf_len is set.
	 * If the user passes in a value with buf_len, then it can
	 * be checked to see if the accompanying buf is big enough.
	 * If it is, the octet string is copied into a pre-malloc'd
	 * buf; otherwise the user must resize buf and call again.
	 * In either case, buf_len is reset to the corrected size.
	 * See PKCS#11 section 11.2.
	 */
#ifdef _LP64
	/* LINTED E_CAST_INT_TO_SMALL_INT */
	if ((buf == NULL) || ((ber_len_t)(*buf_len) < p8obj_octs->bv_len)) {
#else
	if ((buf == NULL) || ((ber_len_t)(*buf_len) < p8obj_octs->bv_len)) {
#endif
		*buf_len = p8obj_octs->bv_len;
		rv = (buf == NULL) ? CKR_OK : CKR_BUFFER_TOO_SMALL;
		goto cleanup_dsapri2asn;
	}

	*buf_len = p8obj_octs->bv_len;
	(void) memcpy(buf, p8obj_octs->bv_val, *buf_len);

cleanup_dsapri2asn:

	freezero(tmp_pad.big_value, tmp_pad.big_value_len);

	if (key_asn != NULLBER)
		ber_free(key_asn, 1);

	if (key_octs != NULL)
		ber_bvfree(key_octs);

	if (p8obj_asn != NULLBER)
		ber_free(p8obj_asn, 1);

	if (p8obj_octs != NULL)
		ber_bvfree(p8obj_octs);

	return (rv);
}

/* Encode DH private key in ASN.1 BER syntax. */
static CK_RV
dh_pri_to_asn1(soft_object_t *objp, uchar_t *buf, ulong_t *buf_len)
{
	CK_RV		rv = CKR_OK;
	BerElement	*key_asn = NULLBER, *p8obj_asn = NULLBER;
	BerValue	*key_octs = NULL, *p8obj_octs = NULL;
	int		version = SOFT_ASN_VERSION;
	biginteger_t	tmp_pad = { NULL, 0 };

	/*
	 * The ASN.1 syntax for a DH private key is:
	 *
	 * PKCS#8	\* PrivateKeyInfo *\
	 * ---------------------------------
	 * Sequence {
	 *	version		INTEGER;
	 *	Sequence {	\* PrivateKeyAlgorithm *\
	 *		OID	0x06,	\* DH algorithm OID *\
	 *		param(DH-params) OCTETSTRING =
	 *			PKCS#3	\* DHParameter *\
	 *			-------------------------
	 *			Sequence {
	 *				prime	INTEGER,
	 *				base	INTEGER
	 *			}
	 *	}
	 *	DHPrivateKey	OCTETSTRING =
	 *		PKCS#1	\* DHPrivateKey *\
	 *		--------------------------
	 *		value		INTEGER
	 * }
	 *
	 * The code below starts building the innermost octets
	 * DHPrivateKey, and then builds the PrivateKeyInfo
	 * sequence around that octet string.  The BER syntax
	 * used in this function is (others may be possible):
	 *	{ i { to { to to } } to }
	 * where "i" is for integers with fixed size
	 * where "to" is for integers that vary in size (length + value)
	 * where "{}" delimit sequences
	 */

	/* DHPrivateKey ... */
	if ((key_asn = ber_alloc()) == NULLBER)
		return (CKR_HOST_MEMORY);

	/* ... value */
	if ((rv = pad_bigint_attr(OBJ_PRI_DH_VALUE(objp), &tmp_pad)) != CKR_OK)
		goto cleanup_dhpri2asn;
	if (ber_printf(key_asn, "to", LBER_INTEGER,
	    tmp_pad.big_value, tmp_pad.big_value_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_dhpri2asn;
	}

	/* Convert key ASN.1 to octet string. */
	if (ber_flatten(key_asn, &key_octs) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_dhpri2asn;
	}

	/* PKCS#8 PrivateKeyInfo ... */
	if ((p8obj_asn = ber_alloc()) == NULLBER) {
		rv = CKR_HOST_MEMORY;
		goto cleanup_dhpri2asn;
	}

	/*
	 * Start off the PKCS#8 object ASN.1:
	 * begin-sequence {
	 *	version
	 *	begin-sequence {
	 *		OID,
	 * ...
	 */
	if (ber_printf(p8obj_asn, "{i{to", version,
	    OID_TAG, DH_OID, sizeof (DH_OID)) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_dhpri2asn;
	}

	/*
	 * Add DH parameters:
	 * ...
	 *		begin-sequence {
	 *			prime,
	 * ...
	 */
	if ((rv = pad_bigint_attr(OBJ_PRI_DH_PRIME(objp), &tmp_pad)) != CKR_OK)
		goto cleanup_dhpri2asn;
	if (ber_printf(p8obj_asn, "{to", LBER_INTEGER,
	    tmp_pad.big_value, tmp_pad.big_value_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_dhpri2asn;
	}

	/*
	 * ...
	 *			base
	 *		} end-sequence
	 */
	if ((rv = pad_bigint_attr(OBJ_PRI_DH_BASE(objp), &tmp_pad)) != CKR_OK)
		goto cleanup_dhpri2asn;
	if (ber_printf(p8obj_asn, "to}", LBER_INTEGER,
	    tmp_pad.big_value, tmp_pad.big_value_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_dhpri2asn;
	}

	/*
	 * Add the key octet string:
	 *	} end-sequence
	 *	DSAPrivateKey
	 * } end-sequence
	 */
	if (ber_printf(p8obj_asn, "}o}",
	    key_octs->bv_val, key_octs->bv_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_dhpri2asn;
	}

	/* Convert PKCS#8 object ASN.1 to octet string. */
	if (ber_flatten(p8obj_asn, &p8obj_octs) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_dhpri2asn;
	}

	/* Ship out the PKCS#8 object ASN.1 octet string, if possible. */
	/*
	 * If the user passes in a null buf, then buf_len is set.
	 * If the user passes in a value with buf_len, then it can
	 * be checked to see if the accompanying buf is big enough.
	 * If it is, the octet string is copied into a pre-malloc'd
	 * buf; otherwise the user must resize buf and call again.
	 * In either case, buf_len is reset to the corrected size.
	 * See PKCS#11 section 11.2.
	 */
#ifdef _LP64
	/* LINTED E_CAST_INT_TO_SMALL_INT */
	if ((buf == NULL) || ((ber_len_t)(*buf_len) < p8obj_octs->bv_len)) {
#else
	if ((buf == NULL) || ((ber_len_t)(*buf_len) < p8obj_octs->bv_len)) {
#endif
		*buf_len = p8obj_octs->bv_len;
		rv = (buf == NULL) ? CKR_OK : CKR_BUFFER_TOO_SMALL;
		goto cleanup_dhpri2asn;
	}

	*buf_len = p8obj_octs->bv_len;
	(void) memcpy(buf, p8obj_octs->bv_val, *buf_len);

cleanup_dhpri2asn:

	freezero(tmp_pad.big_value, tmp_pad.big_value_len);

	if (key_asn != NULLBER)
		ber_free(key_asn, 1);

	if (key_octs != NULL)
		ber_bvfree(key_octs);

	if (p8obj_asn != NULLBER)
		ber_free(p8obj_asn, 1);

	if (p8obj_octs != NULL)
		ber_bvfree(p8obj_octs);

	return (rv);
}

/* Encode DH X9.42 private key in ASN.1 BER syntax. */
static CK_RV
x942_dh_pri_to_asn1(soft_object_t *objp, uchar_t *buf, ulong_t *buf_len)
{
	CK_RV		rv = CKR_OK;
	BerElement	*key_asn = NULLBER, *p8obj_asn = NULLBER;
	BerValue	*key_octs = NULL, *p8obj_octs = NULL;
	int		version = SOFT_ASN_VERSION;
	biginteger_t	tmp_pad = { NULL, 0 };

	/*
	 * The ASN.1 syntax for a X9.42 DH private key is:
	 *
	 * PKCS#8	\* PrivateKeyInfo *\
	 * ---------------------------------
	 * Sequence {
	 *	version		INTEGER;
	 *	Sequence {	\* PrivateKeyAlgorithm *\
	 *		OID	0x06,	\* DH X9.42 algorithm OID *\
	 *		param(DH-params) OCTETSTRING =
	 *			PKCS#3	\* DHParameter *\
	 *			-------------------------
	 *			Sequence {
	 *				prime	INTEGER,
	 *				base	INTEGER,
	 *				subprime INTEGER \* for X9.42 *\
	 *			}
	 *	}
	 *	DHPrivateKey	OCTETSTRING =
	 *		PKCS#1	\* DHPrivateKey *\
	 *		--------------------------
	 *		value		INTEGER
	 * }
	 *
	 * The code below starts building the innermost octets
	 * DHPrivateKey, and then builds the PrivateKeyInfo
	 * sequence around that octet string.  The BER syntax
	 * used in this function is (others may be possible):
	 *	{ i { to { to to } } to }
	 * where "i" is for integers with fixed size
	 * where "to" is for integers that vary in size (length + value)
	 * where "{}" delimit sequences
	 */

	/* DHPrivateKey ... */
	if ((key_asn = ber_alloc()) == NULLBER)
		return (CKR_HOST_MEMORY);

	/* ... value */
	if ((rv = pad_bigint_attr(OBJ_PRI_DH942_VALUE(objp), &tmp_pad)) !=
	    CKR_OK)
		goto cleanup_x942dhpri2asn;
	if (ber_printf(key_asn, "to", LBER_INTEGER,
	    tmp_pad.big_value, tmp_pad.big_value_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_x942dhpri2asn;
	}

	/* Convert key ASN.1 to octet string. */
	if (ber_flatten(key_asn, &key_octs) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_x942dhpri2asn;
	}

	/* PKCS#8 PrivateKeyInfo ... */
	if ((p8obj_asn = ber_alloc()) == NULLBER) {
		rv = CKR_HOST_MEMORY;
		goto cleanup_x942dhpri2asn;
	}

	/*
	 * Start off the PKCS#8 object ASN.1:
	 * begin-sequence {
	 *	version
	 *	begin-sequence {
	 *		OID,
	 * ...
	 */
	if (ber_printf(p8obj_asn, "{i{to", version,
	    OID_TAG, DH942_OID, sizeof (DH942_OID)) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_x942dhpri2asn;
	}

	/*
	 * Add DH parameters:
	 * ...
	 *		begin-sequence {
	 *			prime,
	 * ...
	 */
	if ((rv = pad_bigint_attr(OBJ_PRI_DH942_PRIME(objp), &tmp_pad)) !=
	    CKR_OK)
		goto cleanup_x942dhpri2asn;
	if (ber_printf(p8obj_asn, "{to", LBER_INTEGER,
	    tmp_pad.big_value, tmp_pad.big_value_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_x942dhpri2asn;
	}

	/*
	 * ...
	 *			base,
	 * ...
	 */
	if ((rv = pad_bigint_attr(OBJ_PRI_DH942_BASE(objp), &tmp_pad)) !=
	    CKR_OK)
		goto cleanup_x942dhpri2asn;
	if (ber_printf(p8obj_asn, "to", LBER_INTEGER,
	    tmp_pad.big_value, tmp_pad.big_value_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_x942dhpri2asn;
	}

	/*
	 * ...
	 *			subprime
	 *		} end-sequence
	 */
	if ((rv = pad_bigint_attr(OBJ_PRI_DH942_SUBPRIME(objp), &tmp_pad)) !=
	    CKR_OK)
		goto cleanup_x942dhpri2asn;
	if (ber_printf(p8obj_asn, "to}", LBER_INTEGER,
	    tmp_pad.big_value, tmp_pad.big_value_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_x942dhpri2asn;
	}

	/*
	 * Add the key octet string:
	 *	} end-sequence
	 *	DHPrivateKey
	 * } end-sequence
	 */
	if (ber_printf(p8obj_asn, "}o}",
	    key_octs->bv_val, key_octs->bv_len) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_x942dhpri2asn;
	}

	/* Convert PKCS#8 object ASN.1 to octet string. */
	if (ber_flatten(p8obj_asn, &p8obj_octs) == -1) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_x942dhpri2asn;
	}

	/* Ship out the PKCS#8 object ASN.1 octet string, if possible. */
	/*
	 * If the user passes in a null buf, then buf_len is set.
	 * If the user passes in a value with buf_len, then it can
	 * be checked to see if the accompanying buf is big enough.
	 * If it is, the octet string is copied into a pre-malloc'd
	 * buf; otherwise the user must resize buf and call again.
	 * In either case, buf_len is reset to the corrected size.
	 * See PKCS#11 section 11.2.
	 */
#ifdef _LP64
	/* LINTED E_CAST_INT_TO_SMALL_INT */
	if ((buf == NULL) || ((ber_len_t)(*buf_len) < p8obj_octs->bv_len)) {
#else
	if ((buf == NULL) || ((ber_len_t)(*buf_len) < p8obj_octs->bv_len)) {
#endif
		*buf_len = p8obj_octs->bv_len;
		rv = (buf == NULL) ? CKR_OK : CKR_BUFFER_TOO_SMALL;
		goto cleanup_x942dhpri2asn;
	}

	*buf_len = p8obj_octs->bv_len;
	(void) memcpy(buf, p8obj_octs->bv_val, *buf_len);

cleanup_x942dhpri2asn:

	freezero(tmp_pad.big_value, tmp_pad.big_value_len);

	if (key_asn != NULLBER)
		ber_free(key_asn, 1);

	if (key_octs != NULL)
		ber_bvfree(key_octs);

	if (p8obj_asn != NULLBER)
		ber_free(p8obj_asn, 1);

	if (p8obj_octs != NULL)
		ber_bvfree(p8obj_octs);

	return (rv);
}

/*
 * Encode the object key from the soft_object_t into ASN.1 format.
 */
CK_RV
soft_object_to_asn1(soft_object_t *objp, uchar_t *buf, ulong_t *buf_len)
{
	CK_OBJECT_CLASS class = objp->class;
	CK_KEY_TYPE	keytype = objp->key_type;

	switch (class) {

	case CKO_PRIVATE_KEY:
		switch (keytype) {
		case CKK_RSA:
			return (rsa_pri_to_asn1(objp, buf, buf_len));

		case CKK_DSA:
			return (dsa_pri_to_asn1(objp, buf, buf_len));

		case CKK_DH:
			return (dh_pri_to_asn1(objp, buf, buf_len));

		case CKK_X9_42_DH:
			return (x942_dh_pri_to_asn1(objp, buf, buf_len));

		default:
			return (CKR_FUNCTION_NOT_SUPPORTED);
		} /* keytype */

	default:
		return (CKR_FUNCTION_NOT_SUPPORTED);

	} /* class */
}

/* Decode ASN.1 BER syntax into RSA private key. */
static CK_RV
asn1_to_rsa_pri(private_key_obj_t *keyp, uchar_t *buf, ulong_t buf_len)
{
	CK_RV		rv = CKR_OK;
	BerValue	p8obj_octs, key_octs;
	BerElement	*p8obj_asn = NULLBER, *key_asn = NULLBER;
	ber_len_t	size, tmplen;
	char		*cookie;
	int		version;
	uchar_t		oid[sizeof (RSA_OID) + 1];
	biginteger_t	tmp, tmp_nopad = { NULL, 0 };

	p8obj_octs.bv_val = (char *)buf;
#ifdef _LP64
	/* LINTED E_CAST_INT_TO_SMALL_INT */
	p8obj_octs.bv_len = (ber_len_t)buf_len;
#else
	p8obj_octs.bv_len = (ber_len_t)buf_len;
#endif

	key_octs.bv_val = NULL;
	key_octs.bv_len = 0;

	/* Decode PKCS#8 object ASN.1, verifying it is RSA private key. */
	if ((p8obj_asn = ber_init(&p8obj_octs)) == NULLBER)
		return (CKR_GENERAL_ERROR);

	/* PKCS#8 PrivateKeyInfo ... */
	if (ber_first_element(p8obj_asn, &size, &cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2rsapri;
	}
	/* ... begin-sequence { version, */
	(void) ber_scanf(p8obj_asn, "i", &version);	/* "{i" ? */

	if (ber_next_element(p8obj_asn, &size, cookie) != LBER_SEQUENCE) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2rsapri;
	}
	/* ... begin-sequence { */
	(void) ber_scanf(p8obj_asn, "{");

	if (ber_next_element(p8obj_asn, &size, cookie) != OID_TAG) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2rsapri;
	}
	/* ... OID, \* RSA algorithm OID *\ */
	if (size != sizeof (RSA_OID)) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto cleanup_asn2rsapri;
	}
	size = sizeof (oid);
	(void) ber_scanf(p8obj_asn, "s", oid, &size);
	if (memcmp(oid, RSA_OID, size) != 0) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto cleanup_asn2rsapri;
	}

	if (ber_next_element(p8obj_asn, &size, cookie) != LBER_NULL) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2rsapri;
	}
	/* ... param(NULL) } end-sequence */
	(void) ber_scanf(p8obj_asn, "n");		/* "n}" ? */

	if (ber_next_element(p8obj_asn, &size, cookie) != LBER_OCTETSTRING) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2rsapri;
	}
	/* ... RSAPrivateKey } end-sequence */
	key_octs.bv_len = size + 1;
	if ((key_octs.bv_val = malloc(size + 1)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanup_asn2rsapri;
	}
	(void) ber_scanf(p8obj_asn, "s",		/* "s}" ? */
	    key_octs.bv_val, &key_octs.bv_len);

	/* Decode key octet string into softtoken key object. */
	if ((key_asn = ber_init(&key_octs)) == NULLBER) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup_asn2rsapri;
	}

	/* ... begin-sequence { version, */
	if (ber_first_element(key_asn, &size, &cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2rsapri;
	}
	(void) ber_scanf(key_asn, "i", &version);	/* "{i" ? */

	/* ... modulus, */
	if (ber_next_element(key_asn, &size, cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2rsapri;
	}
	if (size > MAX_RSA_KEY) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto cleanup_asn2rsapri;
	}
	tmplen = size + 1;
	if ((tmp.big_value = malloc(tmplen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanup_asn2rsapri;
	}
	(void) ber_scanf(key_asn, "s", tmp.big_value, &tmplen);
	tmp.big_value_len = tmplen;
	if ((rv = unpad_bigint_attr(tmp, &tmp_nopad)) != CKR_OK) {
		free(tmp.big_value);
		goto cleanup_asn2rsapri;
	}
	free(tmp.big_value);
	copy_bigint_attr(&tmp_nopad, KEY_PRI_RSA_MOD(keyp));

	/* ... public exponent, */
	if (ber_next_element(key_asn, &size, cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto error_asn2rsapri;
	}
	if (size > MAX_RSA_KEY) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto error_asn2rsapri;
	}
	tmplen = size + 1;
	if ((tmp.big_value = malloc(tmplen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto error_asn2rsapri;
	}
	(void) ber_scanf(key_asn, "s", tmp.big_value, &tmplen);
	tmp.big_value_len = tmplen;
	if ((rv = unpad_bigint_attr(tmp, &tmp_nopad)) != CKR_OK) {
		free(tmp.big_value);
		goto error_asn2rsapri;
	}
	free(tmp.big_value);
	copy_bigint_attr(&tmp_nopad, KEY_PRI_RSA_PUBEXPO(keyp));

	/* ... private exponent, */
	if (ber_next_element(key_asn, &size, cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto error_asn2rsapri;
	}
	if (size > MAX_RSA_KEY) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto error_asn2rsapri;
	}
	tmplen = size + 1;
	if ((tmp.big_value = malloc(tmplen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto error_asn2rsapri;
	}
	(void) ber_scanf(key_asn, "s", tmp.big_value, &tmplen);
	tmp.big_value_len = tmplen;
	if ((rv = unpad_bigint_attr(tmp, &tmp_nopad)) != CKR_OK) {
		free(tmp.big_value);
		goto error_asn2rsapri;
	}
	free(tmp.big_value);
	copy_bigint_attr(&tmp_nopad, KEY_PRI_RSA_PRIEXPO(keyp));

	/* ... prime 1, */
	if (ber_next_element(key_asn, &size, cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto error_asn2rsapri;
	}
	if (size > MAX_RSA_KEY) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto error_asn2rsapri;
	}
	tmplen = size + 1;
	if ((tmp.big_value = malloc(tmplen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto error_asn2rsapri;
	}
	(void) ber_scanf(key_asn, "s", tmp.big_value, &tmplen);
	tmp.big_value_len = tmplen;
	if ((rv = unpad_bigint_attr(tmp, &tmp_nopad)) != CKR_OK) {
		free(tmp.big_value);
		goto error_asn2rsapri;
	}
	free(tmp.big_value);
	copy_bigint_attr(&tmp_nopad, KEY_PRI_RSA_PRIME1(keyp));

	/* ... prime 2, */
	if (ber_next_element(key_asn, &size, cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto error_asn2rsapri;
	}
	if (size > MAX_RSA_KEY) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto error_asn2rsapri;
	}
	tmplen = size + 1;
	if ((tmp.big_value = malloc(tmplen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto error_asn2rsapri;
	}
	(void) ber_scanf(key_asn, "s", tmp.big_value, &tmplen);
	tmp.big_value_len = tmplen;
	if ((rv = unpad_bigint_attr(tmp, &tmp_nopad)) != CKR_OK) {
		free(tmp.big_value);
		goto error_asn2rsapri;
	}
	free(tmp.big_value);
	copy_bigint_attr(&tmp_nopad, KEY_PRI_RSA_PRIME2(keyp));

	/* ... exponent 1, */
	if (ber_next_element(key_asn, &size, cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto error_asn2rsapri;
	}
	if (size > MAX_RSA_KEY) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto error_asn2rsapri;
	}
	tmplen = size + 1;
	if ((tmp.big_value = malloc(tmplen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto error_asn2rsapri;
	}
	(void) ber_scanf(key_asn, "s", tmp.big_value, &tmplen);
	tmp.big_value_len = tmplen;
	if ((rv = unpad_bigint_attr(tmp, &tmp_nopad)) != CKR_OK) {
		free(tmp.big_value);
		goto error_asn2rsapri;
	}
	free(tmp.big_value);
	copy_bigint_attr(&tmp_nopad, KEY_PRI_RSA_EXPO1(keyp));

	/* ... exponent 2, */
	if (ber_next_element(key_asn, &size, cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto error_asn2rsapri;
	}
	if (size > MAX_RSA_KEY) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto error_asn2rsapri;
	}
	tmplen = size + 1;
	if ((tmp.big_value = malloc(tmplen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto error_asn2rsapri;
	}
	(void) ber_scanf(key_asn, "s", tmp.big_value, &tmplen);
	tmp.big_value_len = tmplen;
	if ((rv = unpad_bigint_attr(tmp, &tmp_nopad)) != CKR_OK) {
		free(tmp.big_value);
		goto error_asn2rsapri;
	}
	free(tmp.big_value);
	copy_bigint_attr(&tmp_nopad, KEY_PRI_RSA_EXPO2(keyp));

	/* ... coefficient } end-sequence */
	if (ber_next_element(key_asn, &size, cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto error_asn2rsapri;
	}
	if (size > MAX_RSA_KEY) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto error_asn2rsapri;
	}
	tmplen = size + 1;
	if ((tmp.big_value = malloc(tmplen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto error_asn2rsapri;
	}
	(void) ber_scanf(key_asn, "s",		/* "s}" ? */
	    tmp.big_value, &tmplen);
	tmp.big_value_len = tmplen;
	if ((rv = unpad_bigint_attr(tmp, &tmp_nopad)) != CKR_OK) {
		free(tmp.big_value);
		goto error_asn2rsapri;
	}
	free(tmp.big_value);
	copy_bigint_attr(&tmp_nopad, KEY_PRI_RSA_COEF(keyp));

	goto cleanup_asn2rsapri;

error_asn2rsapri:

	bigint_attr_cleanup(KEY_PRI_RSA_MOD(keyp));
	bigint_attr_cleanup(KEY_PRI_RSA_PUBEXPO(keyp));
	bigint_attr_cleanup(KEY_PRI_RSA_PRIEXPO(keyp));
	bigint_attr_cleanup(KEY_PRI_RSA_PRIME1(keyp));
	bigint_attr_cleanup(KEY_PRI_RSA_PRIME2(keyp));
	bigint_attr_cleanup(KEY_PRI_RSA_EXPO1(keyp));
	bigint_attr_cleanup(KEY_PRI_RSA_EXPO2(keyp));
	bigint_attr_cleanup(KEY_PRI_RSA_COEF(keyp));

cleanup_asn2rsapri:

	freezero(tmp_nopad.big_value, tmp_nopad.big_value_len);

	if (p8obj_asn != NULLBER)
		ber_free(p8obj_asn, 1);

	if (key_octs.bv_val != NULL)
		free(key_octs.bv_val);

	if (key_asn != NULLBER)
		ber_free(key_asn, 1);

	return (rv);
}

/* Decode ASN.1 BER syntax into DSA private key. */
static CK_RV
asn1_to_dsa_pri(private_key_obj_t *keyp, uchar_t *buf, ulong_t buf_len)
{
	CK_RV		rv = CKR_OK;
	BerValue	p8obj_octs, key_octs;
	BerElement	*p8obj_asn = NULLBER, *key_asn = NULLBER;
	ber_len_t	size, tmplen;
	char		*cookie;
	int		version;
	uchar_t		oid[sizeof (DSA_OID) + 1];
	biginteger_t	tmp, tmp_nopad = { NULL, 0 };

	p8obj_octs.bv_val = (char *)buf;
#ifdef _LP64
	/* LINTED E_CAST_INT_TO_SMALL_INT */
	p8obj_octs.bv_len = (ber_len_t)buf_len;
#else
	p8obj_octs.bv_len = (ber_len_t)buf_len;
#endif

	key_octs.bv_val = NULL;
	key_octs.bv_len = 0;

	/* Decode PKCS#8 object ASN.1, verifying it is DSA private key. */
	if ((p8obj_asn = ber_init(&p8obj_octs)) == NULLBER)
		return (CKR_GENERAL_ERROR);

	/* PKCS#8 PrivateKeyInfo ... */
	if (ber_first_element(p8obj_asn, &size, &cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2dsapri;
	}
	/* ... begin-sequence { version, */
	(void) ber_scanf(p8obj_asn, "i", &version);	/* "{i" ? */

	if (ber_next_element(p8obj_asn, &size, cookie) != LBER_SEQUENCE) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2dsapri;
	}
	/* ... begin-sequence { */
	(void) ber_scanf(p8obj_asn, "{");

	if (ber_next_element(p8obj_asn, &size, cookie) != OID_TAG) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2dsapri;
	}
	/* ... OID, \* DSA algorithm OID *\ */
	if (size != sizeof (DSA_OID)) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto cleanup_asn2dsapri;
	}
	size = sizeof (oid);
	(void) ber_scanf(p8obj_asn, "s", oid, &size);
	if (memcmp(oid, DSA_OID, size) != 0) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto cleanup_asn2dsapri;
	}

	if (ber_next_element(p8obj_asn, &size, cookie) != LBER_SEQUENCE) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2dsapri;
	}
	/* ... begin-sequence { */
	(void) ber_scanf(p8obj_asn, "{");

	if (ber_next_element(p8obj_asn, &size, cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2dsapri;
	}
	/* ... prime, */
	if (size > MAX_DSA_KEY) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto cleanup_asn2dsapri;
	}
	tmplen = size + 1;
	if ((tmp.big_value = malloc(tmplen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanup_asn2dsapri;
	}
	(void) ber_scanf(p8obj_asn, "s", tmp.big_value, &tmplen);
	tmp.big_value_len = tmplen;
	if ((rv = unpad_bigint_attr(tmp, &tmp_nopad)) != CKR_OK) {
		free(tmp.big_value);
		goto cleanup_asn2dsapri;
	}
	free(tmp.big_value);
	copy_bigint_attr(&tmp_nopad, KEY_PRI_DSA_PRIME(keyp));

	if (ber_next_element(p8obj_asn, &size, cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto error_asn2dsapri;
	}
	/* ... subprime, */
	if (size > MAX_DSA_KEY) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto error_asn2dsapri;
	}
	tmplen = size + 1;
	if ((tmp.big_value = malloc(tmplen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto error_asn2dsapri;
	}
	(void) ber_scanf(p8obj_asn, "s", tmp.big_value, &tmplen);
	tmp.big_value_len = tmplen;
	if ((rv = unpad_bigint_attr(tmp, &tmp_nopad)) != CKR_OK) {
		free(tmp.big_value);
		goto error_asn2dsapri;
	}
	free(tmp.big_value);
	copy_bigint_attr(&tmp_nopad, KEY_PRI_DSA_SUBPRIME(keyp));

	if (ber_next_element(p8obj_asn, &size, cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto error_asn2dsapri;
	}
	/* ... base } end-sequence } end-sequence */
	if (size > MAX_DSA_KEY) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto error_asn2dsapri;
	}
	tmplen = size + 1;
	if ((tmp.big_value = malloc(tmplen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto error_asn2dsapri;
	}
	(void) ber_scanf(p8obj_asn, "s",		/* "s}}" ? */
	    tmp.big_value, &tmplen);
	tmp.big_value_len = tmplen;
	if ((rv = unpad_bigint_attr(tmp, &tmp_nopad)) != CKR_OK) {
		free(tmp.big_value);
		goto error_asn2dsapri;
	}
	free(tmp.big_value);
	copy_bigint_attr(&tmp_nopad, KEY_PRI_DSA_BASE(keyp));

	if (ber_next_element(p8obj_asn, &size, cookie) != LBER_OCTETSTRING) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto error_asn2dsapri;
	}
	/* ... DSAPrivateKey } end-sequence */
	key_octs.bv_len = size + 1;
	if ((key_octs.bv_val = malloc(size + 1)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto error_asn2dsapri;
	}
	(void) ber_scanf(p8obj_asn, "s",		/* "s}" ? */
	    key_octs.bv_val, &key_octs.bv_len);

	/* Decode key octet string into softtoken key object. */
	if ((key_asn = ber_init(&key_octs)) == NULLBER) {
		rv = CKR_GENERAL_ERROR;
		goto error_asn2dsapri;
	}

	if (ber_next_element(key_asn, &size, cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto error_asn2dsapri;
	}
	/* ... value } end-sequence */
	if (size > MAX_DSA_KEY) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto error_asn2dsapri;
	}
	tmplen = size + 1;
	if ((tmp.big_value = malloc(tmplen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto error_asn2dsapri;
	}
	(void) ber_scanf(key_asn, "s",		/* "s}" ? */
	    tmp.big_value, &tmplen);
	tmp.big_value_len = tmplen;
	if ((rv = unpad_bigint_attr(tmp, &tmp_nopad)) != CKR_OK) {
		free(tmp.big_value);
		goto error_asn2dsapri;
	}
	free(tmp.big_value);
	copy_bigint_attr(&tmp_nopad, KEY_PRI_DSA_VALUE(keyp));

	goto cleanup_asn2dsapri;

error_asn2dsapri:

	bigint_attr_cleanup(KEY_PRI_DSA_PRIME(keyp));
	bigint_attr_cleanup(KEY_PRI_DSA_SUBPRIME(keyp));
	bigint_attr_cleanup(KEY_PRI_DSA_BASE(keyp));
	bigint_attr_cleanup(KEY_PRI_DSA_VALUE(keyp));

cleanup_asn2dsapri:

	freezero(tmp_nopad.big_value, tmp_nopad.big_value_len);

	if (p8obj_asn != NULLBER)
		ber_free(p8obj_asn, 1);

	if (key_octs.bv_val != NULL)
		free(key_octs.bv_val);

	if (key_asn != NULLBER)
		ber_free(key_asn, 1);

	return (rv);
}

/* Decode ASN.1 BER syntax into DH private key. */
static CK_RV
asn1_to_dh_pri(private_key_obj_t *keyp, uchar_t *buf, ulong_t buf_len)
{
	CK_RV		rv = CKR_OK;
	BerValue	p8obj_octs, key_octs;
	BerElement	*p8obj_asn = NULLBER, *key_asn = NULLBER;
	ber_len_t	size, tmplen;
	char		*cookie;
	int		version;
	uchar_t		oid[sizeof (DH_OID) + 1];
	biginteger_t	tmp, tmp_nopad = { NULL, 0 };

	p8obj_octs.bv_val = (char *)buf;
#ifdef _LP64
	/* LINTED E_CAST_INT_TO_SMALL_INT */
	p8obj_octs.bv_len = (ber_len_t)buf_len;
#else
	p8obj_octs.bv_len = (ber_len_t)buf_len;
#endif

	key_octs.bv_val = NULL;
	key_octs.bv_len = 0;

	/* Decode PKCS#8 object ASN.1, verifying it is DH private key. */
	if ((p8obj_asn = ber_init(&p8obj_octs)) == NULLBER)
		return (CKR_GENERAL_ERROR);

	/* PKCS#8 PrivateKeyInfo ... */
	if (ber_first_element(p8obj_asn, &size, &cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2dhpri;
	}
	/* ... begin-sequence { version, */
	(void) ber_scanf(p8obj_asn, "i", &version);	/* "{i" ? */

	if (ber_next_element(p8obj_asn, &size, cookie) != LBER_SEQUENCE) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2dhpri;
	}
	/* ... begin-sequence { */
	(void) ber_scanf(p8obj_asn, "{");

	if (ber_next_element(p8obj_asn, &size, cookie) != OID_TAG) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2dhpri;
	}
	/* ... OID, \* DH algorithm OID *\ */
	if (size != sizeof (DH_OID)) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto cleanup_asn2dhpri;
	}
	size = sizeof (oid);
	(void) ber_scanf(p8obj_asn, "s", oid, &size);
	if (memcmp(oid, DH_OID, size) != 0) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto cleanup_asn2dhpri;
	}

	if (ber_next_element(p8obj_asn, &size, cookie) != LBER_SEQUENCE) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2dhpri;
	}
	/* ... begin-sequence { */
	(void) ber_scanf(p8obj_asn, "{");

	if (ber_next_element(p8obj_asn, &size, cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2dhpri;
	}
	/* ... prime, */
	if (size > MAX_DH_KEY) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto cleanup_asn2dhpri;
	}
	tmplen = size + 1;
	if ((tmp.big_value = malloc(tmplen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanup_asn2dhpri;
	}
	(void) ber_scanf(p8obj_asn, "s", tmp.big_value, &tmplen);
	tmp.big_value_len = tmplen;
	if ((rv = unpad_bigint_attr(tmp, &tmp_nopad)) != CKR_OK) {
		free(tmp.big_value);
		goto cleanup_asn2dhpri;
	}
	free(tmp.big_value);
	copy_bigint_attr(&tmp_nopad, KEY_PRI_DH_PRIME(keyp));

	if (ber_next_element(p8obj_asn, &size, cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto error_asn2dhpri;
	}
	/* ... base } end-sequence } end-sequence */
	if (size > MAX_DH_KEY) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto error_asn2dhpri;
	}
	tmplen = size + 1;
	if ((tmp.big_value = malloc(tmplen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto error_asn2dhpri;
	}
	(void) ber_scanf(p8obj_asn, "s",		/* "s}}" ? */
	    tmp.big_value, &tmplen);
	tmp.big_value_len = tmplen;
	if ((rv = unpad_bigint_attr(tmp, &tmp_nopad)) != CKR_OK) {
		free(tmp.big_value);
		goto error_asn2dhpri;
	}
	free(tmp.big_value);
	copy_bigint_attr(&tmp_nopad, KEY_PRI_DH_BASE(keyp));

	if (ber_next_element(p8obj_asn, &size, cookie) != LBER_OCTETSTRING) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto error_asn2dhpri;
	}
	/* ... DHPrivateKey } end-sequence */
	key_octs.bv_len = size + 1;
	if ((key_octs.bv_val = malloc(size + 1)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto error_asn2dhpri;
	}
	(void) ber_scanf(p8obj_asn, "s",		/* "s}" ? */
	    key_octs.bv_val, &key_octs.bv_len);

	/* Decode key octet string into softtoken key object. */
	if ((key_asn = ber_init(&key_octs)) == NULLBER) {
		rv = CKR_GENERAL_ERROR;
		goto error_asn2dhpri;
	}

	if (ber_next_element(key_asn, &size, cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto error_asn2dhpri;
	}
	/* ... value } end-sequence */
	if (size > MAX_DH_KEY) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto error_asn2dhpri;
	}
	tmplen = size + 1;
	if ((tmp.big_value = malloc(tmplen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto error_asn2dhpri;
	}
	(void) ber_scanf(key_asn, "s",		/* "s}" ? */
	    tmp.big_value, &tmplen);
	tmp.big_value_len = tmplen;
	if ((rv = unpad_bigint_attr(tmp, &tmp_nopad)) != CKR_OK) {
		free(tmp.big_value);
		goto error_asn2dhpri;
	}
	free(tmp.big_value);
	copy_bigint_attr(&tmp_nopad, KEY_PRI_DH_VALUE(keyp));

	goto cleanup_asn2dhpri;

error_asn2dhpri:

	bigint_attr_cleanup(KEY_PRI_DH_PRIME(keyp));
	bigint_attr_cleanup(KEY_PRI_DH_BASE(keyp));
	bigint_attr_cleanup(KEY_PRI_DH_VALUE(keyp));

cleanup_asn2dhpri:

	freezero(tmp_nopad.big_value, tmp_nopad.big_value_len);

	if (p8obj_asn != NULLBER)
		ber_free(p8obj_asn, 1);

	if (key_octs.bv_val != NULL)
		free(key_octs.bv_val);

	if (key_asn != NULLBER)
		ber_free(key_asn, 1);

	return (rv);
}

/* Decode ASN.1 BER syntax into DH X9.42 private key. */
static CK_RV
asn1_to_x942_dh_pri(private_key_obj_t *keyp, uchar_t *buf, ulong_t buf_len)
{
	CK_RV		rv = CKR_OK;
	BerValue	p8obj_octs, key_octs;
	BerElement	*p8obj_asn = NULLBER, *key_asn = NULLBER;
	ber_len_t	size, tmplen;
	char		*cookie;
	int		version;
	uchar_t		oid[sizeof (DH942_OID) + 1];
	biginteger_t	tmp, tmp_nopad = { NULL, 0 };

	p8obj_octs.bv_val = (char *)buf;
#ifdef _LP64
	/* LINTED E_CAST_INT_TO_SMALL_INT */
	p8obj_octs.bv_len = (ber_len_t)buf_len;
#else
	p8obj_octs.bv_len = (ber_len_t)buf_len;
#endif

	key_octs.bv_val = NULL;
	key_octs.bv_len = 0;

	/* Decode PKCS#8 object ASN.1, verifying it is DH X9.42 private key. */
	if ((p8obj_asn = ber_init(&p8obj_octs)) == NULLBER)
		return (CKR_GENERAL_ERROR);

	/* PKCS#8 PrivateKeyInfo ... */
	if (ber_first_element(p8obj_asn, &size, &cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2x942dhpri;
	}
	/* ... begin-sequence { version, */
	(void) ber_scanf(p8obj_asn, "i", &version);	/* "{i" ? */

	if (ber_next_element(p8obj_asn, &size, cookie) != LBER_SEQUENCE) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2x942dhpri;
	}
	/* ... begin-sequence { */
	(void) ber_scanf(p8obj_asn, "{");

	if (ber_next_element(p8obj_asn, &size, cookie) != OID_TAG) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2x942dhpri;
	}
	/* ... OID, \* DH X9.42 algorithm OID *\ */
	if (size != sizeof (DH942_OID)) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto cleanup_asn2x942dhpri;
	}
	size = sizeof (oid);
	(void) ber_scanf(p8obj_asn, "s", oid, &size);
	if (memcmp(oid, DH942_OID, size) != 0) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto cleanup_asn2x942dhpri;
	}

	if (ber_next_element(p8obj_asn, &size, cookie) != LBER_SEQUENCE) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2x942dhpri;
	}
	/* ... begin-sequence { */
	(void) ber_scanf(p8obj_asn, "{");

	if (ber_next_element(p8obj_asn, &size, cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto cleanup_asn2x942dhpri;
	}
	/* ... prime, */
	if (size > MAX_DH942_KEY) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto cleanup_asn2x942dhpri;
	}
	tmplen = size + 1;
	if ((tmp.big_value = malloc(tmplen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto cleanup_asn2x942dhpri;
	}
	(void) ber_scanf(p8obj_asn, "s", tmp.big_value, &tmplen);
	tmp.big_value_len = tmplen;
	if ((rv = unpad_bigint_attr(tmp, &tmp_nopad)) != CKR_OK) {
		free(tmp.big_value);
		goto cleanup_asn2x942dhpri;
	}
	free(tmp.big_value);
	copy_bigint_attr(&tmp_nopad, KEY_PRI_DH942_PRIME(keyp));

	if (ber_next_element(p8obj_asn, &size, cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto error_asn2x942dhpri;
	}
	/* ... base, */
	if (size > MAX_DH942_KEY) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto error_asn2x942dhpri;
	}
	tmplen = size + 1;
	if ((tmp.big_value = malloc(tmplen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto error_asn2x942dhpri;
	}
	(void) ber_scanf(p8obj_asn, "s", tmp.big_value, &tmplen);
	tmp.big_value_len = tmplen;
	if ((rv = unpad_bigint_attr(tmp, &tmp_nopad)) != CKR_OK) {
		free(tmp.big_value);
		goto error_asn2x942dhpri;
	}
	free(tmp.big_value);
	copy_bigint_attr(&tmp_nopad, KEY_PRI_DH942_BASE(keyp));

	if (ber_next_element(p8obj_asn, &size, cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto error_asn2x942dhpri;
	}
	/* ... subprime } end-sequence } end-sequence */
	if (size > MAX_DH942_KEY) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto error_asn2x942dhpri;
	}
	tmplen = size + 1;
	if ((tmp.big_value = malloc(tmplen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto error_asn2x942dhpri;
	}
	(void) ber_scanf(p8obj_asn, "s",		/* "s}}" ? */
	    tmp.big_value, &tmplen);
	tmp.big_value_len = tmplen;
	if ((rv = unpad_bigint_attr(tmp, &tmp_nopad)) != CKR_OK) {
		free(tmp.big_value);
		goto error_asn2x942dhpri;
	}
	free(tmp.big_value);
	copy_bigint_attr(&tmp_nopad, KEY_PRI_DH942_SUBPRIME(keyp));

	if (ber_next_element(p8obj_asn, &size, cookie) != LBER_OCTETSTRING) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto error_asn2x942dhpri;
	}
	/* ... DHPrivateKey } end-sequence */
	key_octs.bv_len = size + 1;
	if ((key_octs.bv_val = malloc(size + 1)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto error_asn2x942dhpri;
	}
	(void) ber_scanf(p8obj_asn, "s",		/* "s}" ? */
	    key_octs.bv_val, &key_octs.bv_len);

	/* Decode key octet string into softtoken key object. */
	if ((key_asn = ber_init(&key_octs)) == NULLBER) {
		rv = CKR_GENERAL_ERROR;
		goto error_asn2x942dhpri;
	}

	if (ber_next_element(key_asn, &size, cookie) != LBER_INTEGER) {
		rv = CKR_WRAPPED_KEY_INVALID;
		goto error_asn2x942dhpri;
	}
	/* ... value } end-sequence */
	if (size > MAX_DH942_KEY) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		goto error_asn2x942dhpri;
	}
	tmplen = size + 1;
	if ((tmp.big_value = malloc(tmplen)) == NULL) {
		rv = CKR_HOST_MEMORY;
		goto error_asn2x942dhpri;
	}
	(void) ber_scanf(key_asn, "s",		/* "s}" ? */
	    tmp.big_value, &tmplen);
	tmp.big_value_len = tmplen;
	if ((rv = unpad_bigint_attr(tmp, &tmp_nopad)) != CKR_OK) {
		free(tmp.big_value);
		goto error_asn2x942dhpri;
	}
	free(tmp.big_value);
	copy_bigint_attr(&tmp_nopad, KEY_PRI_DH942_VALUE(keyp));

	goto cleanup_asn2x942dhpri;

error_asn2x942dhpri:

	bigint_attr_cleanup(KEY_PRI_DH942_PRIME(keyp));
	bigint_attr_cleanup(KEY_PRI_DH942_BASE(keyp));
	bigint_attr_cleanup(KEY_PRI_DH942_SUBPRIME(keyp));
	bigint_attr_cleanup(KEY_PRI_DH942_VALUE(keyp));

cleanup_asn2x942dhpri:

	freezero(tmp_nopad.big_value, tmp_nopad.big_value_len);

	if (p8obj_asn != NULLBER)
		ber_free(p8obj_asn, 1);

	if (key_octs.bv_val != NULL)
		free(key_octs.bv_val);

	if (key_asn != NULLBER)
		ber_free(key_asn, 1);

	return (rv);
}

/*
 * Decode the object key from ASN.1 format into soft_object_t.
 */
CK_RV
soft_asn1_to_object(soft_object_t *objp, uchar_t *buf, ulong_t buf_len)
{
	CK_RV		rv = CKR_OK;
	CK_OBJECT_CLASS class = objp->class;
	CK_KEY_TYPE	keytype = objp->key_type;
	private_key_obj_t *pvk;

	switch (class) {

	case CKO_PRIVATE_KEY:
		/* Allocate storage for Private Key Object. */
		if ((pvk = calloc(1, sizeof (private_key_obj_t))) == NULL) {
			rv = CKR_HOST_MEMORY;
			return (rv);
		}

		switch (keytype) {
		case CKK_RSA:
			rv = asn1_to_rsa_pri(pvk, buf, buf_len);
			break;

		case CKK_DSA:
			rv = asn1_to_dsa_pri(pvk, buf, buf_len);
			break;

		case CKK_DH:
			rv = asn1_to_dh_pri(pvk, buf, buf_len);
			break;

		case CKK_X9_42_DH:
			rv = asn1_to_x942_dh_pri(pvk, buf, buf_len);
			break;

		default:
			rv = CKR_FUNCTION_NOT_SUPPORTED;
			break;

		} /* keytype */

		if (rv != CKR_OK)
			free(pvk);
		else
			objp->object_class_u.private_key = pvk;
		break;

	default:
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		break;

	} /* class */

	return (rv);
}
