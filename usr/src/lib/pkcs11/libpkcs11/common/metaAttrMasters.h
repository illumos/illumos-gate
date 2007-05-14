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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _META_ATTRMASTERS_H
#define	_META_ATTRMASTERS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Master object templates
 *
 * [This file should only be included by a single source file. This is a
 * non-traditional header file in that it simply contains a bunch of large,
 * preinitialized static const structures. They're stored here to keep them
 * "out of the way."]
 *
 * In PKCS#11, each object is well-defined... Each object type has an exact
 * set of attributes, and each attribute always has some value. Some
 * attribute values must be specificed when the object is created, others
 * are optional (ie, a default value exisits). Thus, the template an
 * application provides when creating a new object may be a subset of the
 * allowed attributes. The "master" templates presented here, however,
 * are complete.
 */


/*
 * Aliases for some field values in generic_attr_t, so that the initialization
 * below isn't just a confusing mess of B_TRUE and B_FALSE. Lint
 * complaints about using "!Foo" in const initializers,
 * so we #define each value.
 */

#define	unused		0
#define	Mallocd		B_TRUE
#define	Clone		B_TRUE
#define	EmptyValue	B_TRUE
#define	NotMallocd	B_FALSE
#define	NotClone	B_FALSE
#define	NotEmptyValue	B_FALSE
#define	EMPTYDATE	' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '
#define	EMPTY		'\0'

/*
 * A note regarding CKA_CLASS and sub-type (eg CKA_KEY_TYPE)
 *
 * These two attributes have been moved to the top of the master template
 * definitions. All the metaslot code assumes that CKA_CLASS resides in index=0,
 * and the sub-type resides in index=1.
 */


/*
 * Common storage object attributes, Table 19 (p81) of PKCS#11 2.11r1 spec.
 */
#define	COMMON_STORAGE_ATTRIBUTES					\
	{ { CKA_TOKEN, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_FALSE, unused, { unused } },				\
	{ { CKA_PRIVATE, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_FALSE, unused, { unused } },				\
	{ { CKA_MODIFIABLE, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_TRUE, unused, { unused } },				\
	{ { CKA_LABEL, NULL, 0 },					\
		NotMallocd, Clone, EmptyValue, B_FALSE,			\
		unused, unused, { EMPTY } }

/*
 * Common certificate attributes, Table 21 (p83) of PKCS#11 2.11r1 spec.
 * (CKA_CERTIFICATE_TYPE has been moved, to place at top of template)
 *
 */
#define	COMMON_CERTIFICATE_ATTRIBUTES					\
	{ { CKA_TRUSTED, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, NotClone, NotEmptyValue, B_FALSE,		\
		CK_FALSE, unused, { unused } }

/*
 * Common key attributes, Table 25 (p89) of PKCS#11 2.11r1 spec.
 * (CKA_KEY_TYPE has been moved, to place at top of template)
 *
 */
#define	COMMON_KEY_ATTRIBUTES						\
	{ { CKA_ID, NULL, 0 },						\
		NotMallocd, Clone, EmptyValue, B_FALSE,			\
		unused, unused, { EMPTY } },				\
	{ { CKA_START_DATE, NULL, sizeof (CK_DATE) },			\
		NotMallocd, Clone, EmptyValue, B_FALSE,			\
		unused, unused, { EMPTYDATE } },			\
	{ { CKA_END_DATE, NULL, sizeof (CK_DATE) },			\
		NotMallocd, Clone, EmptyValue, B_FALSE,			\
		unused, unused, { EMPTYDATE } },			\
	{ { CKA_DERIVE, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_FALSE, unused, { unused } },				\
	{ { CKA_LOCAL, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, NotClone, NotEmptyValue, B_FALSE,		\
		CK_FALSE, unused, { unused } },				\
	{ { CKA_KEY_GEN_MECHANISM, NULL, sizeof (CK_MECHANISM_TYPE) },	\
		NotMallocd, NotClone, EmptyValue, B_FALSE,		\
		unused, CK_UNAVAILABLE_INFORMATION, { unused } }

/*
 * Common public-key attributes, Table 26 (p90) of PKCS#11 2.11r1 spec.
 *
 * CKA_SUBJECT has the PKCS#11-specified default. The object-usage attributes
 * are token-specific defaults.
 *
 */
#define	COMMON_PUBKEY_ATTRIBUTES					\
	{ { CKA_SUBJECT, NULL, 0 },					\
		NotMallocd, Clone, EmptyValue, B_FALSE,			\
		unused, unused, { EMPTY } },				\
	{ { CKA_ENCRYPT, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_TRUE, unused, { unused } },				\
	{ { CKA_VERIFY, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_TRUE, unused, { unused } },				\
	{ { CKA_VERIFY_RECOVER, NULL, sizeof (CK_BBOOL) },		\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_TRUE, unused, { unused } },				\
	{ { CKA_WRAP, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_TRUE, unused, { unused } },				\
	{ { CKA_TRUSTED, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, NotClone, NotEmptyValue, B_FALSE,		\
		CK_FALSE, unused, { unused } }

/*
 * Common private-key attributes, Table 34 (p97) of PKCS#11 2.11r1 spec.
 */
#define	COMMON_PRIVKEY_ATTRIBUTES					\
	{ { CKA_SUBJECT, NULL, 0 },					\
		NotMallocd, Clone, EmptyValue, B_FALSE,			\
		unused, unused, { EMPTY } },				\
	{ { CKA_SENSITIVE, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_FALSE, unused, { unused } },				\
	{ { CKA_SECONDARY_AUTH, NULL, sizeof (CK_BBOOL) },		\
		NotMallocd, Clone, EmptyValue, B_FALSE,			\
		CK_FALSE, unused, { unused } },				\
	{ { CKA_DECRYPT, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_TRUE, unused, { unused } },				\
	{ { CKA_SIGN, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_TRUE, unused, { unused } },				\
	{ { CKA_SIGN_RECOVER, NULL, sizeof (CK_BBOOL) },		\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_TRUE, unused, { unused } },				\
	{ { CKA_UNWRAP, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_TRUE, unused, { unused } },				\
	{ { CKA_EXTRACTABLE, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_TRUE, unused, { unused } },				\
	{ { CKA_ALWAYS_SENSITIVE, NULL, sizeof (CK_BBOOL) },		\
		NotMallocd, NotClone, NotEmptyValue, B_FALSE,		\
		CK_FALSE, unused, { unused } },				\
	{ { CKA_NEVER_EXTRACTABLE, NULL, sizeof (CK_BBOOL) },		\
		NotMallocd, NotClone, NotEmptyValue, B_FALSE,		\
		CK_FALSE, unused, { unused } }


/*
 * Common secret-key attributes, Table 42 (p108) of PKCS#11 2.11r1 spec.
 */
#define	COMMON_SECKEY_ATTRIBUTES					\
	{ { CKA_SENSITIVE, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_FALSE, unused, { unused } },				\
	{ { CKA_ENCRYPT, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_TRUE, unused, { unused } },				\
	{ { CKA_DECRYPT, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_TRUE, unused, { unused } },				\
	{ { CKA_SIGN, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_TRUE, unused, { unused } },				\
	{ { CKA_VERIFY, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_TRUE, unused, { unused } },				\
	{ { CKA_WRAP, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_TRUE, unused, { unused } },				\
	{ { CKA_UNWRAP, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_TRUE, unused, { unused } },				\
	{ { CKA_EXTRACTABLE, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_TRUE, unused, { unused } },				\
	{ { CKA_ALWAYS_SENSITIVE, NULL, sizeof (CK_BBOOL) },		\
		NotMallocd, NotClone, NotEmptyValue, B_FALSE,		\
		CK_FALSE, unused, { unused } },				\
	{ { CKA_NEVER_EXTRACTABLE, NULL, sizeof (CK_BBOOL) },		\
		NotMallocd, NotClone, NotEmptyValue, B_FALSE,		\
		CK_FALSE, unused, { unused } }

/*
 * Common domain-paramaters attributes, Table 60 (p123) of PKCS#11 2.11r1 spec.
 * (CKA_KEY_TYPE has been removed, to place elsewhere)
 */
#define	COMMON_DOMAIN_ATTRIBUTES					\
	{ { CKA_LOCAL, NULL, sizeof (CK_BBOOL) },			\
		NotMallocd, Clone, NotEmptyValue, B_FALSE,		\
		CK_FALSE, unused, { unused } }


/* ========================= HW Objects ========================= */


/*
 * Master template for: CKO_HW_FEATURE + CKH_CLOCK
 */
static const generic_attr_t OBJ_HW_CLOCK[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_HW_FEATURE, { unused } },
	{ { CKA_HW_FEATURE_TYPE, NULL, sizeof (CK_HW_FEATURE_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKH_CLOCK, { unused } },
	{ { CKA_VALUE, NULL, 16 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTYDATE, EMPTYDATE } }
};


/*
 * Master template for: CKO_HW_FEATURE + CKH_MONOTONIC_COUNTER
 *
 * NOTE: no sub-type for this class!
 */
static const generic_attr_t OBJ_HW_MONOTONIC[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_HW_FEATURE, { unused } },
	{ { CKA_HW_FEATURE_TYPE, NULL, sizeof (CK_HW_FEATURE_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKH_MONOTONIC_COUNTER, { unused } },
	{ { CKA_VALUE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_RESET_ON_INIT, NULL, sizeof (CK_BBOOL) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		CK_FALSE, unused, { unused } },
	{ { CKA_HAS_RESET, NULL, sizeof (CK_BBOOL) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		CK_FALSE, unused, { unused } }
};


/* ========================= Data Objects ========================= */


/*
 * Master template for CKO_DATA + (no subtypes for this class)
 *
 * Defaults are according to PKCS#11.
 *
 * NOTE: no sub-type for this class!
 */
static const generic_attr_t OBJ_DATA[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_DATA, { unused } },
	COMMON_STORAGE_ATTRIBUTES,
	{ { CKA_APPLICATION, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_OBJECT_ID, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_VALUE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } }
};


/* ========================= Certificate Objects ========================= */


/*
 * Master template for CKO_CERTIFICATE + CKC_X_509
 *
 * Defaults are according to PKCS#11.
 */
static const generic_attr_t OBJ_CERT_X509[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_CERTIFICATE, { unused } },
	{ { CKA_CERTIFICATE_TYPE, NULL, sizeof (CK_CERTIFICATE_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKC_X_509, { unused } },
	COMMON_STORAGE_ATTRIBUTES,
	COMMON_CERTIFICATE_ATTRIBUTES,
	{ { CKA_SUBJECT, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_ID, NULL, 0 },
		NotMallocd, Clone, EmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_ISSUER, NULL, 0 },
		NotMallocd, Clone, EmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_SERIAL_NUMBER, NULL, 0 },
		NotMallocd, Clone, EmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_VALUE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } }
};


/*
 * Master template for CKO_CERTIFICATE + CKC_X_509_ATTR_CERT
 *
 * Defaults are according to PKCS#11.
 */
static const generic_attr_t OBJ_CERT_X509ATTR[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_CERTIFICATE, { unused } },
	{ { CKA_CERTIFICATE_TYPE, NULL, sizeof (CK_CERTIFICATE_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKC_X_509_ATTR_CERT, { unused } },
	COMMON_STORAGE_ATTRIBUTES,
	COMMON_CERTIFICATE_ATTRIBUTES,
	{ { CKA_OWNER, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_AC_ISSUER, NULL, 0 },
		NotMallocd, Clone, EmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_SERIAL_NUMBER, NULL, 0 },
		NotMallocd, Clone, EmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_ATTR_TYPES, NULL, 0 },
		NotMallocd, Clone, EmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_VALUE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } }
};


/* ========================= Public Keys ========================= */


/*
 * Master template for CKO_PUBLIC_KEY + CKK_RSA
 */
static const generic_attr_t OBJ_PUBKEY_RSA[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_PUBLIC_KEY, { unused } },
	{ { CKA_KEY_TYPE, NULL, sizeof (CK_KEY_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKK_RSA, { unused } },
	COMMON_STORAGE_ATTRIBUTES,
	COMMON_KEY_ATTRIBUTES,
	COMMON_PUBKEY_ATTRIBUTES,
	{ { CKA_MODULUS, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_MODULUS_BITS, NULL, sizeof (CK_ULONG)},
		NotMallocd, NotClone, NotEmptyValue, B_FALSE,
		unused, 0, { unused } },
	{ { CKA_PUBLIC_EXPONENT, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } }
};


/*
 * Master template for CKO_PUBLIC_KEY + CKK_DSA
 *
 */
static const generic_attr_t OBJ_PUBKEY_DSA[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_PUBLIC_KEY, { unused } },
	{ { CKA_KEY_TYPE, NULL, sizeof (CK_KEY_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKK_DSA, { unused } },
	COMMON_STORAGE_ATTRIBUTES,
	COMMON_KEY_ATTRIBUTES,
	COMMON_PUBKEY_ATTRIBUTES,
	{ { CKA_PRIME, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_SUBPRIME, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_BASE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_VALUE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } }
};


/*
 * Master template for CKO_PUBLIC_KEY + CKK_EC
 *
 */
static const generic_attr_t OBJ_PUBKEY_EC[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_PUBLIC_KEY, { unused } },
	{ { CKA_KEY_TYPE, NULL, sizeof (CK_KEY_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKK_EC, { unused } },
	COMMON_STORAGE_ATTRIBUTES,
	COMMON_KEY_ATTRIBUTES,
	COMMON_PUBKEY_ATTRIBUTES,
	{ { CKA_EC_PARAMS, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_EC_POINT, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } }
};


/*
 * Master template for CKO_PUBLIC_KEY + CKK_DH
 *
 */
static const generic_attr_t OBJ_PUBKEY_DH[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_PUBLIC_KEY, { unused } },
	{ { CKA_KEY_TYPE, NULL, sizeof (CK_KEY_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKK_DH, { unused } },
	COMMON_STORAGE_ATTRIBUTES,
	COMMON_KEY_ATTRIBUTES,
	COMMON_PUBKEY_ATTRIBUTES,
	{ { CKA_PRIME, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_BASE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_VALUE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } }
};


/*
 * Master template for CKO_PUBLIC_KEY + CKK_X9_42_DH
 *
 */
static const generic_attr_t OBJ_PUBKEY_X942DH[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_PUBLIC_KEY, { unused } },
	{ { CKA_KEY_TYPE, NULL, sizeof (CK_KEY_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKK_X9_42_DH, { unused } },
	COMMON_STORAGE_ATTRIBUTES,
	COMMON_KEY_ATTRIBUTES,
	COMMON_PUBKEY_ATTRIBUTES,
	{ { CKA_PRIME, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_BASE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_SUBPRIME, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_VALUE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } }
};


/*
 * Master template for CKO_PUBLIC_KEY + CKK_KEA
 *
 */
static const generic_attr_t OBJ_PUBKEY_KEA[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_PUBLIC_KEY, { unused } },
	{ { CKA_KEY_TYPE, NULL, sizeof (CK_KEY_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKK_KEA, { unused } },
	COMMON_STORAGE_ATTRIBUTES,
	COMMON_KEY_ATTRIBUTES,
	COMMON_PUBKEY_ATTRIBUTES,
	{ { CKA_PRIME, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_BASE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_SUBPRIME, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_VALUE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } }
};


/* ========================= Private Keys ========================= */


/*
 * Master template for CKO_PRIVATE_KEY + CKK_RSA
 *
 */
static const generic_attr_t OBJ_PRIVKEY_RSA[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_PRIVATE_KEY, { unused } },
	{ { CKA_KEY_TYPE, NULL, sizeof (CK_KEY_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKK_RSA, { unused } },
	COMMON_STORAGE_ATTRIBUTES,
	COMMON_KEY_ATTRIBUTES,
	COMMON_PRIVKEY_ATTRIBUTES,
	{ { CKA_MODULUS, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_PRIVATE_EXPONENT, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_PUBLIC_EXPONENT, NULL, 0 },
		NotMallocd, Clone, EmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_PRIME_1, NULL, 0 },
		NotMallocd, Clone, EmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_PRIME_2, NULL, 0 },
		NotMallocd, Clone, EmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_EXPONENT_1, NULL, 0 },
		NotMallocd, Clone, EmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_EXPONENT_2, NULL, 0 },
		NotMallocd, Clone, EmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_COEFFICIENT, NULL, 0 },
		NotMallocd, Clone, EmptyValue, B_FALSE,
		unused, unused, { EMPTY } }
};


/*
 * Master template for CKO_PRIVATE_KEY + CKK_DSA
 *
 */
static const generic_attr_t OBJ_PRIVKEY_DSA[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_PRIVATE_KEY, { unused } },
	{ { CKA_KEY_TYPE, NULL, sizeof (CK_KEY_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKK_DSA, { unused } },
	COMMON_STORAGE_ATTRIBUTES,
	COMMON_KEY_ATTRIBUTES,
	COMMON_PRIVKEY_ATTRIBUTES,
	{ { CKA_PRIME, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_SUBPRIME, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_BASE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_VALUE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } }
};


/*
 * Master template for CKO_PRIVATE_KEY + CKK_EC
 *
 */
static const generic_attr_t OBJ_PRIVKEY_EC[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_PRIVATE_KEY, { unused } },
	{ { CKA_KEY_TYPE, NULL, sizeof (CK_KEY_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKK_EC, { unused } },
	COMMON_STORAGE_ATTRIBUTES,
	COMMON_KEY_ATTRIBUTES,
	COMMON_PRIVKEY_ATTRIBUTES,
	{ { CKA_EC_PARAMS, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_VALUE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } }
};


/*
 * Master template for CKO_PRIVATE_KEY + CKK_DH
 */
static const generic_attr_t OBJ_PRIVKEY_DH[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_PRIVATE_KEY, { unused } },
	{ { CKA_KEY_TYPE, NULL, sizeof (CK_KEY_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKK_DH, { unused } },
	COMMON_STORAGE_ATTRIBUTES,
	COMMON_KEY_ATTRIBUTES,
	COMMON_PRIVKEY_ATTRIBUTES,
	{ { CKA_PRIME, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_BASE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_VALUE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_VALUE_BITS, NULL, sizeof (CK_ULONG) },
		NotMallocd, NotClone, NotEmptyValue, B_FALSE,
		unused, 0, { unused } }
};


/*
 * Master template for CKO_PRIVATE_KEY + CKK_X9_42_DH
 *
 */
static const generic_attr_t OBJ_PRIVKEY_X942DH[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_PRIVATE_KEY, { unused } },
	{ { CKA_KEY_TYPE, NULL, sizeof (CK_KEY_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKK_X9_42_DH, { unused } },
	COMMON_STORAGE_ATTRIBUTES,
	COMMON_KEY_ATTRIBUTES,
	COMMON_PRIVKEY_ATTRIBUTES,
	{ { CKA_PRIME, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_SUBPRIME, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_BASE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_VALUE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } }
};


/*
 * Master template for CKO_PRIVATE_KEY + CKK_KEA
 *
 */
static const generic_attr_t OBJ_PRIVKEY_KEA[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_PRIVATE_KEY, { unused } },
	{ { CKA_KEY_TYPE, NULL, sizeof (CK_KEY_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKK_KEA, { unused } },
	COMMON_STORAGE_ATTRIBUTES,
	COMMON_KEY_ATTRIBUTES,
	COMMON_PRIVKEY_ATTRIBUTES,
	{ { CKA_PRIME, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_BASE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_SUBPRIME, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_VALUE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } }
};


/* ========================= Secret Keys ========================= */


/*
 * Master template for CKO_SECRET_KEY + (fixed-length keytype)
 */
static const generic_attr_t OBJ_SECKEY[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_SECRET_KEY, { unused } },
	{ { CKA_KEY_TYPE, NULL, sizeof (CK_KEY_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKK_GENERIC_SECRET, { unused } },
	COMMON_STORAGE_ATTRIBUTES,
	COMMON_KEY_ATTRIBUTES,
	COMMON_SECKEY_ATTRIBUTES,
	{ { CKA_VALUE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } }
};


/*
 * Master template for CKO_SECRET_KEY + (variable-length keytype)
 *
 */
static const generic_attr_t OBJ_SECKEY_WITHLEN[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_SECRET_KEY, { unused } },
	{ { CKA_KEY_TYPE, NULL, sizeof (CK_KEY_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKK_GENERIC_SECRET, { unused } },
	COMMON_STORAGE_ATTRIBUTES,
	COMMON_KEY_ATTRIBUTES,
	COMMON_SECKEY_ATTRIBUTES,
	{ { CKA_VALUE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_VALUE_LEN, NULL, sizeof (CK_ULONG) },
		NotMallocd, NotClone, NotEmptyValue, B_FALSE,
		unused, 0, { unused } }
};


/* ========================= Domain Parameters ========================= */


/*
 * Master template for CKO_DOMAIN_PARAMETERS + CKK_DSA
 *
 */
static const generic_attr_t OBJ_DOM_DSA[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_DOMAIN_PARAMETERS, { unused } },
	{ { CKA_KEY_TYPE, NULL, sizeof (CK_KEY_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKK_DSA, { unused } },
	COMMON_STORAGE_ATTRIBUTES,
	COMMON_DOMAIN_ATTRIBUTES,
	{ { CKA_PRIME, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_SUBPRIME, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_BASE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_PRIME_BITS, NULL, sizeof (CK_ULONG) },
		NotMallocd, NotClone, NotEmptyValue, B_FALSE,
		unused, 0, { unused } }
};

/*
 * Master template for CKO_DOMAIN_PARAMETERS + CKK_DH
 *
 */
static const generic_attr_t OBJ_DOM_DH[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_DOMAIN_PARAMETERS, { unused } },
	{ { CKA_KEY_TYPE, NULL, sizeof (CK_KEY_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKK_DH, { unused } },
	COMMON_STORAGE_ATTRIBUTES,
	COMMON_DOMAIN_ATTRIBUTES,
	{ { CKA_PRIME, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_BASE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_PRIME_BITS, NULL, sizeof (CK_ULONG) },
		NotMallocd, NotClone, NotEmptyValue, B_FALSE,
		unused, 0, { unused } }
};

/*
 * Master template for CKO_DOMAIN_PARAMETERS + CKK_X9_42_DH
 *
 */
static const generic_attr_t OBJ_DOM_X942DH[] =
{
	{ { CKA_CLASS, NULL, sizeof (CK_OBJECT_CLASS) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKO_DOMAIN_PARAMETERS, { unused } },
	{ { CKA_KEY_TYPE, NULL, sizeof (CK_KEY_TYPE) },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, CKK_X9_42_DH, { unused } },
	COMMON_STORAGE_ATTRIBUTES,
	COMMON_DOMAIN_ATTRIBUTES,
	{ { CKA_PRIME, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_BASE, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_SUBPRIME, NULL, 0 },
		NotMallocd, Clone, NotEmptyValue, B_FALSE,
		unused, unused, { EMPTY } },
	{ { CKA_PRIME_BITS, NULL, sizeof (CK_ULONG) },
		NotMallocd, NotClone, NotEmptyValue, B_FALSE,
		unused, 0, { unused } },
	{ { CKA_SUBPRIME_BITS, NULL, sizeof (CK_ULONG) },
		NotMallocd, NotClone, NotEmptyValue, B_FALSE,
		unused, 0, { unused } }
};

#ifdef	__cplusplus
}
#endif

#endif /* _META_ATTRMASTERS_H */
