/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * The contents of this file are subject to the Netscape Public License
 * Version 1.0(the "NPL"); you may not use this file except in
 * compliance with the NPL.  You may obtain a copy of the NPL at
 * http:/ /www.mozilla.org/NPL/
 *
 * Software distributed under the NPL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the NPL
 * for the specific language governing rights and limitations under the
 * NPL.
 *
 * The Initial Developer of this code under the NPL is Netscape
 * Communications Corporation.  Portions created by Netscape are
 * Copyright(C) 1998 Netscape Communications Corporation.  All Rights
 * Reserved.
 */

/*
 * This is the header file for some Basic Encoding Rules and Distinguished
 * Encoding Rules (BER/DER) routines.
 */

#ifndef BER_DER_H
#define	BER_DER_H

#include <kmfapi.h>

#define	BER_BOOLEAN			1
#define	BER_INTEGER			2
#define	BER_BIT_STRING			3
#define	BER_OCTET_STRING		4
#define	BER_NULL			5
#define	BER_OBJECT_IDENTIFIER		6
#define	BER_ENUMERATED			10
#define	BER_UTF8_STRING			12
#define	BER_SEQUENCE			16
#define	BER_SET				17
#define	BER_PRINTABLE_STRING		19
#define	BER_T61STRING			20
#define	BER_IA5STRING			22
#define	BER_UTCTIME			23
#define	BER_GENTIME			24
#define	BER_GENERALSTRING		27
#define	BER_UNIVERSAL_STRING		28
#define	BER_BMP_STRING			30

#define	BER_CLASS_MASK			0xc0
#define	BER_CLASS_UNIVERSAL		0x00
#define	BER_CLASS_APPLICATION		0x40
#define	BER_CLASS_CONTEXTSPECIFIC	0x80
#define	BER_CLASS_PRIVATE		0xc0
#define	BER_CONSTRUCTED			0x20
#define	BER_CONSTRUCTED_SEQUENCE	(BER_CONSTRUCTED | BER_SEQUENCE)
#define	BER_CONSTRUCTED_SET		(BER_CONSTRUCTED | BER_SET)

#define	KMFBER_BIG_TAG_MASK		0x1f
#define	KMFBER_MORE_TAG_MASK		0x80

#define	KMFBER_DEFAULT		0xFFFFFFFF
#define	KMFBER_ERROR		0xFFFFFFFF
#define	KMFBER_END_OF_SEQORSET	0xfffffffe

/* BerElement set/get options */
#define	KMFBER_OPT_REMAINING_BYTES	0x01
#define	KMFBER_OPT_TOTAL_BYTES		0x02
#define	KMFBER_OPT_USE_DER		0x04
#define	KMFBER_OPT_TRANSLATE_STRINGS	0x08
#define	KMFBER_OPT_BYTES_TO_WRITE	0x10
#define	KMFBER_OPT_DEBUG_LEVEL		0x40

typedef size_t		ber_len_t;  /* for BER len */
typedef long		ber_slen_t; /* signed equivalent of ber_len_t */
typedef int32_t		ber_tag_t;  /* for BER tags */
typedef int32_t		ber_int_t;  /* for BER ints, enums, and Booleans */
typedef uint32_t	ber_uint_t; /* unsigned equivalent of ber_int_t */

typedef struct berelement BerElement;
typedef int (*BERTranslateProc)(char **, ber_uint_t *, int);

typedef struct berval {
	ber_len_t	bv_len;
	char		*bv_val;
} BerValue;

#define	SAFEMEMCPY(d, s, n)	memmove(d, s, n)

BerElement *kmfder_init(const struct berval *bv);
BerElement *kmfber_init(const struct berval *bv);
int kmfber_calc_taglen(ber_tag_t);
int kmfber_calc_lenlen(ber_int_t);
int kmfber_put_len(BerElement *, ber_int_t, int);

/*
 * public decode routines
 */
ber_tag_t kmfber_first_element(BerElement *, ber_len_t *, char **);
ber_tag_t kmfber_next_element(BerElement *, ber_len_t *, char *);
ber_tag_t kmfber_scanf(BerElement *, const char *, ...);

void kmfber_bvfree(struct berval *);
void kmfber_bvecfree(struct berval **);
struct berval *kmfber_bvdup(const struct berval *);

/*
 * public encoding routines
 */
extern int kmfber_printf(BerElement *, const char *, ...);
extern int kmfber_flatten(BerElement *, struct berval **);
extern int kmfber_realloc(BerElement *, ber_len_t);

/*
 * miscellaneous public routines
 */
extern void kmfber_free(BerElement *ber, int freebuf);
extern BerElement* kmfber_alloc(void);
extern BerElement* kmfder_alloc(void);
extern BerElement* kmfber_alloc_t(int);
extern BerElement* kmfber_dup(BerElement *);
extern ber_int_t kmfber_read(BerElement *, char *, ber_len_t);
extern ber_int_t kmfber_write(BerElement *, char *, ber_len_t, int);
extern void kmfber_reset(BerElement *, int);

/* Routines KMF uses to encode/decode Cert objects */
extern KMF_RETURN DerDecodeSignedCertificate(const KMF_DATA *,
	KMF_X509_CERTIFICATE **);
extern KMF_RETURN DerEncodeSignedCertificate(KMF_X509_CERTIFICATE *,
	KMF_DATA *);

KMF_RETURN DerDecodeTbsCertificate(const KMF_DATA *,
	KMF_X509_TBS_CERT **);
KMF_RETURN DerEncodeTbsCertificate(KMF_X509_TBS_CERT *, KMF_DATA *);

KMF_RETURN DerDecodeSignedCsr(const KMF_DATA *, KMF_CSR_DATA **);
extern KMF_RETURN DerEncodeSignedCsr(KMF_CSR_DATA *, KMF_DATA *);
extern KMF_RETURN DerDecodeTbsCsr(const KMF_DATA *, KMF_TBS_CSR **);
extern KMF_RETURN DerEncodeTbsCsr(KMF_TBS_CSR *, KMF_DATA *);

KMF_RETURN ExtractX509CertParts(KMF_DATA *, KMF_DATA *, KMF_DATA *);
extern KMF_RETURN DerEncodeName(KMF_X509_NAME *, KMF_DATA *);
KMF_RETURN DerDecodeName(KMF_DATA *, KMF_X509_NAME *);
KMF_RETURN DerDecodeExtension(KMF_DATA *, KMF_X509_EXTENSION **);
KMF_RETURN CopyRDN(KMF_X509_NAME *, KMF_X509_NAME **);
KMF_RETURN CopySPKI(KMF_X509_SPKI *,
		KMF_X509_SPKI **);
extern KMF_RETURN DerDecodeSPKI(KMF_DATA *, KMF_X509_SPKI *);
extern KMF_RETURN DerDecodeDSASignature(KMF_DATA *, KMF_DATA *);
extern KMF_RETURN DerEncodeDSASignature(KMF_DATA *, KMF_DATA *);
extern KMF_RETURN DerEncodeECDSASignature(KMF_DATA *, KMF_DATA *);
extern KMF_RETURN DerDecodeECDSASignature(KMF_DATA *, KMF_DATA *);
KMF_RETURN DerEncodeAlgoid(KMF_DATA *, KMF_DATA *);
KMF_RETURN DerDecodeSPKI(KMF_DATA *, KMF_X509_SPKI *);
KMF_RETURN DerEncodeSPKI(KMF_X509_SPKI *, KMF_DATA *);
extern KMF_RETURN ExtractSPKIData(const KMF_X509_SPKI *,
	KMF_ALGORITHM_INDEX, KMF_DATA *, uint32_t *);
extern KMF_RETURN AddRDN(KMF_X509_NAME *, KMF_X509_RDN *);
KMF_RETURN DerEncodeRSAPrivateKey(KMF_DATA *, KMF_RAW_RSA_KEY *);
KMF_RETURN DerEncodeDSAPrivateKey(KMF_DATA *, KMF_RAW_DSA_KEY *);
KMF_RETURN DerEncodeECPrivateKey(KMF_DATA *, KMF_RAW_EC_KEY *);

#endif /* BER_DER_H */
