/*
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2012, OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright 2018 OmniOS Community Edition (OmniOSce) Association.
 */
/*
 * Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2000.
 */
/*
 * ====================================================================
 * Copyright (c) 2000-2004 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdlib.h>
#include <kmfapiP.h>
#include <ber_der.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <cryptoutil.h>
#include <synch.h>
#include <thread.h>

/* OPENSSL related headers */
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ocsp.h>
#include <openssl/des.h>
#include <openssl/rand.h>
#include "compat.h"

#define	PRINT_ANY_EXTENSION (\
	KMF_X509_EXT_KEY_USAGE |\
	KMF_X509_EXT_CERT_POLICIES |\
	KMF_X509_EXT_SUBJALTNAME |\
	KMF_X509_EXT_BASIC_CONSTRAINTS |\
	KMF_X509_EXT_NAME_CONSTRAINTS |\
	KMF_X509_EXT_POLICY_CONSTRAINTS |\
	KMF_X509_EXT_EXT_KEY_USAGE |\
	KMF_X509_EXT_INHIBIT_ANY_POLICY |\
	KMF_X509_EXT_AUTH_KEY_ID |\
	KMF_X509_EXT_SUBJ_KEY_ID |\
	KMF_X509_EXT_POLICY_MAPPING)

static uchar_t P[] = { 0x00, 0x8d, 0xf2, 0xa4, 0x94, 0x49, 0x22, 0x76,
	0xaa, 0x3d, 0x25, 0x75, 0x9b, 0xb0, 0x68, 0x69,
	0xcb, 0xea, 0xc0, 0xd8, 0x3a, 0xfb, 0x8d, 0x0c,
	0xf7, 0xcb, 0xb8, 0x32, 0x4f, 0x0d, 0x78, 0x82,
	0xe5, 0xd0, 0x76, 0x2f, 0xc5, 0xb7, 0x21, 0x0e,
	0xaf, 0xc2, 0xe9, 0xad, 0xac, 0x32, 0xab, 0x7a,
	0xac, 0x49, 0x69, 0x3d, 0xfb, 0xf8, 0x37, 0x24,
	0xc2, 0xec, 0x07, 0x36, 0xee, 0x31, 0xc8, 0x02,
	0x91 };

static uchar_t Q[] = { 0x00, 0xc7, 0x73, 0x21, 0x8c, 0x73, 0x7e, 0xc8,
	0xee, 0x99, 0x3b, 0x4f, 0x2d, 0xed, 0x30, 0xf4,
	0x8e, 0xda, 0xce, 0x91, 0x5f };

static uchar_t G[] = { 0x00, 0x62, 0x6d, 0x02, 0x78, 0x39, 0xea, 0x0a,
	0x13, 0x41, 0x31, 0x63, 0xa5, 0x5b, 0x4c, 0xb5,
	0x00, 0x29, 0x9d, 0x55, 0x22, 0x95, 0x6c, 0xef,
	0xcb, 0x3b, 0xff, 0x10, 0xf3, 0x99, 0xce, 0x2c,
	0x2e, 0x71, 0xcb, 0x9d, 0xe5, 0xfa, 0x24, 0xba,
	0xbf, 0x58, 0xe5, 0xb7, 0x95, 0x21, 0x92, 0x5c,
	0x9c, 0xc4, 0x2e, 0x9f, 0x6f, 0x46, 0x4b, 0x08,
	0x8c, 0xc5, 0x72, 0xaf, 0x53, 0xe6, 0xd7, 0x88,
	0x02 };

#define	SET_ERROR(h, c) h->lasterr.kstype = KMF_KEYSTORE_OPENSSL; \
	h->lasterr.errcode = c;

#define	SET_SYS_ERROR(h, c) h->lasterr.kstype = -1; h->lasterr.errcode = c;

/*
 * Declare some new macros for managing stacks of EVP_PKEYS.
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
DECLARE_STACK_OF(EVP_PKEY)

#define	sk_EVP_PKEY_new_null() SKM_sk_new_null(EVP_PKEY)
#define	sk_EVP_PKEY_free(st) SKM_sk_free(EVP_PKEY, (st))
#define	sk_EVP_PKEY_num(st) SKM_sk_num(EVP_PKEY, (st))
#define	sk_EVP_PKEY_value(st, i) SKM_sk_value(EVP_PKEY, (st), (i))
#define	sk_EVP_PKEY_push(st, val) SKM_sk_push(EVP_PKEY, (st), (val))
#define	sk_EVP_PKEY_pop_free(st, free_func) SKM_sk_pop_free(EVP_PKEY, (st), \
	(free_func))

#else
/* LINTED E_STATIC_UNUSED */
DEFINE_STACK_OF(EVP_PKEY)
#endif

mutex_t init_lock = DEFAULTMUTEX;
static int ssl_initialized = 0;
static BIO *bio_err = NULL;

static int
test_for_file(char *, mode_t);
static KMF_RETURN
openssl_parse_bag(PKCS12_SAFEBAG *, char *, int,
    STACK_OF(EVP_PKEY) *, STACK_OF(X509) *);

static KMF_RETURN
local_export_pk12(KMF_HANDLE_T, KMF_CREDENTIAL *, int, KMF_X509_DER_CERT *,
    int, KMF_KEY_HANDLE *, char *);

static KMF_RETURN set_pkey_attrib(EVP_PKEY *, ASN1_TYPE *, int);

static KMF_RETURN
extract_pem(KMF_HANDLE *, char *, char *, KMF_BIGINT *, char *,
    CK_UTF8CHAR *, CK_ULONG, EVP_PKEY **, KMF_DATA **, int *);

static KMF_RETURN
kmf_load_cert(KMF_HANDLE *, char *, char *, KMF_BIGINT *, KMF_CERT_VALIDITY,
    char *, KMF_DATA *);

static KMF_RETURN
load_certs(KMF_HANDLE *, char *, char *, KMF_BIGINT *, KMF_CERT_VALIDITY,
    char *, KMF_DATA **, uint32_t *);

static KMF_RETURN
sslBN2KMFBN(BIGNUM *, KMF_BIGINT *);

static EVP_PKEY *
ImportRawRSAKey(KMF_RAW_RSA_KEY *);

static KMF_RETURN
convertToRawKey(EVP_PKEY *, KMF_RAW_KEY_DATA *);

KMF_RETURN
OpenSSL_FindCert(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

void
OpenSSL_FreeKMFCert(KMF_HANDLE_T, KMF_X509_DER_CERT *);

KMF_RETURN
OpenSSL_StoreCert(KMF_HANDLE_T handle, int, KMF_ATTRIBUTE *);

KMF_RETURN
OpenSSL_DeleteCert(KMF_HANDLE_T handle, int, KMF_ATTRIBUTE *);

KMF_RETURN
OpenSSL_CreateKeypair(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
OpenSSL_StoreKey(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
OpenSSL_EncodePubKeyData(KMF_HANDLE_T,  KMF_KEY_HANDLE *, KMF_DATA *);

KMF_RETURN
OpenSSL_SignData(KMF_HANDLE_T, KMF_KEY_HANDLE *, KMF_OID *,
	KMF_DATA *, KMF_DATA *);

KMF_RETURN
OpenSSL_DeleteKey(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
OpenSSL_ImportCRL(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
OpenSSL_DeleteCRL(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
OpenSSL_ListCRL(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
OpenSSL_FindCertInCRL(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
OpenSSL_CertGetPrintable(KMF_HANDLE_T, const KMF_DATA *,
	KMF_PRINTABLE_ITEM, char *);

KMF_RETURN
OpenSSL_GetErrorString(KMF_HANDLE_T, char **);

KMF_RETURN
OpenSSL_FindPrikeyByCert(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
OpenSSL_DecryptData(KMF_HANDLE_T, KMF_KEY_HANDLE *, KMF_OID *,
	KMF_DATA *, KMF_DATA *);

KMF_RETURN
OpenSSL_CreateOCSPRequest(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
OpenSSL_GetOCSPStatusForCert(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
OpenSSL_FindKey(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
OpenSSL_ExportPK12(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
OpenSSL_CreateSymKey(KMF_HANDLE_T, int, KMF_ATTRIBUTE *);

KMF_RETURN
OpenSSL_GetSymKeyValue(KMF_HANDLE_T, KMF_KEY_HANDLE *, KMF_RAW_SYM_KEY *);

KMF_RETURN
OpenSSL_VerifyCRLFile(KMF_HANDLE_T, char *, KMF_DATA *);

KMF_RETURN
OpenSSL_CheckCRLDate(KMF_HANDLE_T, char *);

static
KMF_PLUGIN_FUNCLIST openssl_plugin_table =
{
	1,				/* Version */
	NULL, /* ConfigureKeystore */
	OpenSSL_FindCert,
	OpenSSL_FreeKMFCert,
	OpenSSL_StoreCert,
	NULL, /* ImportCert */
	OpenSSL_ImportCRL,
	OpenSSL_DeleteCert,
	OpenSSL_DeleteCRL,
	OpenSSL_CreateKeypair,
	OpenSSL_FindKey,
	OpenSSL_EncodePubKeyData,
	OpenSSL_SignData,
	OpenSSL_DeleteKey,
	OpenSSL_ListCRL,
	NULL,	/* FindCRL */
	OpenSSL_FindCertInCRL,
	OpenSSL_GetErrorString,
	OpenSSL_FindPrikeyByCert,
	OpenSSL_DecryptData,
	OpenSSL_ExportPK12,
	OpenSSL_CreateSymKey,
	OpenSSL_GetSymKeyValue,
	NULL,	/* SetTokenPin */
	OpenSSL_StoreKey,
	NULL	/* Finalize */
};

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static mutex_t *lock_cs;
static long *lock_count;

static void
/* ARGSUSED1 */
locking_cb(int mode, int type, char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		(void) mutex_lock(&(lock_cs[type]));
		lock_count[type]++;
	} else {
		(void) mutex_unlock(&(lock_cs[type]));
	}
}

static unsigned long
thread_id()
{
	return ((unsigned long)thr_self());
}
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

KMF_PLUGIN_FUNCLIST *
KMF_Plugin_Initialize()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	int i;
#endif

	(void) mutex_lock(&init_lock);
	if (!ssl_initialized) {
		/*
		 * Add support for extension OIDs that are not yet in the
		 * openssl default set.
		 */
		(void) OBJ_create("2.5.29.30", "nameConstraints",
		    "X509v3 Name Constraints");
		(void) OBJ_create("2.5.29.33", "policyMappings",
		    "X509v3 Policy Mappings");
		(void) OBJ_create("2.5.29.36", "policyConstraints",
		    "X509v3 Policy Constraints");
		(void) OBJ_create("2.5.29.46", "freshestCRL",
		    "X509v3 Freshest CRL");
		(void) OBJ_create("2.5.29.54", "inhibitAnyPolicy",
		    "X509v3 Inhibit Any-Policy");

#if OPENSSL_VERSION_NUMBER < 0x10100000L
		/*
		 * Set up for thread-safe operation.
		 * This is not required for OpenSSL 1.1
		 */
		lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof (mutex_t));
		if (lock_cs == NULL) {
			(void) mutex_unlock(&init_lock);
			return (NULL);
		}

		lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof (long));
		if (lock_count == NULL) {
			OPENSSL_free(lock_cs);
			(void) mutex_unlock(&init_lock);
			return (NULL);
		}

		for (i = 0; i < CRYPTO_num_locks(); i++) {
			lock_count[i] = 0;
			(void) mutex_init(&lock_cs[i], USYNC_THREAD, NULL);
		}

		CRYPTO_set_id_callback((unsigned long (*)())thread_id);
		if (CRYPTO_get_locking_callback() == NULL)
			CRYPTO_set_locking_callback((void (*)())locking_cb);

		(void) OpenSSL_add_all_algorithms();

		/* Enable error strings for reporting */
		(void) ERR_load_crypto_strings();
#endif

		ssl_initialized = 1;
	}
	(void) mutex_unlock(&init_lock);

	return (&openssl_plugin_table);
}

/*
 * Convert an SSL DN to a KMF DN.
 */
static KMF_RETURN
get_x509_dn(X509_NAME *sslDN, KMF_X509_NAME *kmfDN)
{
	KMF_DATA derdata;
	KMF_RETURN rv = KMF_OK;
	uchar_t *tmp;

	/* Convert to raw DER format */
	derdata.Length = i2d_X509_NAME(sslDN, NULL);
	if ((tmp = derdata.Data = (uchar_t *)OPENSSL_malloc(derdata.Length))
	    == NULL) {
		return (KMF_ERR_MEMORY);
	}
	(void) i2d_X509_NAME(sslDN, &tmp);

	/* Decode to KMF format */
	rv = DerDecodeName(&derdata, kmfDN);
	if (rv != KMF_OK) {
		rv = KMF_ERR_BAD_CERT_FORMAT;
	}
	OPENSSL_free(derdata.Data);

	return (rv);
}

int
isdir(char *path)
{
	struct stat s;

	if (stat(path, &s) == -1)
		return (0);

	return ((s.st_mode & S_IFMT) == S_IFDIR);
}

static KMF_RETURN
ssl_cert2KMFDATA(KMF_HANDLE *kmfh, X509 *x509cert, KMF_DATA *cert)
{
	KMF_RETURN rv = KMF_OK;
	unsigned char *buf = NULL, *p;
	int len;

	/*
	 * Convert the X509 internal struct to DER encoded data
	 */
	if ((len = i2d_X509(x509cert, NULL)) < 0) {
		SET_ERROR(kmfh, ERR_get_error());
		rv = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}
	if ((buf = malloc(len)) == NULL) {
		SET_SYS_ERROR(kmfh, errno);
		rv = KMF_ERR_MEMORY;
		goto cleanup;
	}

	/*
	 * i2d_X509 will increment the buf pointer so that we need to
	 * save it.
	 */
	p = buf;
	if ((len = i2d_X509(x509cert, &p)) < 0) {
		SET_ERROR(kmfh, ERR_get_error());
		free(buf);
		rv = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	/* caller's responsibility to free it */
	cert->Data = buf;
	cert->Length = len;

cleanup:
	if (rv != KMF_OK) {
		if (buf)
			free(buf);
		cert->Data = NULL;
		cert->Length = 0;
	}

	return (rv);
}


static KMF_RETURN
check_cert(X509 *xcert, char *issuer, char *subject, KMF_BIGINT *serial,
    boolean_t *match)
{
	KMF_RETURN rv = KMF_OK;
	boolean_t findIssuer = FALSE;
	boolean_t findSubject = FALSE;
	boolean_t findSerial = FALSE;
	KMF_X509_NAME issuerDN, subjectDN;
	KMF_X509_NAME certIssuerDN, certSubjectDN;

	*match = FALSE;
	if (xcert == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	(void) memset(&issuerDN, 0, sizeof (KMF_X509_NAME));
	(void) memset(&subjectDN, 0, sizeof (KMF_X509_NAME));
	(void) memset(&certIssuerDN, 0, sizeof (KMF_X509_NAME));
	(void) memset(&certSubjectDN, 0, sizeof (KMF_X509_NAME));

	if (issuer != NULL && strlen(issuer)) {
		rv = kmf_dn_parser(issuer, &issuerDN);
		if (rv != KMF_OK)
			return (KMF_ERR_BAD_PARAMETER);

		rv = get_x509_dn(X509_get_issuer_name(xcert), &certIssuerDN);
		if (rv != KMF_OK) {
			kmf_free_dn(&issuerDN);
			return (KMF_ERR_BAD_PARAMETER);
		}

		findIssuer = TRUE;
	}
	if (subject != NULL && strlen(subject)) {
		rv = kmf_dn_parser(subject, &subjectDN);
		if (rv != KMF_OK) {
			rv = KMF_ERR_BAD_PARAMETER;
			goto cleanup;
		}

		rv = get_x509_dn(X509_get_subject_name(xcert), &certSubjectDN);
		if (rv != KMF_OK) {
			rv = KMF_ERR_BAD_PARAMETER;
			goto cleanup;
		}
		findSubject = TRUE;
	}
	if (serial != NULL && serial->val != NULL)
		findSerial = TRUE;

	if (findSerial) {
		BIGNUM *bn;

		/* Comparing BIGNUMs is a pain! */
		bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(xcert), NULL);
		if (bn != NULL) {
			int bnlen = BN_num_bytes(bn);

			if (bnlen == serial->len) {
				uchar_t *a = malloc(bnlen);
				if (a == NULL) {
					rv = KMF_ERR_MEMORY;
					BN_free(bn);
					goto cleanup;
				}
				bnlen = BN_bn2bin(bn, a);
				*match = (memcmp(a, serial->val, serial->len) ==
				    0);
				rv = KMF_OK;
				free(a);
			}
			BN_free(bn);
			if (!(*match))
				goto cleanup;
		} else {
			rv = KMF_OK;
			goto cleanup;
		}
	}
	if (findIssuer) {
		*match = (kmf_compare_rdns(&issuerDN, &certIssuerDN) == 0);
		if ((*match) == B_FALSE) {
			/* stop checking and bail */
			rv = KMF_OK;
			goto cleanup;
		}
	}
	if (findSubject) {
		*match = (kmf_compare_rdns(&subjectDN, &certSubjectDN) == 0);
		if ((*match) == B_FALSE) {
			/* stop checking and bail */
			rv = KMF_OK;
			goto cleanup;
		}
	}

	*match = TRUE;
cleanup:
	if (findIssuer) {
		kmf_free_dn(&issuerDN);
		kmf_free_dn(&certIssuerDN);
	}
	if (findSubject) {
		kmf_free_dn(&subjectDN);
		kmf_free_dn(&certSubjectDN);
	}

	return (rv);
}


/*
 * This function loads a certificate file into an X509 data structure, and
 * checks if its issuer, subject or the serial number matches with those
 * values.  If it matches, then return the X509 data structure.
 */
static KMF_RETURN
load_X509cert(KMF_HANDLE *kmfh,
    char *issuer, char *subject, KMF_BIGINT *serial,
    char *pathname, X509 **outcert)
{
	KMF_RETURN rv = KMF_OK;
	X509 *xcert = NULL;
	BIO *bcert = NULL;
	boolean_t  match = FALSE;
	KMF_ENCODE_FORMAT format;

	/*
	 * auto-detect the file format, regardless of what
	 * the 'format' parameters in the params say.
	 */
	rv = kmf_get_file_format(pathname, &format);
	if (rv != KMF_OK) {
		if (rv == KMF_ERR_OPEN_FILE)
			rv = KMF_ERR_CERT_NOT_FOUND;
		return (rv);
	}

	/* Not ASN1(DER) format */
	if ((bcert = BIO_new_file(pathname, "rb")) == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		rv = KMF_ERR_OPEN_FILE;
		goto cleanup;
	}

	if (format == KMF_FORMAT_PEM)
		xcert = PEM_read_bio_X509_AUX(bcert, NULL, NULL, NULL);
	else if (format == KMF_FORMAT_ASN1)
		xcert = d2i_X509_bio(bcert, NULL);
	else if (format == KMF_FORMAT_PKCS12) {
		PKCS12 *p12 = d2i_PKCS12_bio(bcert, NULL);
		if (p12 != NULL) {
			(void) PKCS12_parse(p12, NULL, NULL, &xcert, NULL);
			PKCS12_free(p12);
			p12 = NULL;
		} else {
			SET_ERROR(kmfh, ERR_get_error());
			rv = KMF_ERR_BAD_CERT_FORMAT;
		}
	} else {
		rv = KMF_ERR_BAD_PARAMETER;
		goto cleanup;
	}

	if (xcert == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		rv = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	if (check_cert(xcert, issuer, subject, serial, &match) != KMF_OK ||
	    match == FALSE) {
		rv = KMF_ERR_CERT_NOT_FOUND;
		goto cleanup;
	}

	if (outcert != NULL) {
		*outcert = xcert;
	}

cleanup:
	if (bcert != NULL) (void) BIO_free(bcert);
	if (rv != KMF_OK && xcert != NULL)
		X509_free(xcert);

	return (rv);
}

static int
datacmp(const void *a, const void *b)
{
	KMF_DATA *adata = (KMF_DATA *)a;
	KMF_DATA *bdata = (KMF_DATA *)b;
	if (adata->Length > bdata->Length)
		return (-1);
	if (adata->Length < bdata->Length)
		return (1);
	return (0);
}

static KMF_RETURN
load_certs(KMF_HANDLE *kmfh, char *issuer, char *subject, KMF_BIGINT *serial,
    KMF_CERT_VALIDITY validity, char *pathname,
    KMF_DATA **certlist, uint32_t *numcerts)
{
	KMF_RETURN rv = KMF_OK;
	int i;
	KMF_DATA *certs = NULL;
	int nc = 0;
	int hits = 0;
	KMF_ENCODE_FORMAT format;

	rv = kmf_get_file_format(pathname, &format);
	if (rv != KMF_OK) {
		if (rv == KMF_ERR_OPEN_FILE)
			rv = KMF_ERR_CERT_NOT_FOUND;
		return (rv);
	}
	if (format == KMF_FORMAT_ASN1) {
		/* load a single certificate */
		certs = (KMF_DATA *)malloc(sizeof (KMF_DATA));
		if (certs == NULL)
			return (KMF_ERR_MEMORY);
		certs->Data = NULL;
		certs->Length = 0;
		rv = kmf_load_cert(kmfh, issuer, subject, serial, validity,
		    pathname, certs);
		if (rv == KMF_OK) {
			*certlist = certs;
			*numcerts = 1;
		} else {
			kmf_free_data(certs);
			free(certs);
			certs = NULL;
		}
		return (rv);
	} else if (format == KMF_FORMAT_PKCS12) {
		/* We need a credential to access a PKCS#12 file */
		rv = KMF_ERR_BAD_CERT_FORMAT;
	} else if (format == KMF_FORMAT_PEM ||
	    format != KMF_FORMAT_PEM_KEYPAIR) {

		/* This function only works on PEM files */
		rv = extract_pem(kmfh, issuer, subject, serial, pathname,
		    (uchar_t *)NULL, 0, NULL, &certs, &nc);
	} else {
		return (KMF_ERR_ENCODING);
	}

	if (rv != KMF_OK)
		return (rv);

	for (i = 0; i < nc; i++) {
		if (validity == KMF_NONEXPIRED_CERTS) {
			rv = kmf_check_cert_date(kmfh, &certs[i]);
		} else if (validity == KMF_EXPIRED_CERTS) {
			rv = kmf_check_cert_date(kmfh, &certs[i]);
			if (rv == KMF_OK)
				rv = KMF_ERR_CERT_NOT_FOUND;
			if (rv == KMF_ERR_VALIDITY_PERIOD)
				rv = KMF_OK;
		}
		if (rv != KMF_OK) {
			/* Remove this cert from the list by clearing it. */
			kmf_free_data(&certs[i]);
		} else {
			hits++; /* count valid certs found */
		}
		rv = KMF_OK;
	}
	if (rv == KMF_OK && hits > 0) {
		/*
		 * Sort the list of certs by length to put the cleared ones
		 * at the end so they don't get accessed by the caller.
		 */
		qsort((void *)certs, nc, sizeof (KMF_DATA), datacmp);
		*certlist = certs;

		/* since we sorted the list, just return the number of hits */
		*numcerts = hits;
	} else {
		if (rv == KMF_OK && hits == 0)
			rv = KMF_ERR_CERT_NOT_FOUND;
		if (certs != NULL) {
			free(certs);
			certs = NULL;
		}
	}
	return (rv);
}

static KMF_RETURN
kmf_load_cert(KMF_HANDLE *kmfh,
    char *issuer, char *subject, KMF_BIGINT *serial,
    KMF_CERT_VALIDITY validity,
    char *pathname,
    KMF_DATA *cert)
{
	KMF_RETURN rv = KMF_OK;
	X509 *x509cert = NULL;

	rv = load_X509cert(kmfh, issuer, subject, serial, pathname, &x509cert);
	if (rv == KMF_OK && x509cert != NULL && cert != NULL) {
		rv = ssl_cert2KMFDATA(kmfh, x509cert, cert);
		if (rv != KMF_OK) {
			goto cleanup;
		}
		if (validity == KMF_NONEXPIRED_CERTS) {
			rv = kmf_check_cert_date(kmfh, cert);
		} else if (validity == KMF_EXPIRED_CERTS) {
			rv = kmf_check_cert_date(kmfh, cert);
			if (rv == KMF_OK)  {
				/*
				 * This is a valid cert so skip it.
				 */
				rv = KMF_ERR_CERT_NOT_FOUND;
			}
			if (rv == KMF_ERR_VALIDITY_PERIOD) {
				/*
				 * We want to return success when we
				 * find an invalid cert.
				 */
				rv = KMF_OK;
				goto cleanup;
			}
		}
	}
cleanup:
	if (x509cert != NULL)
		X509_free(x509cert);

	return (rv);
}

static KMF_RETURN
readAltFormatPrivateKey(KMF_DATA *filedata, EVP_PKEY **pkey)
{
	KMF_RETURN ret = KMF_OK;
	KMF_RAW_RSA_KEY rsa;
	BerElement *asn1 = NULL;
	BerValue filebuf;
	BerValue OID = { NULL, 0 };
	BerValue *Mod = NULL, *PubExp = NULL;
	BerValue *PriExp = NULL, *Prime1 = NULL, *Prime2 = NULL;
	BerValue *Coef = NULL;
	BIGNUM *D = NULL, *P = NULL, *Q = NULL, *COEF = NULL;
	BIGNUM *Exp1 = NULL, *Exp2 = NULL, *pminus1 = NULL;
	BIGNUM *qminus1 = NULL;
	BN_CTX *ctx = NULL;

	*pkey = NULL;

	filebuf.bv_val = (char *)filedata->Data;
	filebuf.bv_len = filedata->Length;

	asn1 = kmfder_init(&filebuf);
	if (asn1 == NULL) {
		ret = KMF_ERR_MEMORY;
		goto out;
	}

	if (kmfber_scanf(asn1, "{{Dn{IIIIII}}}",
	    &OID, &Mod, &PubExp, &PriExp, &Prime1,
	    &Prime2, &Coef) == -1)  {
		ret = KMF_ERR_ENCODING;
		goto out;
	}

	/*
	 * We have to derive the 2 Exponents using Bignumber math.
	 * Exp1 = PriExp mod (Prime1 - 1)
	 * Exp2 = PriExp mod (Prime2 - 1)
	 */

	/* D = PrivateExponent */
	D = BN_bin2bn((const uchar_t *)PriExp->bv_val, PriExp->bv_len, D);
	if (D == NULL) {
		ret = KMF_ERR_MEMORY;
		goto out;
	}

	/* P = Prime1 (first prime factor of Modulus) */
	P = BN_bin2bn((const uchar_t *)Prime1->bv_val, Prime1->bv_len, P);
	if (D == NULL) {
		ret = KMF_ERR_MEMORY;
		goto out;
	}

	/* Q = Prime2 (second prime factor of Modulus) */
	Q = BN_bin2bn((const uchar_t *)Prime2->bv_val, Prime2->bv_len, Q);

	if ((ctx = BN_CTX_new()) == NULL) {
		ret = KMF_ERR_MEMORY;
		goto out;
	}

	/* Compute (P - 1) */
	pminus1 = BN_new();
	(void) BN_sub(pminus1, P, BN_value_one());

	/* Exponent1 = D mod (P - 1) */
	Exp1 = BN_new();
	(void) BN_mod(Exp1, D, pminus1, ctx);

	/* Compute (Q - 1) */
	qminus1 = BN_new();
	(void) BN_sub(qminus1, Q, BN_value_one());

	/* Exponent2 = D mod (Q - 1) */
	Exp2 = BN_new();
	(void) BN_mod(Exp2, D, qminus1, ctx);

	/* Coef = (Inverse Q) mod P */
	COEF = BN_new();
	(void) BN_mod_inverse(COEF, Q, P, ctx);

	/* Convert back to KMF format */
	(void) memset(&rsa, 0, sizeof (rsa));

	if ((ret = sslBN2KMFBN(Exp1, &rsa.exp1)) != KMF_OK)
		goto out;
	if ((ret = sslBN2KMFBN(Exp2, &rsa.exp2)) != KMF_OK)
		goto out;
	if ((ret = sslBN2KMFBN(COEF, &rsa.coef)) != KMF_OK)
		goto out;

	rsa.mod.val = (uchar_t *)Mod->bv_val;
	rsa.mod.len = Mod->bv_len;

	rsa.pubexp.val = (uchar_t *)PubExp->bv_val;
	rsa.pubexp.len = PubExp->bv_len;

	rsa.priexp.val = (uchar_t *)PriExp->bv_val;
	rsa.priexp.len = PriExp->bv_len;

	rsa.prime1.val = (uchar_t *)Prime1->bv_val;
	rsa.prime1.len = Prime1->bv_len;

	rsa.prime2.val = (uchar_t *)Prime2->bv_val;
	rsa.prime2.len = Prime2->bv_len;

	*pkey = ImportRawRSAKey(&rsa);
out:
	if (asn1 != NULL)
		kmfber_free(asn1, 1);

	if (OID.bv_val) {
		free(OID.bv_val);
	}
	if (PriExp)
		free(PriExp);

	if (Mod)
		free(Mod);

	if (PubExp)
		free(PubExp);

	if (Coef) {
		(void) memset(Coef->bv_val, 0, Coef->bv_len);
		free(Coef->bv_val);
		free(Coef);
	}
	if (Prime1)
		free(Prime1);
	if (Prime2)
		free(Prime2);

	if (ctx != NULL)
		BN_CTX_free(ctx);

	if (D)
		BN_clear_free(D);
	if (P)
		BN_clear_free(P);
	if (Q)
		BN_clear_free(Q);
	if (pminus1)
		BN_clear_free(pminus1);
	if (qminus1)
		BN_clear_free(qminus1);
	if (Exp1)
		BN_clear_free(Exp1);
	if (Exp2)
		BN_clear_free(Exp2);

	return (ret);

}

static EVP_PKEY *
openssl_load_key(KMF_HANDLE_T handle, const char *file)
{
	BIO *keyfile = NULL;
	EVP_PKEY *pkey = NULL;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	KMF_ENCODE_FORMAT format;
	KMF_RETURN rv;
	KMF_DATA filedata;

	if (file == NULL) {
		return (NULL);
	}

	if (kmf_get_file_format((char *)file, &format) != KMF_OK)
		return (NULL);

	keyfile = BIO_new_file(file, "rb");
	if (keyfile == NULL) {
		goto end;
	}

	if (format == KMF_FORMAT_ASN1) {
		pkey = d2i_PrivateKey_bio(keyfile, NULL);
		if (pkey == NULL) {

			(void) BIO_free(keyfile);
			keyfile = NULL;
			/* Try odd ASN.1 variations */
			rv = kmf_read_input_file(kmfh, (char *)file,
			    &filedata);
			if (rv == KMF_OK) {
				(void) readAltFormatPrivateKey(&filedata,
				    &pkey);
				kmf_free_data(&filedata);
			}
		}
	} else if (format == KMF_FORMAT_PEM ||
	    format == KMF_FORMAT_PEM_KEYPAIR) {
		pkey = PEM_read_bio_PrivateKey(keyfile, NULL, NULL, NULL);
		if (pkey == NULL) {
			KMF_DATA derdata;
			/*
			 * Check if this is the alt. format
			 * RSA private key file.
			 */
			rv = kmf_read_input_file(kmfh, (char *)file,
			    &filedata);
			if (rv == KMF_OK) {
				uchar_t *d = NULL;
				int len;
				rv = kmf_pem_to_der(filedata.Data,
				    filedata.Length, &d, &len);
				if (rv == KMF_OK && d != NULL) {
					derdata.Data = d;
					derdata.Length = (size_t)len;
					(void) readAltFormatPrivateKey(
					    &derdata, &pkey);
					free(d);
				}
				kmf_free_data(&filedata);
			}
		}
	}

end:
	if (pkey == NULL)
		SET_ERROR(kmfh, ERR_get_error());

	if (keyfile != NULL)
		(void) BIO_free(keyfile);

	return (pkey);
}

KMF_RETURN
OpenSSL_FindCert(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	int i, n;
	uint32_t maxcerts = 0;
	uint32_t *num_certs;
	KMF_X509_DER_CERT *kmf_cert = NULL;
	char *dirpath = NULL;
	char *filename = NULL;
	char *fullpath = NULL;
	char *issuer = NULL;
	char *subject = NULL;
	KMF_BIGINT *serial = NULL;
	KMF_CERT_VALIDITY validity;

	num_certs = kmf_get_attr_ptr(KMF_COUNT_ATTR, attrlist, numattr);
	if (num_certs == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* num_certs should reference the size of kmf_cert */
	maxcerts = *num_certs;
	if (maxcerts == 0)
		maxcerts = 0xFFFFFFFF;
	*num_certs = 0;

	/* Get the optional returned certificate list  */
	kmf_cert = kmf_get_attr_ptr(KMF_X509_DER_CERT_ATTR, attrlist,
	    numattr);

	/*
	 * The dirpath attribute and the filename attribute can not be NULL
	 * at the same time.
	 */
	dirpath = kmf_get_attr_ptr(KMF_DIRPATH_ATTR, attrlist, numattr);
	filename = kmf_get_attr_ptr(KMF_CERT_FILENAME_ATTR, attrlist,
	    numattr);

	fullpath = get_fullpath(dirpath, filename);
	if (fullpath == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* Get optional search criteria attributes */
	issuer = kmf_get_attr_ptr(KMF_ISSUER_NAME_ATTR, attrlist, numattr);
	subject = kmf_get_attr_ptr(KMF_SUBJECT_NAME_ATTR, attrlist, numattr);
	serial = kmf_get_attr_ptr(KMF_BIGINT_ATTR, attrlist, numattr);
	rv = kmf_get_attr(KMF_CERT_VALIDITY_ATTR, attrlist, numattr,
	    &validity, NULL);
	if (rv != KMF_OK) {
		validity = KMF_ALL_CERTS;
		rv = KMF_OK;
	}

	if (isdir(fullpath)) {
		DIR *dirp;
		struct dirent *dp;

		n = 0;
		/* open all files in the directory and attempt to read them */
		if ((dirp = opendir(fullpath)) == NULL) {
			return (KMF_ERR_BAD_PARAMETER);
		}
		while ((dp = readdir(dirp)) != NULL) {
			char *fname;
			KMF_DATA *certlist = NULL;
			uint32_t loaded_certs = 0;

			if (strcmp(dp->d_name, ".") == 0 ||
			    strcmp(dp->d_name, "..") == 0)
				continue;

			fname = get_fullpath(fullpath, (char *)&dp->d_name);

			rv = load_certs(kmfh, issuer, subject, serial,
			    validity, fname, &certlist,	&loaded_certs);

			if (rv != KMF_OK) {
				free(fname);
				if (certlist != NULL) {
					for (i = 0; i < loaded_certs; i++)
						kmf_free_data(&certlist[i]);
					free(certlist);
				}
				continue;
			}

			/* If load succeeds, add certdata to the list */
			if (kmf_cert != NULL) {
				for (i = 0; i < loaded_certs &&
				    n < maxcerts; i++) {
					kmf_cert[n].certificate.Data =
					    certlist[i].Data;
					kmf_cert[n].certificate.Length =
					    certlist[i].Length;

					kmf_cert[n].kmf_private.keystore_type =
					    KMF_KEYSTORE_OPENSSL;
					kmf_cert[n].kmf_private.flags =
					    KMF_FLAG_CERT_VALID;
					kmf_cert[n].kmf_private.label =
					    strdup(fname);
					n++;
				}
				/*
				 * If maxcerts < loaded_certs, clean up the
				 * certs that were not used.
				 */
				for (; i < loaded_certs; i++)
					kmf_free_data(&certlist[i]);
			} else {
				for (i = 0; i < loaded_certs; i++)
					kmf_free_data(&certlist[i]);
				n += loaded_certs;
			}
			free(certlist);
			free(fname);
		}
		(*num_certs) = n;
		if (*num_certs == 0)
			rv = KMF_ERR_CERT_NOT_FOUND;
		if (*num_certs > 0)
			rv = KMF_OK;
exit:
		(void) closedir(dirp);
	} else {
		KMF_DATA *certlist = NULL;
		uint32_t loaded_certs = 0;

		rv = load_certs(kmfh, issuer, subject, serial, validity,
		    fullpath, &certlist, &loaded_certs);
		if (rv != KMF_OK) {
			free(fullpath);
			return (rv);
		}

		n = 0;
		if (kmf_cert != NULL && certlist != NULL) {
			for (i = 0; i < loaded_certs && i < maxcerts; i++) {
				kmf_cert[n].certificate.Data =
				    certlist[i].Data;
				kmf_cert[n].certificate.Length =
				    certlist[i].Length;
				kmf_cert[n].kmf_private.keystore_type =
				    KMF_KEYSTORE_OPENSSL;
				kmf_cert[n].kmf_private.flags =
				    KMF_FLAG_CERT_VALID;
				kmf_cert[n].kmf_private.label =
				    strdup(fullpath);
				n++;
			}
			/* If maxcerts < loaded_certs, clean up */
			for (; i < loaded_certs; i++)
				kmf_free_data(&certlist[i]);
		} else if (certlist != NULL) {
			for (i = 0; i < loaded_certs; i++)
				kmf_free_data(&certlist[i]);
			n = loaded_certs;
		}
		if (certlist != NULL)
			free(certlist);
		*num_certs = n;
	}

	free(fullpath);

	return (rv);
}

void
/*ARGSUSED*/
OpenSSL_FreeKMFCert(KMF_HANDLE_T handle,
	KMF_X509_DER_CERT *kmf_cert)
{
	if (kmf_cert != NULL) {
		if (kmf_cert->certificate.Data != NULL) {
			kmf_free_data(&kmf_cert->certificate);
		}
		if (kmf_cert->kmf_private.label)
			free(kmf_cert->kmf_private.label);
	}
}

/*ARGSUSED*/
KMF_RETURN
OpenSSL_StoreCert(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_DATA *cert = NULL;
	char *outfilename = NULL;
	char *dirpath = NULL;
	char *fullpath = NULL;
	KMF_ENCODE_FORMAT format;

	/* Get the cert data */
	cert = kmf_get_attr_ptr(KMF_CERT_DATA_ATTR, attrlist, numattr);
	if (cert == NULL || cert->Data == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* Check the output filename and directory attributes. */
	outfilename = kmf_get_attr_ptr(KMF_CERT_FILENAME_ATTR, attrlist,
	    numattr);
	if (outfilename == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	dirpath = kmf_get_attr_ptr(KMF_DIRPATH_ATTR, attrlist, numattr);
	fullpath = get_fullpath(dirpath, outfilename);
	if (fullpath == NULL)
		return (KMF_ERR_BAD_CERTFILE);

	/* Check the optional format attribute */
	ret = kmf_get_attr(KMF_ENCODE_FORMAT_ATTR, attrlist, numattr,
	    &format, NULL);
	if (ret != KMF_OK) {
		/* If there is no format attribute, then default to PEM */
		format = KMF_FORMAT_PEM;
		ret = KMF_OK;
	} else if (format != KMF_FORMAT_ASN1 && format != KMF_FORMAT_PEM) {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto out;
	}

	/* Store the certificate in the file with the specified format */
	ret = kmf_create_cert_file(cert, format, fullpath);

out:
	if (fullpath != NULL)
		free(fullpath);

	return (ret);
}


KMF_RETURN
OpenSSL_DeleteCert(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	KMF_DATA certdata = { 0, NULL };
	char *dirpath = NULL;
	char *filename = NULL;
	char *fullpath = NULL;
	char *issuer = NULL;
	char *subject = NULL;
	KMF_BIGINT *serial = NULL;
	KMF_CERT_VALIDITY validity;

	/*
	 * Get the DIRPATH and CERT_FILENAME attributes.  They can not be
	 * NULL at the same time.
	 */
	dirpath = kmf_get_attr_ptr(KMF_DIRPATH_ATTR, attrlist, numattr);
	filename = kmf_get_attr_ptr(KMF_CERT_FILENAME_ATTR, attrlist,
	    numattr);
	fullpath = get_fullpath(dirpath, filename);
	if (fullpath == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* Get optional search criteria attributes */
	issuer = kmf_get_attr_ptr(KMF_ISSUER_NAME_ATTR, attrlist, numattr);
	subject = kmf_get_attr_ptr(KMF_SUBJECT_NAME_ATTR, attrlist, numattr);
	serial = kmf_get_attr_ptr(KMF_BIGINT_ATTR, attrlist, numattr);
	rv = kmf_get_attr(KMF_CERT_VALIDITY_ATTR, attrlist, numattr,
	    &validity, NULL);
	if (rv != KMF_OK) {
		validity = KMF_ALL_CERTS;
		rv = KMF_OK;
	}

	if (isdir(fullpath)) {
		DIR *dirp;
		struct dirent *dp;

		/* open all files in the directory and attempt to read them */
		if ((dirp = opendir(fullpath)) == NULL) {
			return (KMF_ERR_BAD_PARAMETER);
		}

		while ((dp = readdir(dirp)) != NULL) {
			if (strcmp(dp->d_name, ".") != 0 &&
			    strcmp(dp->d_name, "..") != 0) {
				char *fname;

				fname = get_fullpath(fullpath,
				    (char *)&dp->d_name);

				if (fname == NULL) {
					rv = KMF_ERR_MEMORY;
					break;
				}

				rv = kmf_load_cert(kmfh, issuer, subject,
				    serial, validity, fname, &certdata);

				if (rv == KMF_ERR_CERT_NOT_FOUND) {
					free(fname);
					kmf_free_data(&certdata);
					rv = KMF_OK;
					continue;
				} else if (rv != KMF_OK) {
					free(fname);
					break;
				}

				if (unlink(fname) != 0) {
					SET_SYS_ERROR(kmfh, errno);
					rv = KMF_ERR_INTERNAL;
					free(fname);
					break;
				}
				free(fname);
				kmf_free_data(&certdata);
			}
		}
		(void) closedir(dirp);
	} else {
		/* Just try to load a single certificate */
		rv = kmf_load_cert(kmfh, issuer, subject, serial, validity,
		    fullpath, &certdata);
		if (rv == KMF_OK) {
			if (unlink(fullpath) != 0) {
				SET_SYS_ERROR(kmfh, errno);
				rv = KMF_ERR_INTERNAL;
			}
		}
	}

out:
	if (fullpath != NULL)
		free(fullpath);

	kmf_free_data(&certdata);

	return (rv);
}

KMF_RETURN
OpenSSL_EncodePubKeyData(KMF_HANDLE_T handle, KMF_KEY_HANDLE *key,
	KMF_DATA *keydata)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	int n;

	if (key == NULL || keydata == NULL ||
	    key->keyp == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (key->keyalg == KMF_RSA) {
		RSA *pubkey = EVP_PKEY_get1_RSA(key->keyp);

		if (!(n = i2d_RSA_PUBKEY(pubkey, &keydata->Data))) {
			SET_ERROR(kmfh, ERR_get_error());
			return (KMF_ERR_ENCODING);
		}
		RSA_free(pubkey);
	} else if (key->keyalg == KMF_DSA) {
		DSA *pubkey = EVP_PKEY_get1_DSA(key->keyp);

		if (!(n = i2d_DSA_PUBKEY(pubkey, &keydata->Data))) {
			SET_ERROR(kmfh, ERR_get_error());
			return (KMF_ERR_ENCODING);
		}
		DSA_free(pubkey);
	} else {
		return (KMF_ERR_BAD_PARAMETER);
	}
	keydata->Length = n;

cleanup:
	if (rv != KMF_OK) {
		if (keydata->Data)
			free(keydata->Data);
		keydata->Data = NULL;
		keydata->Length = 0;
	}

	return (rv);
}

static KMF_RETURN
ssl_write_key(KMF_HANDLE *kmfh, KMF_ENCODE_FORMAT format, BIO *out,
	KMF_CREDENTIAL *cred, EVP_PKEY *pkey, boolean_t private)
{
	int rv = 0;
	RSA *rsa;
	DSA *dsa;

	if (pkey == NULL || out == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	switch (format) {
		case KMF_FORMAT_RAWKEY:
			/* same as ASN.1 */
		case KMF_FORMAT_ASN1:
			if ((rsa = EVP_PKEY_get0_RSA(pkey)) != NULL) {
				if (private)
					rv = i2d_RSAPrivateKey_bio(out, rsa);
				else
					rv = i2d_RSAPublicKey_bio(out, rsa);
			} else if ((dsa = EVP_PKEY_get0_DSA(pkey)) != NULL) {
				rv = i2d_DSAPrivateKey_bio(out, dsa);
			}
			if (rv == 1) {
				rv = KMF_OK;
			} else {
				SET_ERROR(kmfh, rv);
			}
			break;
		case KMF_FORMAT_PEM:
			if ((rsa = EVP_PKEY_get0_RSA(pkey)) != NULL) {
				if (private)
					rv = PEM_write_bio_RSAPrivateKey(out,
					    rsa, NULL, NULL, 0, NULL,
					    (cred != NULL ? cred->cred : NULL));
				else
					rv = PEM_write_bio_RSAPublicKey(out,
					    rsa);
			} else if ((dsa = EVP_PKEY_get0_DSA(pkey)) != NULL) {
				rv = PEM_write_bio_DSAPrivateKey(out,
				    dsa, NULL, NULL, 0, NULL,
				    (cred != NULL ? cred->cred : NULL));
			}

			if (rv == 1) {
				rv = KMF_OK;
			} else {
				SET_ERROR(kmfh, rv);
			}
			break;

		default:
			rv = KMF_ERR_BAD_PARAMETER;
	}

	return (rv);
}

KMF_RETURN
OpenSSL_CreateKeypair(KMF_HANDLE_T handle, int numattr,
	KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	uint32_t eValue = RSA_F4;
	BIGNUM *eValue_bn = NULL;
	RSA *sslPrivKey = NULL;
	DSA *sslDSAKey = NULL;
	EVP_PKEY *eprikey = NULL;
	EVP_PKEY *epubkey = NULL;
	BIO *out = NULL;
	KMF_KEY_HANDLE *pubkey = NULL, *privkey = NULL;
	uint32_t keylen = 1024;
	uint32_t keylen_size = sizeof (uint32_t);
	boolean_t storekey = TRUE;
	KMF_KEY_ALG keytype = KMF_RSA;

	eValue_bn = BN_new();
	if (eValue_bn == NULL)
		return (KMF_ERR_MEMORY);
	if (BN_set_word(eValue_bn, eValue) == 0) {
		rv = KMF_ERR_KEYGEN_FAILED;
		goto cleanup;
	}

	rv = kmf_get_attr(KMF_STOREKEY_BOOL_ATTR, attrlist, numattr,
	    &storekey, NULL);
	if (rv != KMF_OK) {
		/* "storekey" is optional. Default is TRUE */
		rv = KMF_OK;
	}

	rv = kmf_get_attr(KMF_KEYALG_ATTR, attrlist, numattr,
	    (void *)&keytype, NULL);
	if (rv != KMF_OK)
		/* keytype is optional.  KMF_RSA is default */
		rv = KMF_OK;

	pubkey = kmf_get_attr_ptr(KMF_PUBKEY_HANDLE_ATTR, attrlist, numattr);
	if (pubkey == NULL) {
		rv = KMF_ERR_BAD_PARAMETER;
		goto cleanup;
	}

	privkey = kmf_get_attr_ptr(KMF_PRIVKEY_HANDLE_ATTR, attrlist, numattr);
	if (privkey == NULL) {
		rv = KMF_ERR_BAD_PARAMETER;
		goto cleanup;
	}

	(void) memset(pubkey, 0, sizeof (KMF_KEY_HANDLE));
	(void) memset(privkey, 0, sizeof (KMF_KEY_HANDLE));

	eprikey = EVP_PKEY_new();
	if (eprikey == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		rv = KMF_ERR_KEYGEN_FAILED;
		goto cleanup;
	}
	epubkey = EVP_PKEY_new();
	if (epubkey == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		rv = KMF_ERR_KEYGEN_FAILED;
		goto cleanup;
	}
	if (keytype == KMF_RSA) {
		KMF_BIGINT *rsaexp = NULL;

		rsaexp = kmf_get_attr_ptr(KMF_RSAEXP_ATTR, attrlist, numattr);
		if (rsaexp != NULL) {
			if (rsaexp->len > 0 &&
			    rsaexp->len <= sizeof (eValue) &&
			    rsaexp->val != NULL) {
				/* LINTED E_BAD_PTR_CAST_ALIGN */
				eValue = *(uint32_t *)rsaexp->val;
				if (BN_set_word(eValue_bn, eValue) == 0) {
					rv = KMF_ERR_BAD_PARAMETER;
					goto cleanup;
				}
			} else {
				rv = KMF_ERR_BAD_PARAMETER;
				goto cleanup;
			}
		} else {
			/* RSA Exponent is optional. Default is 0x10001 */
			rv = KMF_OK;
		}

		rv = kmf_get_attr(KMF_KEYLENGTH_ATTR, attrlist, numattr,
		    &keylen, &keylen_size);
		if (rv == KMF_ERR_ATTR_NOT_FOUND)
			/* keylen is optional, default is 1024 */
			rv = KMF_OK;
		if (rv != KMF_OK) {
			rv = KMF_ERR_BAD_PARAMETER;
			goto cleanup;
		}

		sslPrivKey = RSA_new();
		if (sslPrivKey == NULL ||
		    RSA_generate_key_ex(sslPrivKey, keylen, eValue_bn, NULL)
		    == 0) {
			SET_ERROR(kmfh, ERR_get_error());
			rv = KMF_ERR_KEYGEN_FAILED;
		} else {
			(void) EVP_PKEY_set1_RSA(eprikey, sslPrivKey);
			privkey->kstype = KMF_KEYSTORE_OPENSSL;
			privkey->keyalg = KMF_RSA;
			privkey->keyclass = KMF_ASYM_PRI;
			privkey->israw = FALSE;
			privkey->keyp = (void *)eprikey;

			/* OpenSSL derives the public key from the private */
			(void) EVP_PKEY_set1_RSA(epubkey, sslPrivKey);
			pubkey->kstype = KMF_KEYSTORE_OPENSSL;
			pubkey->keyalg = KMF_RSA;
			pubkey->israw = FALSE;
			pubkey->keyclass = KMF_ASYM_PUB;
			pubkey->keyp = (void *)epubkey;
		}
	} else if (keytype == KMF_DSA) {
		BIGNUM *p, *q, *g;

		sslDSAKey = DSA_new();
		if (sslDSAKey == NULL) {
			SET_ERROR(kmfh, ERR_get_error());
			return (KMF_ERR_MEMORY);
		}

		p = BN_bin2bn(P, sizeof (P), NULL);
		q = BN_bin2bn(Q, sizeof (Q), NULL);
		g = BN_bin2bn(G, sizeof (G), NULL);
		if (p == NULL || q == NULL || g == NULL) {
			BN_free(p);
			BN_free(q);
			BN_free(g);
			SET_ERROR(kmfh, ERR_get_error());
			rv = KMF_ERR_KEYGEN_FAILED;
			goto cleanup;
		}

		if (DSA_set0_pqg(sslDSAKey, p, q, g) == 0) {
			SET_ERROR(kmfh, ERR_get_error());
			rv = KMF_ERR_KEYGEN_FAILED;
			goto cleanup;
		}

		if (!DSA_generate_key(sslDSAKey)) {
			SET_ERROR(kmfh, ERR_get_error());
			rv = KMF_ERR_KEYGEN_FAILED;
			goto cleanup;
		}

		privkey->kstype = KMF_KEYSTORE_OPENSSL;
		privkey->keyalg = KMF_DSA;
		privkey->keyclass = KMF_ASYM_PRI;
		privkey->israw = FALSE;
		if (EVP_PKEY_set1_DSA(eprikey, sslDSAKey)) {
			privkey->keyp = (void *)eprikey;
		} else {
			SET_ERROR(kmfh, ERR_get_error());
			rv = KMF_ERR_KEYGEN_FAILED;
			goto cleanup;
		}

		pubkey->kstype = KMF_KEYSTORE_OPENSSL;
		pubkey->keyalg = KMF_DSA;
		pubkey->keyclass = KMF_ASYM_PUB;
		pubkey->israw = FALSE;

		if (EVP_PKEY_set1_DSA(epubkey, sslDSAKey)) {
			pubkey->keyp = (void *)epubkey;
		} else {
			SET_ERROR(kmfh, ERR_get_error());
			rv = KMF_ERR_KEYGEN_FAILED;
			goto cleanup;
		}
	}

	if (rv != KMF_OK) {
		goto cleanup;
	}

	if (storekey) {
		KMF_ATTRIBUTE storeattrs[4]; /* max. 4 attributes needed */
		int i = 0;
		char *keyfile = NULL, *dirpath = NULL;
		KMF_ENCODE_FORMAT format;
		/*
		 * Construct a new attribute arrray and call openssl_store_key
		 */
		kmf_set_attr_at_index(storeattrs, i, KMF_PRIVKEY_HANDLE_ATTR,
		    privkey, sizeof (privkey));
		i++;

		dirpath = kmf_get_attr_ptr(KMF_DIRPATH_ATTR, attrlist, numattr);
		if (dirpath != NULL) {
			storeattrs[i].type = KMF_DIRPATH_ATTR;
			storeattrs[i].pValue = dirpath;
			storeattrs[i].valueLen = strlen(dirpath);
			i++;
		} else {
			rv = KMF_OK; /* DIRPATH is optional */
		}
		keyfile = kmf_get_attr_ptr(KMF_KEY_FILENAME_ATTR,
		    attrlist, numattr);
		if (keyfile != NULL) {
			storeattrs[i].type = KMF_KEY_FILENAME_ATTR;
			storeattrs[i].pValue = keyfile;
			storeattrs[i].valueLen = strlen(keyfile);
			i++;
		} else {
			goto cleanup; /* KEYFILE is required */
		}
		rv = kmf_get_attr(KMF_ENCODE_FORMAT_ATTR, attrlist, numattr,
		    (void *)&format, NULL);
		if (rv == KMF_OK) {
			storeattrs[i].type = KMF_ENCODE_FORMAT_ATTR;
			storeattrs[i].pValue = &format;
			storeattrs[i].valueLen = sizeof (format);
			i++;
		}

		rv = OpenSSL_StoreKey(handle, i, storeattrs);
	}

cleanup:
	if (eValue_bn != NULL)
		BN_free(eValue_bn);

	if (rv != KMF_OK) {
		if (eprikey != NULL)
			EVP_PKEY_free(eprikey);

		if (epubkey != NULL)
			EVP_PKEY_free(epubkey);

		if (pubkey->keylabel) {
			free(pubkey->keylabel);
			pubkey->keylabel = NULL;
		}

		if (privkey->keylabel) {
			free(privkey->keylabel);
			privkey->keylabel = NULL;
		}

		pubkey->keyp = NULL;
		privkey->keyp = NULL;
	}

	if (sslPrivKey)
		RSA_free(sslPrivKey);

	if (sslDSAKey)
		DSA_free(sslDSAKey);

	if (out != NULL)
		(void) BIO_free(out);

	return (rv);
}

/*
 * Make sure the BN conversion is properly padded with 0x00
 * bytes.  If not, signature verification for DSA signatures
 * may fail in the case where the bignum value does not use
 * all of the bits.
 */
static int
fixbnlen(const BIGNUM *bn, unsigned char *buf, int len) {
	int bytes = len - BN_num_bytes(bn);

	/* prepend with leading 0x00 if necessary */
	while (bytes-- > 0)
		*buf++ = 0;

	(void) BN_bn2bin(bn, buf);
	/*
	 * Return the desired length since we prepended it
	 * with the necessary 0x00 padding.
	 */
	return (len);
}

KMF_RETURN
OpenSSL_SignData(KMF_HANDLE_T handle, KMF_KEY_HANDLE *key,
	KMF_OID *AlgOID, KMF_DATA *tobesigned, KMF_DATA *output)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	KMF_ALGORITHM_INDEX		AlgId;
	EVP_MD_CTX *ctx;
	const EVP_MD *md;

	if (key == NULL || AlgOID == NULL ||
	    tobesigned == NULL || output == NULL ||
	    tobesigned->Data == NULL ||
	    output->Data == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* Map the OID to an OpenSSL algorithm */
	AlgId = x509_algoid_to_algid(AlgOID);
	if (AlgId == KMF_ALGID_NONE)
		return (KMF_ERR_BAD_ALGORITHM);

	if (key->keyalg == KMF_RSA) {
		EVP_PKEY *pkey = (EVP_PKEY *)key->keyp;
		uchar_t *p;
		int len;
		if (AlgId == KMF_ALGID_MD5WithRSA)
			md = EVP_md5();
		else if (AlgId == KMF_ALGID_SHA1WithRSA)
			md = EVP_sha1();
		else if (AlgId == KMF_ALGID_SHA256WithRSA)
			md = EVP_sha256();
		else if (AlgId == KMF_ALGID_SHA384WithRSA)
			md = EVP_sha384();
		else if (AlgId == KMF_ALGID_SHA512WithRSA)
			md = EVP_sha512();
		else if (AlgId == KMF_ALGID_RSA)
			md = NULL;
		else
			return (KMF_ERR_BAD_ALGORITHM);

		if ((md == NULL) && (AlgId == KMF_ALGID_RSA)) {
			RSA *rsa = EVP_PKEY_get1_RSA((EVP_PKEY *)pkey);

			p = output->Data;
			if ((len = RSA_private_encrypt(tobesigned->Length,
			    tobesigned->Data, p, rsa,
			    RSA_PKCS1_PADDING)) <= 0) {
				SET_ERROR(kmfh, ERR_get_error());
				ret = KMF_ERR_INTERNAL;
			}
			output->Length = len;
		} else {
			if ((ctx = EVP_MD_CTX_new()) == NULL)
				return (KMF_ERR_MEMORY);
			(void) EVP_SignInit_ex(ctx, md, NULL);
			(void) EVP_SignUpdate(ctx, tobesigned->Data,
			    (uint32_t)tobesigned->Length);
			len = (uint32_t)output->Length;
			p = output->Data;
			if (!EVP_SignFinal(ctx, p, (uint32_t *)&len, pkey)) {
				SET_ERROR(kmfh, ERR_get_error());
				len = 0;
				ret = KMF_ERR_INTERNAL;
			}
			output->Length = len;
			EVP_MD_CTX_free(ctx);
		}
	} else if (key->keyalg == KMF_DSA) {
		DSA *dsa = EVP_PKEY_get1_DSA(key->keyp);

		uchar_t hash[EVP_MAX_MD_SIZE];
		uint32_t hashlen;
		DSA_SIG *dsasig;

		if (AlgId == KMF_ALGID_DSA ||
		    AlgId == KMF_ALGID_SHA1WithDSA)
			md = EVP_sha1();
		else if (AlgId == KMF_ALGID_SHA256WithDSA)
			md = EVP_sha256();
		else /* Bad algorithm */
			return (KMF_ERR_BAD_ALGORITHM);

		/*
		 * OpenSSL EVP_Sign operation automatically converts to
		 * ASN.1 output so we do the operations separately so we
		 * are assured of NOT getting ASN.1 output returned.
		 * KMF does not want ASN.1 encoded results because
		 * not all mechanisms return ASN.1 encodings (PKCS#11
		 * and NSS return raw signature data).
		 */
		if ((ctx = EVP_MD_CTX_new()) == NULL)
			return (KMF_ERR_MEMORY);
		(void) EVP_DigestInit_ex(ctx, md, NULL);
		(void) EVP_DigestUpdate(ctx, tobesigned->Data,
		    tobesigned->Length);
		(void) EVP_DigestFinal_ex(ctx, hash, &hashlen);

		/* Only sign first 20 bytes for SHA2 */
		if (AlgId == KMF_ALGID_SHA256WithDSA)
			hashlen = 20;
		dsasig = DSA_do_sign(hash, hashlen, dsa);
		if (dsasig != NULL) {
			int i;
			const BIGNUM *r, *s;

			DSA_SIG_get0(dsasig, &r, &s);
			output->Length = i = fixbnlen(r, output->Data,
			    hashlen);

			output->Length += fixbnlen(s, &output->Data[i],
			    hashlen);

			DSA_SIG_free(dsasig);
		} else {
			SET_ERROR(kmfh, ERR_get_error());
		}
		EVP_MD_CTX_free(ctx);
	} else {
		return (KMF_ERR_BAD_PARAMETER);
	}
cleanup:
	return (ret);
}

KMF_RETURN
/*ARGSUSED*/
OpenSSL_DeleteKey(KMF_HANDLE_T handle,
	int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = KMF_OK;
	KMF_KEY_HANDLE *key;
	boolean_t destroy = B_TRUE;

	key = kmf_get_attr_ptr(KMF_KEY_HANDLE_ATTR, attrlist, numattr);
	if (key == NULL || key->keyp == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = kmf_get_attr(KMF_DESTROY_BOOL_ATTR, attrlist, numattr,
	    (void *)&destroy, NULL);
	if (rv != KMF_OK) {
		/* "destroy" is optional. Default is TRUE */
		rv = KMF_OK;
	}

	if (key->keyclass != KMF_ASYM_PUB &&
	    key->keyclass != KMF_ASYM_PRI &&
	    key->keyclass != KMF_SYMMETRIC)
		return (KMF_ERR_BAD_KEY_CLASS);

	if (key->keyclass == KMF_SYMMETRIC) {
		kmf_free_raw_sym_key((KMF_RAW_SYM_KEY *)key->keyp);
		key->keyp = NULL;
	} else {
		if (key->keyp != NULL) {
			EVP_PKEY_free(key->keyp);
			key->keyp = NULL;
		}
	}

	if (key->keylabel != NULL) {
		EVP_PKEY *pkey = NULL;
		/* If the file exists, make sure it is a proper key. */
		pkey = openssl_load_key(handle, key->keylabel);
		if (pkey == NULL) {
			if (key->keylabel != NULL) {
				free(key->keylabel);
				key->keylabel = NULL;
			}
			return (KMF_ERR_KEY_NOT_FOUND);
		}
		EVP_PKEY_free(pkey);

		if (destroy) {
			if (unlink(key->keylabel) != 0) {
				KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
				SET_SYS_ERROR(kmfh, errno);
				rv = KMF_ERR_INTERNAL;
			}
		}
		if (key->keylabel != NULL) {
			free(key->keylabel);
			key->keylabel = NULL;
		}
	}
	return (rv);
}

KMF_RETURN
OpenSSL_GetErrorString(KMF_HANDLE_T handle, char **msgstr)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	char str[256];	/* OpenSSL needs at least 120 byte buffer */

	ERR_error_string_n(kmfh->lasterr.errcode, str, sizeof (str));
	if (strlen(str)) {
		*msgstr = (char *)strdup(str);
		if ((*msgstr) == NULL)
			ret = KMF_ERR_MEMORY;
	} else {
		*msgstr = NULL;
	}

	return (ret);
}

static int
ext2NID(int kmfext)
{
	switch (kmfext) {
		case KMF_X509_EXT_KEY_USAGE:
			return (NID_key_usage);
		case KMF_X509_EXT_PRIV_KEY_USAGE_PERIOD:
			return (NID_private_key_usage_period);
		case KMF_X509_EXT_CERT_POLICIES:
			return (NID_certificate_policies);
		case KMF_X509_EXT_SUBJ_ALTNAME:
			return (NID_subject_alt_name);
		case KMF_X509_EXT_ISSUER_ALTNAME:
			return (NID_issuer_alt_name);
		case KMF_X509_EXT_BASIC_CONSTRAINTS:
			return (NID_basic_constraints);
		case KMF_X509_EXT_EXT_KEY_USAGE:
			return (NID_ext_key_usage);
		case KMF_X509_EXT_AUTH_KEY_ID:
			return (NID_authority_key_identifier);
		case KMF_X509_EXT_CRL_DIST_POINTS:
			return (NID_crl_distribution_points);
		case KMF_X509_EXT_SUBJ_KEY_ID:
			return (NID_subject_key_identifier);
		case KMF_X509_EXT_POLICY_MAPPINGS:
			return (OBJ_sn2nid("policyMappings"));
		case KMF_X509_EXT_NAME_CONSTRAINTS:
			return (OBJ_sn2nid("nameConstraints"));
		case KMF_X509_EXT_POLICY_CONSTRAINTS:
			return (OBJ_sn2nid("policyConstraints"));
		case KMF_X509_EXT_INHIBIT_ANY_POLICY:
			return (OBJ_sn2nid("inhibitAnyPolicy"));
		case KMF_X509_EXT_FRESHEST_CRL:
			return (OBJ_sn2nid("freshestCRL"));
		default:
			return (NID_undef);
	}
}

KMF_RETURN
OpenSSL_CertGetPrintable(KMF_HANDLE_T handle, const KMF_DATA *pcert,
	KMF_PRINTABLE_ITEM flag, char *resultStr)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	X509 *xcert = NULL;
	unsigned char *outbuf = NULL;
	unsigned char *outbuf_p;
	int j;
	int ext_index, nid, len;
	BIO *mem = NULL;
	STACK_OF(OPENSSL_STRING) *emlst = NULL;
	X509_EXTENSION *ex;

	if (pcert == NULL || pcert->Data == NULL || pcert->Length == 0) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	/* copy cert data to outbuf */
	outbuf = malloc(pcert->Length);
	if (outbuf == NULL) {
		return (KMF_ERR_MEMORY);
	}
	(void) memcpy(outbuf, pcert->Data, pcert->Length);

	outbuf_p = outbuf; /* use a temp pointer; required by openssl */
	xcert = d2i_X509(NULL, (const uchar_t **)&outbuf_p, pcert->Length);
	if (xcert == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_ENCODING;
		goto out;
	}

	mem = BIO_new(BIO_s_mem());
	if (mem == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_MEMORY;
		goto out;
	}

	switch (flag) {
	case KMF_CERT_ISSUER:
		(void) X509_NAME_print_ex(mem, X509_get_issuer_name(xcert), 0,
		    XN_FLAG_SEP_CPLUS_SPC);
		len = BIO_gets(mem, resultStr, KMF_CERT_PRINTABLE_LEN);
		break;

	case KMF_CERT_SUBJECT:
		(void) X509_NAME_print_ex(mem, X509_get_subject_name(xcert), 0,
		    XN_FLAG_SEP_CPLUS_SPC);
		len = BIO_gets(mem, resultStr, KMF_CERT_PRINTABLE_LEN);
		break;

	case KMF_CERT_VERSION:
		(void) snprintf(resultStr, KMF_CERT_PRINTABLE_LEN,
		    "%ld", X509_get_version(xcert));
		len = strlen(resultStr);
		break;

	case KMF_CERT_SERIALNUM:
		if (i2a_ASN1_INTEGER(mem, X509_get_serialNumber(xcert)) > 0) {
			(void) strcpy(resultStr, "0x");
			len = BIO_gets(mem, &resultStr[2],
			    KMF_CERT_PRINTABLE_LEN - 2);
		}
		break;

	case KMF_CERT_NOTBEFORE:
		(void) ASN1_TIME_print(mem, X509_getm_notBefore(xcert));
		len = BIO_gets(mem, resultStr, KMF_CERT_PRINTABLE_LEN);
		break;

	case KMF_CERT_NOTAFTER:
		(void) ASN1_TIME_print(mem, X509_getm_notAfter(xcert));
		len = BIO_gets(mem, resultStr, KMF_CERT_PRINTABLE_LEN);
		break;

	case KMF_CERT_PUBKEY_DATA:
		{
			RSA *rsa;
			DSA *dsa;

			EVP_PKEY *pkey = X509_get_pubkey(xcert);
			if (pkey == NULL) {
				SET_ERROR(kmfh, ERR_get_error());
				ret = KMF_ERR_ENCODING;
				goto out;
			}

			if ((rsa = EVP_PKEY_get0_RSA(pkey)) != NULL) {
				(void) BIO_printf(mem,
				    "RSA Public Key: (%d bit)\n",
				    RSA_bits(rsa));
				(void) RSA_print(mem, rsa, 0);

			} else if ((dsa = EVP_PKEY_get0_DSA(pkey)) != NULL) {
				(void) BIO_printf(mem,
				    "%12sDSA Public Key:\n", "");
				(void) DSA_print(mem, dsa, 0);
			} else {
				(void) BIO_printf(mem,
				    "%12sUnknown Public Key:\n", "");
			}
			(void) BIO_printf(mem, "\n");
			EVP_PKEY_free(pkey);
		}
		len = BIO_read(mem, resultStr, KMF_CERT_PRINTABLE_LEN);
		break;
	case KMF_CERT_SIGNATURE_ALG:
	case KMF_CERT_PUBKEY_ALG:
		{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
			ASN1_OBJECT *alg = NULL;
#else
			const ASN1_OBJECT *alg = NULL;
#endif

			if (flag == KMF_CERT_SIGNATURE_ALG) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
				alg = xcert->sig_alg->algorithm;
#else
				const X509_ALGOR *sig_alg = NULL;

				X509_get0_signature(NULL, &sig_alg, xcert);
				if (sig_alg != NULL)
					X509_ALGOR_get0(&alg, NULL, NULL,
					    sig_alg);
#endif
			} else {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
				alg = xcert->cert_info->key->algor->algorithm;
#else
				X509_PUBKEY *key = X509_get_X509_PUBKEY(xcert);

				if (key != NULL)
					(void) X509_PUBKEY_get0_param(
					    (ASN1_OBJECT **)&alg, NULL, 0,
					    NULL, key);
#endif
			}

			if (alg == NULL)
				len = -1;
			else if ((len = i2a_ASN1_OBJECT(mem, alg)) > 0)
				len = BIO_read(mem, resultStr,
				    KMF_CERT_PRINTABLE_LEN);
		}
		break;

	case KMF_CERT_EMAIL:
		emlst = X509_get1_email(xcert);
		for (j = 0; j < sk_OPENSSL_STRING_num(emlst); j++)
			(void) BIO_printf(mem, "%s\n",
			    sk_OPENSSL_STRING_value(emlst, j));

		len = BIO_gets(mem, resultStr, KMF_CERT_PRINTABLE_LEN);
		X509_email_free(emlst);
		break;
	case KMF_X509_EXT_ISSUER_ALTNAME:
	case KMF_X509_EXT_SUBJ_ALTNAME:
	case KMF_X509_EXT_KEY_USAGE:
	case KMF_X509_EXT_PRIV_KEY_USAGE_PERIOD:
	case KMF_X509_EXT_CERT_POLICIES:
	case KMF_X509_EXT_BASIC_CONSTRAINTS:
	case KMF_X509_EXT_NAME_CONSTRAINTS:
	case KMF_X509_EXT_POLICY_CONSTRAINTS:
	case KMF_X509_EXT_EXT_KEY_USAGE:
	case KMF_X509_EXT_INHIBIT_ANY_POLICY:
	case KMF_X509_EXT_AUTH_KEY_ID:
	case KMF_X509_EXT_SUBJ_KEY_ID:
	case KMF_X509_EXT_POLICY_MAPPINGS:
	case KMF_X509_EXT_CRL_DIST_POINTS:
	case KMF_X509_EXT_FRESHEST_CRL:
		nid = ext2NID(flag);
		if (nid == NID_undef) {
			ret = KMF_ERR_EXTENSION_NOT_FOUND;
			goto out;
		}

		ext_index = X509_get_ext_by_NID(xcert, nid, -1);
		if (ext_index == -1) {
			SET_ERROR(kmfh, ERR_get_error());

			ret = KMF_ERR_EXTENSION_NOT_FOUND;
			goto out;
		}
		ex = X509_get_ext(xcert, ext_index);

		(void) i2a_ASN1_OBJECT(mem, X509_EXTENSION_get_object(ex));

		if (BIO_printf(mem, ": %s\n",
		    X509_EXTENSION_get_critical(ex) ? "critical" : "") <= 0) {
			SET_ERROR(kmfh, ERR_get_error());
			ret = KMF_ERR_ENCODING;
			goto out;
		}
		if (!X509V3_EXT_print(mem, ex, X509V3_EXT_DUMP_UNKNOWN, 4)) {
			(void) BIO_printf(mem, "%*s", 4, "");
			(void) ASN1_STRING_print(mem,
			    X509_EXTENSION_get_data(ex));
		}
		if (BIO_write(mem, "\n", 1) <= 0) {
			SET_ERROR(kmfh, ERR_get_error());
			ret = KMF_ERR_ENCODING;
			goto out;
		}
		len = BIO_read(mem, resultStr, KMF_CERT_PRINTABLE_LEN);
	}
	if (len <= 0) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_ENCODING;
	}

out:
	if (outbuf != NULL) {
		free(outbuf);
	}

	if (xcert != NULL) {
		X509_free(xcert);
	}

	if (mem != NULL) {
		(void) BIO_free(mem);
	}

	return (ret);
}

KMF_RETURN
/*ARGSUSED*/
OpenSSL_FindPrikeyByCert(KMF_HANDLE_T handle, int numattr,
    KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = KMF_OK;
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_OPENSSL;
	KMF_KEY_CLASS keyclass = KMF_ASYM_PRI;
	KMF_KEY_HANDLE *key = NULL;
	uint32_t numkeys = 1; /* 1 key only */
	char *dirpath = NULL;
	char *keyfile = NULL;
	KMF_ATTRIBUTE new_attrlist[16];
	int i = 0;

	/*
	 * This is really just a FindKey operation, reuse the
	 * FindKey function.
	 */
	kmf_set_attr_at_index(new_attrlist, i,
	    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
	i++;

	kmf_set_attr_at_index(new_attrlist, i,
	    KMF_COUNT_ATTR, &numkeys, sizeof (uint32_t));
	i++;

	kmf_set_attr_at_index(new_attrlist, i,
	    KMF_KEYCLASS_ATTR, &keyclass, sizeof (keyclass));
	i++;

	key = kmf_get_attr_ptr(KMF_KEY_HANDLE_ATTR, attrlist, numattr);
	if (key == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	} else {
		kmf_set_attr_at_index(new_attrlist, i,
		    KMF_KEY_HANDLE_ATTR, key, sizeof (KMF_KEY_HANDLE));
		i++;
	}

	dirpath = kmf_get_attr_ptr(KMF_DIRPATH_ATTR, attrlist, numattr);
	if (dirpath != NULL) {
		kmf_set_attr_at_index(new_attrlist, i,
		    KMF_DIRPATH_ATTR, dirpath, strlen(dirpath));
		i++;
	}

	keyfile = kmf_get_attr_ptr(KMF_KEY_FILENAME_ATTR, attrlist, numattr);
	if (keyfile == NULL)
		return (KMF_ERR_BAD_PARAMETER);
	else {
		kmf_set_attr_at_index(new_attrlist, i,
		    KMF_KEY_FILENAME_ATTR, keyfile, strlen(keyfile));
		i++;
	}

	rv = OpenSSL_FindKey(handle, i, new_attrlist);
	return (rv);
}

KMF_RETURN
/*ARGSUSED*/
OpenSSL_DecryptData(KMF_HANDLE_T handle, KMF_KEY_HANDLE *key,
	KMF_OID *AlgOID, KMF_DATA *ciphertext,
	KMF_DATA *output)
{
	KMF_RETURN		ret = KMF_OK;
	RSA *rsa = NULL;
	unsigned int in_len = 0, out_len = 0;
	unsigned int total_decrypted = 0, modulus_len = 0;
	uint8_t *in_data, *out_data;
	int i, blocks;

	if (key == NULL || AlgOID == NULL ||
	    ciphertext == NULL || output == NULL ||
	    ciphertext->Data == NULL ||
	    output->Data == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (key->keyalg == KMF_RSA) {
		rsa = EVP_PKEY_get1_RSA((EVP_PKEY *)key->keyp);
		modulus_len = RSA_size(rsa);
	} else {
		return (KMF_ERR_BAD_PARAMETER);
	}

	blocks = ciphertext->Length/modulus_len;
	out_data = output->Data;
	in_data = ciphertext->Data;
	out_len = modulus_len - 11;
	in_len = modulus_len;

	for (i = 0; i < blocks; i++) {
		out_len  = RSA_private_decrypt(in_len,
		    in_data, out_data, rsa, RSA_PKCS1_PADDING);

		if (out_len == 0) {
			ret = KMF_ERR_INTERNAL;
			goto cleanup;
		}

		out_data += out_len;
		total_decrypted += out_len;
		in_data += in_len;
	}

	output->Length = total_decrypted;

cleanup:
	RSA_free(rsa);
	if (ret != KMF_OK)
		output->Length = 0;

	return (ret);

}

/*
 *  This function will create a certid from issuer_cert and user_cert.
 *  The caller should use OCSP_CERTID_free(OCSP_CERTID *) to deallocate
 *  certid memory after use.
 */
static KMF_RETURN
create_certid(KMF_HANDLE_T handle, const KMF_DATA *issuer_cert,
    const KMF_DATA *user_cert, OCSP_CERTID **certid)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	X509   *issuer = NULL;
	X509   *cert = NULL;
	unsigned char *ptmp;

	if (issuer_cert == NULL || user_cert == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	/* convert the DER-encoded issuer cert to an internal X509 */
	ptmp = issuer_cert->Data;
	issuer = d2i_X509(NULL, (const uchar_t **)&ptmp,
	    issuer_cert->Length);
	if (issuer == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_OCSP_BAD_ISSUER;
		goto end;
	}

	/* convert the DER-encoded user cert to an internal X509 */
	ptmp = user_cert->Data;
	cert = d2i_X509(NULL, (const uchar_t **)&ptmp,
	    user_cert->Length);
	if (cert == NULL) {
		SET_ERROR(kmfh, ERR_get_error());

		ret = KMF_ERR_OCSP_BAD_CERT;
		goto end;
	}

	/* create a CERTID */
	*certid = OCSP_cert_to_id(NULL, cert, issuer);
	if (*certid == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_OCSP_CERTID;
		goto end;
	}

end:
	if (issuer != NULL) {
		X509_free(issuer);
	}

	if (cert != NULL) {
		X509_free(cert);
	}

	return (ret);
}

KMF_RETURN
OpenSSL_CreateOCSPRequest(KMF_HANDLE_T handle,
	int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	OCSP_CERTID *id = NULL;
	OCSP_REQUEST *req = NULL;
	BIO *derbio = NULL;
	char *reqfile;
	KMF_DATA *issuer_cert;
	KMF_DATA *user_cert;

	user_cert = kmf_get_attr_ptr(KMF_USER_CERT_DATA_ATTR,
	    attrlist, numattr);
	if (user_cert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	issuer_cert = kmf_get_attr_ptr(KMF_ISSUER_CERT_DATA_ATTR,
	    attrlist, numattr);
	if (issuer_cert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	reqfile = kmf_get_attr_ptr(KMF_OCSP_REQUEST_FILENAME_ATTR,
	    attrlist, numattr);
	if (reqfile == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	ret = create_certid(handle, issuer_cert, user_cert, &id);
	if (ret != KMF_OK) {
		return (ret);
	}

	/* Create an OCSP request */
	req = OCSP_REQUEST_new();
	if (req == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_OCSP_CREATE_REQUEST;
		goto end;
	}

	if (!OCSP_request_add0_id(req, id)) {
		ret = KMF_ERR_OCSP_CREATE_REQUEST;
		goto end;
	}

	/* Write the request to the output file with DER encoding */
	derbio = BIO_new_file(reqfile, "wb");
	if (!derbio) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_OPEN_FILE;
		goto end;
	}
	if (i2d_OCSP_REQUEST_bio(derbio, req) <= 0) {
		ret = KMF_ERR_ENCODING;
	}

end:
	/*
	 * We don't need to free "id" explicitely, because OCSP_REQUEST_free()
	 * will also deallocate certid's space.
	 */
	if (req != NULL) {
		OCSP_REQUEST_free(req);
	}

	if (derbio != NULL) {
		(void) BIO_free(derbio);
	}

	return (ret);
}

/* ocsp_find_signer_sk() is copied from openssl source */
static X509 *ocsp_find_signer_sk(STACK_OF(X509) *certs, OCSP_BASICRESP *bs)
{
	int i;
	unsigned char tmphash[SHA_DIGEST_LENGTH], *keyhash;
	const ASN1_OCTET_STRING *pid;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	OCSP_RESPID *id = bs->tbsResponseData->responderId;

	if (id->type == V_OCSP_RESPID_NAME)
		return (X509_find_by_subject(certs, id->value.byName));

	pid = id->value.byKey;
#else
	const X509_NAME *pname;

	if (OCSP_resp_get0_id(bs, &pid, &pname) == 0)
		return (NULL);

	if (pname != NULL)
		return (X509_find_by_subject(certs, (X509_NAME *)pname));
#endif

	/* Lookup by key hash */

	/* If key hash isn't SHA1 length then forget it */
	if (pid->length != SHA_DIGEST_LENGTH)
		return (NULL);

	keyhash = pid->data;
	/* Calculate hash of each key and compare */
	for (i = 0; i < sk_X509_num(certs); i++) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		X509 *x = sk_X509_value(certs, i);
		/* Use pubkey_digest to get the key ID value */
		(void) X509_pubkey_digest(x, EVP_sha1(), tmphash, NULL);
		if (!memcmp(keyhash, tmphash, SHA_DIGEST_LENGTH))
			return (x);
	}
	return (NULL);
}

/* ocsp_find_signer() is copied from openssl source */
/* ARGSUSED2 */
static int
ocsp_find_signer(X509 **psigner, OCSP_BASICRESP *bs, STACK_OF(X509) *certs,
    X509_STORE *st, unsigned long flags)
{
	X509 *signer;
	if ((signer = ocsp_find_signer_sk(certs, bs)))	{
		*psigner = signer;
		return (2);
	}

	if (!(flags & OCSP_NOINTERN) &&
	    (signer = ocsp_find_signer_sk(
	    (STACK_OF(X509) *)OCSP_resp_get0_certs(bs), bs))) {
		*psigner = signer;
		return (1);
	}
	/* Maybe lookup from store if by subject name */

	*psigner = NULL;
	return (0);
}

/*
 * This function will verify the signature of a basic response, using
 * the public key from the OCSP responder certificate.
 */
static KMF_RETURN
check_response_signature(KMF_HANDLE_T handle, OCSP_BASICRESP *bs,
    KMF_DATA *signer_cert, KMF_DATA *issuer_cert)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	STACK_OF(X509) *cert_stack = NULL;
	X509 *signer = NULL;
	X509 *issuer = NULL;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_PKEY *skey = NULL;
#else
	STACK_OF(X509) *cert_stack2 = NULL;
#endif
	unsigned char *ptmp;

	if (bs == NULL || issuer_cert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * Find the certificate that signed the basic response.
	 *
	 * If signer_cert is not NULL, we will use that as the signer cert.
	 * Otherwise, we will check if the issuer cert is actually the signer.
	 * If we still do not find a signer, we will look for it from the
	 * certificate list came with the response file.
	 */
	if (signer_cert != NULL) {
		ptmp = signer_cert->Data;
		signer = d2i_X509(NULL, (const uchar_t **)&ptmp,
		    signer_cert->Length);
		if (signer == NULL) {
			SET_ERROR(kmfh, ERR_get_error());
			ret = KMF_ERR_OCSP_BAD_SIGNER;
			goto end;
		}
	} else {
		/*
		 * Convert the issuer cert into X509 and push it into a
		 * stack to be used by ocsp_find_signer().
		 */
		ptmp = issuer_cert->Data;
		issuer = d2i_X509(NULL, (const uchar_t **)&ptmp,
		    issuer_cert->Length);
		if (issuer == NULL) {
			SET_ERROR(kmfh, ERR_get_error());
			ret = KMF_ERR_OCSP_BAD_ISSUER;
			goto end;
		}

		if ((cert_stack = sk_X509_new_null()) == NULL) {
			ret = KMF_ERR_INTERNAL;
			goto end;
		}

		if (sk_X509_push(cert_stack, issuer) == NULL) {
			ret = KMF_ERR_INTERNAL;
			goto end;
		}

		ret = ocsp_find_signer(&signer, bs, cert_stack, NULL, 0);
		if (!ret) {
			/* can not find the signer */
			ret = KMF_ERR_OCSP_BAD_SIGNER;
			goto end;
		}
	}

	/* Verify the signature of the response */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	skey = X509_get_pubkey(signer);
	if (skey == NULL) {
		ret = KMF_ERR_OCSP_BAD_SIGNER;
		goto end;
	}

	ret = OCSP_BASICRESP_verify(bs, skey, 0);
#else
	/*
	 * Technique based on
	 * https://mta.openssl.org/pipermail/openssl-users/
	 *	2017-October/006814.html
	 */
	if ((cert_stack2 = sk_X509_new_null()) == NULL) {
		ret = KMF_ERR_INTERNAL;
		goto end;
	}

	if (sk_X509_push(cert_stack2, signer) == NULL) {
		ret = KMF_ERR_INTERNAL;
		goto end;
	}

	ret = OCSP_basic_verify(bs, cert_stack2, NULL, OCSP_NOVERIFY);
#endif

	if (ret == 0) {
		ret = KMF_ERR_OCSP_RESPONSE_SIGNATURE;
		goto end;
	}

end:
	if (issuer != NULL) {
		X509_free(issuer);
	}

	if (signer != NULL) {
		X509_free(signer);
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	if (skey != NULL) {
		EVP_PKEY_free(skey);
	}
#else
	if (cert_stack2 != NULL) {
		sk_X509_free(cert_stack2);
	}
#endif

	if (cert_stack != NULL) {
		sk_X509_free(cert_stack);
	}

	return (ret);
}

KMF_RETURN
OpenSSL_GetOCSPStatusForCert(KMF_HANDLE_T handle,
	int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN ret = KMF_OK;
	BIO *derbio = NULL;
	OCSP_RESPONSE *resp = NULL;
	OCSP_BASICRESP *bs = NULL;
	OCSP_CERTID *id = NULL;
	OCSP_SINGLERESP *single = NULL;
	ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;
	int index, status, reason;
	KMF_DATA *issuer_cert;
	KMF_DATA *user_cert;
	KMF_DATA *signer_cert;
	KMF_DATA *response;
	int *response_reason, *response_status, *cert_status;
	boolean_t ignore_response_sign = B_FALSE;	/* default is FALSE */
	uint32_t response_lifetime;

	issuer_cert = kmf_get_attr_ptr(KMF_ISSUER_CERT_DATA_ATTR,
	    attrlist, numattr);
	if (issuer_cert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	user_cert = kmf_get_attr_ptr(KMF_USER_CERT_DATA_ATTR,
	    attrlist, numattr);
	if (user_cert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	response = kmf_get_attr_ptr(KMF_OCSP_RESPONSE_DATA_ATTR,
	    attrlist, numattr);
	if (response == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	response_status = kmf_get_attr_ptr(KMF_OCSP_RESPONSE_STATUS_ATTR,
	    attrlist, numattr);
	if (response_status == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	response_reason = kmf_get_attr_ptr(KMF_OCSP_RESPONSE_REASON_ATTR,
	    attrlist, numattr);
	if (response_reason == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	cert_status = kmf_get_attr_ptr(KMF_OCSP_RESPONSE_CERT_STATUS_ATTR,
	    attrlist, numattr);
	if (cert_status == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* Read in the response */
	derbio = BIO_new_mem_buf(response->Data, response->Length);
	if (!derbio) {
		ret = KMF_ERR_MEMORY;
		return (ret);
	}

	resp = d2i_OCSP_RESPONSE_bio(derbio, NULL);
	if (resp == NULL) {
		ret = KMF_ERR_OCSP_MALFORMED_RESPONSE;
		goto end;
	}

	/* Check the response status */
	status = OCSP_response_status(resp);
	*response_status = status;
	if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		ret = KMF_ERR_OCSP_RESPONSE_STATUS;
		goto end;
	}

#ifdef DEBUG
	printf("Successfully checked the response file status.\n");
#endif /* DEBUG */

	/* Extract basic response */
	bs = OCSP_response_get1_basic(resp);
	if (bs == NULL) {
		ret = KMF_ERR_OCSP_NO_BASIC_RESPONSE;
		goto end;
	}

#ifdef DEBUG
	printf("Successfully retrieved the basic response.\n");
#endif /* DEBUG */

	/* Check the basic response signature if required */
	ret = kmf_get_attr(KMF_IGNORE_RESPONSE_SIGN_ATTR, attrlist, numattr,
	    (void *)&ignore_response_sign, NULL);
	if (ret != KMF_OK)
		ret = KMF_OK;

	signer_cert = kmf_get_attr_ptr(KMF_SIGNER_CERT_DATA_ATTR,
	    attrlist, numattr);

	if (ignore_response_sign == B_FALSE) {
		ret = check_response_signature(handle, bs,
		    signer_cert, issuer_cert);
		if (ret != KMF_OK)
			goto end;
	}

#ifdef DEBUG
	printf("Successfully verified the response signature.\n");
#endif /* DEBUG */

	/* Create a certid for the certificate in question */
	ret = create_certid(handle, issuer_cert, user_cert, &id);
	if (ret != KMF_OK) {
		ret = KMF_ERR_OCSP_CERTID;
		goto end;
	}

#ifdef DEBUG
	printf("successfully created a certid for the cert.\n");
#endif /* DEBUG */

	/* Find the index of the single response for the certid */
	index = OCSP_resp_find(bs, id, -1);
	if (index < 0) {
		/* cound not find this certificate in the response */
		ret = KMF_ERR_OCSP_UNKNOWN_CERT;
		goto end;
	}

#ifdef DEBUG
	printf("Successfully found the single response index for the cert.\n");
#endif /* DEBUG */

	/* Retrieve the single response and get the cert status */
	single = OCSP_resp_get0(bs, index);
	status = OCSP_single_get0_status(single, &reason, &rev, &thisupd,
	    &nextupd);
	if (status == V_OCSP_CERTSTATUS_GOOD) {
		*cert_status = OCSP_GOOD;
	} else if (status == V_OCSP_CERTSTATUS_UNKNOWN) {
		*cert_status = OCSP_UNKNOWN;
	} else { /* revoked */
		*cert_status = OCSP_REVOKED;
		*response_reason = reason;
	}
	ret = KMF_OK;

	/* resp. time is optional, so we don't care about the return code. */
	(void) kmf_get_attr(KMF_RESPONSE_LIFETIME_ATTR, attrlist, numattr,
	    (void *)&response_lifetime, NULL);

	if (!OCSP_check_validity(thisupd, nextupd, 300,
	    response_lifetime)) {
		ret = KMF_ERR_OCSP_STATUS_TIME_INVALID;
		goto end;
	}

#ifdef DEBUG
	printf("Successfully verify the time.\n");
#endif /* DEBUG */

end:
	if (derbio != NULL)
		(void) BIO_free(derbio);

	if (resp != NULL)
		OCSP_RESPONSE_free(resp);

	if (bs != NULL)
		OCSP_BASICRESP_free(bs);

	if (id != NULL)
		OCSP_CERTID_free(id);

	return (ret);
}

static KMF_RETURN
fetch_key(KMF_HANDLE_T handle, char *path,
	KMF_KEY_CLASS keyclass, KMF_KEY_HANDLE *key)
{
	KMF_RETURN rv = KMF_OK;
	EVP_PKEY *pkey = NULL;
	KMF_RAW_SYM_KEY *rkey = NULL;

	if (keyclass == KMF_ASYM_PRI ||
	    keyclass == KMF_ASYM_PUB) {
		pkey = openssl_load_key(handle, path);
		if (pkey == NULL) {
			return (KMF_ERR_KEY_NOT_FOUND);
		}
		if (key != NULL) {
			if (EVP_PKEY_get0_RSA(pkey) != NULL)
				key->keyalg = KMF_RSA;
			else if (EVP_PKEY_get0_DSA(pkey) != NULL)
				key->keyalg = KMF_DSA;

			key->kstype = KMF_KEYSTORE_OPENSSL;
			key->keyclass = keyclass;
			key->keyp = (void *)pkey;
			key->israw = FALSE;
			if (path != NULL &&
			    ((key->keylabel = strdup(path)) == NULL)) {
				EVP_PKEY_free(pkey);
				return (KMF_ERR_MEMORY);
			}
		} else {
			EVP_PKEY_free(pkey);
			pkey = NULL;
		}
	} else if (keyclass == KMF_SYMMETRIC) {
		KMF_ENCODE_FORMAT fmt;
		/*
		 * If the file is a recognized format,
		 * then it is NOT a symmetric key.
		 */
		rv = kmf_get_file_format(path, &fmt);
		if (rv == KMF_OK || fmt != 0) {
			return (KMF_ERR_KEY_NOT_FOUND);
		} else if (rv == KMF_ERR_ENCODING) {
			/*
			 * If we don't know the encoding,
			 * it is probably  a symmetric key.
			 */
			rv = KMF_OK;
		} else if (rv == KMF_ERR_OPEN_FILE) {
			return (KMF_ERR_KEY_NOT_FOUND);
		}

		if (key != NULL) {
			KMF_DATA keyvalue;
			rkey = malloc(sizeof (KMF_RAW_SYM_KEY));
			if (rkey == NULL) {
				rv = KMF_ERR_MEMORY;
				goto out;
			}

			(void) memset(rkey, 0, sizeof (KMF_RAW_SYM_KEY));
			rv = kmf_read_input_file(handle, path, &keyvalue);
			if (rv != KMF_OK)
				goto out;

			rkey->keydata.len = keyvalue.Length;
			rkey->keydata.val = keyvalue.Data;

			key->kstype = KMF_KEYSTORE_OPENSSL;
			key->keyclass = keyclass;
			key->israw = TRUE;
			key->keyp = (void *)rkey;
			if (path != NULL &&
			    ((key->keylabel = strdup(path)) == NULL)) {
				rv = KMF_ERR_MEMORY;
			}
		}
	}
out:
	if (rv != KMF_OK) {
		if (rkey != NULL) {
			kmf_free_raw_sym_key(rkey);
		}
		if (pkey != NULL)
			EVP_PKEY_free(pkey);

		if (key != NULL) {
			key->keyalg = KMF_KEYALG_NONE;
			key->keyclass = KMF_KEYCLASS_NONE;
			key->keyp = NULL;
		}
	}

	return (rv);
}

KMF_RETURN
OpenSSL_FindKey(KMF_HANDLE_T handle,
	int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = KMF_OK;
	char *fullpath = NULL;
	uint32_t maxkeys;
	KMF_KEY_HANDLE *key;
	uint32_t *numkeys;
	KMF_KEY_CLASS keyclass;
	KMF_RAW_KEY_DATA *rawkey;
	char *dirpath;
	char *keyfile;

	if (handle == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	numkeys = kmf_get_attr_ptr(KMF_COUNT_ATTR, attrlist, numattr);
	if (numkeys == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = kmf_get_attr(KMF_KEYCLASS_ATTR, attrlist, numattr,
	    (void *)&keyclass, NULL);
	if (rv != KMF_OK)
		return (KMF_ERR_BAD_PARAMETER);

	if (keyclass != KMF_ASYM_PUB &&
	    keyclass != KMF_ASYM_PRI &&
	    keyclass != KMF_SYMMETRIC)
		return (KMF_ERR_BAD_KEY_CLASS);

	dirpath = kmf_get_attr_ptr(KMF_DIRPATH_ATTR, attrlist, numattr);
	keyfile = kmf_get_attr_ptr(KMF_KEY_FILENAME_ATTR, attrlist, numattr);

	fullpath = get_fullpath(dirpath, keyfile);

	if (fullpath == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	maxkeys = *numkeys;
	if (maxkeys == 0)
		maxkeys = 0xFFFFFFFF;
	*numkeys = 0;

	key = kmf_get_attr_ptr(KMF_KEY_HANDLE_ATTR, attrlist, numattr);
	/* it is okay to have "keys" contains NULL */

	/*
	 * The caller may want a list of the raw key data as well.
	 * Useful for importing keys from a file into other keystores.
	 */
	rawkey = kmf_get_attr_ptr(KMF_RAW_KEY_ATTR, attrlist, numattr);

	if (isdir(fullpath)) {
		DIR *dirp;
		struct dirent *dp;
		int n = 0;

		/* open all files in the directory and attempt to read them */
		if ((dirp = opendir(fullpath)) == NULL) {
			return (KMF_ERR_BAD_PARAMETER);
		}
		rewinddir(dirp);
		while ((dp = readdir(dirp)) != NULL && n < maxkeys) {
			if (strcmp(dp->d_name, ".") &&
			    strcmp(dp->d_name, "..")) {
				char *fname;

				fname = get_fullpath(fullpath,
				    (char *)&dp->d_name);

				rv = fetch_key(handle, fname,
				    keyclass, key ? &key[n] : NULL);

				if (rv == KMF_OK) {
					if (key != NULL && rawkey != NULL)
						rv = convertToRawKey(
						    key[n].keyp, &rawkey[n]);
					n++;
				}

				if (rv != KMF_OK || key == NULL)
					free(fname);
			}
		}
		(void) closedir(dirp);
		free(fullpath);
		(*numkeys) = n;
	} else {
		rv = fetch_key(handle, fullpath, keyclass, key);
		if (rv == KMF_OK)
			(*numkeys) = 1;

		if (rv != KMF_OK || key == NULL)
			free(fullpath);

		if (rv == KMF_OK && key != NULL && rawkey != NULL) {
			rv = convertToRawKey(key->keyp, rawkey);
		}
	}

	if (rv == KMF_OK && (*numkeys) == 0)
		rv = KMF_ERR_KEY_NOT_FOUND;
	else if (rv == KMF_ERR_KEY_NOT_FOUND && (*numkeys) > 0)
		rv = KMF_OK;

	return (rv);
}

#define	HANDLE_PK12_ERROR { \
	SET_ERROR(kmfh, ERR_get_error()); \
	rv = KMF_ERR_ENCODING; \
	goto out; \
}

static int
add_alias_to_bag(PKCS12_SAFEBAG *bag, X509 *xcert)
{
	unsigned char *alias;
	int len;

	if (xcert != NULL && (alias = X509_alias_get0(xcert, &len)) != NULL) {
		if (PKCS12_add_friendlyname_asc(bag,
		    (const char *)alias, len) == 0)
			return (0);
	}
	return (1);
}

static PKCS7 *
add_cert_to_safe(X509 *sslcert, KMF_CREDENTIAL *cred,
	uchar_t *keyid, unsigned int keyidlen)
{
	PKCS12_SAFEBAG *bag = NULL;
	PKCS7 *cert_authsafe = NULL;
	STACK_OF(PKCS12_SAFEBAG) *bag_stack;

	bag_stack = sk_PKCS12_SAFEBAG_new_null();
	if (bag_stack == NULL)
		return (NULL);

	/* Convert cert from X509 struct to PKCS#12 bag */
	bag = PKCS12_SAFEBAG_create_cert(sslcert);
	if (bag == NULL) {
		goto out;
	}

	/* Add the key id to the certificate bag. */
	if (keyidlen > 0 && !PKCS12_add_localkeyid(bag, keyid, keyidlen)) {
		goto out;
	}

	if (!add_alias_to_bag(bag, sslcert))
		goto out;

	/* Pile it on the bag_stack. */
	if (!sk_PKCS12_SAFEBAG_push(bag_stack, bag)) {
		goto out;
	}
	/* Turn bag_stack of certs into encrypted authsafe. */
	cert_authsafe = PKCS12_pack_p7encdata(
	    NID_pbe_WithSHA1And40BitRC2_CBC,
	    cred->cred, cred->credlen, NULL, 0,
	    PKCS12_DEFAULT_ITER, bag_stack);

out:
	if (bag_stack != NULL)
		sk_PKCS12_SAFEBAG_pop_free(bag_stack, PKCS12_SAFEBAG_free);

	return (cert_authsafe);
}

static PKCS7 *
add_key_to_safe(EVP_PKEY *pkey, KMF_CREDENTIAL *cred,
	uchar_t *keyid,  unsigned int keyidlen,
	char *label, int label_len)
{
	PKCS8_PRIV_KEY_INFO *p8 = NULL;
	STACK_OF(PKCS12_SAFEBAG) *bag_stack = NULL;
	PKCS12_SAFEBAG *bag = NULL;
	PKCS7 *key_authsafe = NULL;

	p8 = EVP_PKEY2PKCS8(pkey);
	if (p8 == NULL) {
		return (NULL);
	}
	/* Put the shrouded key into a PKCS#12 bag. */
	bag = PKCS12_SAFEBAG_create_pkcs8_encrypt(
	    NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
	    cred->cred, cred->credlen,
	    NULL, 0, PKCS12_DEFAULT_ITER, p8);

	/* Clean up the PKCS#8 shrouded key, don't need it now. */
	PKCS8_PRIV_KEY_INFO_free(p8);
	p8 = NULL;

	if (bag == NULL) {
		return (NULL);
	}
	if (keyidlen && !PKCS12_add_localkeyid(bag, keyid, keyidlen))
		goto out;
	if (label != NULL && !PKCS12_add_friendlyname(bag, label, label_len))
		goto out;

	/* Start a PKCS#12 safebag container for the private key. */
	bag_stack = sk_PKCS12_SAFEBAG_new_null();
	if (bag_stack == NULL)
		goto out;

	/* Pile on the private key on the bag_stack. */
	if (!sk_PKCS12_SAFEBAG_push(bag_stack, bag))
		goto out;

	key_authsafe = PKCS12_pack_p7data(bag_stack);

out:
	if (bag_stack != NULL)
		sk_PKCS12_SAFEBAG_pop_free(bag_stack, PKCS12_SAFEBAG_free);
	bag_stack = NULL;
	return (key_authsafe);
}

static EVP_PKEY *
ImportRawRSAKey(KMF_RAW_RSA_KEY *key)
{
	RSA		*rsa = NULL;
	EVP_PKEY	*newkey = NULL;
	BIGNUM		*n = NULL, *e = NULL, *d = NULL,
			*p = NULL, *q = NULL,
			*dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;

	if ((rsa = RSA_new()) == NULL)
		goto cleanup;

	if ((n = BN_bin2bn(key->mod.val, key->mod.len, NULL)) == NULL)
		goto cleanup;

	if ((e = BN_bin2bn(key->pubexp.val, key->pubexp.len, NULL)) == NULL)
		goto cleanup;

	if (key->priexp.val != NULL &&
	    (d = BN_bin2bn(key->priexp.val, key->priexp.len, NULL)) == NULL)
		goto cleanup;

	if (key->prime1.val != NULL &&
	    (p = BN_bin2bn(key->prime1.val, key->prime1.len, NULL)) == NULL)
		goto cleanup;

	if (key->prime2.val != NULL &&
	    (q = BN_bin2bn(key->prime2.val, key->prime2.len, NULL)) == NULL)
		goto cleanup;

	if (key->exp1.val != NULL &&
	    (dmp1 = BN_bin2bn(key->exp1.val, key->exp1.len, NULL)) == NULL)
		goto cleanup;

	if (key->exp2.val != NULL &&
	    (dmq1 = BN_bin2bn(key->exp2.val, key->exp2.len, NULL)) == NULL)
		goto cleanup;

	if (key->coef.val != NULL &&
	    (iqmp = BN_bin2bn(key->coef.val, key->coef.len, NULL)) == NULL)
		goto cleanup;

	if (RSA_set0_key(rsa, n, e, d) == 0)
		goto cleanup;
	n = e = d = NULL;
	if (RSA_set0_factors(rsa, p, q) == 0)
		goto cleanup;
	p = q = NULL;
	if (RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp) == 0)
		goto cleanup;
	dmp1 = dmq1 = iqmp = NULL;

	if ((newkey = EVP_PKEY_new()) == NULL)
		goto cleanup;

	(void) EVP_PKEY_set1_RSA(newkey, rsa);

cleanup:
	/* The original key must be freed once here or it leaks memory */
	if (rsa)
		RSA_free(rsa);
	BN_free(n);
	BN_free(e);
	BN_free(d);
	BN_free(p);
	BN_free(q);
	BN_free(dmp1);
	BN_free(dmq1);
	BN_free(iqmp);

	return (newkey);
}

static EVP_PKEY *
ImportRawDSAKey(KMF_RAW_DSA_KEY *key)
{
	DSA		*dsa = NULL;
	EVP_PKEY	*newkey = NULL;
	BIGNUM		*p = NULL, *q = NULL, *g = NULL,
			*priv_key = NULL, *pub_key = NULL;

	if ((dsa = DSA_new()) == NULL)
		goto cleanup;

	if ((p = BN_bin2bn(key->prime.val, key->prime.len, NULL)) == NULL)
		goto cleanup;

	if ((q = BN_bin2bn(key->subprime.val, key->subprime.len, NULL)) == NULL)
		goto cleanup;

	if ((g = BN_bin2bn(key->base.val, key->base.len, NULL)) == NULL)
		goto cleanup;

	if ((priv_key = BN_bin2bn(key->value.val, key->value.len,
	    NULL)) == NULL)
		goto cleanup;

	if (key->pubvalue.val != NULL && (pub_key =
	    BN_bin2bn(key->pubvalue.val, key->pubvalue.len, NULL)) == NULL)
		goto cleanup;

	if (DSA_set0_pqg(dsa, p, q, g) == 0)
		goto cleanup;
	p = q = g = NULL;
	if (DSA_set0_key(dsa, pub_key, priv_key) == 0)
		goto cleanup;
	pub_key = priv_key = 0;

	if ((newkey = EVP_PKEY_new()) == NULL)
		goto cleanup;

	(void) EVP_PKEY_set1_DSA(newkey, dsa);

cleanup:
	/* The original key must be freed once here or it leaks memory */
	if (dsa)
		DSA_free(dsa);
	BN_free(p);
	BN_free(q);
	BN_free(g);
	BN_free(priv_key);
	BN_free(pub_key);

	return (newkey);
}

static EVP_PKEY *
raw_key_to_pkey(KMF_KEY_HANDLE *key)
{
	EVP_PKEY *pkey = NULL;
	KMF_RAW_KEY_DATA *rawkey;
	ASN1_TYPE *attr = NULL;
	KMF_RETURN ret;

	if (key == NULL || !key->israw)
		return (NULL);

	rawkey = (KMF_RAW_KEY_DATA *)key->keyp;
	if (rawkey->keytype == KMF_RSA) {
		pkey = ImportRawRSAKey(&rawkey->rawdata.rsa);
	} else if (rawkey->keytype == KMF_DSA) {
		pkey = ImportRawDSAKey(&rawkey->rawdata.dsa);
	} else if (rawkey->keytype == KMF_ECDSA) {
		/*
		 * OpenSSL in Solaris does not support EC for
		 * legal reasons
		 */
		return (NULL);
	} else {
		/* wrong kind of key */
		return (NULL);
	}

	if (rawkey->label != NULL) {
		if ((attr = ASN1_TYPE_new()) == NULL) {
			EVP_PKEY_free(pkey);
			return (NULL);
		}
		attr->value.bmpstring = ASN1_STRING_type_new(V_ASN1_BMPSTRING);
		(void) ASN1_STRING_set(attr->value.bmpstring, rawkey->label,
		    strlen(rawkey->label));
		attr->type = V_ASN1_BMPSTRING;
		attr->value.ptr = (char *)attr->value.bmpstring;
		ret = set_pkey_attrib(pkey, attr, NID_friendlyName);
		if (ret != KMF_OK) {
			EVP_PKEY_free(pkey);
			ASN1_TYPE_free(attr);
			return (NULL);
		}
	}
	if (rawkey->id.Data != NULL) {
		if ((attr = ASN1_TYPE_new()) == NULL) {
			EVP_PKEY_free(pkey);
			return (NULL);
		}
		attr->value.octet_string =
		    ASN1_STRING_type_new(V_ASN1_OCTET_STRING);
		attr->type = V_ASN1_OCTET_STRING;
		(void) ASN1_STRING_set(attr->value.octet_string,
		    rawkey->id.Data, rawkey->id.Length);
		attr->value.ptr = (char *)attr->value.octet_string;
		ret = set_pkey_attrib(pkey, attr, NID_localKeyID);
		if (ret != KMF_OK) {
			EVP_PKEY_free(pkey);
			ASN1_TYPE_free(attr);
			return (NULL);
		}
	}
	return (pkey);
}

/*
 * Search a list of private keys to find one that goes with the certificate.
 */
static EVP_PKEY *
find_matching_key(X509 *xcert, int numkeys, KMF_KEY_HANDLE *keylist)
{
	int i;
	EVP_PKEY *pkey = NULL;

	if (numkeys == 0 || keylist == NULL || xcert == NULL)
		return (NULL);
	for (i = 0; i < numkeys; i++) {
		if (keylist[i].israw)
			pkey = raw_key_to_pkey(&keylist[i]);
		else
			pkey = (EVP_PKEY *)keylist[i].keyp;
		if (pkey != NULL) {
			if (X509_check_private_key(xcert, pkey)) {
				return (pkey);
			} else {
				EVP_PKEY_free(pkey);
				pkey = NULL;
			}
		}
	}
	return (pkey);
}

static KMF_RETURN
local_export_pk12(KMF_HANDLE_T handle,
	KMF_CREDENTIAL *cred,
	int numcerts, KMF_X509_DER_CERT *certlist,
	int numkeys, KMF_KEY_HANDLE *keylist,
	char *filename)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	BIO *bio = NULL;
	PKCS7 *cert_authsafe = NULL;
	PKCS7 *key_authsafe = NULL;
	STACK_OF(PKCS7) *authsafe_stack = NULL;
	PKCS12 *p12_elem = NULL;
	int i;

	if (numcerts == 0 && numkeys == 0)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * Open the output file.
	 */
	if ((bio = BIO_new_file(filename, "wb")) == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		rv = KMF_ERR_OPEN_FILE;
		goto cleanup;
	}

	/* Start a PKCS#7 stack. */
	authsafe_stack = sk_PKCS7_new_null();
	if (authsafe_stack == NULL) {
		rv = KMF_ERR_MEMORY;
		goto cleanup;
	}
	if (numcerts > 0) {
		for (i = 0; rv == KMF_OK && i < numcerts; i++) {
			const uchar_t *p = certlist[i].certificate.Data;
			long len = certlist[i].certificate.Length;
			X509 *xcert = NULL;
			EVP_PKEY *pkey = NULL;
			unsigned char keyid[EVP_MAX_MD_SIZE];
			unsigned int keyidlen = 0;

			xcert = d2i_X509(NULL, &p, len);
			if (xcert == NULL) {
				SET_ERROR(kmfh, ERR_get_error());
				rv = KMF_ERR_ENCODING;
			}
			if (certlist[i].kmf_private.label != NULL) {
				/* Set alias attribute */
				(void) X509_alias_set1(xcert,
				    (uchar_t *)certlist[i].kmf_private.label,
				    strlen(certlist[i].kmf_private.label));
			}
			/* Check if there is a key corresponding to this cert */
			pkey = find_matching_key(xcert, numkeys, keylist);

			/*
			 * If key is found, get fingerprint and create a
			 * safebag.
			 */
			if (pkey != NULL) {
				(void) X509_digest(xcert, EVP_sha1(),
				    keyid, &keyidlen);
				key_authsafe = add_key_to_safe(pkey, cred,
				    keyid, keyidlen,
				    certlist[i].kmf_private.label,
				    (certlist[i].kmf_private.label ?
				    strlen(certlist[i].kmf_private.label) : 0));

				if (key_authsafe == NULL) {
					X509_free(xcert);
					EVP_PKEY_free(pkey);
					goto cleanup;
				}
				/* Put the key safe into the Auth Safe */
				if (!sk_PKCS7_push(authsafe_stack,
				    key_authsafe)) {
					X509_free(xcert);
					EVP_PKEY_free(pkey);
					goto cleanup;
				}
			}

			/* create a certificate safebag */
			cert_authsafe = add_cert_to_safe(xcert, cred, keyid,
			    keyidlen);
			if (cert_authsafe == NULL) {
				X509_free(xcert);
				EVP_PKEY_free(pkey);
				goto cleanup;
			}
			if (!sk_PKCS7_push(authsafe_stack, cert_authsafe)) {
				X509_free(xcert);
				EVP_PKEY_free(pkey);
				goto cleanup;
			}

			X509_free(xcert);
			if (pkey)
				EVP_PKEY_free(pkey);
		}
	} else if (numcerts == 0 && numkeys > 0) {
		/*
		 * If only adding keys to the file.
		 */
		for (i = 0; i < numkeys; i++) {
			EVP_PKEY *pkey = NULL;

			if (keylist[i].israw)
				pkey = raw_key_to_pkey(&keylist[i]);
			else
				pkey = (EVP_PKEY *)keylist[i].keyp;

			if (pkey == NULL)
				continue;

			key_authsafe = add_key_to_safe(pkey, cred,
			    NULL, 0, NULL, 0);

			if (key_authsafe == NULL) {
				EVP_PKEY_free(pkey);
				goto cleanup;
			}
			if (!sk_PKCS7_push(authsafe_stack, key_authsafe)) {
				EVP_PKEY_free(pkey);
				goto cleanup;
			}
		}
	}
	p12_elem = PKCS12_init(NID_pkcs7_data);
	if (p12_elem == NULL) {
		goto cleanup;
	}

	/* Put the PKCS#7 stack into the PKCS#12 element. */
	if (!PKCS12_pack_authsafes(p12_elem, authsafe_stack)) {
		goto cleanup;
	}

	/* Set the integrity MAC on the PKCS#12 element. */
	if (!PKCS12_set_mac(p12_elem, cred->cred, cred->credlen,
	    NULL, 0, PKCS12_DEFAULT_ITER, NULL)) {
		goto cleanup;
	}

	/* Write the PKCS#12 element to the export file. */
	if (!i2d_PKCS12_bio(bio, p12_elem)) {
		goto cleanup;
	}
	PKCS12_free(p12_elem);

cleanup:
	/* Clear away the PKCS#7 stack, we're done with it. */
	if (authsafe_stack)
		sk_PKCS7_pop_free(authsafe_stack, PKCS7_free);

	if (bio != NULL)
		(void) BIO_free_all(bio);

	return (rv);
}

KMF_RETURN
openssl_build_pk12(KMF_HANDLE_T handle, int numcerts,
    KMF_X509_DER_CERT *certlist, int numkeys, KMF_KEY_HANDLE *keylist,
    KMF_CREDENTIAL *p12cred, char *filename)
{
	KMF_RETURN rv;

	if (certlist == NULL && keylist == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = local_export_pk12(handle, p12cred, numcerts, certlist,
	    numkeys, keylist, filename);

	return (rv);
}

KMF_RETURN
OpenSSL_ExportPK12(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv;
	KMF_HANDLE *kmfh = (KMF_HANDLE  *)handle;
	char *fullpath = NULL;
	char *dirpath = NULL;
	char *certfile = NULL;
	char *keyfile = NULL;
	char *filename = NULL;
	KMF_CREDENTIAL *p12cred = NULL;
	KMF_X509_DER_CERT certdata;
	KMF_KEY_HANDLE key;
	int gotkey = 0;
	int gotcert = 0;

	if (handle == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 *  First, find the certificate.
	 */
	dirpath = kmf_get_attr_ptr(KMF_DIRPATH_ATTR, attrlist, numattr);
	certfile = kmf_get_attr_ptr(KMF_CERT_FILENAME_ATTR, attrlist, numattr);
	if (certfile != NULL) {
		fullpath = get_fullpath(dirpath, certfile);
		if (fullpath == NULL)
			return (KMF_ERR_BAD_PARAMETER);

		if (isdir(fullpath)) {
			free(fullpath);
			return (KMF_ERR_AMBIGUOUS_PATHNAME);
		}

		(void) memset(&certdata, 0, sizeof (certdata));
		rv = kmf_load_cert(kmfh, NULL, NULL, NULL, NULL,
		    fullpath, &certdata.certificate);
		if (rv != KMF_OK)
			goto end;

		gotcert++;
		certdata.kmf_private.keystore_type = KMF_KEYSTORE_OPENSSL;
		free(fullpath);
	}

	/*
	 * Now find the private key.
	 */
	keyfile = kmf_get_attr_ptr(KMF_KEY_FILENAME_ATTR, attrlist, numattr);
	if (keyfile != NULL) {
		fullpath = get_fullpath(dirpath, keyfile);
		if (fullpath == NULL)
			return (KMF_ERR_BAD_PARAMETER);

		if (isdir(fullpath)) {
			free(fullpath);
			return (KMF_ERR_AMBIGUOUS_PATHNAME);
		}

		(void) memset(&key, 0, sizeof (KMF_KEY_HANDLE));
		rv = fetch_key(handle, fullpath, KMF_ASYM_PRI, &key);
		if (rv != KMF_OK)
			goto end;
		gotkey++;
	}

	/*
	 * Open the output file.
	 */
	filename = kmf_get_attr_ptr(KMF_OUTPUT_FILENAME_ATTR, attrlist,
	    numattr);
	if (filename == NULL) {
		rv = KMF_ERR_BAD_PARAMETER;
		goto end;
	}

	/* Stick the key and the cert into a PKCS#12 file */
	p12cred = kmf_get_attr_ptr(KMF_PK12CRED_ATTR, attrlist, numattr);
	if (p12cred == NULL) {
		rv = KMF_ERR_BAD_PARAMETER;
		goto end;
	}

	rv = local_export_pk12(handle, p12cred, 1, &certdata,
	    1, &key, filename);

end:
	if (fullpath)
		free(fullpath);

	if (gotcert)
		kmf_free_kmf_cert(handle, &certdata);
	if (gotkey)
		kmf_free_kmf_key(handle, &key);
	return (rv);
}

/*
 * Helper function to extract keys and certificates from
 * a single PEM file.  Typically the file should contain a
 * private key and an associated public key wrapped in an x509 cert.
 * However, the file may be just a list of X509 certs with no keys.
 */
static KMF_RETURN
extract_pem(KMF_HANDLE *kmfh,
	char *issuer, char *subject, KMF_BIGINT *serial,
	char *filename, CK_UTF8CHAR *pin,
	CK_ULONG pinlen, EVP_PKEY **priv_key, KMF_DATA **certs,
	int *numcerts)
/* ARGSUSED6 */
{
	KMF_RETURN rv = KMF_OK;
	FILE *fp;
	STACK_OF(X509_INFO) *x509_info_stack = NULL;
	int i, ncerts = 0, matchcerts = 0;
	EVP_PKEY *pkey = NULL;
	X509_INFO *info;
	X509 *x;
	X509_INFO **cert_infos = NULL;
	KMF_DATA *certlist = NULL;

	if (priv_key)
		*priv_key = NULL;
	if (certs)
		*certs = NULL;
	fp = fopen(filename, "r");
	if (fp == NULL)
		return (KMF_ERR_OPEN_FILE);

	x509_info_stack = PEM_X509_INFO_read(fp, NULL, NULL, pin);
	if (x509_info_stack == NULL) {
		(void) fclose(fp);
		return (KMF_ERR_ENCODING);
	}
	cert_infos = (X509_INFO **)malloc(sk_X509_INFO_num(x509_info_stack) *
	    sizeof (X509_INFO *));
	if (cert_infos == NULL) {
		(void) fclose(fp);
		rv = KMF_ERR_MEMORY;
		goto err;
	}

	for (i = 0; i < sk_X509_INFO_num(x509_info_stack); i++) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		cert_infos[ncerts] = sk_X509_INFO_value(x509_info_stack, i);
		ncerts++;
	}

	if (ncerts == 0) {
		(void) fclose(fp);
		rv = KMF_ERR_CERT_NOT_FOUND;
		goto err;
	}

	if (priv_key != NULL) {
		rewind(fp);
		pkey = PEM_read_PrivateKey(fp, NULL, NULL, pin);
	}
	(void) fclose(fp);

	x = cert_infos[ncerts - 1]->x509;
	/*
	 * Make sure the private key matchs the last cert in the file.
	 */
	if (pkey != NULL && !X509_check_private_key(x, pkey)) {
		EVP_PKEY_free(pkey);
		rv = KMF_ERR_KEY_MISMATCH;
		goto err;
	}

	certlist = (KMF_DATA *)calloc(ncerts, sizeof (KMF_DATA));
	if (certlist == NULL) {
		if (pkey != NULL)
			EVP_PKEY_free(pkey);
		rv = KMF_ERR_MEMORY;
		goto err;
	}

	/*
	 * Convert all of the certs to DER format.
	 */
	matchcerts = 0;
	for (i = 0; rv == KMF_OK && certs != NULL && i < ncerts; i++) {
		boolean_t match = FALSE;
		info =  cert_infos[ncerts - 1 - i];

		rv = check_cert(info->x509, issuer, subject, serial, &match);
		if (rv != KMF_OK || match != TRUE) {
			rv = KMF_OK;
			continue;
		}

		rv = ssl_cert2KMFDATA(kmfh, info->x509,
			&certlist[matchcerts++]);

		if (rv != KMF_OK) {
			int j;
			for (j = 0; j < matchcerts; j++)
				kmf_free_data(&certlist[j]);
			free(certlist);
			certlist = NULL;
			ncerts = matchcerts = 0;
		}
	}

	if (numcerts != NULL)
		*numcerts = matchcerts;

	if (certs != NULL)
		*certs = certlist;
	else if (certlist != NULL) {
		for (i = 0; i < ncerts; i++)
			kmf_free_data(&certlist[i]);
		free(certlist);
		certlist = NULL;
	}

	if (priv_key == NULL && pkey != NULL)
		EVP_PKEY_free(pkey);
	else if (priv_key != NULL && pkey != NULL)
		*priv_key = pkey;

err:
	/* Cleanup the stack of X509 info records */
	for (i = 0; i < sk_X509_INFO_num(x509_info_stack); i++) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		info = (X509_INFO *)sk_X509_INFO_value(x509_info_stack, i);
		X509_INFO_free(info);
	}
	if (x509_info_stack)
		sk_X509_INFO_free(x509_info_stack);

	if (cert_infos != NULL)
		free(cert_infos);

	return (rv);
}

static KMF_RETURN
openssl_parse_bags(const STACK_OF(PKCS12_SAFEBAG) *bags, char *pin,
	STACK_OF(EVP_PKEY) *keys, STACK_OF(X509) *certs)
{
	KMF_RETURN ret;
	int i;

	for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		PKCS12_SAFEBAG *bag = sk_PKCS12_SAFEBAG_value(bags, i);
		ret = openssl_parse_bag(bag, pin, (pin ? strlen(pin) : 0),
		    keys, certs);

		if (ret != KMF_OK)
			return (ret);
	}

	return (ret);
}

static KMF_RETURN
set_pkey_attrib(EVP_PKEY *pkey, ASN1_TYPE *attrib, int nid)
{
	X509_ATTRIBUTE *attr = NULL;

	if (pkey == NULL || attrib == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	attr = X509_ATTRIBUTE_create(nid, attrib->type, attrib->value.ptr);
	if (attr != NULL) {
		int i;

		if ((i = EVP_PKEY_get_attr_by_NID(pkey, nid, -1)) != -1)
			(void) EVP_PKEY_delete_attr(pkey, i);
		if (EVP_PKEY_add1_attr(pkey, attr) == 0) {
			X509_ATTRIBUTE_free(attr);
			return (KMF_ERR_MEMORY);
		}
	} else {
		return (KMF_ERR_MEMORY);
	}

	return (KMF_OK);
}

static KMF_RETURN
openssl_parse_bag(PKCS12_SAFEBAG *bag, char *pass, int passlen,
	STACK_OF(EVP_PKEY) *keylist, STACK_OF(X509) *certlist)
{
	KMF_RETURN ret = KMF_OK;
	PKCS8_PRIV_KEY_INFO *p8 = NULL;
	EVP_PKEY *pkey = NULL;
	X509 *xcert = NULL;
	const ASN1_TYPE *keyid = NULL;
	const ASN1_TYPE *fname = NULL;
	uchar_t *data = NULL;

	keyid = PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID);
	fname = PKCS12_SAFEBAG_get0_attr(bag, NID_friendlyName);

	switch (PKCS12_SAFEBAG_get_nid(bag)) {
		case NID_keyBag:
			if (keylist == NULL)
				goto end;
			pkey = EVP_PKCS82PKEY(
			    PKCS12_SAFEBAG_get0_p8inf(bag));
			if (pkey == NULL)
				ret = KMF_ERR_PKCS12_FORMAT;

			break;
		case NID_pkcs8ShroudedKeyBag:
			if (keylist == NULL)
				goto end;
			p8 = PKCS12_decrypt_skey(bag, pass, passlen);
			if (p8 == NULL)
				return (KMF_ERR_AUTH_FAILED);
			pkey = EVP_PKCS82PKEY(p8);
			PKCS8_PRIV_KEY_INFO_free(p8);
			if (pkey == NULL)
				ret = KMF_ERR_PKCS12_FORMAT;
			break;
		case NID_certBag:
			if (certlist == NULL)
				goto end;
			if (PKCS12_SAFEBAG_get_bag_nid(bag) !=
			    NID_x509Certificate)
				return (KMF_ERR_PKCS12_FORMAT);
			xcert = PKCS12_SAFEBAG_get1_cert(bag);
			if (xcert == NULL) {
				ret = KMF_ERR_PKCS12_FORMAT;
				goto end;
			}
			if (keyid != NULL) {
				if (X509_keyid_set1(xcert,
				    keyid->value.octet_string->data,
				    keyid->value.octet_string->length) == 0) {
					ret = KMF_ERR_PKCS12_FORMAT;
					goto end;
				}
			}
			if (fname != NULL) {
				int len, r;
				len = ASN1_STRING_to_UTF8(&data,
				    fname->value.asn1_string);
				if (len > 0 && data != NULL) {
					r = X509_alias_set1(xcert, data, len);
					if (r == NULL) {
						ret = KMF_ERR_PKCS12_FORMAT;
						goto end;
					}
				} else {
					ret = KMF_ERR_PKCS12_FORMAT;
					goto end;
				}
			}
			if (sk_X509_push(certlist, xcert) == 0)
				ret = KMF_ERR_MEMORY;
			else
				xcert = NULL;
			break;
		case NID_safeContentsBag:
			return (openssl_parse_bags(
			    PKCS12_SAFEBAG_get0_safes(bag),
			    pass, keylist, certlist));
		default:
			ret = KMF_ERR_PKCS12_FORMAT;
			break;
	}

	/*
	 * Set the ID and/or FriendlyName attributes on the key.
	 * If converting to PKCS11 objects, these can translate to CKA_ID
	 * and CKA_LABEL values.
	 */
	if (pkey != NULL && ret == KMF_OK) {
		ASN1_TYPE *attr = NULL;
		if (keyid != NULL && keyid->type == V_ASN1_OCTET_STRING) {
			if ((attr = ASN1_TYPE_new()) == NULL)
				return (KMF_ERR_MEMORY);
			attr->value.octet_string =
			    ASN1_STRING_dup(keyid->value.octet_string);
			attr->type = V_ASN1_OCTET_STRING;
			attr->value.ptr = (char *)attr->value.octet_string;
			ret = set_pkey_attrib(pkey, attr, NID_localKeyID);
			OPENSSL_free(attr);
		}

		if (ret == KMF_OK && fname != NULL &&
		    fname->type == V_ASN1_BMPSTRING) {
			if ((attr = ASN1_TYPE_new()) == NULL)
				return (KMF_ERR_MEMORY);
			attr->value.bmpstring =
			    ASN1_STRING_dup(fname->value.bmpstring);
			attr->type = V_ASN1_BMPSTRING;
			attr->value.ptr = (char *)attr->value.bmpstring;
			ret = set_pkey_attrib(pkey, attr, NID_friendlyName);
			OPENSSL_free(attr);
		}

		if (ret == KMF_OK && keylist != NULL &&
		    sk_EVP_PKEY_push(keylist, pkey) == 0)
			ret = KMF_ERR_MEMORY;
	}
	if (ret == KMF_OK && keylist != NULL)
		pkey = NULL;
end:
	if (pkey != NULL)
		EVP_PKEY_free(pkey);
	if (xcert != NULL)
		X509_free(xcert);
	if (data != NULL)
		OPENSSL_free(data);

	return (ret);
}

static KMF_RETURN
openssl_pkcs12_parse(PKCS12 *p12, char *pin,
	STACK_OF(EVP_PKEY) *keys,
	STACK_OF(X509) *certs,
	STACK_OF(X509) *ca)
/* ARGSUSED3 */
{
	KMF_RETURN ret = KMF_OK;
	STACK_OF(PKCS7) *asafes = NULL;
	STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
	int i, bagnid;
	PKCS7 *p7;

	if (p12 == NULL || (keys == NULL && certs == NULL))
		return (KMF_ERR_BAD_PARAMETER);

	if (pin == NULL || *pin == NULL) {
		if (PKCS12_verify_mac(p12, NULL, 0)) {
			pin = NULL;
		} else if (PKCS12_verify_mac(p12, "", 0)) {
			pin = "";
		} else {
			return (KMF_ERR_AUTH_FAILED);
		}
	} else if (!PKCS12_verify_mac(p12, pin, -1)) {
		return (KMF_ERR_AUTH_FAILED);
	}

	if ((asafes = PKCS12_unpack_authsafes(p12)) == NULL)
		return (KMF_ERR_PKCS12_FORMAT);

	for (i = 0; ret == KMF_OK && i < sk_PKCS7_num(asafes); i++) {
		bags = NULL;
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		p7 = sk_PKCS7_value(asafes, i);
		bagnid = OBJ_obj2nid(p7->type);

		if (bagnid == NID_pkcs7_data) {
			bags = PKCS12_unpack_p7data(p7);
		} else if (bagnid == NID_pkcs7_encrypted) {
			bags = PKCS12_unpack_p7encdata(p7, pin,
			    (pin ? strlen(pin) : 0));
		} else {
			continue;
		}
		if (bags == NULL) {
			ret = KMF_ERR_PKCS12_FORMAT;
			goto out;
		}

		if (openssl_parse_bags(bags, pin, keys, certs) != KMF_OK)
			ret = KMF_ERR_PKCS12_FORMAT;

		sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
	}
out:
	if (asafes != NULL)
		sk_PKCS7_pop_free(asafes, PKCS7_free);

	return (ret);
}

/*
 * Helper function to decrypt and parse PKCS#12 import file.
 */
static KMF_RETURN
extract_pkcs12(BIO *fbio, CK_UTF8CHAR *pin, CK_ULONG pinlen,
	STACK_OF(EVP_PKEY) **priv_key, STACK_OF(X509) **certs,
	STACK_OF(X509) **ca)
/* ARGSUSED2 */
{
	PKCS12			*pk12, *pk12_tmp;
	STACK_OF(EVP_PKEY)	*pkeylist = NULL;
	STACK_OF(X509)		*xcertlist = NULL;
	STACK_OF(X509)		*cacertlist = NULL;

	if ((pk12 = PKCS12_new()) == NULL) {
		return (KMF_ERR_MEMORY);
	}

	if ((pk12_tmp = d2i_PKCS12_bio(fbio, &pk12)) == NULL) {
		/* This is ok; it seems to mean there is no more to read. */
		if (ERR_GET_LIB(ERR_peek_error()) == ERR_LIB_ASN1 &&
		    ERR_GET_REASON(ERR_peek_error()) == ASN1_R_HEADER_TOO_LONG)
			goto end_extract_pkcs12;

		PKCS12_free(pk12);
		return (KMF_ERR_PKCS12_FORMAT);
	}
	pk12 = pk12_tmp;

	xcertlist = sk_X509_new_null();
	if (xcertlist == NULL) {
		PKCS12_free(pk12);
		return (KMF_ERR_MEMORY);
	}
	pkeylist = sk_EVP_PKEY_new_null();
	if (pkeylist == NULL) {
		sk_X509_pop_free(xcertlist, X509_free);
		PKCS12_free(pk12);
		return (KMF_ERR_MEMORY);
	}

	if (openssl_pkcs12_parse(pk12, (char *)pin, pkeylist, xcertlist,
	    cacertlist) != KMF_OK) {
		sk_X509_pop_free(xcertlist, X509_free);
		sk_EVP_PKEY_pop_free(pkeylist, EVP_PKEY_free);
		PKCS12_free(pk12);
		return (KMF_ERR_PKCS12_FORMAT);
	}

	if (priv_key && pkeylist)
		*priv_key = pkeylist;
	else if (pkeylist)
		sk_EVP_PKEY_pop_free(pkeylist, EVP_PKEY_free);
	if (certs && xcertlist)
		*certs = xcertlist;
	else if (xcertlist)
		sk_X509_pop_free(xcertlist, X509_free);
	if (ca && cacertlist)
		*ca = cacertlist;
	else if (cacertlist)
		sk_X509_pop_free(cacertlist, X509_free);

end_extract_pkcs12:

	PKCS12_free(pk12);
	return (KMF_OK);
}

static KMF_RETURN
sslBN2KMFBN(BIGNUM *from, KMF_BIGINT *to)
{
	KMF_RETURN rv = KMF_OK;
	uint32_t sz;

	sz = BN_num_bytes(from);
	to->val = (uchar_t *)malloc(sz);
	if (to->val == NULL)
		return (KMF_ERR_MEMORY);

	if ((to->len = BN_bn2bin(from, to->val)) != sz) {
		free(to->val);
		to->val = NULL;
		to->len = 0;
		rv = KMF_ERR_MEMORY;
	}

	return (rv);
}

static KMF_RETURN
exportRawRSAKey(RSA *rsa, KMF_RAW_KEY_DATA *key)
{
	KMF_RETURN rv;
	KMF_RAW_RSA_KEY *kmfkey = &key->rawdata.rsa;

	const BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmpq, *iqmp;

	RSA_get0_key(rsa, &n, &e, &d);
	RSA_get0_factors(rsa, &p, &q);
	RSA_get0_crt_params(rsa, &dmp1, &dmpq, &iqmp);

	(void) memset(kmfkey, 0, sizeof (KMF_RAW_RSA_KEY));
	if ((rv = sslBN2KMFBN((BIGNUM *)n, &kmfkey->mod)) != KMF_OK)
		goto cleanup;

	if ((rv = sslBN2KMFBN((BIGNUM *)e, &kmfkey->pubexp)) != KMF_OK)
		goto cleanup;

	if (d != NULL)
		if ((rv = sslBN2KMFBN((BIGNUM *)d, &kmfkey->priexp)) != KMF_OK)
			goto cleanup;

	if (p != NULL)
		if ((rv = sslBN2KMFBN((BIGNUM *)p, &kmfkey->prime1)) != KMF_OK)
			goto cleanup;

	if (q != NULL)
		if ((rv = sslBN2KMFBN((BIGNUM *)q, &kmfkey->prime2)) != KMF_OK)
			goto cleanup;

	if (dmp1 != NULL)
		if ((rv = sslBN2KMFBN((BIGNUM *)dmp1, &kmfkey->exp1)) != KMF_OK)
			goto cleanup;

	if (dmpq != NULL)
		if ((rv = sslBN2KMFBN((BIGNUM *)dmpq, &kmfkey->exp2)) != KMF_OK)
			goto cleanup;

	if (iqmp != NULL)
		if ((rv = sslBN2KMFBN((BIGNUM *)iqmp, &kmfkey->coef)) != KMF_OK)
			goto cleanup;
cleanup:
	if (rv != KMF_OK)
		kmf_free_raw_key(key);
	else
		key->keytype = KMF_RSA;

	/*
	 * Free the reference to this key, SSL will not actually free
	 * the memory until the refcount == 0, so this is safe.
	 */
	RSA_free(rsa);

	return (rv);
}

static KMF_RETURN
exportRawDSAKey(DSA *dsa, KMF_RAW_KEY_DATA *key)
{
	KMF_RETURN rv;
	KMF_RAW_DSA_KEY *kmfkey = &key->rawdata.dsa;
	const BIGNUM *p, *q, *g, *priv_key;

	DSA_get0_pqg(dsa, &p, &q, &g);
	DSA_get0_key(dsa, NULL, &priv_key);

	(void) memset(kmfkey, 0, sizeof (KMF_RAW_DSA_KEY));
	if ((rv = sslBN2KMFBN((BIGNUM *)p, &kmfkey->prime)) != KMF_OK)
		goto cleanup;

	if ((rv = sslBN2KMFBN((BIGNUM *)q, &kmfkey->subprime)) != KMF_OK)
		goto cleanup;

	if ((rv = sslBN2KMFBN((BIGNUM *)g, &kmfkey->base)) != KMF_OK)
		goto cleanup;

	if ((rv = sslBN2KMFBN((BIGNUM *)priv_key, &kmfkey->value)) != KMF_OK)
		goto cleanup;

cleanup:
	if (rv != KMF_OK)
		kmf_free_raw_key(key);
	else
		key->keytype = KMF_DSA;

	/*
	 * Free the reference to this key, SSL will not actually free
	 * the memory until the refcount == 0, so this is safe.
	 */
	DSA_free(dsa);

	return (rv);
}

static KMF_RETURN
add_cert_to_list(KMF_HANDLE *kmfh, X509 *sslcert,
	KMF_X509_DER_CERT **certlist, int *ncerts)
{
	KMF_RETURN rv = KMF_OK;
	KMF_X509_DER_CERT *list = (*certlist);
	KMF_X509_DER_CERT cert;
	int n = (*ncerts);

	if (list == NULL) {
		list = (KMF_X509_DER_CERT *)malloc(sizeof (KMF_X509_DER_CERT));
	} else {
		list = (KMF_X509_DER_CERT *)realloc(list,
		    sizeof (KMF_X509_DER_CERT) * (n + 1));
	}

	if (list == NULL)
		return (KMF_ERR_MEMORY);

	(void) memset(&cert, 0, sizeof (cert));
	rv = ssl_cert2KMFDATA(kmfh, sslcert, &cert.certificate);
	if (rv == KMF_OK) {
		int len = 0;
		/* Get the alias name for the cert if there is one */
		char *a = (char *)X509_alias_get0(sslcert, &len);
		if (a != NULL)
			cert.kmf_private.label = strdup(a);
		cert.kmf_private.keystore_type = KMF_KEYSTORE_OPENSSL;

		list[n] = cert;
		(*ncerts) = n + 1;

		*certlist = list;
	} else {
		free(list);
	}

	return (rv);
}

static KMF_RETURN
add_key_to_list(KMF_RAW_KEY_DATA **keylist,
	KMF_RAW_KEY_DATA *newkey, int *nkeys)
{
	KMF_RAW_KEY_DATA *list = (*keylist);
	int n = (*nkeys);

	if (list == NULL) {
		list = (KMF_RAW_KEY_DATA *)malloc(sizeof (KMF_RAW_KEY_DATA));
	} else {
		list = (KMF_RAW_KEY_DATA *)realloc(list,
		    sizeof (KMF_RAW_KEY_DATA) * (n + 1));
	}

	if (list == NULL)
		return (KMF_ERR_MEMORY);

	list[n] = *newkey;
	(*nkeys) = n + 1;

	*keylist = list;

	return (KMF_OK);
}

static KMF_RETURN
convertToRawKey(EVP_PKEY *pkey, KMF_RAW_KEY_DATA *key)
{
	KMF_RETURN rv = KMF_OK;
	X509_ATTRIBUTE *attr;
	RSA *rsa;
	DSA *dsa;
	int loc;

	if (pkey == NULL || key == NULL)
		return (KMF_ERR_BAD_PARAMETER);
	/* Convert SSL key to raw key */
	if ((rsa = EVP_PKEY_get1_RSA(pkey)) != NULL) {
		rv = exportRawRSAKey(rsa, key);
		if (rv != KMF_OK)
			return (rv);
	} else if ((dsa = EVP_PKEY_get1_DSA(pkey)) != NULL) {
		rv = exportRawDSAKey(dsa, key);
		if (rv != KMF_OK)
			return (rv);
	} else
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * If friendlyName, add it to record.
	 */

	if ((loc = EVP_PKEY_get_attr_by_NID(pkey,
	    NID_friendlyName, -1)) != -1 &&
	    (attr = EVP_PKEY_get_attr(pkey, loc))) {
		ASN1_TYPE *ty = NULL;
		int numattr = X509_ATTRIBUTE_count(attr);
		if (numattr > 0) {
			ty = X509_ATTRIBUTE_get0_type(attr, 0);
		}
		if (ty != NULL) {
			key->label = OPENSSL_uni2asc(ty->value.bmpstring->data,
			    ty->value.bmpstring->length);
		}
	} else {
		key->label = NULL;
	}

	/*
	 * If KeyID, add it to record as a KMF_DATA object.
	 */
	if ((loc = EVP_PKEY_get_attr_by_NID(pkey,
	    NID_localKeyID, -1)) != -1 &&
	    (attr = EVP_PKEY_get_attr(pkey, loc)) != NULL) {
		ASN1_TYPE *ty = NULL;
		int numattr = X509_ATTRIBUTE_count(attr);
		if (numattr > 0)
			ty = X509_ATTRIBUTE_get0_type(attr, 0);
		key->id.Data = (uchar_t *)malloc(
		    ty->value.octet_string->length);
		if (key->id.Data == NULL)
			return (KMF_ERR_MEMORY);
		(void) memcpy(key->id.Data, ty->value.octet_string->data,
		    ty->value.octet_string->length);
		key->id.Length = ty->value.octet_string->length;
	} else {
		(void) memset(&key->id, 0, sizeof (KMF_DATA));
	}

	return (rv);
}

static KMF_RETURN
convertPK12Objects(
	KMF_HANDLE *kmfh,
	STACK_OF(EVP_PKEY) *sslkeys,
	STACK_OF(X509) *sslcert,
	STACK_OF(X509) *sslcacerts,
	KMF_RAW_KEY_DATA **keylist, int *nkeys,
	KMF_X509_DER_CERT **certlist, int *ncerts)
{
	KMF_RETURN rv = KMF_OK;
	KMF_RAW_KEY_DATA key;
	int i;

	for (i = 0; sslkeys != NULL && i < sk_EVP_PKEY_num(sslkeys); i++) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		EVP_PKEY *pkey = sk_EVP_PKEY_value(sslkeys, i);
		rv = convertToRawKey(pkey, &key);
		if (rv == KMF_OK)
			rv = add_key_to_list(keylist, &key, nkeys);

		if (rv != KMF_OK)
			return (rv);
	}

	/* Now add the certificate to the certlist */
	for (i = 0; sslcert != NULL && i < sk_X509_num(sslcert); i++) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		X509 *cert = sk_X509_value(sslcert, i);
		rv = add_cert_to_list(kmfh, cert, certlist, ncerts);
		if (rv != KMF_OK)
			return (rv);
	}

	/* Also add any included CA certs to the list */
	for (i = 0; sslcacerts != NULL && i < sk_X509_num(sslcacerts); i++) {
		X509 *c;
		/*
		 * sk_X509_value() is macro that embeds a cast to (X509 *).
		 * Here it translates into ((X509 *)sk_value((ca), (i))).
		 * Lint is complaining about the embedded casting, and
		 * to fix it, you need to fix openssl header files.
		 */
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		c = sk_X509_value(sslcacerts, i);

		/* Now add the ca cert to the certlist */
		rv = add_cert_to_list(kmfh, c, certlist, ncerts);
		if (rv != KMF_OK)
			return (rv);
	}
	return (rv);
}

KMF_RETURN
openssl_import_objects(KMF_HANDLE *kmfh,
	char *filename, KMF_CREDENTIAL *cred,
	KMF_X509_DER_CERT **certlist, int *ncerts,
	KMF_RAW_KEY_DATA **keylist, int *nkeys)
{
	KMF_RETURN	rv = KMF_OK;
	KMF_ENCODE_FORMAT format;
	BIO		*bio = NULL;
	STACK_OF(EVP_PKEY)	*privkeys = NULL;
	STACK_OF(X509)		*certs = NULL;
	STACK_OF(X509)		*cacerts = NULL;

	/*
	 * auto-detect the file format, regardless of what
	 * the 'format' parameters in the params say.
	 */
	rv = kmf_get_file_format(filename, &format);
	if (rv != KMF_OK) {
		return (rv);
	}

	/* This function only works for PEM or PKCS#12 files */
	if (format != KMF_FORMAT_PEM &&
	    format != KMF_FORMAT_PEM_KEYPAIR &&
	    format != KMF_FORMAT_PKCS12)
		return (KMF_ERR_ENCODING);

	*certlist = NULL;
	*keylist = NULL;
	*ncerts = 0;
	*nkeys = 0;

	if (format == KMF_FORMAT_PKCS12) {
		bio = BIO_new_file(filename, "rb");
		if (bio == NULL) {
			SET_ERROR(kmfh, ERR_get_error());
			rv = KMF_ERR_OPEN_FILE;
			goto end;
		}

		rv = extract_pkcs12(bio, (uchar_t *)cred->cred,
		    (uint32_t)cred->credlen, &privkeys, &certs, &cacerts);

		if (rv  == KMF_OK)
			/* Convert keys and certs to exportable format */
			rv = convertPK12Objects(kmfh, privkeys, certs, cacerts,
			    keylist, nkeys, certlist, ncerts);
	} else {
		EVP_PKEY *pkey;
		KMF_DATA *certdata = NULL;
		KMF_X509_DER_CERT *kmfcerts = NULL;
		int i;
		rv = extract_pem(kmfh, NULL, NULL, NULL, filename,
		    (uchar_t *)cred->cred, (uint32_t)cred->credlen,
		    &pkey, &certdata, ncerts);

		/* Reached end of import file? */
		if (rv == KMF_OK && pkey != NULL) {
			privkeys = sk_EVP_PKEY_new_null();
			if (privkeys == NULL) {
				rv = KMF_ERR_MEMORY;
				goto end;
			}
			(void) sk_EVP_PKEY_push(privkeys, pkey);
			/* convert the certificate list here */
			if (*ncerts > 0 && certlist != NULL) {
				kmfcerts = (KMF_X509_DER_CERT *)calloc(*ncerts,
				    sizeof (KMF_X509_DER_CERT));
				if (kmfcerts == NULL) {
					rv = KMF_ERR_MEMORY;
					goto end;
				}
				for (i = 0; i < *ncerts; i++) {
					kmfcerts[i].certificate = certdata[i];
					kmfcerts[i].kmf_private.keystore_type =
					    KMF_KEYSTORE_OPENSSL;
				}
				*certlist = kmfcerts;
			}
			/*
			 * Convert keys to exportable format, the certs
			 * are already OK.
			 */
			rv = convertPK12Objects(kmfh, privkeys, NULL, NULL,
			    keylist, nkeys, NULL, NULL);
		}
	}
end:
	if (bio != NULL)
		(void) BIO_free(bio);

	if (privkeys)
		sk_EVP_PKEY_pop_free(privkeys, EVP_PKEY_free);
	if (certs)
		sk_X509_pop_free(certs, X509_free);
	if (cacerts)
		sk_X509_pop_free(cacerts, X509_free);

	return (rv);
}

static KMF_RETURN
create_deskey(DES_cblock **deskey)
{
	DES_cblock *key;

	key = (DES_cblock *) malloc(sizeof (DES_cblock));
	if (key == NULL) {
		return (KMF_ERR_MEMORY);
	}

	if (DES_random_key(key) == 0) {
		free(key);
		return (KMF_ERR_KEYGEN_FAILED);
	}

	*deskey = key;
	return (KMF_OK);
}

#define	KEYGEN_RETRY 3
#define	DES3_KEY_SIZE 24

static KMF_RETURN
create_des3key(unsigned char **des3key)
{
	KMF_RETURN ret = KMF_OK;
	DES_cblock *deskey1 = NULL;
	DES_cblock *deskey2 = NULL;
	DES_cblock *deskey3 = NULL;
	unsigned char *newkey = NULL;
	int retry;

	if ((newkey = malloc(DES3_KEY_SIZE)) == NULL) {
		return (KMF_ERR_MEMORY);
	}

	/* create the 1st DES key */
	if ((ret = create_deskey(&deskey1)) != KMF_OK) {
		goto out;
	}

	/*
	 * Create the 2nd DES key and make sure its value is different
	 * from the 1st DES key.
	 */
	retry = 0;
	do {
		if (deskey2 != NULL) {
			free(deskey2);
			deskey2 = NULL;
		}

		if ((ret = create_deskey(&deskey2)) != KMF_OK) {
			goto out;
		}

		if (memcmp((const void *) deskey1, (const void *) deskey2, 8)
		    == 0) {
			ret = KMF_ERR_KEYGEN_FAILED;
			retry++;
		}
	} while (ret == KMF_ERR_KEYGEN_FAILED && retry < KEYGEN_RETRY);

	if (ret != KMF_OK) {
		goto out;
	}

	/*
	 * Create the 3rd DES key and make sure its value is different
	 * from the 2nd DES key.
	 */
	retry = 0;
	do {
		if (deskey3 != NULL) {
			free(deskey3);
			deskey3 = NULL;
		}

		if ((ret = create_deskey(&deskey3)) != KMF_OK) {
			goto out;
		}

		if (memcmp((const void *)deskey2, (const void *)deskey3, 8)
		    == 0) {
			ret = KMF_ERR_KEYGEN_FAILED;
			retry++;
		}
	} while (ret == KMF_ERR_KEYGEN_FAILED && retry < KEYGEN_RETRY);

	if (ret != KMF_OK) {
		goto out;
	}

	/* Concatenate 3 DES keys into a DES3 key */
	(void) memcpy((void *)newkey, (const void *)deskey1, 8);
	(void) memcpy((void *)(newkey + 8), (const void *)deskey2, 8);
	(void) memcpy((void *)(newkey + 16), (const void *)deskey3, 8);
	*des3key = newkey;

out:
	if (deskey1 != NULL)
		free(deskey1);

	if (deskey2 != NULL)
		free(deskey2);

	if (deskey3 != NULL)
		free(deskey3);

	if (ret != KMF_OK && newkey != NULL)
		free(newkey);

	return (ret);
}

KMF_RETURN
OpenSSL_CreateSymKey(KMF_HANDLE_T handle,
	int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	char *fullpath = NULL;
	KMF_RAW_SYM_KEY *rkey = NULL;
	DES_cblock *deskey = NULL;
	unsigned char *des3key = NULL;
	unsigned char *random = NULL;
	int fd = -1;
	KMF_KEY_HANDLE *symkey;
	KMF_KEY_ALG keytype;
	uint32_t keylen;
	uint32_t keylen_size = sizeof (keylen);
	char *dirpath;
	char *keyfile;

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED);

	symkey = kmf_get_attr_ptr(KMF_KEY_HANDLE_ATTR, attrlist, numattr);
	if (symkey == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	dirpath = kmf_get_attr_ptr(KMF_DIRPATH_ATTR, attrlist, numattr);

	keyfile = kmf_get_attr_ptr(KMF_KEY_FILENAME_ATTR, attrlist, numattr);
	if (keyfile == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	ret = kmf_get_attr(KMF_KEYALG_ATTR, attrlist, numattr,
	    (void *)&keytype, NULL);
	if (ret != KMF_OK)
		return (KMF_ERR_BAD_PARAMETER);

	ret = kmf_get_attr(KMF_KEYLENGTH_ATTR, attrlist, numattr,
	    &keylen, &keylen_size);
	if (ret == KMF_ERR_ATTR_NOT_FOUND &&
	    (keytype == KMF_DES || keytype == KMF_DES3))
		/* keylength is not required for DES and 3DES */
		ret = KMF_OK;
	if (ret != KMF_OK)
		return (KMF_ERR_BAD_PARAMETER);

	fullpath = get_fullpath(dirpath, keyfile);
	if (fullpath == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* If the requested file exists, return an error */
	if (test_for_file(fullpath, 0400) == 1) {
		free(fullpath);
		return (KMF_ERR_DUPLICATE_KEYFILE);
	}

	fd = open(fullpath, O_CREAT|O_TRUNC|O_RDWR, 0400);
	if (fd == -1) {
		ret = KMF_ERR_OPEN_FILE;
		goto out;
	}

	rkey = malloc(sizeof (KMF_RAW_SYM_KEY));
	if (rkey == NULL) {
		ret = KMF_ERR_MEMORY;
		goto out;
	}
	(void) memset(rkey, 0, sizeof (KMF_RAW_SYM_KEY));

	if (keytype == KMF_DES) {
		if ((ret = create_deskey(&deskey)) != KMF_OK) {
			goto out;
		}
		rkey->keydata.val = (uchar_t *)deskey;
		rkey->keydata.len = 8;

		symkey->keyalg = KMF_DES;

	} else if (keytype == KMF_DES3) {
		if ((ret = create_des3key(&des3key)) != KMF_OK) {
			goto out;
		}
		rkey->keydata.val = (uchar_t *)des3key;
		rkey->keydata.len = DES3_KEY_SIZE;
		symkey->keyalg = KMF_DES3;

	} else if (keytype == KMF_AES || keytype == KMF_RC4 ||
	    keytype == KMF_GENERIC_SECRET) {
		int bytes;

		if (keylen % 8 != 0) {
			ret = KMF_ERR_BAD_KEY_SIZE;
			goto out;
		}

		if (keytype == KMF_AES) {
			if (keylen != 128 &&
			    keylen != 192 &&
			    keylen != 256) {
				ret = KMF_ERR_BAD_KEY_SIZE;
				goto out;
			}
		}

		bytes = keylen/8;
		random = malloc(bytes);
		if (random == NULL) {
			ret = KMF_ERR_MEMORY;
			goto out;
		}
		if (RAND_bytes(random, bytes) != 1) {
			ret = KMF_ERR_KEYGEN_FAILED;
			goto out;
		}

		rkey->keydata.val = (uchar_t *)random;
		rkey->keydata.len = bytes;
		symkey->keyalg = keytype;

	} else {
		ret = KMF_ERR_BAD_KEY_TYPE;
		goto out;
	}

	(void) write(fd, (const void *) rkey->keydata.val, rkey->keydata.len);

	symkey->kstype = KMF_KEYSTORE_OPENSSL;
	symkey->keyclass = KMF_SYMMETRIC;
	symkey->keylabel = (char *)fullpath;
	symkey->israw = TRUE;
	symkey->keyp = rkey;

out:
	if (fd != -1)
		(void) close(fd);

	if (ret != KMF_OK && fullpath != NULL) {
		free(fullpath);
	}
	if (ret != KMF_OK) {
		kmf_free_raw_sym_key(rkey);
		symkey->keyp = NULL;
		symkey->keyalg = KMF_KEYALG_NONE;
	}

	return (ret);
}

/*
 * Check a file to see if it is a CRL file with PEM or DER format.
 * If success, return its format in the "pformat" argument.
 */
KMF_RETURN
OpenSSL_IsCRLFile(KMF_HANDLE_T handle, char *filename, int *pformat)
{
	KMF_RETURN	ret = KMF_OK;
	KMF_HANDLE	*kmfh = (KMF_HANDLE *)handle;
	BIO		*bio = NULL;
	X509_CRL   	*xcrl = NULL;

	if (filename == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	bio = BIO_new_file(filename, "rb");
	if (bio == NULL)	{
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_OPEN_FILE;
		goto out;
	}

	if ((xcrl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL)) != NULL) {
		*pformat = KMF_FORMAT_PEM;
		goto out;
	}
	(void) BIO_free(bio);

	/*
	 * Now try to read it as raw DER data.
	 */
	bio = BIO_new_file(filename, "rb");
	if (bio == NULL)	{
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_OPEN_FILE;
		goto out;
	}

	if ((xcrl = d2i_X509_CRL_bio(bio, NULL)) != NULL) {
		*pformat = KMF_FORMAT_ASN1;
	} else {
		ret = KMF_ERR_BAD_CRLFILE;
	}

out:
	if (bio != NULL)
		(void) BIO_free(bio);

	if (xcrl != NULL)
		X509_CRL_free(xcrl);

	return (ret);
}

KMF_RETURN
OpenSSL_GetSymKeyValue(KMF_HANDLE_T handle, KMF_KEY_HANDLE *symkey,
    KMF_RAW_SYM_KEY *rkey)
{
	KMF_RETURN	rv = KMF_OK;
	KMF_HANDLE	*kmfh = (KMF_HANDLE *)handle;
	KMF_DATA	keyvalue;

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED);

	if (symkey == NULL || rkey == NULL)
		return (KMF_ERR_BAD_PARAMETER);
	else if (symkey->keyclass != KMF_SYMMETRIC)
		return (KMF_ERR_BAD_KEY_CLASS);

	if (symkey->israw) {
		KMF_RAW_SYM_KEY *rawkey = (KMF_RAW_SYM_KEY *)symkey->keyp;

		if (rawkey == NULL ||
		    rawkey->keydata.val == NULL ||
		    rawkey->keydata.len == 0)
			return (KMF_ERR_BAD_KEYHANDLE);

		rkey->keydata.len = rawkey->keydata.len;
		if ((rkey->keydata.val = malloc(rkey->keydata.len)) == NULL)
			return (KMF_ERR_MEMORY);
		(void) memcpy(rkey->keydata.val, rawkey->keydata.val,
		    rkey->keydata.len);
	} else {
		rv = kmf_read_input_file(handle, symkey->keylabel, &keyvalue);
		if (rv != KMF_OK)
			return (rv);
		rkey->keydata.len = keyvalue.Length;
		rkey->keydata.val = keyvalue.Data;
	}

	return (rv);
}

/*
 * substitute for the unsafe access(2) function.
 * If the file in question already exists, return 1.
 * else 0.  If an error occurs during testing (other
 * than EEXIST), return -1.
 */
static int
test_for_file(char *filename, mode_t mode)
{
	int fd;

	/*
	 * Try to create the file with the EXCL flag.
	 * The call should fail if the file exists.
	 */
	fd = open(filename, O_WRONLY|O_CREAT|O_EXCL, mode);
	if (fd == -1 && errno == EEXIST)
		return (1);
	else if (fd == -1) /* some other error */
		return (-1);

	/* The file did NOT exist.  Delete the testcase. */
	(void) close(fd);
	(void) unlink(filename);
	return (0);
}

KMF_RETURN
OpenSSL_StoreKey(KMF_HANDLE_T handle, int numattr,
	KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE	*kmfh = (KMF_HANDLE *)handle;
	KMF_KEY_HANDLE *pubkey = NULL, *prikey = NULL;
	KMF_RAW_KEY_DATA *rawkey;
	EVP_PKEY *pkey = NULL;
	KMF_ENCODE_FORMAT format = KMF_FORMAT_PEM;
	KMF_CREDENTIAL cred = { NULL, 0 };
	BIO *out = NULL;
	int keys = 0;
	char *fullpath = NULL;
	char *keyfile = NULL;
	char *dirpath = NULL;

	pubkey = kmf_get_attr_ptr(KMF_PUBKEY_HANDLE_ATTR, attrlist, numattr);
	if (pubkey != NULL)
		keys++;

	prikey = kmf_get_attr_ptr(KMF_PRIVKEY_HANDLE_ATTR, attrlist, numattr);
	if (prikey != NULL)
		keys++;

	rawkey = kmf_get_attr_ptr(KMF_RAW_KEY_ATTR, attrlist, numattr);
	if (rawkey != NULL)
		keys++;

	/*
	 * Exactly 1 type of key must be passed to this function.
	 */
	if (keys != 1)
		return (KMF_ERR_BAD_PARAMETER);

	keyfile = (char *)kmf_get_attr_ptr(KMF_KEY_FILENAME_ATTR, attrlist,
	    numattr);
	if (keyfile == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	dirpath = kmf_get_attr_ptr(KMF_DIRPATH_ATTR, attrlist, numattr);

	fullpath = get_fullpath(dirpath, keyfile);

	/* Once we have the full path, we don't need the pieces */
	if (fullpath == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* If the requested file exists, return an error */
	if (test_for_file(fullpath, 0400) == 1) {
		free(fullpath);
		return (KMF_ERR_DUPLICATE_KEYFILE);
	}

	rv = kmf_get_attr(KMF_ENCODE_FORMAT_ATTR, attrlist, numattr,
	    &format, NULL);
	if (rv != KMF_OK)
		/* format is optional. */
		rv = KMF_OK;

	/* CRED is not required for OpenSSL files */
	(void) kmf_get_attr(KMF_CREDENTIAL_ATTR, attrlist, numattr,
	    &cred, NULL);

	/* Store the private key to the keyfile */
	out = BIO_new_file(fullpath, "wb");
	if (out == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		rv = KMF_ERR_OPEN_FILE;
		goto end;
	}

	if (prikey != NULL && prikey->keyp != NULL) {
		if (prikey->keyalg == KMF_RSA ||
		    prikey->keyalg == KMF_DSA) {
			pkey = (EVP_PKEY *)prikey->keyp;

			rv = ssl_write_key(kmfh, format,
			    out, &cred, pkey, TRUE);

			if (rv == KMF_OK && prikey->keylabel == NULL) {
				prikey->keylabel = strdup(fullpath);
				if (prikey->keylabel == NULL)
					rv = KMF_ERR_MEMORY;
			}
		}
	} else if (pubkey != NULL && pubkey->keyp != NULL) {
		if (pubkey->keyalg == KMF_RSA ||
		    pubkey->keyalg == KMF_DSA) {
			pkey = (EVP_PKEY *)pubkey->keyp;

			rv = ssl_write_key(kmfh, format,
			    out, &cred, pkey, FALSE);

			if (rv == KMF_OK && pubkey->keylabel == NULL) {
				pubkey->keylabel = strdup(fullpath);
				if (pubkey->keylabel == NULL)
					rv = KMF_ERR_MEMORY;
			}
		}
	} else if (rawkey != NULL) {
		if (rawkey->keytype == KMF_RSA) {
			pkey = ImportRawRSAKey(&rawkey->rawdata.rsa);
		} else if (rawkey->keytype == KMF_DSA) {
			pkey = ImportRawDSAKey(&rawkey->rawdata.dsa);
		} else {
			rv = KMF_ERR_BAD_PARAMETER;
		}
		if (pkey != NULL) {
			KMF_KEY_CLASS kclass = KMF_ASYM_PRI;

			rv = kmf_get_attr(KMF_KEYCLASS_ATTR, attrlist, numattr,
			    (void *)&kclass, NULL);
			if (rv != KMF_OK)
				rv = KMF_OK;
			rv = ssl_write_key(kmfh, format, out,
			    &cred, pkey, (kclass == KMF_ASYM_PRI));
			EVP_PKEY_free(pkey);
		}
	}

end:

	if (out)
		(void) BIO_free(out);


	if (rv == KMF_OK)
		(void) chmod(fullpath, 0400);

	free(fullpath);
	return (rv);
}

KMF_RETURN
OpenSSL_ImportCRL(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	X509_CRL *xcrl = NULL;
	X509 *xcert = NULL;
	EVP_PKEY *pkey;
	KMF_ENCODE_FORMAT format;
	BIO *in = NULL, *out = NULL;
	int openssl_ret = 0;
	KMF_ENCODE_FORMAT outformat;
	boolean_t crlcheck = FALSE;
	char *certfile, *dirpath, *crlfile, *incrl, *outcrl, *outcrlfile;

	if (numattr == 0 || attrlist == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	/* CRL check is optional */
	(void) kmf_get_attr(KMF_CRL_CHECK_ATTR, attrlist, numattr,
	    &crlcheck, NULL);

	certfile = kmf_get_attr_ptr(KMF_CERT_FILENAME_ATTR, attrlist, numattr);
	if (crlcheck == B_TRUE && certfile == NULL) {
		return (KMF_ERR_BAD_CERTFILE);
	}

	dirpath = kmf_get_attr_ptr(KMF_DIRPATH_ATTR, attrlist, numattr);
	incrl = kmf_get_attr_ptr(KMF_CRL_FILENAME_ATTR, attrlist, numattr);
	outcrl = kmf_get_attr_ptr(KMF_CRL_OUTFILE_ATTR, attrlist, numattr);

	crlfile = get_fullpath(dirpath, incrl);

	if (crlfile == NULL)
		return (KMF_ERR_BAD_CRLFILE);

	outcrlfile = get_fullpath(dirpath, outcrl);
	if (outcrlfile == NULL)
		return (KMF_ERR_BAD_CRLFILE);

	if (isdir(outcrlfile)) {
		free(outcrlfile);
		return (KMF_ERR_BAD_CRLFILE);
	}

	ret = kmf_is_crl_file(handle, crlfile, &format);
	if (ret != KMF_OK) {
		free(outcrlfile);
		return (ret);
	}

	in = BIO_new_file(crlfile, "rb");
	if (in == NULL)	{
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_OPEN_FILE;
		goto end;
	}

	if (format == KMF_FORMAT_ASN1) {
		xcrl = d2i_X509_CRL_bio(in, NULL);
	} else if (format == KMF_FORMAT_PEM) {
		xcrl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
	}

	if (xcrl == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_BAD_CRLFILE;
		goto end;
	}

	/* If bypasscheck is specified, no need to verify. */
	if (crlcheck == B_FALSE)
		goto output;

	ret = kmf_is_cert_file(handle, certfile, &format);
	if (ret != KMF_OK)
		goto end;

	/* Read in the CA cert file and convert to X509 */
	if (BIO_read_filename(in, certfile) <= 0) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_OPEN_FILE;
		goto end;
	}

	if (format == KMF_FORMAT_ASN1) {
		xcert = d2i_X509_bio(in, NULL);
	} else if (format == KMF_FORMAT_PEM) {
		xcert = PEM_read_bio_X509(in, NULL, NULL, NULL);
	} else {
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto end;
	}

	if (xcert == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto end;
	}
	/* Now get the public key from the CA cert */
	pkey = X509_get_pubkey(xcert);
	if (pkey == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_BAD_CERTFILE;
		goto end;
	}

	/* Verify the CRL with the CA's public key */
	openssl_ret = X509_CRL_verify(xcrl, pkey);
	EVP_PKEY_free(pkey);
	if (openssl_ret > 0) {
		ret = KMF_OK;  /* verify succeed */
	} else {
		SET_ERROR(kmfh, openssl_ret);
		ret = KMF_ERR_BAD_CRLFILE;
	}

output:
	ret = kmf_get_attr(KMF_ENCODE_FORMAT_ATTR, attrlist, numattr,
	    &outformat, NULL);
	if (ret != KMF_OK) {
		ret = KMF_OK;
		outformat = KMF_FORMAT_PEM;
	}

	out = BIO_new_file(outcrlfile, "wb");
	if (out == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_OPEN_FILE;
		goto end;
	}

	if (outformat == KMF_FORMAT_ASN1) {
		openssl_ret = (int)i2d_X509_CRL_bio(out, xcrl);
	} else if (outformat == KMF_FORMAT_PEM) {
		openssl_ret = PEM_write_bio_X509_CRL(out, xcrl);
	} else {
		ret = KMF_ERR_BAD_PARAMETER;
		goto end;
	}

	if (openssl_ret <= 0) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_WRITE_FILE;
	} else {
		ret = KMF_OK;
	}

end:
	if (xcrl != NULL)
		X509_CRL_free(xcrl);

	if (xcert != NULL)
		X509_free(xcert);

	if (in != NULL)
		(void) BIO_free(in);

	if (out != NULL)
		(void) BIO_free(out);

	if (outcrlfile != NULL)
		free(outcrlfile);

	return (ret);
}

KMF_RETURN
OpenSSL_ListCRL(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	X509_CRL   *x = NULL;
	KMF_ENCODE_FORMAT format;
	char *crlfile = NULL;
	BIO *in = NULL;
	BIO *mem = NULL;
	long len;
	char *memptr;
	char *data = NULL;
	char **crldata;
	char *crlfilename, *dirpath;

	if (numattr == 0 || attrlist == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}
	crlfilename = kmf_get_attr_ptr(KMF_CRL_FILENAME_ATTR,
	    attrlist, numattr);
	if (crlfilename == NULL)
		return (KMF_ERR_BAD_CRLFILE);

	crldata = (char **)kmf_get_attr_ptr(KMF_CRL_DATA_ATTR,
	    attrlist, numattr);

	if (crldata == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	dirpath = kmf_get_attr_ptr(KMF_DIRPATH_ATTR, attrlist, numattr);

	crlfile = get_fullpath(dirpath, crlfilename);

	if (crlfile == NULL)
		return (KMF_ERR_BAD_CRLFILE);

	if (isdir(crlfile)) {
		free(crlfile);
		return (KMF_ERR_BAD_CRLFILE);
	}

	ret = kmf_is_crl_file(handle, crlfile, &format);
	if (ret != KMF_OK) {
		free(crlfile);
		return (ret);
	}

	if (bio_err == NULL)
		bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

	in = BIO_new_file(crlfile, "rb");
	if (in == NULL)	{
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_OPEN_FILE;
		goto end;
	}

	if (format == KMF_FORMAT_ASN1) {
		x = d2i_X509_CRL_bio(in, NULL);
	} else if (format == KMF_FORMAT_PEM) {
		x = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
	}

	if (x == NULL) { /* should not happen */
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_OPEN_FILE;
		goto end;
	}

	mem = BIO_new(BIO_s_mem());
	if (mem == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_MEMORY;
		goto end;
	}

	(void) X509_CRL_print(mem, x);
	len = BIO_get_mem_data(mem, &memptr);
	if (len <= 0) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_MEMORY;
		goto end;
	}

	data = malloc(len + 1);
	if (data == NULL) {
		ret = KMF_ERR_MEMORY;
		goto end;
	}

	(void) memcpy(data, memptr, len);
	data[len] = '\0';
	*crldata = data;

end:
	if (x != NULL)
		X509_CRL_free(x);

	if (crlfile != NULL)
		free(crlfile);

	if (in != NULL)
		(void) BIO_free(in);

	if (mem != NULL)
		(void) BIO_free(mem);

	return (ret);
}

KMF_RETURN
OpenSSL_DeleteCRL(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	KMF_ENCODE_FORMAT format;
	char *crlfile = NULL;
	BIO *in = NULL;
	char *crlfilename, *dirpath;

	if (numattr == 0 || attrlist == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	crlfilename = kmf_get_attr_ptr(KMF_CRL_FILENAME_ATTR,
	    attrlist, numattr);

	if (crlfilename == NULL)
		return (KMF_ERR_BAD_CRLFILE);

	dirpath = kmf_get_attr_ptr(KMF_DIRPATH_ATTR, attrlist, numattr);

	crlfile = get_fullpath(dirpath, crlfilename);

	if (crlfile == NULL)
		return (KMF_ERR_BAD_CRLFILE);

	if (isdir(crlfile)) {
		ret = KMF_ERR_BAD_CRLFILE;
		goto end;
	}

	ret = kmf_is_crl_file(handle, crlfile, &format);
	if (ret != KMF_OK)
		goto end;

	if (unlink(crlfile) != 0) {
		SET_SYS_ERROR(kmfh, errno);
		ret = KMF_ERR_INTERNAL;
		goto end;
	}

end:
	if (in != NULL)
		(void) BIO_free(in);
	if (crlfile != NULL)
		free(crlfile);

	return (ret);
}

KMF_RETURN
OpenSSL_FindCertInCRL(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	KMF_ENCODE_FORMAT format;
	BIO *in = NULL;
	X509   *xcert = NULL;
	X509_CRL   *xcrl = NULL;
	STACK_OF(X509_REVOKED) *revoke_stack = NULL;
	X509_REVOKED *revoke;
	int i;
	char *crlfilename, *crlfile, *dirpath, *certfile;

	if (numattr == 0 || attrlist == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	crlfilename = kmf_get_attr_ptr(KMF_CRL_FILENAME_ATTR,
	    attrlist, numattr);

	if (crlfilename == NULL)
		return (KMF_ERR_BAD_CRLFILE);

	certfile = kmf_get_attr_ptr(KMF_CERT_FILENAME_ATTR, attrlist, numattr);
	if (certfile == NULL)
		return (KMF_ERR_BAD_CRLFILE);

	dirpath = kmf_get_attr_ptr(KMF_DIRPATH_ATTR, attrlist, numattr);

	crlfile = get_fullpath(dirpath, crlfilename);

	if (crlfile == NULL)
		return (KMF_ERR_BAD_CRLFILE);

	if (isdir(crlfile)) {
		ret = KMF_ERR_BAD_CRLFILE;
		goto end;
	}

	ret = kmf_is_crl_file(handle, crlfile, &format);
	if (ret != KMF_OK)
		goto end;

	/* Read the CRL file and load it into a X509_CRL structure */
	in = BIO_new_file(crlfilename, "rb");
	if (in == NULL)	{
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_OPEN_FILE;
		goto end;
	}

	if (format == KMF_FORMAT_ASN1) {
		xcrl = d2i_X509_CRL_bio(in, NULL);
	} else if (format == KMF_FORMAT_PEM) {
		xcrl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
	}

	if (xcrl == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_BAD_CRLFILE;
		goto end;
	}
	(void) BIO_free(in);

	/* Read the Certificate file and load it into a X509 structure */
	ret = kmf_is_cert_file(handle, certfile, &format);
	if (ret != KMF_OK)
		goto end;

	in = BIO_new_file(certfile, "rb");
	if (in == NULL)	{
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_OPEN_FILE;
		goto end;
	}

	if (format == KMF_FORMAT_ASN1) {
		xcert = d2i_X509_bio(in, NULL);
	} else if (format == KMF_FORMAT_PEM) {
		xcert = PEM_read_bio_X509(in, NULL, NULL, NULL);
	}

	if (xcert == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_BAD_CERTFILE;
		goto end;
	}

	/* Check if the certificate and the CRL have same issuer */
	if (X509_NAME_cmp(X509_get_issuer_name(xcert),
	    X509_CRL_get_issuer(xcrl)) != 0) {
		ret = KMF_ERR_ISSUER;
		goto end;
	}

	/* Check to see if the certificate serial number is revoked */
	revoke_stack = X509_CRL_get_REVOKED(xcrl);
	if (sk_X509_REVOKED_num(revoke_stack) <= 0) {
		/* No revoked certificates in the CRL file */
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_EMPTY_CRL;
		goto end;
	}

	for (i = 0; i < sk_X509_REVOKED_num(revoke_stack); i++) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		revoke = sk_X509_REVOKED_value(revoke_stack, i);
		if (ASN1_INTEGER_cmp(X509_get_serialNumber(xcert),
		    X509_REVOKED_get0_serialNumber(revoke)) == 0) {
			break;
		}
	}

	if (i < sk_X509_REVOKED_num(revoke_stack)) {
		ret = KMF_OK;
	} else {
		ret = KMF_ERR_NOT_REVOKED;
	}

end:
	if (in != NULL)
		(void) BIO_free(in);
	if (xcrl != NULL)
		X509_CRL_free(xcrl);
	if (xcert != NULL)
		X509_free(xcert);

	return (ret);
}

KMF_RETURN
OpenSSL_VerifyCRLFile(KMF_HANDLE_T handle, char *crlname, KMF_DATA *tacert)
{
	KMF_RETURN	ret = KMF_OK;
	KMF_HANDLE	*kmfh = (KMF_HANDLE *)handle;
	BIO		*bcrl = NULL;
	X509_CRL   	*xcrl = NULL;
	X509		*xcert = NULL;
	EVP_PKEY	*pkey;
	int		sslret;
	KMF_ENCODE_FORMAT crl_format;
	unsigned char	*p;
	long		len;

	if (handle == NULL || crlname == NULL || tacert == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	ret = kmf_get_file_format(crlname, &crl_format);
	if (ret != KMF_OK)
		return (ret);

	bcrl = BIO_new_file(crlname, "rb");
	if (bcrl == NULL)	{
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_OPEN_FILE;
		goto cleanup;
	}

	if (crl_format == KMF_FORMAT_ASN1) {
		xcrl = d2i_X509_CRL_bio(bcrl, NULL);
	} else if (crl_format == KMF_FORMAT_PEM) {
		xcrl = PEM_read_bio_X509_CRL(bcrl, NULL, NULL, NULL);
	} else {
		ret = KMF_ERR_BAD_PARAMETER;
		goto cleanup;
	}

	if (xcrl == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_BAD_CRLFILE;
		goto cleanup;
	}

	p = tacert->Data;
	len = tacert->Length;
	xcert = d2i_X509(NULL, (const uchar_t **)&p, len);

	if (xcert == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_BAD_CERTFILE;
		goto cleanup;
	}

	/* Get issuer certificate public key */
	pkey = X509_get_pubkey(xcert);
	if (pkey == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	/* Verify CRL signature */
	sslret = X509_CRL_verify(xcrl, pkey);
	EVP_PKEY_free(pkey);
	if (sslret > 0) {
		ret = KMF_OK;
	} else {
		SET_ERROR(kmfh, sslret);
		ret = KMF_ERR_BAD_CRLFILE;
	}

cleanup:
	if (bcrl != NULL)
		(void) BIO_free(bcrl);

	if (xcrl != NULL)
		X509_CRL_free(xcrl);

	if (xcert != NULL)
		X509_free(xcert);

	return (ret);

}

KMF_RETURN
OpenSSL_CheckCRLDate(KMF_HANDLE_T handle, char *crlname)
{
	KMF_RETURN	ret = KMF_OK;
	KMF_HANDLE	*kmfh = (KMF_HANDLE *)handle;
	KMF_ENCODE_FORMAT crl_format;
	BIO		*bcrl = NULL;
	X509_CRL   	*xcrl = NULL;
	int		i;

	if (handle == NULL || crlname == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	ret = kmf_is_crl_file(handle, crlname, &crl_format);
	if (ret != KMF_OK)
		return (ret);

	bcrl = BIO_new_file(crlname, "rb");
	if (bcrl == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_OPEN_FILE;
		goto cleanup;
	}

	if (crl_format == KMF_FORMAT_ASN1)
		xcrl = d2i_X509_CRL_bio(bcrl, NULL);
	else if (crl_format == KMF_FORMAT_PEM)
		xcrl = PEM_read_bio_X509_CRL(bcrl, NULL, NULL, NULL);

	if (xcrl == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_BAD_CRLFILE;
		goto cleanup;
	}
	i = X509_cmp_time(X509_CRL_get0_lastUpdate(xcrl), NULL);
	if (i >= 0) {
		ret = KMF_ERR_VALIDITY_PERIOD;
		goto cleanup;
	}
	if (X509_CRL_get0_nextUpdate(xcrl)) {
		i = X509_cmp_time(X509_CRL_get0_nextUpdate(xcrl), NULL);

		if (i <= 0) {
			ret = KMF_ERR_VALIDITY_PERIOD;
			goto cleanup;
		}
	}

	ret = KMF_OK;

cleanup:
	if (bcrl != NULL)
		(void) BIO_free(bcrl);

	if (xcrl != NULL)
		X509_CRL_free(xcrl);

	return (ret);
}
