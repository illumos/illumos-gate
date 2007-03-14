/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <openssl/bn.h>
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

static BIO *bio_err = NULL;
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

mutex_t init_lock = DEFAULTMUTEX;
static int ssl_initialized = 0;

static KMF_RETURN
extract_objects(KMF_HANDLE *, KMF_FINDCERT_PARAMS *, char *,
	CK_UTF8CHAR *, CK_ULONG, EVP_PKEY **, KMF_DATA **, int *);

static KMF_RETURN
kmf_load_cert(KMF_HANDLE *, KMF_FINDCERT_PARAMS *, char *, KMF_DATA *);

static KMF_RETURN
sslBN2KMFBN(BIGNUM *, KMF_BIGINT *);

static EVP_PKEY *
ImportRawRSAKey(KMF_RAW_RSA_KEY *);

KMF_RETURN
OpenSSL_FindCert(KMF_HANDLE_T,
	KMF_FINDCERT_PARAMS *,
	KMF_X509_DER_CERT *,
	uint32_t *);

void
OpenSSL_FreeKMFCert(KMF_HANDLE_T, KMF_X509_DER_CERT *);

KMF_RETURN
OpenSSL_StoreCert(KMF_HANDLE_T handle, KMF_STORECERT_PARAMS *, KMF_DATA *);

KMF_RETURN
OpenSSL_DeleteCert(KMF_HANDLE_T handle, KMF_DELETECERT_PARAMS *);

KMF_RETURN
OpenSSL_CreateKeypair(KMF_HANDLE_T, KMF_CREATEKEYPAIR_PARAMS *,
	KMF_KEY_HANDLE *, KMF_KEY_HANDLE *);

KMF_RETURN
OpenSSL_EncodePubKeyData(KMF_HANDLE_T,  KMF_KEY_HANDLE *, KMF_DATA *);

KMF_RETURN
OpenSSL_SignData(KMF_HANDLE_T, KMF_KEY_HANDLE *, KMF_OID *,
	KMF_DATA *, KMF_DATA *);

KMF_RETURN
OpenSSL_DeleteKey(KMF_HANDLE_T, KMF_DELETEKEY_PARAMS *,
	KMF_KEY_HANDLE *, boolean_t);

KMF_RETURN
OpenSSL_ImportCRL(KMF_HANDLE_T, KMF_IMPORTCRL_PARAMS *);

KMF_RETURN
OpenSSL_DeleteCRL(KMF_HANDLE_T, KMF_DELETECRL_PARAMS *);

KMF_RETURN
OpenSSL_ListCRL(KMF_HANDLE_T, KMF_LISTCRL_PARAMS *, char **);

KMF_RETURN
OpenSSL_FindCertInCRL(KMF_HANDLE_T, KMF_FINDCERTINCRL_PARAMS *);

KMF_RETURN
OpenSSL_CertGetPrintable(KMF_HANDLE_T, const KMF_DATA *,
	KMF_PRINTABLE_ITEM, char *);

KMF_RETURN
OpenSSL_GetErrorString(KMF_HANDLE_T, char **);

KMF_RETURN
OpenSSL_GetPrikeyByCert(KMF_HANDLE_T, KMF_CRYPTOWITHCERT_PARAMS *, KMF_DATA *,
	KMF_KEY_HANDLE *, KMF_KEY_ALG);

KMF_RETURN
OpenSSL_DecryptData(KMF_HANDLE_T, KMF_KEY_HANDLE *, KMF_OID *,
	KMF_DATA *, KMF_DATA *);

KMF_RETURN
OpenSSL_CreateOCSPRequest(KMF_HANDLE_T, KMF_OCSPREQUEST_PARAMS *,
	char *reqfile);

KMF_RETURN
OpenSSL_GetOCSPStatusForCert(KMF_HANDLE_T, KMF_OCSPRESPONSE_PARAMS_INPUT *,
    KMF_OCSPRESPONSE_PARAMS_OUTPUT *);

KMF_RETURN
OpenSSL_FindKey(KMF_HANDLE_T, KMF_FINDKEY_PARAMS *,
	KMF_KEY_HANDLE *, uint32_t *);

KMF_RETURN
OpenSSL_ExportP12(KMF_HANDLE_T,
	KMF_EXPORTP12_PARAMS *,
	int, KMF_X509_DER_CERT *,
	int, KMF_KEY_HANDLE *,
	char *);

KMF_RETURN
OpenSSL_StorePrivateKey(KMF_HANDLE_T, KMF_STOREKEY_PARAMS *,
	KMF_RAW_KEY_DATA *);

KMF_RETURN
OpenSSL_CreateSymKey(KMF_HANDLE_T, KMF_CREATESYMKEY_PARAMS *,
	KMF_KEY_HANDLE *);

KMF_RETURN
OpenSSL_GetSymKeyValue(KMF_HANDLE_T, KMF_KEY_HANDLE *, KMF_RAW_SYM_KEY *);

KMF_RETURN
OpenSSL_VerifyCRLFile(KMF_HANDLE_T, KMF_VERIFYCRL_PARAMS *);

KMF_RETURN
OpenSSL_CheckCRLDate(KMF_HANDLE_T, KMF_CHECKCRLDATE_PARAMS *);

KMF_RETURN
OpenSSL_VerifyDataWithCert(KMF_HANDLE_T, KMF_ALGORITHM_INDEX,
	KMF_DATA *, KMF_DATA *, KMF_DATA *);

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
	OpenSSL_GetPrikeyByCert,
	OpenSSL_DecryptData,
	OpenSSL_ExportP12,
	OpenSSL_StorePrivateKey,
	OpenSSL_CreateSymKey,
	OpenSSL_GetSymKeyValue,
	NULL,	/* SetTokenPin */
	OpenSSL_VerifyDataWithCert,
	NULL	/* Finalize */
};

static mutex_t *lock_cs;
static long *lock_count;

static void
/*ARGSUSED*/
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

KMF_PLUGIN_FUNCLIST *
KMF_Plugin_Initialize()
{
	int i;

	(void) mutex_lock(&init_lock);
	if (!ssl_initialized) {
		OpenSSL_add_all_algorithms();

		/* Enable error strings for reporting */
		ERR_load_crypto_strings();

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
		/*
		 * Set up for thread-safe operation.
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
		CRYPTO_set_locking_callback((void (*)())locking_cb);
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

static int
isdir(char *path)
{
	struct stat s;

	if (stat(path, &s) == -1)
		return (0);

	return (s.st_mode & S_IFDIR);
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
check_cert(X509 *xcert, KMF_FINDCERT_PARAMS *params, boolean_t *match)
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

	if (params->issuer != NULL && strlen(params->issuer)) {
		rv = KMF_DNParser(params->issuer, &issuerDN);
		if (rv != KMF_OK)
			return (KMF_ERR_BAD_PARAMETER);

		rv = get_x509_dn(xcert->cert_info->issuer, &certIssuerDN);
		if (rv != KMF_OK) {
			KMF_FreeDN(&issuerDN);
			return (KMF_ERR_BAD_PARAMETER);
		}

		findIssuer = TRUE;
	}
	if (params->subject != NULL && strlen(params->subject)) {
		rv = KMF_DNParser(params->subject, &subjectDN);
		if (rv != KMF_OK) {
			rv = KMF_ERR_BAD_PARAMETER;
			goto cleanup;
		}

		rv = get_x509_dn(xcert->cert_info->subject, &certSubjectDN);
		if (rv != KMF_OK) {
			rv = KMF_ERR_BAD_PARAMETER;
			goto cleanup;
		}
		findSubject = TRUE;
	}
	if (params->serial != NULL && params->serial->val != NULL)
		findSerial = TRUE;

	if (findSerial) {
		BIGNUM *bn;

		/* Comparing BIGNUMs is a pain! */
		bn = ASN1_INTEGER_to_BN(xcert->cert_info->serialNumber, NULL);
		if (bn != NULL) {
			int bnlen = BN_num_bytes(bn);

			if (bnlen == params->serial->len) {
				uchar_t *a = malloc(bnlen);
				if (a == NULL) {
					rv = KMF_ERR_MEMORY;
					BN_free(bn);
					goto cleanup;
				}
				bnlen = BN_bn2bin(bn, a);
				*match = !memcmp(a,
					params->serial->val,
					params->serial->len);
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
		*match = !KMF_CompareRDNs(&issuerDN, &certIssuerDN);
		if (!(*match)) {
			rv = KMF_OK;
			goto cleanup;
		}
	}
	if (findSubject) {
		*match = !KMF_CompareRDNs(&subjectDN, &certSubjectDN);
		if (!(*match)) {
			rv = KMF_OK;
			goto cleanup;
		}
	}

	*match = TRUE;
cleanup:
	if (findIssuer) {
		KMF_FreeDN(&issuerDN);
		KMF_FreeDN(&certIssuerDN);
	}
	if (findSubject) {
		KMF_FreeDN(&subjectDN);
		KMF_FreeDN(&certSubjectDN);
	}

	return (rv);
}

static KMF_RETURN
load_X509cert(KMF_HANDLE *kmfh,
	KMF_FINDCERT_PARAMS *params,
	char *pathname,
	X509 **outcert)
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
	rv = KMF_GetFileFormat(pathname, &format);
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

	if (check_cert(xcert, params, &match) != KMF_OK || match == FALSE) {
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
load_certs(KMF_HANDLE *kmfh, KMF_FINDCERT_PARAMS *params, char *pathname,
	KMF_DATA **certlist, uint32_t *numcerts)
{
	KMF_RETURN rv = KMF_OK;
	int i;
	KMF_DATA *certs = NULL;
	int nc = 0;
	int hits = 0;
	KMF_ENCODE_FORMAT format;

	rv = KMF_GetFileFormat(pathname, &format);
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
		rv = kmf_load_cert(kmfh, params, pathname, certs);
		if (rv == KMF_OK) {
			*certlist = certs;
			*numcerts = 1;
		}
		return (rv);
	} else if (format == KMF_FORMAT_PKCS12) {
		/* We need a credential to access a PKCS#12 file */
		rv = KMF_ERR_BAD_CERT_FORMAT;
	} else if (format == KMF_FORMAT_PEM ||
		format != KMF_FORMAT_PEM_KEYPAIR) {

		/* This function only works on PEM files */
		rv = extract_objects(kmfh, params, pathname,
			(uchar_t *)NULL, 0, NULL,
			&certs, &nc);
	} else {
		return (KMF_ERR_ENCODING);
	}

	if (rv != KMF_OK)
		return (rv);

	for (i = 0; i < nc; i++) {
		if (params->find_cert_validity == KMF_NONEXPIRED_CERTS) {
			rv = KMF_CheckCertDate(kmfh, &certs[i]);
		} else if (params->find_cert_validity == KMF_EXPIRED_CERTS) {
			rv = KMF_CheckCertDate(kmfh, &certs[i]);
			if (rv == KMF_OK)
				rv = KMF_ERR_CERT_NOT_FOUND;
			if (rv == KMF_ERR_VALIDITY_PERIOD)
				rv = KMF_OK;
		}
		if (rv != KMF_OK) {
			/* Remove this cert from the list by clearing it. */
			KMF_FreeData(&certs[i]);
		} else {
			hits++; /* count valid certs found */
		}
		rv = KMF_OK;
	}
	if (rv == KMF_OK && hits == 0) {
		rv = KMF_ERR_CERT_NOT_FOUND;
	} else if (rv == KMF_OK && hits > 0) {
		/*
		 * Sort the list of certs by length to put the cleared ones
		 * at the end so they don't get accessed by the caller.
		 */
		qsort((void *)certs, nc, sizeof (KMF_DATA), datacmp);
		*certlist = certs;

		/* since we sorted the list, just return the number of hits */
		*numcerts = hits;
	}
	return (rv);
}

static KMF_RETURN
kmf_load_cert(KMF_HANDLE *kmfh,
	KMF_FINDCERT_PARAMS *params,
	char *pathname,
	KMF_DATA *cert)
{
	KMF_RETURN rv = KMF_OK;
	X509 *x509cert = NULL;

	rv = load_X509cert(kmfh, params, pathname, &x509cert);
	if (rv == KMF_OK && x509cert != NULL && cert != NULL) {
		rv = ssl_cert2KMFDATA(kmfh, x509cert, cert);
		if (rv != KMF_OK) {
			goto cleanup;
		}
		if (params->find_cert_validity == KMF_NONEXPIRED_CERTS) {
			rv = KMF_CheckCertDate(kmfh, cert);
		} else if (params->find_cert_validity == KMF_EXPIRED_CERTS) {
			rv = KMF_CheckCertDate(kmfh, cert);
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

	if (KMF_GetFileFormat((char *)file, &format) != KMF_OK)
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
			rv = KMF_ReadInputFile(kmfh, (char *)file,
				&filedata);
			if (rv == KMF_OK) {
				(void) readAltFormatPrivateKey(&filedata,
					&pkey);
				KMF_FreeData(&filedata);
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
			rv = KMF_ReadInputFile(kmfh, (char *)file,
				&filedata);
			if (rv == KMF_OK) {
				uchar_t *d = NULL;
				int len;
				rv = KMF_Pem2Der(filedata.Data,
					filedata.Length, &d, &len);
				if (rv == KMF_OK && d != NULL) {
					derdata.Data = d;
					derdata.Length = (size_t)len;
					(void) readAltFormatPrivateKey(
						&derdata, &pkey);
					free(d);
				}
				KMF_FreeData(&filedata);
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
OpenSSL_FindCert(KMF_HANDLE_T handle,
	KMF_FINDCERT_PARAMS *params,
	KMF_X509_DER_CERT *kmf_cert,
	uint32_t *num_certs)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	char *fullpath;
	int i;

	if (num_certs == NULL || params == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	*num_certs = 0;

	fullpath = get_fullpath(params->sslparms.dirpath,
		params->sslparms.certfile);

	if (fullpath == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (isdir(fullpath)) {
		DIR *dirp;
		struct dirent *dp;
		int n = 0;

		/* open all files in the directory and attempt to read them */
		if ((dirp = opendir(fullpath)) == NULL) {
			return (KMF_ERR_BAD_PARAMETER);
		}
		while ((dp = readdir(dirp)) != NULL) {
			char *fname;
			KMF_DATA *certlist = NULL;
			uint32_t numcerts = 0;

			if (strcmp(dp->d_name, ".") == 0 ||
			    strcmp(dp->d_name, "..") == 0)
				continue;

			fname = get_fullpath(fullpath,
				(char *)&dp->d_name);

			rv = load_certs(kmfh, params, fname, &certlist,
				&numcerts);

			if (rv != KMF_OK) {
				free(fname);
				if (certlist != NULL) {
					for (i = 0; i < numcerts; i++)
						KMF_FreeData(&certlist[i]);
					free(certlist);
				}
				continue;
			}

			/* If load succeeds, add certdata to the list */
			if (kmf_cert != NULL) {
				for (i = 0; i < numcerts; i++) {
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
				free(certlist);
			} else {
				for (i = 0; i < numcerts; i++)
					KMF_FreeData(&certlist[i]);
				free(certlist);
				n += numcerts;
			}
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
		uint32_t numcerts = 0;

		rv = load_certs(kmfh, params, fullpath, &certlist, &numcerts);
		if (rv != KMF_OK) {
			free(fullpath);
			return (rv);
		}

		if (kmf_cert != NULL && certlist != NULL) {
			for (i = 0; i < numcerts; i++) {
				kmf_cert[i].certificate.Data =
					certlist[i].Data;
				kmf_cert[i].certificate.Length =
					certlist[i].Length;
				kmf_cert[i].kmf_private.keystore_type =
					KMF_KEYSTORE_OPENSSL;
				kmf_cert[i].kmf_private.flags =
					KMF_FLAG_CERT_VALID;
				kmf_cert[i].kmf_private.label =
					strdup(fullpath);
			}
			free(certlist);
		} else {
			if (certlist != NULL) {
				for (i = 0; i < numcerts; i++)
					KMF_FreeData(&certlist[i]);
				free(certlist);
			}
		}
		*num_certs = numcerts;
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
			free(kmf_cert->certificate.Data);
			kmf_cert->certificate.Data = NULL;
			kmf_cert->certificate.Length = 0;
		}
		if (kmf_cert->kmf_private.label)
			free(kmf_cert->kmf_private.label);
	}
}

KMF_RETURN
OpenSSL_StoreCert(KMF_HANDLE_T handle, KMF_STORECERT_PARAMS *params,
    KMF_DATA * pcert)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	X509 *xcert = NULL;
	FILE *fp;
	unsigned char *outbuf;
	unsigned char *outbuf_p;
	char *fullpath;
	int outbuflen;
	int len;
	KMF_ENCODE_FORMAT format;

	if (params == NULL || params->ks_opt_u.openssl_opts.certfile == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	/*
	 * check if the cert output format is supported by OPENSSL.
	 * however, since the keystore for OPENSSL is just a file, we have
	 * no way to store the format along with the file.
	 */
	format = params->sslparms.format;
	if (format != KMF_FORMAT_ASN1 && format != KMF_FORMAT_PEM)
		return (KMF_ERR_BAD_CERT_FORMAT);


	fullpath = get_fullpath(params->sslparms.dirpath,
		params->sslparms.certfile);
	if (fullpath == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * When storing a certificate, you must specify a filename.
	 */
	if (isdir(fullpath)) {
		free(fullpath);
		return (KMF_ERR_BAD_PARAMETER);
	}

	/* copy cert data to outbuf */
	outbuflen = pcert->Length;
	outbuf = malloc(outbuflen);
	if (outbuf == NULL) {
		free(fullpath);
		return (KMF_ERR_MEMORY);
	}
	(void) memcpy(outbuf, pcert->Data, pcert->Length);

	if ((fp = fopen(fullpath, "w")) ==
		NULL) {
		SET_SYS_ERROR(kmfh, errno);
		ret = KMF_ERR_INTERNAL;
		goto out;
	}

	if (format == KMF_FORMAT_ASN1) {
		len = fwrite(outbuf, 1, outbuflen, fp);
		if (len != outbuflen) {
			SET_SYS_ERROR(kmfh, errno);
			ret = KMF_ERR_WRITE_FILE;
		} else {
			ret = KMF_OK;
		}
		goto out;
	}

	/*
	 * The output format is not KMF_FORMAT_ASN1, so we will
	 * Convert the cert data to OpenSSL internal X509 first.
	 */
	outbuf_p = outbuf; /* use a temp pointer; required by openssl */
	xcert = d2i_X509(NULL, (const uchar_t **)&outbuf_p, outbuflen);
	if (xcert == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_ENCODING;
		goto out;
	}

	if (format == KMF_FORMAT_PEM) {
		/* Convert to the PEM format and write it out */
		if (!PEM_write_X509(fp, xcert)) {
			SET_ERROR(kmfh, ERR_get_error());
			ret = KMF_ERR_ENCODING;
		} else {
			ret = KMF_OK;
		}
		goto out;
	}

out:
	if (fullpath != NULL)
		free(fullpath);

	if (outbuf != NULL) {
		free(outbuf);
	}
	if (fp != NULL) {
		(void) fclose(fp);
	}

	if (xcert != NULL) {
		X509_free(xcert);
	}

	return (ret);
}

KMF_RETURN
OpenSSL_DeleteCert(KMF_HANDLE_T handle, KMF_DELETECERT_PARAMS *params)
{
	KMF_RETURN rv;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	char *fullpath = NULL;
	KMF_DATA certdata = {NULL, 0};

	if (params == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	fullpath = get_fullpath(params->sslparms.dirpath,
		params->sslparms.certfile);

	if (fullpath == NULL)
		return (KMF_ERR_BAD_PARAMETER);

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

				rv = kmf_load_cert(kmfh, params, fname,
				    &certdata);

				if (rv == KMF_ERR_CERT_NOT_FOUND) {
					free(fname);
					if (certdata.Data)
						free(certdata.Data);
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
				if (certdata.Data)
					free(certdata.Data);
			}
		}
		(void) closedir(dirp);
	} else {
		/* Just try to load a single certificate */
		rv = kmf_load_cert(kmfh, params, fullpath, &certdata);
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

	if (certdata.Data)
		free(certdata.Data);

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
ssl_write_private_key(KMF_HANDLE *kmfh, KMF_ENCODE_FORMAT format, BIO *out,
	KMF_CREDENTIAL *cred, EVP_PKEY *pkey)
{
	int rv = 0;
	RSA *rsa;
	DSA *dsa;

	switch (format) {
		case KMF_FORMAT_ASN1:
			if (pkey->type == EVP_PKEY_RSA) {
				rsa = EVP_PKEY_get1_RSA(pkey);
				rv = i2d_RSAPrivateKey_bio(out, rsa);
				RSA_free(rsa);
			} else if (pkey->type == EVP_PKEY_DSA) {
				dsa = EVP_PKEY_get1_DSA(pkey);
				rv = i2d_DSAPrivateKey_bio(out, dsa);
				DSA_free(dsa);
			}
			if (rv == 1) {
				rv = KMF_OK;
			} else {
				SET_ERROR(kmfh, rv);
			}
			break;
		case KMF_FORMAT_PEM:
			if (pkey->type == EVP_PKEY_RSA) {
				rsa = EVP_PKEY_get1_RSA(pkey);
				rv = PEM_write_bio_RSAPrivateKey(out,
					rsa,
					NULL /* encryption type */,
					NULL, 0, NULL,
					cred->cred);
				RSA_free(rsa);
			} else if (pkey->type == EVP_PKEY_DSA) {
				dsa = EVP_PKEY_get1_DSA(pkey);
				rv = PEM_write_bio_DSAPrivateKey(out,
					dsa,
					NULL /* encryption type */,
					NULL, 0, NULL,
					cred->cred);
				DSA_free(dsa);
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
OpenSSL_CreateKeypair(KMF_HANDLE_T handle, KMF_CREATEKEYPAIR_PARAMS *params,
	KMF_KEY_HANDLE *privkey, KMF_KEY_HANDLE *pubkey)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	int format;
	uint32_t eValue = 0x010001;
	RSA *sslPrivKey = NULL;
	DSA *sslDSAKey = NULL;
	EVP_PKEY *eprikey = NULL;
	EVP_PKEY *epubkey = NULL;
	BIO *out = NULL;
	char *fullpath = NULL;

	if (params == NULL || params->sslparms.keyfile == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	fullpath = get_fullpath(params->sslparms.dirpath,
			params->sslparms.keyfile);

	if (fullpath == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* If the requested file exists, return an error */
	if (access(fullpath, F_OK) == 0) {
		free(fullpath);
		return (KMF_ERR_DUPLICATE_KEYFILE);
	}

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
	if (params->keytype == KMF_RSA) {
		if (params->rsa_exponent.len > 0 &&
		    params->rsa_exponent.len <= sizeof (eValue) &&
		    params->rsa_exponent.val != NULL)
			/*LINTED*/
			eValue = *(uint32_t *)params->rsa_exponent.val;

		sslPrivKey = RSA_generate_key(params->keylength, eValue,
			NULL, NULL);
		if (sslPrivKey == NULL) {
			SET_ERROR(kmfh, ERR_get_error());
			rv = KMF_ERR_KEYGEN_FAILED;
		} else {
			if (privkey != NULL &&
				EVP_PKEY_set1_RSA(eprikey, sslPrivKey)) {
				privkey->kstype = KMF_KEYSTORE_OPENSSL;
				privkey->keyalg = KMF_RSA;
				privkey->keyclass = KMF_ASYM_PRI;
				privkey->israw = FALSE;
				privkey->keylabel = (char *)strdup(fullpath);
				privkey->keyp = (void *)eprikey;
			}
			/* OpenSSL derives the public key from the private */
			if (pubkey != NULL &&
				EVP_PKEY_set1_RSA(epubkey, sslPrivKey)) {
				pubkey->kstype = KMF_KEYSTORE_OPENSSL;
				pubkey->keyalg = KMF_RSA;
				pubkey->israw = FALSE;
				pubkey->keyclass = KMF_ASYM_PUB;
				pubkey->keylabel = (char *)strdup(fullpath);
				pubkey->keyp = (void *)epubkey;
			}
		}
	} else if (params->keytype == KMF_DSA) {
		sslDSAKey = DSA_new();
		if (sslDSAKey == NULL) {
			SET_ERROR(kmfh, ERR_get_error());
			return (KMF_ERR_MEMORY);
		}

		if ((sslDSAKey->p = BN_bin2bn(P, sizeof (P), sslDSAKey->p)) ==
			NULL) {
			SET_ERROR(kmfh, ERR_get_error());
			rv = KMF_ERR_KEYGEN_FAILED;
			goto cleanup;
		}
		if ((sslDSAKey->q = BN_bin2bn(Q, sizeof (Q), sslDSAKey->q)) ==
			NULL) {
			SET_ERROR(kmfh, ERR_get_error());
			rv = KMF_ERR_KEYGEN_FAILED;
			goto cleanup;
		}
		if ((sslDSAKey->g = BN_bin2bn(G, sizeof (G), sslDSAKey->g)) ==
			NULL) {
			SET_ERROR(kmfh, ERR_get_error());
			rv = KMF_ERR_KEYGEN_FAILED;
			goto cleanup;
		}

		if (!DSA_generate_key(sslDSAKey)) {
			SET_ERROR(kmfh, ERR_get_error());
			rv = KMF_ERR_KEYGEN_FAILED;
			goto cleanup;
		}

		if (privkey != NULL) {
			privkey->kstype = KMF_KEYSTORE_OPENSSL;
			privkey->keyalg = KMF_DSA;
			privkey->keyclass = KMF_ASYM_PRI;
			privkey->israw = FALSE;
			privkey->keylabel = (char *)strdup(fullpath);
			if (EVP_PKEY_set1_DSA(eprikey, sslDSAKey)) {
				privkey->keyp = (void *)eprikey;
			} else {
				SET_ERROR(kmfh, ERR_get_error());
				rv = KMF_ERR_KEYGEN_FAILED;
				goto cleanup;
			}
		}
		if (pubkey != NULL) {
			DSA *dp = DSA_new();
			/* Make a copy for the public key */
			if (dp != NULL) {
				if ((dp->p = BN_new()) == NULL) {
					SET_ERROR(kmfh, ERR_get_error());
					rv = KMF_ERR_MEMORY;
					DSA_free(dp);
					goto cleanup;
				}
				if ((dp->q = BN_new()) == NULL) {
					SET_ERROR(kmfh, ERR_get_error());
					rv = KMF_ERR_MEMORY;
					BN_free(dp->p);
					DSA_free(dp);
					goto cleanup;
				}
				if ((dp->g = BN_new()) == NULL) {
					SET_ERROR(kmfh, ERR_get_error());
					rv = KMF_ERR_MEMORY;
					BN_free(dp->q);
					BN_free(dp->p);
					DSA_free(dp);
					goto cleanup;
				}
				if ((dp->pub_key = BN_new()) == NULL) {
					SET_ERROR(kmfh, ERR_get_error());
					rv = KMF_ERR_MEMORY;
					BN_free(dp->q);
					BN_free(dp->p);
					BN_free(dp->g);
					DSA_free(dp);
					goto cleanup;
				}
				(void) BN_copy(dp->p, sslDSAKey->p);
				(void) BN_copy(dp->q, sslDSAKey->q);
				(void) BN_copy(dp->g, sslDSAKey->g);
				(void) BN_copy(dp->pub_key, sslDSAKey->pub_key);

				pubkey->kstype = KMF_KEYSTORE_OPENSSL;
				pubkey->keyalg = KMF_DSA;
				pubkey->keyclass = KMF_ASYM_PUB;
				pubkey->israw = FALSE;
				pubkey->keylabel = (char *)strdup(fullpath);

				if (EVP_PKEY_set1_DSA(epubkey, sslDSAKey)) {
					pubkey->keyp = (void *)epubkey;
				} else {
					SET_ERROR(kmfh, ERR_get_error());
					rv = KMF_ERR_KEYGEN_FAILED;
					goto cleanup;
				}
			}
		}
	}

	if (rv != KMF_OK) {
		goto cleanup;
	}

	/* Store the private key to the keyfile */
	format = params->sslparms.format;
	out = BIO_new_file(fullpath, "wb");
	if (out == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		rv = KMF_ERR_OPEN_FILE;
		goto cleanup;
	}
	rv = ssl_write_private_key(kmfh, format, out, &params->cred, eprikey);

cleanup:
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

	if (fullpath)
		free(fullpath);

	/* Protect the file by making it read-only */
	if (rv == KMF_OK) {
		(void) chmod(fullpath, 0400);
	}
	return (rv);
}

KMF_RETURN
OpenSSL_SignData(KMF_HANDLE_T handle, KMF_KEY_HANDLE *key,
	KMF_OID *AlgOID, KMF_DATA *tobesigned, KMF_DATA *output)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	KMF_ALGORITHM_INDEX		AlgId;
	EVP_MD_CTX ctx;
	const EVP_MD *md;

	if (key == NULL || AlgOID == NULL ||
		tobesigned == NULL || output == NULL ||
		tobesigned->Data == NULL ||
		output->Data == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* Map the OID to an OpenSSL algorithm */
	AlgId = X509_AlgorithmOidToAlgId(AlgOID);
	if (AlgId == KMF_ALGID_NONE)
		return (KMF_ERR_BAD_PARAMETER);

	if (key->keyalg == KMF_RSA) {
		EVP_PKEY *pkey = (EVP_PKEY *)key->keyp;
		uchar_t *p;
		int len;
		if (AlgId == KMF_ALGID_MD5WithRSA)
			md = EVP_md5();
		else if (AlgId == KMF_ALGID_MD2WithRSA)
			md = EVP_md2();
		else if (AlgId == KMF_ALGID_SHA1WithRSA)
			md = EVP_sha1();
		else if (AlgId == KMF_ALGID_RSA)
			md = NULL;
		else
			return (KMF_ERR_BAD_PARAMETER);

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
			(void) EVP_MD_CTX_init(&ctx);
			(void) EVP_SignInit_ex(&ctx, md, NULL);
			(void) EVP_SignUpdate(&ctx, tobesigned->Data,
				(uint32_t)tobesigned->Length);
			len = (uint32_t)output->Length;
			p = output->Data;
			if (!EVP_SignFinal(&ctx, p, (uint32_t *)&len, pkey)) {
				SET_ERROR(kmfh, ERR_get_error());
				len = 0;
				ret = KMF_ERR_INTERNAL;
			}
			output->Length = len;
			(void) EVP_MD_CTX_cleanup(&ctx);
		}
	} else if (key->keyalg == KMF_DSA) {
		DSA *dsa = EVP_PKEY_get1_DSA(key->keyp);

		uchar_t hash[EVP_MAX_MD_SIZE];
		uint32_t hashlen;
		DSA_SIG *dsasig;

		/*
		 * OpenSSL EVP_Sign operation automatically converts to
		 * ASN.1 output so we do the operations separately so we
		 * are assured of NOT getting ASN.1 output returned.
		 * KMF does not want ASN.1 encoded results because
		 * not all mechanisms return ASN.1 encodings (PKCS#11
		 * and NSS return raw signature data).
		 */
		md = EVP_sha1();
		EVP_MD_CTX_init(&ctx);
		(void) EVP_DigestInit_ex(&ctx, md, NULL);
		(void) EVP_DigestUpdate(&ctx, tobesigned->Data,
			tobesigned->Length);
		(void) EVP_DigestFinal_ex(&ctx, hash, &hashlen);
		(void) EVP_MD_CTX_cleanup(&ctx);

		dsasig = DSA_do_sign(hash, hashlen, dsa);
		if (dsasig != NULL) {
			int i;
			output->Length = i = BN_bn2bin(dsasig->r, output->Data);
			output->Length += BN_bn2bin(dsasig->s,
				&output->Data[i]);
			DSA_SIG_free(dsasig);
		} else {
			SET_ERROR(kmfh, ERR_get_error());
		}
	} else {
		return (KMF_ERR_BAD_PARAMETER);
	}
cleanup:
	return (ret);
}

KMF_RETURN
/*ARGSUSED*/
OpenSSL_DeleteKey(KMF_HANDLE_T handle, KMF_DELETEKEY_PARAMS *params,
	KMF_KEY_HANDLE *key, boolean_t destroy)
{
	KMF_RETURN rv = KMF_OK;
	if (key == NULL || key->keyp == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (key->keyclass != KMF_ASYM_PUB &&
		key->keyclass != KMF_ASYM_PRI &&
		key->keyclass != KMF_SYMMETRIC)
		return (KMF_ERR_BAD_KEY_CLASS);

	if (key->keyclass == KMF_SYMMETRIC) {
		KMF_FreeRawSymKey((KMF_RAW_SYM_KEY *)key->keyp);
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
			free(key->keylabel);
			key->keylabel = NULL;
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
OpenSSL_ImportCRL(KMF_HANDLE_T handle, KMF_IMPORTCRL_PARAMS *params)
{
	KMF_RETURN 	ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	X509_CRL   	*xcrl = NULL;
	X509		*xcert = NULL;
	EVP_PKEY	*pkey;
	KMF_ENCODE_FORMAT format;
	BIO *in = NULL, *out = NULL;
	int openssl_ret = 0;
	char *outcrlfile = NULL;
	KMF_ENCODE_FORMAT outformat;

	if (params == NULL || params->sslparms.crlfile == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	if (params->sslparms.crl_check == B_TRUE &&
	    params->sslparms.certfile == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	outcrlfile = get_fullpath(params->sslparms.dirpath,
		params->sslparms.outcrlfile);

	if (outcrlfile == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (isdir(outcrlfile)) {
		free(outcrlfile);
		return (KMF_ERR_BAD_PARAMETER);
	}

	ret = KMF_IsCRLFile(handle, params->sslparms.crlfile, &format);
	if (ret != KMF_OK) {
		free(outcrlfile);
		return (ret);
	}

	in = BIO_new_file(params->sslparms.crlfile, "rb");
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
	if (params->sslparms.crl_check == B_FALSE) {
		goto output;
	}

	ret = KMF_IsCertFile(handle, params->sslparms.certfile, &format);
	if (ret != KMF_OK)
		goto end;

	/* Read in the CA cert file and convert to X509 */
	if (BIO_read_filename(in, params->sslparms.certfile) <= 0) {
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
	if (!pkey) {
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
	outformat = params->sslparms.format;

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
OpenSSL_ListCRL(KMF_HANDLE_T handle, KMF_LISTCRL_PARAMS *params,
    char **crldata)
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

	if (params == NULL || params->sslparms.crlfile == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	crlfile = get_fullpath(params->sslparms.dirpath,
		params->sslparms.crlfile);

	if (crlfile == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (isdir(crlfile)) {
		free(crlfile);
		return (KMF_ERR_BAD_PARAMETER);
	}

	ret = KMF_IsCRLFile(handle, crlfile, &format);
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
OpenSSL_DeleteCRL(KMF_HANDLE_T handle, KMF_DELETECRL_PARAMS *params)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	KMF_ENCODE_FORMAT format;
	char *crlfile = NULL;
	BIO *in = NULL;

	if (params == NULL || params->sslparms.crlfile == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	crlfile = get_fullpath(params->sslparms.dirpath,
		params->sslparms.crlfile);

	if (crlfile == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (isdir(crlfile)) {
		ret = KMF_ERR_BAD_PARAMETER;
		goto end;
	}

	ret = KMF_IsCRLFile(handle, crlfile, &format);
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
OpenSSL_FindCertInCRL(KMF_HANDLE_T handle, KMF_FINDCERTINCRL_PARAMS *params)
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

	if (params == NULL || params->sslparms.crlfile == NULL ||
	    params->sslparms.certfile == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	ret = KMF_IsCRLFile(handle, params->sslparms.crlfile, &format);
	if (ret != KMF_OK)
		return (ret);

	/* Read the CRL file and load it into a X509_CRL structure */
	in = BIO_new_file(params->sslparms.crlfile, "rb");
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
	ret = KMF_IsCertFile(handle, params->sslparms.certfile, &format);
	if (ret != KMF_OK)
		goto end;

	in = BIO_new_file(params->sslparms.certfile, "rb");
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
	if (X509_NAME_cmp(xcert->cert_info->issuer, xcrl->crl->issuer) != 0) {
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
		/*LINTED*/
		revoke = sk_X509_REVOKED_value(revoke_stack, i);
		if (ASN1_INTEGER_cmp(xcert->cert_info->serialNumber,
		    revoke->serialNumber) == 0) {
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
	char *tmpstr = NULL;
	int j;
	int ext_index, nid, len;
	BIO *mem = NULL;
	STACK *emlst = NULL;
	X509_EXTENSION *ex;
	X509_CINF *ci;

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
		tmpstr = i2s_ASN1_INTEGER(NULL, xcert->cert_info->version);
		(void) strncpy(resultStr, tmpstr, KMF_CERT_PRINTABLE_LEN);
		OPENSSL_free(tmpstr);
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
		(void) ASN1_TIME_print(mem, X509_get_notBefore(xcert));
		len = BIO_gets(mem, resultStr, KMF_CERT_PRINTABLE_LEN);
		break;

	case KMF_CERT_NOTAFTER:
		(void) ASN1_TIME_print(mem, X509_get_notAfter(xcert));
		len = BIO_gets(mem, resultStr, KMF_CERT_PRINTABLE_LEN);
		break;

	case KMF_CERT_PUBKEY_DATA:
		{
			EVP_PKEY *pkey = X509_get_pubkey(xcert);
			if (pkey == NULL) {
				SET_ERROR(kmfh, ERR_get_error());
				ret = KMF_ERR_ENCODING;
				goto out;
			}

			if (pkey->type == EVP_PKEY_RSA) {
				(void) BIO_printf(mem,
					"RSA Public Key: (%d bit)\n",
					BN_num_bits(pkey->pkey.rsa->n));
				(void) RSA_print(mem, pkey->pkey.rsa, 0);
			} else if (pkey->type == EVP_PKEY_DSA) {
				(void) BIO_printf(mem,
					"%12sDSA Public Key:\n", "");
				(void) DSA_print(mem, pkey->pkey.dsa, 0);
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
		if (flag == KMF_CERT_SIGNATURE_ALG) {
			len = i2a_ASN1_OBJECT(mem,
				xcert->sig_alg->algorithm);
		} else {
			len = i2a_ASN1_OBJECT(mem,
				xcert->cert_info->key->algor->algorithm);
		}

		if (len > 0) {
			len = BIO_read(mem, resultStr,
				KMF_CERT_PRINTABLE_LEN);
		}
		break;

	case KMF_CERT_EMAIL:
		emlst = X509_get1_email(xcert);
		for (j = 0; j < sk_num(emlst); j++)
			(void) BIO_printf(mem, "%s\n", sk_value(emlst, j));

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
		ci = xcert->cert_info;

		ext_index = X509v3_get_ext_by_NID(ci->extensions, nid, -1);
		if (ext_index == -1) {
			SET_ERROR(kmfh, ERR_get_error());

			ret = KMF_ERR_EXTENSION_NOT_FOUND;
			goto out;
		}
		ex = X509v3_get_ext(ci->extensions, ext_index);

		(void) i2a_ASN1_OBJECT(mem, X509_EXTENSION_get_object(ex));

		if (BIO_printf(mem, ": %s\n",
			X509_EXTENSION_get_critical(ex) ? "critical" : "") <=
			0) {
			SET_ERROR(kmfh, ERR_get_error());
			ret = KMF_ERR_ENCODING;
			goto out;
		}
		if (!X509V3_EXT_print(mem, ex, X509V3_EXT_DUMP_UNKNOWN, 4)) {
			(void) BIO_printf(mem, "%*s", 4, "");
			(void) M_ASN1_OCTET_STRING_print(mem, ex->value);
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
OpenSSL_GetPrikeyByCert(KMF_HANDLE_T handle,
	KMF_CRYPTOWITHCERT_PARAMS *params,
	KMF_DATA *SignerCertData, KMF_KEY_HANDLE *key,
	KMF_KEY_ALG keytype)
{
	KMF_RETURN rv = KMF_OK;
	KMF_FINDKEY_PARAMS fkparms;
	uint32_t numkeys = 0;

	if (params == NULL || params->sslparms.keyfile == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * This is really just a FindKey operation, reuse the
	 * FindKey function.
	 */
	(void *)memset(&fkparms, 0, sizeof (fkparms));
	fkparms.kstype = KMF_KEYSTORE_OPENSSL;
	fkparms.keyclass = KMF_ASYM_PRI;
	fkparms.keytype = keytype;
	fkparms.format = params->format;
	fkparms.sslparms = params->sslparms;

	rv = OpenSSL_FindKey(handle, &fkparms, key, &numkeys);

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
OpenSSL_CreateOCSPRequest(KMF_HANDLE_T handle, KMF_OCSPREQUEST_PARAMS *params,
    char *reqfile)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	OCSP_CERTID *id = NULL;
	OCSP_REQUEST *req = NULL;
	BIO *derbio = NULL;

	if (params->user_cert == NULL || params->issuer_cert == NULL ||
	    reqfile == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	ret = create_certid(handle, params->issuer_cert, params->user_cert,
	    &id);
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
	 * will deallocate certid's space also.
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
static X509 *ocsp_find_signer_sk(STACK_OF(X509) *certs, OCSP_RESPID *id)
{
	int i;
	unsigned char tmphash[SHA_DIGEST_LENGTH], *keyhash;

	/* Easy if lookup by name */
	if (id->type == V_OCSP_RESPID_NAME)
		return (X509_find_by_subject(certs, id->value.byName));

	/* Lookup by key hash */

	/* If key hash isn't SHA1 length then forget it */
	if (id->value.byKey->length != SHA_DIGEST_LENGTH)
		return (NULL);

	keyhash = id->value.byKey->data;
	/* Calculate hash of each key and compare */
	for (i = 0; i < sk_X509_num(certs); i++) {
		/*LINTED*/
		X509 *x = sk_X509_value(certs, i);
		(void) X509_pubkey_digest(x, EVP_sha1(), tmphash, NULL);
		if (!memcmp(keyhash, tmphash, SHA_DIGEST_LENGTH))
			return (x);
	}
	return (NULL);
}

/* ocsp_find_signer() is copied from openssl source */
/*ARGSUSED*/
static int
ocsp_find_signer(X509 **psigner, OCSP_BASICRESP *bs, STACK_OF(X509) *certs,
    X509_STORE *st, unsigned long flags)
{
	X509 *signer;
	OCSP_RESPID *rid = bs->tbsResponseData->responderId;
	if ((signer = ocsp_find_signer_sk(certs, rid)))	{
		*psigner = signer;
		return (2);
	}
	if (!(flags & OCSP_NOINTERN) &&
	    (signer = ocsp_find_signer_sk(bs->certs, rid))) {
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
	EVP_PKEY *skey = NULL;
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
	skey = X509_get_pubkey(signer);
	if (skey == NULL) {
		ret = KMF_ERR_OCSP_BAD_SIGNER;
		goto end;
	}

	ret = OCSP_BASICRESP_verify(bs, skey, 0);
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

	if (skey != NULL) {
		EVP_PKEY_free(skey);
	}

	if (cert_stack != NULL) {
		sk_X509_free(cert_stack);
	}

	return (ret);
}



KMF_RETURN
OpenSSL_GetOCSPStatusForCert(KMF_HANDLE_T handle,
    KMF_OCSPRESPONSE_PARAMS_INPUT *params_in,
    KMF_OCSPRESPONSE_PARAMS_OUTPUT *params_out)
{
	KMF_RETURN ret = KMF_OK;
	BIO *derbio = NULL;
	OCSP_RESPONSE *resp = NULL;
	OCSP_BASICRESP *bs = NULL;
	OCSP_CERTID *id = NULL;
	OCSP_SINGLERESP *single = NULL;
	ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;
	int index, status, reason;

	if (params_in == NULL || params_in->issuer_cert == NULL ||
	    params_in->user_cert == NULL || params_in->response == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	if (params_out == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	/* Read in the response */
	derbio = BIO_new_mem_buf(params_in->response->Data,
	    params_in->response->Length);
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
	params_out->response_status = status;
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
	if (params_in->ignore_response_sign == B_FALSE) {
		ret = check_response_signature(handle, bs,
		    params_in->signer_cert, params_in->issuer_cert);
		if (ret != KMF_OK)
			goto end;
	}

#ifdef DEBUG
	printf("Successfully verified the response signature.\n");
#endif /* DEBUG */

	/* Create a certid for the certificate in question */
	ret = create_certid(handle, params_in->issuer_cert,
	    params_in->user_cert, &id);
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
		params_out->cert_status = OCSP_GOOD;
	} else if (status == V_OCSP_CERTSTATUS_UNKNOWN) {
		params_out->cert_status = OCSP_UNKNOWN;
	} else { /* revoked */
		params_out->cert_status = OCSP_REVOKED;
		params_out->reason = reason;
	}
	ret = KMF_OK;

	/* Verify the time */
	if (!OCSP_check_validity(thisupd, nextupd, 300,
	    params_in->response_lifetime)) {
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
	EVP_PKEY *pkey;
	KMF_RAW_SYM_KEY *rkey = NULL;

	/* Make sure the requested file actually exists. */
	if (access(path, F_OK) != 0) {
		return (KMF_ERR_KEY_NOT_FOUND);
	}

	if (keyclass == KMF_ASYM_PRI ||
	    keyclass == KMF_ASYM_PUB) {
		pkey = openssl_load_key(handle, path);
		if (pkey == NULL) {
			return (KMF_ERR_KEY_NOT_FOUND);
		}
		if (key != NULL) {
			if (pkey->type == EVP_PKEY_RSA)
				key->keyalg = KMF_RSA;
			else if (pkey->type == EVP_PKEY_DSA)
				key->keyalg = KMF_DSA;

			key->kstype = KMF_KEYSTORE_OPENSSL;
			key->keyclass = keyclass;
			key->keyp = (void *)pkey;
			key->israw = FALSE;
			key->keylabel = path;
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
		rv = KMF_GetFileFormat(path, &fmt);
		if (rv == KMF_OK || fmt != 0) {
			return (KMF_ERR_KEY_NOT_FOUND);
		} else if (rv == KMF_ERR_ENCODING) {
			/*
			 * If we don't know the encoding,
			 * it is probably  a symmetric key.
			 */
			rv = KMF_OK;
		}

		if (key != NULL) {
			KMF_DATA keyvalue;
			rkey = malloc(sizeof (KMF_RAW_SYM_KEY));
			if (rkey == NULL) {
				rv = KMF_ERR_MEMORY;
				goto out;
			}

			(void) memset(rkey, 0, sizeof (KMF_RAW_SYM_KEY));
			rv = KMF_ReadInputFile(handle, path, &keyvalue);
			if (rv != KMF_OK)
				goto out;

			rkey->keydata.len = keyvalue.Length;
			rkey->keydata.val = keyvalue.Data;

			key->kstype = KMF_KEYSTORE_OPENSSL;
			key->keyclass = keyclass;
			key->israw = TRUE;
			key->keylabel = path;
			key->keyp = (void *)rkey;
		}
	}
out:
	if (rv != KMF_OK) {
		if (rkey != NULL) {
			KMF_FreeRawSymKey(rkey);
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
OpenSSL_FindKey(KMF_HANDLE_T handle, KMF_FINDKEY_PARAMS *params,
	KMF_KEY_HANDLE *key, uint32_t *numkeys)
{
	KMF_RETURN rv = KMF_OK;
	char *fullpath = NULL;

	if (handle == NULL || params == NULL || numkeys == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (params->keyclass != KMF_ASYM_PUB &&
		params->keyclass != KMF_ASYM_PRI &&
		params->keyclass != KMF_SYMMETRIC)
		return (KMF_ERR_BAD_KEY_CLASS);

	fullpath = get_fullpath(params->sslparms.dirpath,
		params->sslparms.keyfile);

	if (fullpath == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	*numkeys = 0;

	if (isdir(fullpath)) {
		DIR *dirp;
		struct dirent *dp;
		int n = 0;

		/* open all files in the directory and attempt to read them */
		if ((dirp = opendir(fullpath)) == NULL) {
			return (KMF_ERR_BAD_PARAMETER);
		}
		rewinddir(dirp);
		while ((dp = readdir(dirp)) != NULL) {
			if (strcmp(dp->d_name, ".") &&
			    strcmp(dp->d_name, "..")) {
				char *fname;

				fname = get_fullpath(fullpath,
					(char *)&dp->d_name);

				rv = fetch_key(handle, fname,
					params->keyclass,
					key ? &key[n] : NULL);

				if (rv == KMF_OK)
					n++;

				if (rv != KMF_OK || key == NULL)
					free(fname);
			}
		}
		(void) closedir(dirp);
		free(fullpath);
		(*numkeys) = n;
	} else {
		rv = fetch_key(handle, fullpath, params->keyclass, key);
		if (rv == KMF_OK)
			(*numkeys) = 1;

		if (rv != KMF_OK || key == NULL)
			free(fullpath);
	}

	if ((*numkeys) == 0)
		rv = KMF_ERR_KEY_NOT_FOUND;

	return (rv);
}

#define	HANDLE_PK12_ERROR { \
	SET_ERROR(kmfh, ERR_get_error()); \
	rv = KMF_ERR_ENCODING; \
	goto out; \
}

static KMF_RETURN
write_pkcs12(KMF_HANDLE *kmfh,
	BIO *bio,
	KMF_CREDENTIAL *cred,
	EVP_PKEY *pkey,
	X509 *sslcert)
{
	KMF_RETURN rv = KMF_OK;
	STACK_OF(PKCS12_SAFEBAG)	*bag_stack = NULL;
	PKCS12_SAFEBAG			*bag = NULL;
	PKCS7				*cert_authsafe = NULL;
	PKCS8_PRIV_KEY_INFO		*p8 = NULL;
	PKCS7				*key_authsafe = NULL;
	STACK_OF(PKCS7)			*authsafe_stack = NULL;
	PKCS12				*p12_elem = NULL;
	char				*lab = NULL;
	int				lab_len = 0;
	unsigned char keyid[EVP_MAX_MD_SIZE];
	unsigned int keyidlen = 0;

	/* Must have at least a cert OR a key */
	if (sslcert == NULL && pkey == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(keyid, 0, sizeof (keyid));
	/*
	 * Section 1:
	 *
	 * The first PKCS#12 container (safebag) will hold the certificates
	 * associated with this key.  The result of this section is a
	 * PIN-encrypted PKCS#7 container (authsafe).  If there are no
	 * certificates, there is no point in creating the "safebag" or the
	 * "authsafe" so we go to the next section.
	 */
	if (sslcert != NULL && pkey != NULL) {
		if (X509_check_private_key(sslcert, pkey)) {
			(void) X509_digest(sslcert, EVP_sha1(), keyid,
				&keyidlen);
		} else {
			/* The key doesn't match the cert */
			HANDLE_PK12_ERROR
		}
	}

	bag_stack = sk_PKCS12_SAFEBAG_new_null();
	if (bag_stack == NULL)
		return (KMF_ERR_MEMORY);

	if (sslcert != NULL) {
		/* Convert cert from X509 struct to PKCS#12 bag */
		bag = PKCS12_x5092certbag(sslcert);
		if (bag == NULL) {
			HANDLE_PK12_ERROR
		}

		/* Add the key id to the certificate bag. */
		if (keyidlen > 0 &&
			!PKCS12_add_localkeyid(bag, keyid, keyidlen)) {
			HANDLE_PK12_ERROR
		}

		/* Pile it on the bag_stack. */
		if (!sk_PKCS12_SAFEBAG_push(bag_stack, bag)) {
			HANDLE_PK12_ERROR
		}
#if 0
		/* No support for CA certs yet */
		if (cacerts != NULL && ncacerts > 0) {
			int i;
			for (i = 0; i < ncacerts; i++) {
				KMF_X509_DER_CERT *c = &cacerts[i];
				X509 *ca = NULL;

				uchar_t *p = (uchar_t *)c->certificate.Data;
				ca = d2i_X509(NULL, &p,
					c->certificate.Length);
				if (ca == NULL) {
					HANDLE_PK12_ERROR
				}
				/* Convert CA cert to PKCS#12 bag. */
				bag = PKCS12_x5092certbag(ca);
				if (bag == NULL) {
					sk_PKCS12_SAFEBAG_pop_free(bag_stack,
					    PKCS12_SAFEBAG_free);
					HANDLE_PK12_ERROR
				}
				/* Pile it onto the bag_stack. */
				if (!sk_PKCS12_SAFEBAG_push(bag_stack, bag)) {
					HANDLE_PK12_ERROR
				}
			}
		}
#endif
		/* Turn bag_stack of certs into encrypted authsafe. */
		cert_authsafe = PKCS12_pack_p7encdata(
			NID_pbe_WithSHA1And40BitRC2_CBC,
			cred->cred,
			cred->credlen, NULL, 0,
			PKCS12_DEFAULT_ITER,
			bag_stack);

		/* Clear away this bag_stack, we're done with it. */
		sk_PKCS12_SAFEBAG_pop_free(bag_stack, PKCS12_SAFEBAG_free);
		bag_stack = NULL;

		if (cert_authsafe == NULL) {
			HANDLE_PK12_ERROR
		}
	}
	/*
	 * Section 2:
	 *
	 * The second PKCS#12 container (safebag) will hold the private key
	 * that goes with the certificates above.  The results of this section
	 * is an unencrypted PKCS#7 container (authsafe).  If there is no
	 * private key, there is no point in creating the "safebag" or the
	 * "authsafe" so we go to the next section.
	 */
	if (pkey != NULL) {
		p8 = EVP_PKEY2PKCS8(pkey);
		if (p8 == NULL) {
			HANDLE_PK12_ERROR
		}
		/* Put the shrouded key into a PKCS#12 bag. */
		bag = PKCS12_MAKE_SHKEYBAG(
			NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
			cred->cred, cred->credlen,
			NULL, 0, PKCS12_DEFAULT_ITER, p8);

		/* Clean up the PKCS#8 shrouded key, don't need it now. */
		PKCS8_PRIV_KEY_INFO_free(p8);
		p8 = NULL;

		if (bag == NULL) {
			HANDLE_PK12_ERROR
		}
		if (keyidlen &&
			!PKCS12_add_localkeyid(bag, keyid, keyidlen)) {
			HANDLE_PK12_ERROR
		}
		if (lab != NULL) {
			if (!PKCS12_add_friendlyname(bag,
				(char *)lab, lab_len)) {
				HANDLE_PK12_ERROR
			}
		}
		/* Start a PKCS#12 safebag container for the private key. */
		bag_stack = sk_PKCS12_SAFEBAG_new_null();
		if (bag_stack == NULL) {
			HANDLE_PK12_ERROR
		}

		/* Pile on the private key on the bag_stack. */
		if (!sk_PKCS12_SAFEBAG_push(bag_stack, bag)) {
			HANDLE_PK12_ERROR
		}
		key_authsafe = PKCS12_pack_p7data(bag_stack);

		/* Clear away this bag_stack, we're done with it. */
		sk_PKCS12_SAFEBAG_pop_free(bag_stack, PKCS12_SAFEBAG_free);
		bag_stack = NULL;

		if (key_authsafe == NULL) {
			HANDLE_PK12_ERROR
		}
	}
	/*
	 * Section 3:
	 *
	 * This is where the two PKCS#7 containers, one for the certificates
	 * and one for the private key, are put together into a PKCS#12
	 * element.  This final PKCS#12 element is written to the export file.
	 */

	/* Start a PKCS#7 stack. */
	authsafe_stack = sk_PKCS7_new_null();
	if (authsafe_stack == NULL) {
		HANDLE_PK12_ERROR
	}
	if (key_authsafe != NULL) {
		if (!sk_PKCS7_push(authsafe_stack, key_authsafe)) {
			HANDLE_PK12_ERROR
		}
	}
	if (cert_authsafe != NULL) {
		if (!sk_PKCS7_push(authsafe_stack, cert_authsafe)) {
			HANDLE_PK12_ERROR
		}
	}
	p12_elem = PKCS12_init(NID_pkcs7_data);
	if (p12_elem == NULL) {
		sk_PKCS7_pop_free(authsafe_stack, PKCS7_free);
		HANDLE_PK12_ERROR
	}

	/* Put the PKCS#7 stack into the PKCS#12 element. */
	if (!PKCS12_pack_authsafes(p12_elem, authsafe_stack)) {
		HANDLE_PK12_ERROR
	}
	/* Clear away the PKCS#7 stack, we're done with it. */
	sk_PKCS7_pop_free(authsafe_stack, PKCS7_free);
	authsafe_stack = NULL;

	/* Set the integrity MAC on the PKCS#12 element. */
	if (!PKCS12_set_mac(p12_elem, cred->cred, cred->credlen,
		NULL, 0, PKCS12_DEFAULT_ITER, NULL)) {
		HANDLE_PK12_ERROR
	}

	/* Write the PKCS#12 element to the export file. */
	if (!i2d_PKCS12_bio(bio, p12_elem)) {
		HANDLE_PK12_ERROR
	}

	PKCS12_free(p12_elem);
out:
	if (rv != KMF_OK) {
		/* Clear away this bag_stack, we're done with it. */
		sk_PKCS12_SAFEBAG_pop_free(bag_stack, PKCS12_SAFEBAG_free);
		sk_PKCS7_pop_free(authsafe_stack, PKCS7_free);
	}
	return (rv);
}

static EVP_PKEY *
ImportRawRSAKey(KMF_RAW_RSA_KEY *key)
{
	RSA		*rsa = NULL;
	EVP_PKEY 	*newkey = NULL;

	if ((rsa = RSA_new()) == NULL)
		return (NULL);

	if ((rsa->n = BN_bin2bn(key->mod.val, key->mod.len, rsa->n)) == NULL)
		return (NULL);

	if ((rsa->e = BN_bin2bn(key->pubexp.val, key->pubexp.len, rsa->e)) ==
		NULL)
		return (NULL);

	if (key->priexp.val != NULL)
		if ((rsa->d = BN_bin2bn(key->priexp.val, key->priexp.len,
			rsa->d)) == NULL)
			return (NULL);

	if (key->prime1.val != NULL)
		if ((rsa->p = BN_bin2bn(key->prime1.val, key->prime1.len,
			rsa->p)) == NULL)
			return (NULL);

	if (key->prime2.val != NULL)
		if ((rsa->q = BN_bin2bn(key->prime2.val, key->prime2.len,
			rsa->q)) == NULL)
			return (NULL);

	if (key->exp1.val != NULL)
		if ((rsa->dmp1 = BN_bin2bn(key->exp1.val, key->exp1.len,
			rsa->dmp1)) == NULL)
			return (NULL);

	if (key->exp2.val != NULL)
		if ((rsa->dmq1 = BN_bin2bn(key->exp2.val, key->exp2.len,
			rsa->dmq1)) == NULL)
			return (NULL);

	if (key->coef.val != NULL)
		if ((rsa->iqmp = BN_bin2bn(key->coef.val, key->coef.len,
			rsa->iqmp)) == NULL)
			return (NULL);

	if ((newkey = EVP_PKEY_new()) == NULL)
		return (NULL);

	(void) EVP_PKEY_set1_RSA(newkey, rsa);

	/* The original key must be freed once here or it leaks memory */
	RSA_free(rsa);

	return (newkey);
}

static EVP_PKEY *
ImportRawDSAKey(KMF_RAW_DSA_KEY *key)
{
	DSA		*dsa = NULL;
	EVP_PKEY 	*newkey = NULL;

	if ((dsa = DSA_new()) == NULL)
		return (NULL);

	if ((dsa->p = BN_bin2bn(key->prime.val, key->prime.len,
		dsa->p)) == NULL)
		return (NULL);

	if ((dsa->q = BN_bin2bn(key->subprime.val, key->subprime.len,
		dsa->q)) == NULL)
		return (NULL);

	if ((dsa->g = BN_bin2bn(key->base.val, key->base.len,
		dsa->g)) == NULL)
		return (NULL);

	if ((dsa->priv_key = BN_bin2bn(key->value.val, key->value.len,
		dsa->priv_key)) == NULL)
		return (NULL);

	if ((newkey = EVP_PKEY_new()) == NULL)
		return (NULL);

	(void) EVP_PKEY_set1_DSA(newkey, dsa);

	/* The original key must be freed once here or it leaks memory */
	DSA_free(dsa);
	return (newkey);
}

static KMF_RETURN
ExportPK12FromRawData(KMF_HANDLE_T handle,
	KMF_CREDENTIAL *cred,
	int numcerts, KMF_X509_DER_CERT *certlist,
	int numkeys, KMF_KEY_HANDLE *keylist,
	char *filename)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	BIO *bio = NULL;
	X509 *xcert = NULL;
	EVP_PKEY *pkey = NULL;
	int i;

	/*
	 * Open the output file.
	 */
	if ((bio = BIO_new_file(filename, "wb")) == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		rv = KMF_ERR_OPEN_FILE;
		goto cleanup;
	}

	if (numcerts > 0 && numkeys > 0) {
		for (i = 0; rv == KMF_OK && i < numcerts; i++) {
			KMF_RAW_KEY_DATA *key = NULL;
			const uchar_t *p = certlist[i].certificate.Data;
			long len = certlist[i].certificate.Length;

			if (i < numkeys) {
				key = (KMF_RAW_KEY_DATA *)keylist[i].keyp;

				if (key->keytype == KMF_RSA) {
					pkey = ImportRawRSAKey(
						&key->rawdata.rsa);
				} else if (key->keytype == KMF_DSA) {
					pkey = ImportRawDSAKey(
						&key->rawdata.dsa);
				} else {
					rv = KMF_ERR_BAD_PARAMETER;
				}
			}

			xcert = d2i_X509(NULL, &p, len);
			if (xcert == NULL) {
				SET_ERROR(kmfh, ERR_get_error());
				rv = KMF_ERR_ENCODING;
			}
			/* Stick the key and the cert into a PKCS#12 file */
			rv = write_pkcs12(kmfh, bio, cred, pkey, xcert);
			if (xcert)
				X509_free(xcert);
			if (pkey)
				EVP_PKEY_free(pkey);
		}
	}

cleanup:

	if (bio != NULL)
		(void) BIO_free_all(bio);

	return (rv);
}

KMF_RETURN
OpenSSL_ExportP12(KMF_HANDLE_T handle,
	KMF_EXPORTP12_PARAMS *params,
	int numcerts, KMF_X509_DER_CERT *certlist,
	int numkeys, KMF_KEY_HANDLE *keylist,
	char *filename)
{
	KMF_RETURN rv;
	KMF_HANDLE *kmfh = (KMF_HANDLE  *)handle;
	KMF_FINDCERT_PARAMS fcargs;
	BIO *bio = NULL;
	X509 *xcert = NULL;
	char *fullpath = NULL;
	EVP_PKEY *pkey = NULL;

	/*
	 *  First, find the certificate.
	 */
	if (params == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * If the caller already sent the raw keys and certs,
	 * shortcut the search and just export that
	 * data.
	 *
	 * One *may* export a key OR a cert by itself.
	 */
	if (certlist != NULL || keylist != NULL) {
		rv = ExportPK12FromRawData(handle,
			&params->p12cred,
			numcerts, certlist,
			numkeys, keylist,
			filename);
		return (rv);
	}

	if (params->sslparms.certfile != NULL) {
		fullpath = get_fullpath(params->sslparms.dirpath,
			params->sslparms.certfile);

		if (fullpath == NULL)
			return (KMF_ERR_BAD_PARAMETER);

		if (isdir(fullpath)) {
			free(fullpath);
			return (KMF_ERR_AMBIGUOUS_PATHNAME);
		}

		(void *)memset(&fcargs, 0, sizeof (fcargs));
		fcargs.kstype = params->kstype;
		fcargs.certLabel = params->certLabel;
		fcargs.issuer = params->issuer;
		fcargs.subject = params->subject;
		fcargs.serial = params->serial;
		fcargs.idstr = params->idstr;
		fcargs.sslparms.dirpath = NULL;
		fcargs.sslparms.certfile = fullpath;
		fcargs.sslparms.format = params->sslparms.format;

		rv = load_X509cert(kmfh, &fcargs, fullpath, &xcert);
		if (rv != KMF_OK)
			goto end;
	}

	/*
	 * Now find the private key.
	 */
	if (params->sslparms.keyfile != NULL) {
		fullpath = get_fullpath(params->sslparms.dirpath,
			params->sslparms.keyfile);

		if (fullpath == NULL)
			return (KMF_ERR_BAD_PARAMETER);

		if (isdir(fullpath)) {
			free(fullpath);
			return (KMF_ERR_AMBIGUOUS_PATHNAME);
		}

		pkey = openssl_load_key(handle, fullpath);
		if (pkey == NULL) {
			rv = KMF_ERR_KEY_NOT_FOUND;
			goto end;
		}
	}

	/*
	 * Open the output file.
	 */
	if ((bio = BIO_new_file(filename, "wb")) == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		rv = KMF_ERR_OPEN_FILE;
		goto end;
	}

	/* Stick the key and the cert into a PKCS#12 file */
	rv = write_pkcs12(kmfh, bio, &params->p12cred,
		pkey, xcert);

end:
	if (fullpath)
		free(fullpath);
	if (xcert)
		X509_free(xcert);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (bio)
		(void) BIO_free(bio);

	return (rv);
}

#define	MAX_CHAIN_LENGTH 100
/*
 * Helper function to extract keys and certificates from
 * a single PEM file.  Typically the file should contain a
 * private key and an associated public key wrapped in an x509 cert.
 * However, the file may be just a list of X509 certs with no keys.
 */
static KMF_RETURN
extract_objects(KMF_HANDLE *kmfh, KMF_FINDCERT_PARAMS *params,
	char *filename, CK_UTF8CHAR *pin,
	CK_ULONG pinlen, EVP_PKEY **priv_key, KMF_DATA **certs,
	int *numcerts)
/* ARGSUSED */
{
	KMF_RETURN rv = KMF_OK;
	FILE *fp;
	STACK_OF(X509_INFO) *x509_info_stack;
	int i, ncerts = 0, matchcerts = 0;
	EVP_PKEY *pkey = NULL;
	X509_INFO *info;
	X509 *x;
	X509_INFO *cert_infos[MAX_CHAIN_LENGTH];
	KMF_DATA *certlist = NULL;

	if (priv_key)
		*priv_key = NULL;
	if (certs)
		*certs = NULL;
	fp = fopen(filename, "r");
	if (fp == NULL) {
		return (KMF_ERR_OPEN_FILE);
	}
	x509_info_stack = PEM_X509_INFO_read(fp, NULL, NULL, pin);
	if (x509_info_stack == NULL) {
		(void) fclose(fp);
		return (KMF_ERR_ENCODING);
	}

	/*LINTED*/
	while ((info = sk_X509_INFO_pop(x509_info_stack)) != NULL &&
		ncerts < MAX_CHAIN_LENGTH) {
		cert_infos[ncerts] = info;
		ncerts++;
	}

	if (ncerts == 0) {
		(void) fclose(fp);
		return (KMF_ERR_CERT_NOT_FOUND);
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
		return (KMF_ERR_KEY_MISMATCH);
	}

	certlist = (KMF_DATA *)malloc(ncerts * sizeof (KMF_DATA));
	if (certlist == NULL) {
		if (pkey != NULL)
			EVP_PKEY_free(pkey);
		X509_INFO_free(info);
		return (KMF_ERR_MEMORY);
	}

	/*
	 * Convert all of the certs to DER format.
	 */
	matchcerts = 0;
	for (i = 0; rv == KMF_OK && certs != NULL && i < ncerts; i++) {
		boolean_t match = FALSE;
		info =  cert_infos[ncerts - 1 - i];

		if (params != NULL) {
			rv = check_cert(info->x509, params, &match);
			if (rv != KMF_OK || match != TRUE) {
				X509_INFO_free(info);
				rv = KMF_OK;
				continue;
			}
		}

		rv = ssl_cert2KMFDATA(kmfh, info->x509,
			&certlist[matchcerts++]);

		if (rv != KMF_OK) {
			free(certlist);
			certlist = NULL;
			ncerts = matchcerts = 0;
		}

		X509_INFO_free(info);
	}

	if (numcerts != NULL)
		*numcerts = matchcerts;
	if (certs != NULL)
		*certs = certlist;

	if (priv_key == NULL && pkey != NULL)
		EVP_PKEY_free(pkey);
	else if (priv_key != NULL && pkey != NULL)
		*priv_key = pkey;

	return (rv);
}

/*
 * Helper function to decrypt and parse PKCS#12 import file.
 */
static KMF_RETURN
extract_pkcs12(BIO *fbio, CK_UTF8CHAR *pin, CK_ULONG pinlen,
	EVP_PKEY **priv_key, X509 **cert, STACK_OF(X509) **ca)
/* ARGSUSED */
{
	PKCS12		*pk12, *pk12_tmp;
	EVP_PKEY	*temp_pkey = NULL;
	X509		*temp_cert = NULL;
	STACK_OF(X509)	*temp_ca = NULL;

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

	if (PKCS12_parse(pk12, (char *)pin, &temp_pkey, &temp_cert,
	    &temp_ca) <= 0) {
		PKCS12_free(pk12);
		return (KMF_ERR_PKCS12_FORMAT);
	}

end_extract_pkcs12:

	*priv_key = temp_pkey;
	*cert = temp_cert;
	*ca = temp_ca;

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

	(void) memset(kmfkey, 0, sizeof (KMF_RAW_RSA_KEY));
	if ((rv = sslBN2KMFBN(rsa->n, &kmfkey->mod)) != KMF_OK)
		goto cleanup;

	if ((rv = sslBN2KMFBN(rsa->e, &kmfkey->pubexp)) != KMF_OK)
		goto cleanup;

	if (rsa->d != NULL)
		if ((rv = sslBN2KMFBN(rsa->d, &kmfkey->priexp)) != KMF_OK)
			goto cleanup;

	if (rsa->p != NULL)
		if ((rv = sslBN2KMFBN(rsa->p, &kmfkey->prime1)) != KMF_OK)
			goto cleanup;

	if (rsa->q != NULL)
		if ((rv = sslBN2KMFBN(rsa->q, &kmfkey->prime2)) != KMF_OK)
			goto cleanup;

	if (rsa->dmp1 != NULL)
		if ((rv = sslBN2KMFBN(rsa->dmp1, &kmfkey->exp1)) != KMF_OK)
			goto cleanup;

	if (rsa->dmq1 != NULL)
		if ((rv = sslBN2KMFBN(rsa->dmq1, &kmfkey->exp2)) != KMF_OK)
			goto cleanup;

	if (rsa->iqmp != NULL)
		if ((rv = sslBN2KMFBN(rsa->iqmp, &kmfkey->coef)) != KMF_OK)
			goto cleanup;
cleanup:
	if (rv != KMF_OK)
		KMF_FreeRawKey(key);
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

	(void) memset(kmfkey, 0, sizeof (KMF_RAW_DSA_KEY));
	if ((rv = sslBN2KMFBN(dsa->p, &kmfkey->prime)) != KMF_OK)
		goto cleanup;

	if ((rv = sslBN2KMFBN(dsa->q, &kmfkey->subprime)) != KMF_OK)
		goto cleanup;

	if ((rv = sslBN2KMFBN(dsa->g, &kmfkey->base)) != KMF_OK)
		goto cleanup;

	if ((rv = sslBN2KMFBN(dsa->priv_key, &kmfkey->value)) != KMF_OK)
		goto cleanup;

cleanup:
	if (rv != KMF_OK)
		KMF_FreeRawKey(key);
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
	KMF_DATA **certlist, int *ncerts)
{
	KMF_RETURN rv = KMF_OK;
	KMF_DATA *list = (*certlist);
	KMF_DATA cert;
	int n = (*ncerts);

	if (list == NULL) {
		list = (KMF_DATA *)malloc(sizeof (KMF_DATA));
	} else {
		list = (KMF_DATA *)realloc(list, sizeof (KMF_DATA) * (n + 1));
	}

	if (list == NULL)
		return (KMF_ERR_MEMORY);

	rv = ssl_cert2KMFDATA(kmfh, sslcert, &cert);
	if (rv == KMF_OK) {
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
convertPK12Objects(
	KMF_HANDLE *kmfh,
	EVP_PKEY *sslkey, X509 *sslcert, STACK_OF(X509) *sslcacerts,
	KMF_RAW_KEY_DATA **keylist, int *nkeys,
	KMF_DATA **certlist, int *ncerts)
{
	KMF_RETURN rv = KMF_OK;
	KMF_RAW_KEY_DATA key;
	int i;

	if (sslkey != NULL) {
		/* Convert SSL key to raw key */
		switch (sslkey->type) {
			case EVP_PKEY_RSA:
				rv = exportRawRSAKey(EVP_PKEY_get1_RSA(sslkey),
					&key);
				if (rv != KMF_OK)
					return (rv);

				break;
			case EVP_PKEY_DSA:
				rv = exportRawDSAKey(EVP_PKEY_get1_DSA(sslkey),
					&key);
				if (rv != KMF_OK)
					return (rv);

				break;
			default:
				return (KMF_ERR_BAD_PARAMETER);
		}

		rv = add_key_to_list(keylist, &key, nkeys);
		if (rv != KMF_OK)
			return (rv);
	}

	/* Now add the certificate to the certlist */
	if (sslcert != NULL) {
		rv = add_cert_to_list(kmfh, sslcert, certlist, ncerts);
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
openssl_read_pkcs12(KMF_HANDLE *kmfh,
	char *filename, KMF_CREDENTIAL *cred,
	KMF_DATA **certlist, int *ncerts,
	KMF_RAW_KEY_DATA **keylist, int *nkeys)
{
	KMF_RETURN	rv = KMF_OK;
	BIO		*bio = NULL;
	EVP_PKEY	*privkey = NULL;
	X509		*cert = NULL;
	STACK_OF(X509)	*cacerts = NULL;

	bio = BIO_new_file(filename, "rb");
	if (bio == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		rv = KMF_ERR_OPEN_FILE;
		goto end;
	}

	*certlist = NULL;
	*keylist = NULL;
	*ncerts = 0;
	*nkeys = 0;
	while (rv == KMF_OK) {
		rv = extract_pkcs12(bio,
			(uchar_t *)cred->cred,
			(uint32_t)cred->credlen,
			&privkey, &cert, &cacerts);

		/* Reached end of import file? */
		if (rv == KMF_OK && privkey == NULL &&
			cert == NULL && cacerts == NULL)
			break;

		if (rv == KMF_OK)
			/* Convert keys and certs to exportable format */
			rv = convertPK12Objects(kmfh, privkey, cert, cacerts,
				keylist, nkeys, certlist, ncerts);

		if (privkey)
			EVP_PKEY_free(privkey);

		if (cert)
			X509_free(cert);

		if (cacerts)
			sk_X509_free(cacerts);
	}
end:
	if (bio != NULL)
		(void) BIO_free(bio);

	if (privkey)
		EVP_PKEY_free(privkey);

	if (cert)
		X509_free(cert);

	if (cacerts)
		sk_X509_free(cacerts);

	return (rv);
}

KMF_RETURN
openssl_import_keypair(KMF_HANDLE *kmfh,
	char *filename, KMF_CREDENTIAL *cred,
	KMF_DATA **certlist, int *ncerts,
	KMF_RAW_KEY_DATA **keylist, int *nkeys)
{
	KMF_RETURN	rv = KMF_OK;
	EVP_PKEY	*privkey = NULL;
	KMF_ENCODE_FORMAT format;

	/*
	 * auto-detect the file format, regardless of what
	 * the 'format' parameters in the params say.
	 */
	rv = KMF_GetFileFormat(filename, &format);
	if (rv != KMF_OK) {
		if (rv == KMF_ERR_OPEN_FILE)
			rv = KMF_ERR_CERT_NOT_FOUND;
		return (rv);
	}

	/* This function only works on PEM files */
	if (format != KMF_FORMAT_PEM &&
		format != KMF_FORMAT_PEM_KEYPAIR)
		return (KMF_ERR_ENCODING);

	*certlist = NULL;
	*keylist = NULL;
	*ncerts = 0;
	*nkeys = 0;
	rv = extract_objects(kmfh, NULL, filename,
		(uchar_t *)cred->cred,
		(uint32_t)cred->credlen,
		&privkey, certlist, ncerts);

	/* Reached end of import file? */
	if (rv == KMF_OK)
		/* Convert keys and certs to exportable format */
		rv = convertPK12Objects(kmfh, privkey, NULL, NULL,
			keylist, nkeys, NULL, NULL);

end:
	if (privkey)
		EVP_PKEY_free(privkey);

	return (rv);
}

KMF_RETURN
OpenSSL_StorePrivateKey(KMF_HANDLE_T handle, KMF_STOREKEY_PARAMS *params,
	KMF_RAW_KEY_DATA *key)
{
	KMF_RETURN	rv = KMF_OK;
	KMF_HANDLE	*kmfh = (KMF_HANDLE *)handle;
	char		*fullpath;
	EVP_PKEY	*pkey = NULL;
	BIO		*bio = NULL;

	if (key != NULL) {
		if (key->keytype == KMF_RSA) {
			pkey = ImportRawRSAKey(&key->rawdata.rsa);
		} else if (key->keytype == KMF_DSA) {
			pkey = ImportRawDSAKey(&key->rawdata.dsa);
		} else {
			rv = KMF_ERR_BAD_PARAMETER;
		}
	} else {
		rv = KMF_ERR_BAD_PARAMETER;
	}
	if (rv != KMF_OK || pkey == NULL)
		return (rv);

	fullpath = get_fullpath(params->sslparms.dirpath,
			params->sslparms.keyfile);

	if (fullpath == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* If the requested file exists, return an error */
	if (access(fullpath, F_OK) == 0) {
		free(fullpath);
		return (KMF_ERR_DUPLICATE_KEYFILE);
	}

	bio = BIO_new_file(fullpath, "wb");
	if (bio == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		rv = KMF_ERR_OPEN_FILE;
		goto cleanup;
	}

	rv = ssl_write_private_key(kmfh,
		params->sslparms.format,
		bio, &params->cred, pkey);

cleanup:
	if (fullpath)
		free(fullpath);

	if (pkey)
		EVP_PKEY_free(pkey);

	if (bio)
		(void) BIO_free(bio);

	/* Protect the file by making it read-only */
	if (rv == KMF_OK) {
		(void) chmod(fullpath, 0400);
	}
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
OpenSSL_CreateSymKey(KMF_HANDLE_T handle, KMF_CREATESYMKEY_PARAMS *params,
	KMF_KEY_HANDLE *symkey)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	char *fullpath = NULL;
	KMF_RAW_SYM_KEY *rkey = NULL;
	DES_cblock *deskey = NULL;
	unsigned char *des3key = NULL;
	unsigned char *random = NULL;
	int fd = -1;

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED);

	if (params == NULL || params->sslparms.keyfile == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	fullpath = get_fullpath(params->sslparms.dirpath,
		params->sslparms.keyfile);
	if (fullpath == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* If the requested file exists, return an error */
	if (access(fullpath, F_OK) == 0) {
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

	if (params->keytype == KMF_DES) {
		if ((ret = create_deskey(&deskey)) != KMF_OK) {
			goto out;
		}
		rkey->keydata.val = (uchar_t *)deskey;
		rkey->keydata.len = 8;

		symkey->keyalg = KMF_DES;

	} else if (params->keytype == KMF_DES3) {
		if ((ret = create_des3key(&des3key)) != KMF_OK) {
			goto out;
		}
		rkey->keydata.val = (uchar_t *)des3key;
		rkey->keydata.len = DES3_KEY_SIZE;
		symkey->keyalg = KMF_DES3;
	} else if (params->keytype == KMF_AES || params->keytype == KMF_RC4 ||
	    params->keytype == KMF_GENERIC_SECRET) {
		int bytes;

		if (params->keylength % 8 != 0) {
			ret = KMF_ERR_BAD_KEY_SIZE;
			goto out;
		}

		if (params->keytype == KMF_AES) {
			if (params->keylength != 128 &&
			    params->keylength != 192 &&
			    params->keylength != 256) {
				ret = KMF_ERR_BAD_KEY_SIZE;
				goto out;
			}
		}

		bytes = params->keylength/8;
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
		symkey->keyalg = params->keytype;

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
		KMF_FreeRawSymKey(rkey);
		symkey->keyp = NULL;
		symkey->keyalg = KMF_KEYALG_NONE;
	}

	return (ret);
}


KMF_RETURN
OpenSSL_VerifyCRLFile(KMF_HANDLE_T handle, KMF_VERIFYCRL_PARAMS *params)
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

	if (params->crl_name == NULL || params->tacert == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	ret = KMF_GetFileFormat(params->crl_name, &crl_format);
	if (ret != KMF_OK)
		return (ret);

	bcrl = BIO_new_file(params->crl_name, "rb");
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

	p = params->tacert->Data;
	len = params->tacert->Length;
	xcert = d2i_X509(NULL, (const uchar_t **)&p, len);

	if (xcert == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_BAD_CERTFILE;
		goto cleanup;
	}

	/* Get issuer certificate public key */
	pkey = X509_get_pubkey(xcert);
	if (!pkey) {
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
OpenSSL_CheckCRLDate(KMF_HANDLE_T handle,
	KMF_CHECKCRLDATE_PARAMS *params)
{

	KMF_RETURN	ret = KMF_OK;
	KMF_HANDLE	*kmfh = (KMF_HANDLE *)handle;
	KMF_ENCODE_FORMAT crl_format;
	BIO		*bcrl = NULL;
	X509_CRL   	*xcrl = NULL;
	int		i;

	if (params == NULL || params->crl_name == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	ret = KMF_IsCRLFile(handle, params->crl_name, &crl_format);
	if (ret != KMF_OK)
		return (ret);

	bcrl = BIO_new_file(params->crl_name, "rb");
	if (bcrl == NULL)	{
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_OPEN_FILE;
		goto cleanup;
	}

	if (crl_format == KMF_FORMAT_ASN1) {
		xcrl = d2i_X509_CRL_bio(bcrl, NULL);
	} else if (crl_format == KMF_FORMAT_PEM) {
		xcrl = PEM_read_bio_X509_CRL(bcrl, NULL, NULL, NULL);
	}

	if (xcrl == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_BAD_CRLFILE;
		goto cleanup;
	}

	i = X509_cmp_time(X509_CRL_get_lastUpdate(xcrl), NULL);
	if (i >= 0) {
		ret = KMF_ERR_VALIDITY_PERIOD;
		goto cleanup;
	}

	if (X509_CRL_get_nextUpdate(xcrl)) {
		i = X509_cmp_time(X509_CRL_get_nextUpdate(xcrl), NULL);

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

/*
 * Check a file to see if it is a certficate file with PEM or DER format.
 * If success, return its format in the pformat argument.
 */
KMF_RETURN
OpenSSL_IsCertFile(KMF_HANDLE_T handle, char *filename,
	KMF_ENCODE_FORMAT *pformat)
{
	KMF_RETURN	ret = KMF_OK;
	KMF_HANDLE	*kmfh = (KMF_HANDLE *)handle;
	BIO		*bio = NULL;
	X509		*xcert = NULL;

	if (filename == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	ret = KMF_GetFileFormat(filename, pformat);
	if (ret != KMF_OK)
		return (ret);

	bio = BIO_new_file(filename, "rb");
	if (bio == NULL)	{
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_OPEN_FILE;
		goto out;
	}

	if ((*pformat) == KMF_FORMAT_PEM) {
		if ((xcert = PEM_read_bio_X509(bio, NULL,
			NULL, NULL)) == NULL) {
			ret = KMF_ERR_BAD_CERTFILE;
		}
	} else if ((*pformat) == KMF_FORMAT_ASN1) {
		if ((xcert = d2i_X509_bio(bio, NULL)) == NULL) {
			ret = KMF_ERR_BAD_CERTFILE;
		}
	} else {
		ret = KMF_ERR_BAD_CERTFILE;
	}

out:
	if (bio != NULL)
		(void) BIO_free(bio);

	if (xcert != NULL)
		X509_free(xcert);

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
		rv = KMF_ReadInputFile(handle, symkey->keylabel, &keyvalue);
		if (rv != KMF_OK)
			return (rv);
		rkey->keydata.len = keyvalue.Length;
		rkey->keydata.val = keyvalue.Data;
	}

	return (rv);
}

/*
 * id-sha1    OBJECT IDENTIFIER ::= {
 *     iso(1) identified-organization(3) oiw(14) secsig(3)
 *     algorithms(2) 26
 * }
 */
#define	ASN1_SHA1_OID_PREFIX_LEN 15
static uchar_t SHA1_DER_PREFIX[ASN1_SHA1_OID_PREFIX_LEN] = {
	0x30, 0x21, 0x30, 0x09,
	0x06, 0x05, 0x2b, 0x0e,
	0x03, 0x02, 0x1a, 0x05,
	0x00, 0x04, 0x14
};

/*
 * id-md2 OBJECT IDENTIFIER ::= {
 *     iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 2
 * }
 */
#define	ASN1_MD2_OID_PREFIX_LEN 18
static uchar_t MD2_DER_PREFIX[ASN1_MD2_OID_PREFIX_LEN] = {
	0x30, 0x20, 0x30, 0x0c,
	0x06, 0x08, 0x2a, 0x86,
	0x48, 0x86, 0xf7, 0x0d,
	0x02, 0x02, 0x05, 0x00,
	0x04, 0x10
};

/*
 * id-md5 OBJECT IDENTIFIER ::= {
 *     iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 5
 * }
 */
#define	ASN1_MD5_OID_PREFIX_LEN 18
static uchar_t MD5_DER_PREFIX[ASN1_MD5_OID_PREFIX_LEN] = {
	0x30, 0x20, 0x30, 0x0c,
	0x06, 0x08, 0x2a, 0x86,
	0x48, 0x86, 0xf7, 0x0d,
	0x02, 0x05, 0x05, 0x00,
	0x04, 0x10
};

KMF_RETURN
OpenSSL_VerifyDataWithCert(KMF_HANDLE_T handle,
	KMF_ALGORITHM_INDEX algid, KMF_DATA *indata,
	KMF_DATA *insig, KMF_DATA *cert)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE	*kmfh = (KMF_HANDLE *)handle;
	X509	*xcert = NULL;
	EVP_PKEY *pkey = NULL;
	uchar_t *p;
	uchar_t *rsaout = NULL;
	uchar_t *pfx = NULL;
	const EVP_MD *md;
	int pfxlen = 0, len;

	if (handle == NULL || indata == NULL ||
	    indata->Data == NULL || indata->Length == 0 ||
	    insig == NULL|| insig->Data == NULL || insig->Length == 0 ||
	    cert == NULL || cert->Data == NULL || cert->Length == 0)
		return (KMF_ERR_BAD_PARAMETER);

	p = cert->Data;
	xcert = d2i_X509(NULL, (const uchar_t **)&p, cert->Length);
	if (xcert == NULL) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	pkey = X509_get_pubkey(xcert);
	if (!pkey) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_BAD_CERT_FORMAT;
		goto cleanup;
	}

	if (algid != KMF_ALGID_NONE) {
		switch (algid) {
			case KMF_ALGID_MD5WithRSA:
				md = EVP_md5();
				break;
			case KMF_ALGID_MD2WithRSA:
				md = EVP_md2();
				break;
			case KMF_ALGID_SHA1WithRSA:
				md = EVP_sha1();
				break;
			case KMF_ALGID_RSA:
				md = NULL;
				break;
			default:
				ret = KMF_ERR_BAD_PARAMETER;
				goto cleanup;
		}
	} else {
		/* Get the hash type from the cert signature */
		md = EVP_get_digestbyobj(xcert->sig_alg->algorithm);
		if (md == NULL) {
			SET_ERROR(kmfh, ERR_get_error());
			ret = KMF_ERR_BAD_PARAMETER;
			goto cleanup;
		}
	}
	switch (EVP_MD_type(md)) {
		case NID_md2:
		case NID_md2WithRSAEncryption:
			pfxlen = ASN1_MD2_OID_PREFIX_LEN;
			pfx = MD2_DER_PREFIX;
			break;
		case NID_md5:
		case NID_md5WithRSAEncryption:
			pfxlen = ASN1_MD5_OID_PREFIX_LEN;
			pfx = MD5_DER_PREFIX;
			break;
		case NID_sha1:
		case NID_sha1WithRSAEncryption:
			pfxlen = ASN1_SHA1_OID_PREFIX_LEN;
			pfx = SHA1_DER_PREFIX;
			break;
		default: /* Unsupported */
			pfxlen = 0;
			pfx = NULL;
			break;
	}

	/* RSA with no hash is a special case */
	rsaout = malloc(RSA_size(pkey->pkey.rsa));
	if (rsaout == NULL)
		return (KMF_ERR_MEMORY);

	/* Decrypt the input signature */
	len = RSA_public_decrypt(insig->Length,
		insig->Data, rsaout, pkey->pkey.rsa, RSA_PKCS1_PADDING);
	if (len < 1) {
		SET_ERROR(kmfh, ERR_get_error());
		ret = KMF_ERR_BAD_PARAMETER;
	} else {
		size_t hashlen = 0;
		uint32_t dlen;
		char *digest = NULL;

		/*
		 * If the AlgId requires it, hash the input data before
		 * comparing it to the decrypted signature.
		 */
		if (md) {
			EVP_MD_CTX ctx;

			hashlen = md->md_size;

			digest = malloc(hashlen + pfxlen);
			if (digest == NULL)
				return (KMF_ERR_MEMORY);
			/* Add the prefix to the comparison buffer. */
			if (pfx && pfxlen > 0) {
				(void) memcpy(digest, pfx, pfxlen);
			}
			(void) EVP_DigestInit(&ctx, md);
			(void) EVP_DigestUpdate(&ctx, indata->Data,
				indata->Length);

			/* Add the digest AFTER the ASN1 prefix */
			(void) EVP_DigestFinal(&ctx,
				(uchar_t *)digest + pfxlen, &dlen);

			dlen += pfxlen;
		} else {
			digest = (char *)indata->Data;
			dlen = indata->Length;
		}

		/*
		 * The result of the RSA decryption should be ASN1(OID | Hash).
		 * Compare the output hash to the input data for the final
		 * result.
		 */
		if (memcmp(rsaout, digest, dlen))
			ret = KMF_ERR_INTERNAL;
		else
			ret = KMF_OK;

		/* If we had to allocate space for the digest, free it now */
		if (hashlen)
			free(digest);
	}
cleanup:
	if (pkey)
		EVP_PKEY_free(pkey);

	if (xcert)
		X509_free(xcert);

	if (rsaout)
		free(rsaout);

	return (ret);
}
