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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef _KMFAPIP_H
#define	_KMFAPIP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <kmfapi.h>
#include <kmfpolicy.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Plugin function table */
typedef struct {
	ushort_t	version;
	KMF_RETURN	(*ConfigureKeystore) (
			KMF_HANDLE_T,
			KMF_CONFIG_PARAMS *);

	KMF_RETURN	(*FindCert) (
			KMF_HANDLE_T,
			KMF_FINDCERT_PARAMS	*,
			KMF_X509_DER_CERT *,
			uint32_t *);

	void		(*FreeKMFCert) (
			KMF_HANDLE_T,
			KMF_X509_DER_CERT *);

	KMF_RETURN	(*StoreCert) (
			KMF_HANDLE_T,
			KMF_STORECERT_PARAMS *,
			KMF_DATA *);

	KMF_RETURN	(*ImportCert) (
			KMF_HANDLE_T,
			KMF_IMPORTCERT_PARAMS *);

	KMF_RETURN	(*ImportCRL) (
			KMF_HANDLE_T,
			KMF_IMPORTCRL_PARAMS *);

	KMF_RETURN	(*DeleteCert) (
			KMF_HANDLE_T,
			KMF_DELETECERT_PARAMS *);

	KMF_RETURN	(*DeleteCRL) (
			KMF_HANDLE_T,
			KMF_DELETECRL_PARAMS *);

	KMF_RETURN	(*CreateKeypair) (
			KMF_HANDLE_T,
			KMF_CREATEKEYPAIR_PARAMS *,
			KMF_KEY_HANDLE *,
			KMF_KEY_HANDLE *);

	KMF_RETURN	(*FindKey) (
			KMF_HANDLE_T,
			KMF_FINDKEY_PARAMS *,
			KMF_KEY_HANDLE *,
			uint32_t *);

	KMF_RETURN	(*EncodePubkeyData) (
			KMF_HANDLE_T,
			KMF_KEY_HANDLE *,
			KMF_DATA *);

	KMF_RETURN	(*SignData) (
			KMF_HANDLE_T,
			KMF_KEY_HANDLE *,
			KMF_OID *,
			KMF_DATA *,
			KMF_DATA *);

	KMF_RETURN	(*DeleteKey) (
			KMF_HANDLE_T,
			KMF_DELETEKEY_PARAMS *,
			KMF_KEY_HANDLE *,
			boolean_t);

	KMF_RETURN	(*ListCRL) (
			KMF_HANDLE_T,
			KMF_LISTCRL_PARAMS *,
			char **);

	KMF_RETURN	(*FindCRL) (
			KMF_HANDLE_T,
			KMF_FINDCRL_PARAMS *,
			char **,
			int *);

	KMF_RETURN	(*FindCertInCRL) (
			KMF_HANDLE_T,
			KMF_FINDCERTINCRL_PARAMS *);

	KMF_RETURN	(*GetErrorString) (
			KMF_HANDLE_T,
			char **);

	KMF_RETURN	(*GetPrikeyByCert) (
			KMF_HANDLE_T,
			KMF_CRYPTOWITHCERT_PARAMS *,
			KMF_DATA *,
			KMF_KEY_HANDLE *,
			KMF_KEY_ALG);

	KMF_RETURN	(*DecryptData) (
			KMF_HANDLE_T,
			KMF_KEY_HANDLE *,
			KMF_OID *,
			KMF_DATA *,
			KMF_DATA *);

	KMF_RETURN	(*ExportP12)(
			KMF_HANDLE_T,
			KMF_EXPORTP12_PARAMS *,
			int, KMF_X509_DER_CERT *,
			int, KMF_KEY_HANDLE *,
			char *);

	KMF_RETURN	(*StorePrivateKey)(
			KMF_HANDLE_T,
			KMF_STOREKEY_PARAMS *,
			KMF_RAW_KEY_DATA *);

	KMF_RETURN	(*CreateSymKey) (
			KMF_HANDLE_T,
			KMF_CREATESYMKEY_PARAMS *,
			KMF_KEY_HANDLE *);

	KMF_RETURN	(*GetSymKeyValue) (
			KMF_HANDLE_T,
			KMF_KEY_HANDLE *,
			KMF_RAW_SYM_KEY *);

	KMF_RETURN	(*SetTokenPin) (
			KMF_HANDLE_T,
			KMF_SETPIN_PARAMS *,
			KMF_CREDENTIAL *);

	void		(*Finalize) ();

} KMF_PLUGIN_FUNCLIST;

typedef struct {
	KMF_KEYSTORE_TYPE	type;
	char			*applications;
	char 			*path;
	void 			*dldesc;
	KMF_PLUGIN_FUNCLIST	*funclist;
} KMF_PLUGIN;

typedef struct _KMF_PLUGIN_LIST {
	KMF_PLUGIN		*plugin;
	struct _KMF_PLUGIN_LIST *next;
} KMF_PLUGIN_LIST;

typedef struct _kmf_handle {
	/*
	 * session handle opened by KMF_SelectToken() to talk
	 * to a specific slot in Crypto framework. It is used
	 * by pkcs11 plugin module.
	 */
	CK_SESSION_HANDLE	pk11handle;
	KMF_ERROR		lasterr;
	KMF_POLICY_RECORD	*policy;
	KMF_PLUGIN_LIST		*plugins;
} KMF_HANDLE;

#define	CLEAR_ERROR(h, rv) { \
	if (h == NULL) { \
		rv = KMF_ERR_BAD_PARAMETER; \
	} else { \
		h->lasterr.errcode = 0; \
		h->lasterr.kstype = 0; \
		rv = KMF_OK; \
	} \
}

#define	KMF_PLUGIN_INIT_SYMBOL	"KMF_Plugin_Initialize"

#ifndef KMF_PLUGIN_PATH
#if defined(__sparcv9)
#define	KMF_PLUGIN_PATH "/usr/lib/security/sparcv9/"
#elif defined(__sparc)
#define	KMF_PLUGIN_PATH "/usr/lib/security/"
#elif defined(__i386)
#define	KMF_PLUGIN_PATH "/usr/lib/security/"
#elif defined(__amd64)
#define	KMF_PLUGIN_PATH "/usr/lib/security/amd64/"
#endif
#endif /* !KMF_PLUGIN_PATH */

KMF_PLUGIN_FUNCLIST *KMF_Plugin_Initialize();

KMF_RETURN
SignCert(KMF_HANDLE_T, const KMF_DATA *, KMF_KEY_HANDLE *, KMF_DATA *);

KMF_RETURN
VerifyCertWithKey(KMF_HANDLE_T, KMF_DATA *, const KMF_DATA *);

KMF_RETURN
VerifyCertWithCert(KMF_HANDLE_T, const KMF_DATA *, const KMF_DATA *);

KMF_RETURN
VerifyDataWithCert(KMF_HANDLE_T, KMF_DATA *, KMF_DATA *, const KMF_DATA *);

KMF_RETURN
VerifyDataWithKey(KMF_HANDLE_T, KMF_DATA *, KMF_ALGORITHM_INDEX, KMF_DATA *,
	KMF_DATA *);

KMF_RETURN
EncryptWithCert(KMF_HANDLE_T, KMF_DATA *, KMF_DATA *, KMF_DATA *);

KMF_RETURN
DecryptWithCert(KMF_HANDLE_T, KMF_DATA *, KMF_KEY_HANDLE *, KMF_DATA *,
	KMF_DATA *);

KMF_RETURN
SignCsr(KMF_HANDLE_T, const KMF_DATA *, KMF_KEY_HANDLE *,
		KMF_X509_ALGORITHM_IDENTIFIER *, KMF_DATA *);

KMF_BOOL PKCS_ConvertAlgorithmId2PKCSKeyType(
	KMF_ALGORITHM_INDEX, CK_KEY_TYPE *);

KMF_RETURN PKCS_VerifyData(
	KMF_HANDLE *,
	KMF_ALGORITHM_INDEX,
	KMF_X509_SPKI *,
	KMF_DATA *, KMF_DATA *);

KMF_RETURN PKCS_EncryptData(
	KMF_HANDLE *,
	KMF_ALGORITHM_INDEX,
	KMF_X509_SPKI *,
	KMF_DATA *,
	KMF_DATA *);

KMF_PLUGIN *FindPlugin(KMF_HANDLE_T, KMF_KEYSTORE_TYPE);

KMF_BOOL IsEqualOid(KMF_OID *, KMF_OID *);

KMF_OID *X509_AlgIdToAlgorithmOid(KMF_ALGORITHM_INDEX);

KMF_ALGORITHM_INDEX X509_AlgorithmOidToAlgId(KMF_OID *);
KMF_RETURN GetIDFromSPKI(KMF_X509_SPKI *, KMF_DATA *);
CK_RV DigestData(CK_SESSION_HANDLE, KMF_DATA *, KMF_DATA *);

KMF_RETURN KMF_SetAltName(KMF_X509_EXTENSIONS *,
	KMF_OID *, int, KMF_GENERALNAMECHOICES, char *);
KMF_RETURN GetSequenceContents(char *, size_t, char **, size_t *);
KMF_X509_EXTENSION *FindExtn(KMF_X509_EXTENSIONS *, KMF_OID *);
KMF_RETURN add_an_extension(KMF_X509_EXTENSIONS *exts,
	KMF_X509_EXTENSION *newextn);
KMF_RETURN set_integer(KMF_DATA *, void *, int);
void free_keyidlist(KMF_OID *, int);
KMF_RETURN copy_data(KMF_DATA *, KMF_DATA *);
void Cleanup_PK11_Session(KMF_HANDLE_T handle);
void free_dp_name(KMF_CRL_DIST_POINT *);
void free_dp(KMF_CRL_DIST_POINT *);
KMF_RETURN set_key_usage_extension(KMF_X509_EXTENSIONS *,
	int, uint32_t);
int is_pk11_ready();
KMF_RETURN KMF_SelectToken(KMF_HANDLE_T, char *, int);


/* Indexes into the key parts array for RSA keys */
#define	KMF_RSA_MODULUS			(0)
#define	KMF_RSA_PUBLIC_EXPONENT		(1)
#define	KMF_RSA_PRIVATE_EXPONENT	(2)
#define	KMF_RSA_PRIME1			(3)
#define	KMF_RSA_PRIME2			(4)
#define	KMF_RSA_EXPONENT1		(5)
#define	KMF_RSA_EXPONENT2		(6)
#define	KMF_RSA_COEFFICIENT		(7)

/* Key part counts for RSA keys */
#define	KMF_NUMBER_RSA_PUBLIC_KEY_PARTS		(2)
#define	KMF_NUMBER_RSA_PRIVATE_KEY_PARTS	(8)

/* Key part counts for DSA keys */
#define	KMF_NUMBER_DSA_PUBLIC_KEY_PARTS		(4)
#define	KMF_NUMBER_DSA_PRIVATE_KEY_PARTS	(4)

/* Indexes into the key parts array for DSA keys */
#define	KMF_DSA_PRIME		(0)
#define	KMF_DSA_SUB_PRIME	(1)
#define	KMF_DSA_BASE		(2)
#define	KMF_DSA_PUBLIC_VALUE	(3)

#ifndef max
#define	max(a, b) ((a) < (b) ? (b) : (a))
#endif

/* Maximum key parts for all algorithms */
#define	KMF_MAX_PUBLIC_KEY_PARTS \
	(max(KMF_NUMBER_RSA_PUBLIC_KEY_PARTS, \
	KMF_NUMBER_DSA_PUBLIC_KEY_PARTS))

#define	KMF_MAX_PRIVATE_KEY_PARTS \
	(max(KMF_NUMBER_RSA_PRIVATE_KEY_PARTS, \
	KMF_NUMBER_DSA_PRIVATE_KEY_PARTS))

#define	KMF_MAX_KEY_PARTS \
	(max(KMF_MAX_PUBLIC_KEY_PARTS, KMF_MAX_PRIVATE_KEY_PARTS))

typedef enum {
	KMF_ALGMODE_NONE	= 0,
	KMF_ALGMODE_CUSTOM,
	KMF_ALGMODE_PUBLIC_KEY,
	KMF_ALGMODE_PRIVATE_KEY,
	KMF_ALGMODE_PKCS1_EMSA_V15
} KMF_SIGNATURE_MODE;

#define	KMF_CERT_PRINTABLE_LEN	1024
#define	SHA1_HASH_LENGTH 20

#define	OCSPREQ_TEMPNAME	"/tmp/ocsp.reqXXXXXX"
#define	OCSPRESP_TEMPNAME	"/tmp/ocsp.respXXXXXX"

#ifdef __cplusplus
}
#endif
#endif /* _KMFAPIP_H */
