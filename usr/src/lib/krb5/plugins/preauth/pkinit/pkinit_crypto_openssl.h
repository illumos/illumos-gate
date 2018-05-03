/*
 * COPYRIGHT (C) 2006,2007
 * THE REGENTS OF THE UNIVERSITY OF MICHIGAN
 * ALL RIGHTS RESERVED
 *
 * Permission is granted to use, copy, create derivative works
 * and redistribute this software and such derivative works
 * for any purpose, so long as the name of The University of
 * Michigan is not used in any advertising or publicity
 * pertaining to the use of distribution of this software
 * without specific, written prior authorization.  If the
 * above copyright notice or any other identification of the
 * University of Michigan is included in any copy of any
 * portion of this software, then the disclaimer below must
 * also be included.
 *
 * THIS SOFTWARE IS PROVIDED AS IS, WITHOUT REPRESENTATION
 * FROM THE UNIVERSITY OF MICHIGAN AS TO ITS FITNESS FOR ANY
 * PURPOSE, AND WITHOUT WARRANTY BY THE UNIVERSITY OF
 * MICHIGAN OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING
 * WITHOUT LIMITATION THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
 * REGENTS OF THE UNIVERSITY OF MICHIGAN SHALL NOT BE LIABLE
 * FOR ANY DAMAGES, INCLUDING SPECIAL, INDIRECT, INCIDENTAL, OR
 * CONSEQUENTIAL DAMAGES, WITH RESPECT TO ANY CLAIM ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OF THE SOFTWARE, EVEN
 * IF IT HAS BEEN OR IS HEREAFTER ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGES.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef _PKINIT_CRYPTO_OPENSSL_H
#define _PKINIT_CRYPTO_OPENSSL_H

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/obj_mac.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <openssl/asn1_mac.h>
#else
#include <openssl/asn1t.h>
#endif

#include "pkinit.h"

#define DN_BUF_LEN  256
#define MAX_CREDS_ALLOWED 20

struct _pkinit_cred_info {
    X509 *cert;
    EVP_PKEY *key;
#ifndef WITHOUT_PKCS11
    CK_BYTE_PTR cert_id;
    int cert_id_len;
#endif
};
typedef struct _pkinit_cred_info * pkinit_cred_info;

struct _pkinit_identity_crypto_context {
    pkinit_cred_info creds[MAX_CREDS_ALLOWED+1];
    STACK_OF(X509) *my_certs;   /* available user certs */
    int cert_index;             /* cert to use out of available certs*/
    EVP_PKEY *my_key;           /* available user keys if in filesystem */
    STACK_OF(X509) *trustedCAs; /* available trusted ca certs */
    STACK_OF(X509) *intermediateCAs;   /* available intermediate ca certs */
    STACK_OF(X509_CRL) *revoked;    /* available crls */
    int pkcs11_method;
    krb5_prompter_fct prompter;
    void *prompter_data;
#ifndef WITHOUT_PKCS11
    char *p11_module_name;
    CK_SLOT_ID slotid;
    char *token_label;
    char *cert_label;
    char *PIN; /* Solaris Kerberos: */
    /* These are crypto-specific */
    void *p11_module;
    CK_SESSION_HANDLE session;
    CK_FUNCTION_LIST_PTR p11;
    CK_BYTE_PTR cert_id;
    int cert_id_len;
    CK_MECHANISM_TYPE mech;
    /* Solaris Kerberos: need to keep some state */
    uint_t p11flags;
    /*
     * Solaris Kerberos:
     * If PKCS#11 is already being used by the process then C_Finalize should
     * not be called by pkinit as it would invalidate any PKCS#11 sessions the
     * process was using prior to loading the pkinit plugin. "finalize_pkcs11"
     * indicates whether or not C_Finalize should be called by pkinit.
     */
    krb5_boolean finalize_pkcs11;
#endif
};

/* Solaris Kerberos: need to know if login was done */
#define	C_LOGIN_DONE 0x1 /* The session is logged in. */
#define	C_PROMPTED_USER 0x2 /* The user was prompted for token. */
#define	C_SKIP_PKCS11_AUTH 0x4 /* User does not want to do PKCS11 auth */

struct _pkinit_plg_crypto_context {
    DH *dh_1024;
    DH *dh_2048;
    DH *dh_4096;
    ASN1_OBJECT *id_pkinit_authData;
    ASN1_OBJECT *id_pkinit_authData9;
    ASN1_OBJECT *id_pkinit_DHKeyData;
    ASN1_OBJECT *id_pkinit_rkeyData;
    ASN1_OBJECT *id_pkinit_san;
    ASN1_OBJECT *id_ms_san_upn;
    ASN1_OBJECT *id_pkinit_KPClientAuth;
    ASN1_OBJECT *id_pkinit_KPKdc;
    ASN1_OBJECT *id_ms_kp_sc_logon;
    ASN1_OBJECT *id_kp_serverAuth;
};

struct _pkinit_req_crypto_context {
    X509 *received_cert;
    DH *dh;
};

#define CERT_MAGIC 0x53534c43
struct _pkinit_cert_data {
    unsigned int magic;
    pkinit_plg_crypto_context plgctx;
    pkinit_req_crypto_context reqctx;
    pkinit_identity_crypto_context idctx;
    pkinit_cred_info cred;
    unsigned int index;	    /* Index of this cred in the creds[] array */
};

#define ITER_MAGIC 0x53534c49
struct _pkinit_cert_iter_data {
    unsigned int magic;
    pkinit_plg_crypto_context plgctx;
    pkinit_req_crypto_context reqctx;
    pkinit_identity_crypto_context idctx;
    unsigned int index;
};

/* Solaris Kerberos */
static krb5_error_code openssl_init(void);

static krb5_error_code pkinit_init_pkinit_oids(pkinit_plg_crypto_context );
static void pkinit_fini_pkinit_oids(pkinit_plg_crypto_context );

static krb5_error_code pkinit_init_dh_params(pkinit_plg_crypto_context );
static void pkinit_fini_dh_params(pkinit_plg_crypto_context );

static krb5_error_code pkinit_init_certs(pkinit_identity_crypto_context ctx);
static void pkinit_fini_certs(pkinit_identity_crypto_context ctx);

static krb5_error_code pkinit_init_pkcs11(pkinit_identity_crypto_context ctx);
static void pkinit_fini_pkcs11(pkinit_identity_crypto_context ctx);

static krb5_error_code pkinit_encode_dh_params
	(const BIGNUM *, const BIGNUM *, const BIGNUM *,
		unsigned char **, unsigned int *);
static DH *pkinit_decode_dh_params
	(DH **, unsigned char **, unsigned int );
static int pkinit_check_dh_params
	(const BIGNUM *p1, const BIGNUM *p2, const BIGNUM *g1,
		const BIGNUM *q1);

static krb5_error_code pkinit_sign_data
	(krb5_context context, pkinit_identity_crypto_context cryptoctx,
		unsigned char *data, unsigned int data_len,
		unsigned char **sig, unsigned int *sig_len);

static krb5_error_code create_signature
	(unsigned char **, unsigned int *, unsigned char *, unsigned int,
		EVP_PKEY *pkey);

static krb5_error_code pkinit_decode_data
	(krb5_context context, pkinit_identity_crypto_context cryptoctx,
		unsigned char *data, unsigned int data_len,
		unsigned char **decoded, unsigned int *decoded_len);

static krb5_error_code decode_data
	(unsigned char **, unsigned int *, unsigned char *, unsigned int,
		EVP_PKEY *pkey, X509 *cert);

#ifdef DEBUG_DH
static void print_dh(DH *, char *);
static void print_pubkey(BIGNUM *, char *);
#endif

static int prepare_enc_data
	(unsigned char *indata, int indata_len, unsigned char **outdata,
		int *outdata_len);

static int openssl_callback (int, X509_STORE_CTX *);
static int openssl_callback_ignore_crls (int, X509_STORE_CTX *);

static int pkcs7_decrypt
	(krb5_context context, pkinit_identity_crypto_context id_cryptoctx,
		PKCS7 *p7, BIO *bio);

static BIO * pkcs7_dataDecode
	(krb5_context context, pkinit_identity_crypto_context id_cryptoctx,
		PKCS7 *p7);

static ASN1_OBJECT * pkinit_pkcs7type2oid
	(pkinit_plg_crypto_context plg_cryptoctx, int pkcs7_type);

static krb5_error_code pkinit_create_sequence_of_principal_identifiers
	(krb5_context context, pkinit_plg_crypto_context plg_cryptoctx,
		pkinit_req_crypto_context req_cryptoctx,
		pkinit_identity_crypto_context id_cryptoctx,
		int type, krb5_data **out_data);

#ifndef WITHOUT_PKCS11
static krb5_error_code pkinit_find_private_key
	(pkinit_identity_crypto_context, CK_ATTRIBUTE_TYPE usage,
		CK_OBJECT_HANDLE *objp);
static krb5_error_code pkinit_login
	(krb5_context context, pkinit_identity_crypto_context id_cryptoctx,
		CK_TOKEN_INFO *tip);
static void * pkinit_C_LoadModule(const char *modname, CK_FUNCTION_LIST_PTR_PTR p11p);
static CK_RV pkinit_C_UnloadModule(void *handle);
#ifdef SILLYDECRYPT
CK_RV pkinit_C_Decrypt
	(pkinit_identity_crypto_context id_cryptoctx,
		CK_BYTE_PTR pEncryptedData, CK_ULONG  ulEncryptedDataLen,
		CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
#endif

static krb5_error_code pkinit_sign_data_pkcs11
	(krb5_context context, pkinit_identity_crypto_context id_cryptoctx,
		unsigned char *data, unsigned int data_len,
		unsigned char **sig, unsigned int *sig_len);
static krb5_error_code pkinit_decode_data_pkcs11
	(krb5_context context, pkinit_identity_crypto_context id_cryptoctx,
		unsigned char *data, unsigned int data_len,
		unsigned char **decoded_data, unsigned int *decoded_data_len);
#endif	/* WITHOUT_PKCS11 */

static krb5_error_code pkinit_sign_data_fs
	(krb5_context context, pkinit_identity_crypto_context id_cryptoctx,
		unsigned char *data, unsigned int data_len,
		unsigned char **sig, unsigned int *sig_len);
static krb5_error_code pkinit_decode_data_fs
	(krb5_context context, pkinit_identity_crypto_context id_cryptoctx,
		unsigned char *data, unsigned int data_len,
		unsigned char **decoded_data, unsigned int *decoded_data_len);

static krb5_error_code der_decode_data
	(unsigned char *, long, unsigned char **, long *);

static krb5_error_code
create_krb5_invalidCertificates(krb5_context context,
				pkinit_plg_crypto_context plg_cryptoctx,
				pkinit_req_crypto_context req_cryptoctx,
				pkinit_identity_crypto_context id_cryptoctx,
				krb5_external_principal_identifier *** ids);

static krb5_error_code
create_identifiers_from_stack(STACK_OF(X509) *sk,
			      krb5_external_principal_identifier *** ids);
#ifdef LONGHORN_BETA_COMPAT
static int
wrap_signeddata(unsigned char *data, unsigned int data_len,
		unsigned char **out, unsigned int *out_len,
		int is_longhorn_server);
#else
static int
wrap_signeddata(unsigned char *data, unsigned int data_len,
		unsigned char **out, unsigned int *out_len);
#endif

/* This handy macro borrowed from crypto/x509v3/v3_purp.c */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define ku_reject(x, usage) \
	(((x)->ex_flags & EXFLAG_KUSAGE) && !((x)->ex_kusage & (usage)))
#else
#define ku_reject(x, usage) \
	((X509_get_extension_flags(x) & EXFLAG_KUSAGE) && \
	!(X509_get_key_usage(x) & (usage)))
#endif

static char *
pkinit_pkcs11_code_to_text(int err);

#endif	/* _PKINIT_CRYPTO_OPENSSL_H */
