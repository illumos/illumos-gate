/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2018 RackTop Systems.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef LIBCRYPTO_COMPAT_H
#define	LIBCRYPTO_COMPAT_H

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ecdsa.h>
#include <openssl/dh.h>
#include <openssl/evp.h>

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q);
int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp);
void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e,
    const BIGNUM **d);
void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q);
void RSA_get0_crt_params(const RSA *r, const BIGNUM **dmp1,
    const BIGNUM **dmq1, const BIGNUM **iqmp);

void DSA_get0_pqg(const DSA *d, const BIGNUM **p, const BIGNUM **q,
    const BIGNUM **g);
int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g);
void DSA_get0_key(const DSA *d, const BIGNUM **pub_key,
    const BIGNUM **priv_key);
int DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key);

void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s);
DSA *EVP_PKEY_get0_DSA(EVP_PKEY *pkey);

void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);

void DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q,
    const BIGNUM **g);
int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g);
void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key);
int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key);
int DH_set_length(DH *dh, long length);

const unsigned char *EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx);
unsigned char *EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx);
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
#define	EVP_CIPHER_impl_ctx_size(e) e->ctx_size
#define	EVP_CIPHER_CTX_get_cipher_data(ctx) ctx->cipher_data

RSA_METHOD *RSA_meth_dup(const RSA_METHOD *meth);
int RSA_meth_set1_name(RSA_METHOD *meth, const char *name);
#define	RSA_meth_get_finish(meth) meth->finish
int RSA_meth_set_priv_enc(RSA_METHOD *meth,
    int (*priv_enc) (int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding));
int RSA_meth_set_priv_dec(RSA_METHOD *meth,
    int (*priv_dec) (int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding));
int RSA_meth_set_finish(RSA_METHOD *meth, int (*finish) (RSA *rsa));
void RSA_meth_free(RSA_METHOD *meth);

int RSA_bits(const RSA *r);

RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey);

#define	OCSP_resp_get0_certs(bs) ((bs)->certs)
#define	PKCS12_SAFEBAG_get0_attr(bag, attr) PKCS12_get_attr(bag, attr)
#define	PKCS12_SAFEBAG_get_nid(bag) M_PKCS12_bag_type(bag)
#define	PKCS12_SAFEBAG_get0_p8inf(bag) ((bag)->value.keybag)
#define	PKCS12_SAFEBAG_get0_safes(bag) ((bag)->value.safes)
#define	PKCS12_SAFEBAG_create_cert PKCS12_x5092certbag
#define	PKCS12_SAFEBAG_create_pkcs8_encrypt PKCS12_MAKE_SHKEYBAG
#define	PKCS12_SAFEBAG_get_bag_nid M_PKCS12_cert_bag_type
#define	PKCS12_SAFEBAG_get1_cert PKCS12_certbag2x509
#define	X509_REVOKED_get0_serialNumber(revoke) ((revoke)->serialNumber)
#define	X509_CRL_get0_lastUpdate(xcrl) X509_CRL_get_lastUpdate(xcrl)
#define	X509_CRL_get0_nextUpdate(xcrl) X509_CRL_get_nextUpdate(xcrl)
#define	X509_getm_notBefore  X509_get_notBefore
#define	X509_getm_notAfter X509_get_notAfter

#endif /* OPENSSL_VERSION_NUMBER || LIBRESSL_VERSION_NUMBER */

#endif /* LIBCRYPTO_COMPAT_H */
