/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <strings.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "kssladm.h"

static void
print_crypto_error(void)
{
	ERR_load_crypto_strings();
	ERR_print_errors_fp(stderr);
}

/* ARGSUSED */
static int
pem_password_callback(char *buf, int size, int rwflag, void *userdata)
{
	return (get_passphrase((const char *)userdata, buf, size));
}


static STACK_OF(X509_INFO) *
PEM_get_x509_info_stack(const char *filename, char *passphrase)
{
	FILE *fp;
	STACK_OF(X509_INFO) *x509_info_stack;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		perror("Unable to open pem file for reading");
		return (NULL);
	}
	if (verbose)
		(void) printf("In PEM_get_x509_info_stack: %s opened\n",
		    filename);

	OpenSSL_add_all_algorithms();

	x509_info_stack = PEM_X509_INFO_read(
	    fp, NULL, pem_password_callback, passphrase);
	(void) fclose(fp);

	if (x509_info_stack == NULL) {
		print_crypto_error();
	}

	return (x509_info_stack);
}


RSA *
PEM_get_rsa_key(const char *filename, char *passphrase)
{
	FILE *fp;
	RSA *rsa_key;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		perror("Unable to open pem file for reading");
		return (NULL);
	}
	if (verbose)
		(void) printf("In PEM_get_rsa_key: %s opened\n", filename);

	OpenSSL_add_all_algorithms();

	rsa_key = PEM_read_RSAPrivateKey(
	    fp, NULL, pem_password_callback, passphrase);
	(void) fclose(fp);

	if (rsa_key == NULL) {
		print_crypto_error();
	}

	return (rsa_key);
}

uchar_t *
get_modulus(uchar_t *ber_buf, int buflen, int *modlen)
{
	int i, j, v;
	X509 *x;
	EVP_PKEY *pkey;
	BIGNUM *bn;
	uchar_t *m = NULL, *mptr;

	x = d2i_X509(NULL, &ber_buf, buflen);
	if (x != NULL) {
		pkey = X509_get_pubkey(x);
		if (pkey == NULL) {
			X509_free(x);
			return (NULL);
		}

		bn = pkey->pkey.rsa->n;
		mptr = m = malloc(bn->top * BN_BYTES);
		for (i = bn->top - 1; i >= 0; i--) {
			for (j = BN_BITS2 - 8; j >= 0; j -= 8) {
				v = ((int)(bn->d[i] >> (long)j)) & 0xff;
				*m = v;
				m++;
			}
		}
		*modlen = bn->top * BN_BYTES;
		EVP_PKEY_free(pkey);
		X509_free(x);
	}

	return (mptr);
}

static uchar_t *
X509_to_bytes(X509 *cert, int *cert_size)
{
	uchar_t *cert_buf = NULL;
	int size;

	size = i2d_X509(cert, &cert_buf);
	if (size < 0)  {
		perror("Invalid cert\n");
		return (NULL);
	}

	*cert_size = size;
	return (cert_buf);
}


/* Returns DER encoded cert */
uchar_t *
PEM_get_cert(const char *filename, char *passphrase, int *cert_size)
{
	STACK_OF(X509_INFO) *x509_info_stack;
	uchar_t *cert_buf;
	X509_INFO *info;

	x509_info_stack = PEM_get_x509_info_stack(filename, passphrase);
	if (x509_info_stack == NULL) {
		return (NULL);
	}

	/* LINTED */
	info = sk_X509_INFO_pop(x509_info_stack);
	if (info == NULL || info->x509 == NULL) {
		(void) fprintf(stderr, "No cert found\n");
		return (NULL);
	}

	cert_buf = X509_to_bytes(info->x509, cert_size);
	X509_INFO_free(info);
	return (cert_buf);
}

#include <openssl/pkcs12.h>
static PKCS12 *
PKCS12_load(const char *filename)
{
	FILE *fp;
	PKCS12 *p12;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		perror("Unnable to open file for reading");
		return (NULL);
	}

	OpenSSL_add_all_algorithms();

	p12 = d2i_PKCS12_fp(fp, NULL);
	(void) fclose(fp);
	if (p12 == NULL) {
		ERR_load_PKCS12_strings();
		ERR_print_errors_fp(stderr);
		(void) fprintf(stderr, "Unable to load from %s\n", filename);
		return (NULL);
	}

	return (p12);
}

int
PKCS12_get_rsa_key_cert(const char *filename, const char *password_file,
	RSA **rsa, uchar_t **cert, int *cert_size)
{
	int rv = -1;
	EVP_PKEY *pkey = NULL;
	X509 *x509 = NULL;
	char *password = NULL;
	char password_buf[1024];
	PKCS12 *p12;

	p12 = PKCS12_load(filename);
	if (p12 == NULL) {
		goto out0;
	}

	if (! PKCS12_verify_mac(p12, NULL, 0)) {
		if (get_passphrase(
		    password_file, password_buf, sizeof (password_buf)) <= 0) {
			perror("Unnable to read passphrase");
			goto out0;
		}

		password = password_buf;
	}

	(void) PKCS12_parse(p12, password, &pkey, &x509, NULL);

	PKCS12_free(p12);
	if (pkey == NULL) {
		(void) fprintf(stderr, "No key returned\n");
		goto out0;
	}
	if (x509 == NULL) {
		(void) fprintf(stderr, "No cert returned\n");
		goto out1;
	}

	*rsa = EVP_PKEY_get1_RSA(pkey);
	if (*rsa == NULL) {
		goto out2;
	}

	*cert = X509_to_bytes(x509, cert_size);

	if (*cert != NULL) {
		rv = 0;
	}

out2:
	X509_free(x509);
out1:
	EVP_PKEY_free(pkey);
out0:
	return (rv);
}
