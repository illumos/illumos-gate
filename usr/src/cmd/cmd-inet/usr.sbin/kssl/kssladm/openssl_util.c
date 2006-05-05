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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <strings.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
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
PEM_get_x509_info_stack(const char *filename, char *password_file)
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
	    fp, NULL, pem_password_callback, password_file);
	(void) fclose(fp);

	if (x509_info_stack == NULL) {
		print_crypto_error();
	}

	return (x509_info_stack);
}

static EVP_PKEY *
PEM_get_key(const char *filename, const char *password_file)
{
	FILE *fp;
	EVP_PKEY *pkey = NULL;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		perror("Unable to open pem file for reading");
		return (NULL);
	}
	if (verbose)
		(void) printf("In PEM_get_key: %s opened\n", filename);

	OpenSSL_add_all_algorithms();

	pkey = PEM_read_PrivateKey(fp, NULL, pem_password_callback,
	    (char *)password_file);
	(void) fclose(fp);

	if (pkey == NULL) {
		print_crypto_error();
	}

	return (pkey);
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

static uchar_t **
init_cert_vars(int **rlens)
{
	int i;
	uchar_t **cert_bufs;
	int *lcert_lens;

	cert_bufs = (uchar_t **)malloc(MAX_CHAIN_LENGTH * sizeof (uchar_t **));
	if (cert_bufs == NULL)
		return (NULL);
	for (i = 0; i < MAX_CHAIN_LENGTH; i++)
		cert_bufs[i] = NULL;

	lcert_lens = malloc(MAX_CHAIN_LENGTH * sizeof (int));
	if (lcert_lens == NULL) {
		free(cert_bufs);
		return (NULL);
	}
	for (i = 0; i < MAX_CHAIN_LENGTH; i++)
		lcert_lens[i] = 0;

	*rlens = lcert_lens;
	return (cert_bufs);
}

static void
print_subject(X509 *x)
{
	char buf[256];

	(void) X509_NAME_oneline(X509_get_subject_name(x),
	    buf, sizeof (buf));
	(void) fprintf(stdout, "/* subject: %s */ \n", buf);
}

/*
 * Returns DER encoded certs in an array of pointers
 * and their sizes in cert_sizes. If the rsa argument is
 * not NULL, we return the RSA key in it. The caller needs
 * to free the structures when done.
 */
uchar_t **
PEM_get_rsa_key_certs(const char *filename, char *password_file,
    RSA **rsa, int **cert_sizes, int *n)
{
	int i, cert_size, ncerts;
	int *cert_lens;
	uchar_t **cert_bufs;
	EVP_PKEY *pkey = NULL;
	X509_INFO *info;
	X509_INFO *cert_infos[MAX_CHAIN_LENGTH];
	STACK_OF(X509_INFO) *x509_info_stack;

	x509_info_stack = PEM_get_x509_info_stack(filename, password_file);
	if (x509_info_stack == NULL) {
		return (NULL);
	}

	ncerts = 0;
	/* LINTED */
	while ((info = sk_X509_INFO_pop(x509_info_stack)) != NULL &&
	    ncerts < MAX_CHAIN_LENGTH) {
		cert_infos[ncerts] = info;
		ncerts++;
		if (verbose)
			print_subject(info->x509);
	}

	if (ncerts == 0) {
		(void) fprintf(stderr, "No cert found\n");
		return (NULL);
	}

	if (rsa != NULL) {
		X509 *x;

		pkey = PEM_get_key(filename, password_file);
		if (pkey == NULL)
			return (NULL);

		x = cert_infos[ncerts - 1]->x509;
		if (!X509_check_private_key(x, pkey)) {
			(void) fprintf(stderr, "Error: Server certificate "
			    "and server private key do not match.\n");
			EVP_PKEY_free(pkey);
			return (NULL);
		}

		*rsa = EVP_PKEY_get1_RSA(pkey);
	}

	if ((cert_bufs = init_cert_vars(&cert_lens)) == NULL) {
		if (pkey != NULL)
			EVP_PKEY_free(pkey);
		return (NULL);
	}

	/*
	 * cert_infos[] is constructed from a stack of certificates structure
	 * and hence the order is high level CA certificate first. SSL protocol
	 * needs the certificates in the order of low level CA certificate
	 * first. So, we walk cert_infos[] in reverse order below.
	 */
	for (i = 0; i < ncerts; i++) {
		info =  cert_infos[ncerts - 1 - i];
		cert_bufs[i] = X509_to_bytes(info->x509, &cert_size);
		cert_lens[i] = cert_size;
		X509_INFO_free(info);
	}

	*cert_sizes = cert_lens;
	*n = ncerts;
	return (cert_bufs);
}

static PKCS12 *
PKCS12_load(const char *filename)
{
	FILE *fp;
	PKCS12 *p12;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		perror("Unable to open file for reading");
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

/*
 * Returns DER encoded certs in an array of pointers and their
 * sizes in cert_sizes. The RSA key is returned in the rsa argument.
 * The caller needs to free the structures when done.
 */
uchar_t **
PKCS12_get_rsa_key_certs(const char *filename, const char *password_file,
    RSA **rsa, int **cert_sizes, int *n)
{
	int i, ncerts, cert_size;
	int *cert_lens;
	char *password = NULL;
	char password_buf[1024];
	uchar_t **cert_bufs = NULL;
	uchar_t *cert_buf;
	PKCS12 *p12 = NULL;
	EVP_PKEY *pkey = NULL;
	X509 *x509 = NULL;
	X509 *certs[MAX_CHAIN_LENGTH];
	STACK_OF(X509) *ca = NULL;

	p12 = PKCS12_load(filename);
	if (p12 == NULL) {
		return (NULL);
	}

	if (! PKCS12_verify_mac(p12, NULL, 0)) {
		if (get_passphrase(
		    password_file, password_buf, sizeof (password_buf)) <= 0) {
			perror("Unable to read passphrase");
			goto done;
		}

		password = password_buf;
	}

	if (PKCS12_parse(p12, password, &pkey, &x509, &ca) <= 0) {
		(void) fprintf(stderr, "Unable to parse PKCS12 file.\n");
		goto done;
	}

	if (pkey == NULL) {
		(void) fprintf(stderr, "No key returned\n");
		goto done;
	}
	if (x509 == NULL) {
		(void) fprintf(stderr, "No cert returned\n");
		goto done;
	}

	if (!X509_check_private_key(x509, pkey)) {
		(void) fprintf(stderr, "Error: Server certificate and server "
		    "private key do not match.\n");
		goto done;
	}

	cert_buf = X509_to_bytes(x509, &cert_size);
	if (cert_buf == NULL)
		goto done;
	X509_free(x509);

	*rsa = EVP_PKEY_get1_RSA(pkey);
	if (*rsa == NULL) {
		goto done;
	}

	if ((cert_bufs = init_cert_vars(&cert_lens)) == NULL) {
		RSA_free(*rsa);
		goto done;
	}

	ncerts = 0;
	cert_bufs[0] = cert_buf;
	cert_lens[0] = cert_size;
	ncerts++;

	/* LINTED */
	while ((ca != NULL) && ((x509 = sk_X509_pop(ca)) != NULL) &&
	    ncerts < MAX_CHAIN_LENGTH) {
		certs[ncerts] = x509;
		ncerts++;
		if (verbose)
			print_subject(x509);
	}

	/*
	 * certs[1..ncerts-1] is constructed from a stack of certificates
	 * structure and hence the order is high level CA certificate first.
	 * SSL protocol needs the certificates in the order of low level CA
	 * certificate first. So, we walk certs[] in reverse order below.
	 */
	for (i = 1; i < ncerts; i++) {
		x509 =  certs[ncerts - i];
		cert_bufs[i] = X509_to_bytes(x509, &cert_size);
		cert_lens[i] = cert_size;
		X509_free(x509);
	}

	*cert_sizes = cert_lens;
	*n = ncerts;

done:
	if (pkey != NULL)
		EVP_PKEY_free(pkey);
	if (p12 != NULL)
		PKCS12_free(p12);

	return (cert_bufs);
}
