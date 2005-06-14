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
 * This file includes interfaces to be used together with SSL to get PKCS#12
 * certs and pass them to SSL.  They replace similar functions for PEM,
 * already provided for within SSL.
 *
 * The interfaces included here are:
 *   sunw_p12_use_certfile - gets the user's cert from a pkcs12 file & pass
 *                it to SSL.
 *   sunw_p12_use_keyfile - gets the RSA private key from a pkcs12 file and
 *                pass it to SSL
 *   sunw_p12_use_trustfile - read the pkcs12 trust anchor (aka certificate
 *                authority certs) file into memory and hand them off to SSL.
 *
 * These functions use the sunw_PKCS12_parse to read the certs.
 *
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

#include <openssl/pkcs12.h>
#include <p12access.h>
#include <p12err.h>

static PKCS12 *p12_read_file(char *);
static int p12_doparse(PKCS12 *, char *, int, EVP_PKEY **,
    X509 **, STACK_OF(X509) **);
static int checkfile(char *);
static int check_password(PKCS12 *, char *);

/*
 * sunw_use_x509cert - pass an x509 client certificate to ssl
 *
 * Arguments:
 *   ctx        - SSL's context structure
 *   cert	- Certificate to pass in x509 format
 *
 * Returns:
 *   <=0 	- Error occurred.  Check the error stack for specifics.
 *   >0         - Success.  Cert was successfully added.
 */
static int
sunw_use_x509cert(SSL_CTX *ctx, X509 *cert)
{
	ERR_clear_error();

	if (ctx == NULL || cert == NULL) {
		SUNWerr(SUNW_F_USE_X509CERT, SUNW_R_INVALID_ARG);
		return (-1);
	}

	if (SSL_CTX_use_certificate(ctx, cert) != 1) {
		SUNWerr(SUNW_F_USE_X509CERT, SUNW_R_CERT_ERR);
		return (-1);
	}
	return (1);
}

/*
 * sunw_use_pkey - pass an EVP_PKEY private key to ssl
 *
 * Arguments:
 *   ctx        - SSL's context structure
 *   pkey	- EVP_PKEY formatted private key
 *
 * Returns:
 *   <=0 	- Error occurred.  Check the error stack for specifics.
 *   >0         - Success.
 */
static int
sunw_use_pkey(SSL_CTX *ctx, EVP_PKEY *pkey)
{
	ERR_clear_error();
	if (ctx == NULL || pkey == NULL) {
		SUNWerr(SUNW_F_USE_PKEY, SUNW_R_INVALID_ARG);
		return (-1);
	}

	if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
		SUNWerr(SUNW_F_USE_PKEY, SUNW_R_PKEY_ERR);
		return (-1);
	}

	return (1);
}

/*
 * sunw_use_tastore - take a stack of X509 certs and add them to the
 *              SSL store of trust anchors (aka CA certs).
 *
 * This function takes the certs in the stack and passes them into
 * SSL for addition to the cache of TA certs.
 *
 * Arguments:
 *   ctx        - SSL's context structure
 *   ta_certs   - Stack of certs to add to the list of SSL trust anchors.
 *
 * Returns:
 *   <=0 	- Error occurred.  Check the error stack for specifics.
 *   >0         - Success.  Certs were successfully added.
 */
static int
sunw_use_tastore(SSL_CTX *ctx, STACK_OF(X509) *ta_certs)
{
	X509 *tmp;
	int ret = -1;
	int i;

	ERR_clear_error();
	if (ctx == NULL || ctx->cert_store == NULL || ta_certs == NULL) {
		SUNWerr(SUNW_F_USE_TASTORE, SUNW_R_INVALID_ARG);
		return (-1);
	}

	if (sk_X509_num(ta_certs) == 0) {
		SUNWerr(SUNW_F_USE_TASTORE, SUNW_R_NO_TRUST_ANCHOR);
		return (-1);
	}

	for (i = 0; i < sk_X509_num(ta_certs); i++) {
		tmp = sk_X509_value(ta_certs, i);

		ret = X509_STORE_add_cert(ctx->cert_store, tmp);
		if (ret == 0) {
			if (ERR_GET_REASON(ERR_peek_error()) ==
					X509_R_CERT_ALREADY_IN_HASH_TABLE) {
				ERR_clear_error();
				continue;
			}
			SUNWerr(SUNW_F_USE_TASTORE, SUNW_R_ADD_TRUST_ERR);
			return (-1);
		} else if (ret < 0) {
			break;
		}
	}

	if (ret < 0) {
		SUNWerr(SUNW_F_USE_TASTORE, SUNW_R_ADD_TRUST_ERR);
	}

	return (ret);
}

/*
 * sunw_p12_use_certfile - read a client certificate from a pkcs12 file and
 *              pass it in to SSL.
 *
 * Read in the certificate in pkcs12-formated file.  Use the provided
 * passphrase to decrypt it. Pass the cert to SSL.
 *
 * Arguments:
 *   ctx        - SSL's context structure
 *   filename	- Name of file with the client certificate.
 *   passwd     - Passphrase for pkcs12 data.
 *
 * Returns:
 *   <=0 	- Error occurred.  Check the error stack for specifics.
 *   >0         - Success.  Cert was successfully added.
 */
int
sunw_p12_use_certfile(SSL_CTX *ctx, char *filename, char *passwd)
{
	PKCS12 *p12 = NULL;
	X509 *cert = NULL;
	int ret = -1;

	ERR_clear_error();
	if (ctx == NULL || filename == NULL) {
		SUNWerr(SUNW_F_USE_CERTFILE, SUNW_R_INVALID_ARG);
		return (-1);
	}

	p12 = p12_read_file(filename);
	if (p12 != NULL) {
		ret = p12_doparse(p12, passwd, DO_UNMATCHING, NULL,
		    &cert, NULL);
		if (ret > 0 && cert != NULL) {
			if (sunw_use_x509cert(ctx, cert) == -1) {
				/*
				 * Error already on stack
				 */
				ret = -1;
			}
		}
	}

	if (p12 != NULL)
		PKCS12_free(p12);

	if (ret == -1 && cert != NULL) {
		X509_free(cert);
		cert = NULL;
	}

	return (ret);
}

/*
 * sunw_p12_use_keyfile - read a RSA private key from a pkcs12 file and pass
 *              it in to SSL.
 *
 * Read in the RSA private key in pkcs12 format. Use the provided
 * passphrase to decrypt it. Pass the cert to SSL.
 *
 * Arguments:
 *   ctx        - SSL's context structure
 *   filename	- Name of file with private key.
 *   passwd     - Passphrase for pkcs12 data.
 *
 * Returns:
 *   <=0 	- Error occurred.  Check the error stack for specifics.
 *   >0         - Success.  Key was successfully added.
 */
int
sunw_p12_use_keyfile(SSL_CTX *ctx, char *filename, char *passwd)
{
	EVP_PKEY *pkey = NULL;
	PKCS12 *p12 = NULL;
	int ret = -1;

	ERR_clear_error();
	if (ctx == NULL || filename == NULL) {
		SUNWerr(SUNW_F_USE_KEYFILE, SUNW_R_INVALID_ARG);
		return (-1);
	}

	p12 = p12_read_file(filename);
	if (p12 != NULL) {
		ret = p12_doparse(p12, passwd, DO_UNMATCHING, &pkey, NULL,
		    NULL);
		if (ret > 0 && pkey != NULL) {
			if (sunw_use_pkey(ctx, pkey) != 1) {
				/*
				 * Error already on stack
				 */
				ret = -1;
			}
		} else {
			SUNWerr(SUNW_F_USE_KEYFILE, SUNW_R_BAD_PKEY);
		}
	} else {
		SUNWerr(SUNW_F_USE_KEYFILE, SUNW_R_PKEY_READ_ERR);
	}

	if (p12 != NULL)
		PKCS12_free(p12);

	if (ret == -1 && pkey != NULL) {
		sunw_evp_pkey_free(pkey);
		pkey = NULL;
	}

	return (ret);
}

/*
 * sunw_p12_use_trustfile - read a list of trustanchors from a pkcs12 file and
 *              pass the stack in to SSL.
 *
 * Read in the trust anchors from pkcs12-formated file. Use the provided
 * passphrase to decrypt it. Pass the cert to SSL.
 *
 * Arguments:
 *   ctx        - SSL's context structure
 *   filename	- Name of file with the certificates.
 *   passwd     - Passphrase for pkcs12 data.
 *
 * Returns:
 *   <=0 	- Error occurred.  Check the error stack for specifics.
 *   >0         - Success.  Trust anchors were successfully added.
 */
int
sunw_p12_use_trustfile(SSL_CTX *ctx, char *filename, char *passwd)
{
	PKCS12 *p12 = NULL;
	STACK_OF(X509) *ta_sk = NULL;
	int ret = -1;

	ERR_clear_error();
	if (ctx == NULL || filename == NULL) {
		SUNWerr(SUNW_F_USE_TRUSTFILE, SUNW_R_INVALID_ARG);
		return (-1);
	}

	p12 = p12_read_file(filename);
	if (p12 != NULL) {
		ret = p12_doparse(p12, passwd, DO_NONE, NULL, NULL,
		    &ta_sk);
		if (ret > 0 && ta_sk != NULL)
			ret = sunw_use_tastore(ctx, ta_sk);
		else {
			SUNWerr(SUNW_F_USE_TRUSTFILE, SUNW_R_BAD_TRUST);
			ret = -1;
		}
	} else {
		SUNWerr(SUNW_F_USE_TRUSTFILE, SUNW_R_READ_TRUST_ERR);
	}

	if (p12 != NULL)
		PKCS12_free(p12);

	if (ta_sk != NULL)
		sk_X509_pop_free(ta_sk, X509_free);

	return (ret);
}

/*
 * p12_read_file - read a pkcs12 file and get its contents.  Return the
 *                 pkcs12 structures.
 *
 * Arguments:
 *   filename	- Name of file with the client certificate.
 *
 *
 * Returns:
 *   NULL 	- Error occurred.  Check the error stack for specifics.
 *   != NULL	- Success.  The return value is the address of a pkcs12
 *                structure.
 */
static PKCS12 *
p12_read_file(char *filename)
{
	PKCS12 *p12 = NULL;
	FILE *fp = NULL;
	int ret = 0;

	ERR_clear_error();
	if (checkfile(filename) == -1) {
		/*
		 * Error already on stack
		 */
		return (NULL);
	}

	if ((fp = fopen(filename, "r")) == 0) {
		SYSerr(SYS_F_FOPEN, errno);
		return (NULL);
	}

	p12 = d2i_PKCS12_fp(fp, NULL);
	if (p12 == NULL) {
		SUNWerr(SUNW_F_READ_FILE, SUNW_R_READ_ERR);
		ret = -1;
	}

	if (fp != NULL)
		(void) fclose(fp);

	if (ret == -1 && p12 != NULL) {
		PKCS12_free(p12);
		p12 = NULL;
	}

	return (p12);
}

/*
 * p12_doparse - Given a pkcs12 structure, check the passphrase and then
 *               parse it.
 *
 * Arguments:
 *   p12	- Structure with pkcs12 data which has been read in
 *   passwd     - Passphrase for pkcs12 data & key.
 *   matchty    - How to decide which matching entry to take... See the
 *                DO_* definitions for valid values.
 *   pkey       - Points at pointer to private key structure.
 *   cert       - Points at pointer to client certificate structure
 *   ca         - Points at pointer to list of CA certs
 *
 * Returns:
 *   <=0 	- Error occurred.  Check the error stack for specifics.
 *   >0         - Success.  Bits set reflect the kind of information
 *                returned.  (See the FOUND_* definitions.)
 */
static int
p12_doparse(PKCS12 *p12, char *passwd, int matchty,
    EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca)
{
	int ret = 0;

	ERR_clear_error();

	/*
	 * Check passphrase (including null one).
	 */
	if (check_password(p12, passwd) == 0)  {
		SUNWerr(SUNW_F_DOPARSE, SUNW_R_MAC_VERIFY_FAILURE);
		return (-1);
	}

	ret = sunw_PKCS12_parse(p12, passwd, matchty, NULL, 0, NULL,
	    pkey, cert, ca);
	if (ret <= 0) {
		/*
		 * Error already on stack
		 */
		return (-1);
	}

	return (ret);
}

/*
 * checkfile - given a file name, verify that the file exists and is
 *             readable.
 */
/* ARGSUSED */
static int
checkfile(char *filename)
{
#ifndef _BOOT
	struct stat sbuf;

	if (access(filename, R_OK) == -1 || stat(filename, &sbuf) == -1) {
		SYSerr(SYS_F_FOPEN, errno);
		return (-1);
	}

	if (!S_ISREG(sbuf.st_mode)) {
		SUNWerr(SUNW_F_CHECKFILE, SUNW_R_BAD_FILETYPE);
		return (-1);
	}
#endif
	return (0);
}

/*
 * check_password - do various password checks to see if the current password
 *                  will work or we need to prompt for a new one.
 *
 * Arguments:
 *   pass   - password to check
 *
 * Returns:
 *   1      - Password is OK.
 *   0      - Password not valid.  Error stack was set - use ERR_get_error() to
 *            to get the error.
 */
static int
check_password(PKCS12 *p12, char *pass)
{
	int ret = 1;

	/*
	 * If password is zero length or NULL then try verifying both cases
	 * to determine which password is correct. The reason for this is that
	 * under PKCS#12 password based encryption no password and a zero
	 * length password are two different things.  Otherwise, calling
	 * PKCS12_verify_mac() with a length of -1 means that the length
	 * can be determined via strlen().
	 */
	/* Check the mac */
	if (pass == NULL || *pass == '\0') {
		if (PKCS12_verify_mac(p12, NULL, 0) == 0 &&
		    PKCS12_verify_mac(p12, "", 0) == 0)
			ret = 0;
	} else if (PKCS12_verify_mac(p12, pass, -1) == 0) {
		ret = 0;
	}

	return (ret);
}
