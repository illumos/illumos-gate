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


/*
 * Module: security.c
 * Description:
 *	Module for handling certificates and various
 *	utilities to access their data.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <pkgstrct.h>
#include <pkginfo.h>
#include <locale.h>
#include <libintl.h>
#include <unistd.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "pkgerr.h"
#include "pkglib.h"
#include "pkglibmsgs.h"
#include "pkglocale.h"
#include "p12lib.h"

/* length of allowable passwords */
#define	MAX_PASSLEN		128

/*
 * Name:	init_security
 * Description:	Initializes structures, libraries, for security operations
 * Arguments:	none
 * Returns:	0 if we couldn't initialize, non-zero otherwise
 */
void
sec_init(void)
{
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ERR_load_SUNW_strings();
	(void) SSL_library_init();
}

/*
 * get_cert_chain - Builds a chain of certificates, from a given
 * user certificate to a trusted certificate.
 *
 * Arguments:
 * err - Error object to add errors to
 * cert - User cert to start with
 * cas - Trusted certs to use as trust anchors
 * chain - The resulting chain of certs (in the form of an
 * ordered set) is placed here.
 *
 * Returns:
 *   0 - Success - chain is stored in 'chain'.
 * non-zero - Failure, errors recorded in err
 */
int
get_cert_chain(PKG_ERR *err, X509 *cert, STACK_OF(X509) *clcerts,
    STACK_OF(X509) *cas, STACK_OF(X509) **chain)
{
	X509_STORE_CTX	*store_ctx = NULL;
	X509_STORE 	*ca_store = NULL;
	X509		*ca_cert = NULL;
	int i;
	int ret = 0;

	if ((ca_store = X509_STORE_new()) == NULL) {
		pkgerr_add(err, PKGERR_NOMEM,
		    gettext(ERR_MEM));
		ret = 1;
		goto cleanup;
	}

	/* add all ca certs into the store */
	for (i = 0; i < sk_X509_num(cas); i++) {
		/* LINTED pointer cast may result in improper alignment */
		ca_cert = sk_X509_value(cas, i);
		if (X509_STORE_add_cert(ca_store, ca_cert) == 0) {
			pkgerr_add(err, PKGERR_NOMEM, gettext(ERR_MEM));
			ret = 1;
			goto cleanup;
		}
	}

	/* initialize context object used during the chain resolution */

	if ((store_ctx = X509_STORE_CTX_new()) == NULL) {
		pkgerr_add(err, PKGERR_NOMEM, gettext(ERR_MEM));
		ret = 1;
		goto cleanup;
	}

	(void) X509_STORE_CTX_init(store_ctx, ca_store, cert, clcerts);
	/* attempt to verify the cert, which builds the cert chain */
	if (X509_verify_cert(store_ctx) <= 0) {
		pkgerr_add(err, PKGERR_CHAIN,
		    gettext(ERR_CERTCHAIN),
		    get_subject_display_name(cert),
		    X509_verify_cert_error_string(store_ctx->error));
		ret = 1;
		goto cleanup;
	}
	*chain = X509_STORE_CTX_get1_chain(store_ctx);

cleanup:
	if (ca_store != NULL)
		(void) X509_STORE_free(ca_store);
	if (store_ctx != NULL) {
		(void) X509_STORE_CTX_cleanup(store_ctx);
		(void) X509_STORE_CTX_free(store_ctx);
	}

	return (ret);
}

/*
 * Name:		get_subject_name
 * Description:	Retrieves a name used for identifying a certificate's subject.
 *
 * Arguments:	cert - The certificate to get the name from
 *
 * Returns :	A static buffer containing the common name (CN) of the
 * 		subject of the cert.
 *
 *		if the CN is not available, returns a string with the entire
 * X509 distinguished name.
 */
char
*get_subject_display_name(X509 *cert)
{

	X509_NAME	*xname;
	static char	sname[ATTR_MAX];

	xname = X509_get_subject_name(cert);
	if (X509_NAME_get_text_by_NID(xname,
	    NID_commonName, sname,
	    ATTR_MAX) <= 0) {
		(void) strncpy(sname,
		    X509_NAME_oneline(xname,
			NULL, 0), ATTR_MAX);
		sname[ATTR_MAX - 1] = '\0';
	}
	return (sname);
}

/*
 * Name:		get_display_name
 * Description:	Retrieves a name used for identifying a certificate's issuer.
 *
 * Arguments:	cert - The certificate to get the name from
 *
 * Returns :	A static buffer containing the common name (CN)
 *		of the issuer of the cert.
 *
 *		if the CN is not available, returns a string with the entire
 *		X509 distinguished name.
 */
char
*get_issuer_display_name(X509 *cert)
{

	X509_NAME	*xname;
	static char	sname[ATTR_MAX];

	xname = X509_get_issuer_name(cert);
	if (X509_NAME_get_text_by_NID(xname,
	    NID_commonName, sname,
	    ATTR_MAX) <= 0) {
		(void) strncpy(sname,
		    X509_NAME_oneline(xname,
			NULL, 0), ATTR_MAX);
		sname[ATTR_MAX - 1] = '\0';
	}
	return (sname);
}


/*
 * Name:		get_serial_num
 * Description:	Retrieves the serial number of an X509 cert
 *
 * Arguments:	cert - The certificate to get the data from
 *
 * Returns :	A static buffer containing the serial number
 *		of the cert
 *
 *		if the SN is not available, returns NULL
 */
char
*get_serial_num(X509 *cert)
{
	static char	 sn_str[ATTR_MAX];
	ASN1_INTEGER	*sn;

	if ((sn = X509_get_serialNumber(cert)) != 0) {
		return (NULL);
	} else {
		(void) snprintf(sn_str, ATTR_MAX, "%ld",
		    ASN1_INTEGER_get(sn));
	}

	return (sn_str);
}

/*
 * Name:		get_fingerprint
 * Description:	Generates a fingerprint string given
 *		a digest algorithm with which to calculate
 *		the fingerprint
 *
 * Arguments:	cert - The certificate to get the data from
 * Arguments:	alg - The algorithm to use to calculate the fingerprint
 *
 * Returns :	A static buffer containing the digest
 *		NULL if cert is NULL, or digest cannot be calculated
 */
char
*get_fingerprint(X509 *cert, const EVP_MD *alg)
{
	static char	 fp_str[ATTR_MAX];
	char		 tmp[ATTR_MAX] = "";
	unsigned int n;
	unsigned char md[EVP_MAX_MD_SIZE];
	int i;

	if (!X509_digest(cert, alg, md, &n)) {
		return (NULL);
	}

	/* start with empty string */
	fp_str[0] = '\0';

	for (i = 0; i < (int)n; i++) {
		/* form a byte of the fingerprint */
		(void) snprintf(tmp, ATTR_MAX, "%02X:", md[i]);
		/* cat it onto the end of the result */
		(void) strlcat(fp_str, tmp, ATTR_MAX);
	}

	/* nuke trailing ':' */
	fp_str[strlen(fp_str) - 1] = '\0';

	return (fp_str);
}
