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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pkglocs.h>
#include <locale.h>
#include <libintl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <fcntl.h>
#include <libintl.h>
#include <dirent.h>
#include <openssl/err.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <pkglib.h>
#include <p12lib.h>
#include <install.h>
#include <libadm.h>
#include <libinst.h>
#include "pkgadm.h"
#include "pkgadm_msgs.h"


/*
 * Function:	load_cert_and_key
 * Description:	Loads a public key certificate and associated private key
 *		from a stream.
 * Parameters:	err	- Where to write errors to for underlying library calls
 *		incert - File to read certs and keys from
 *		format - The format of the file
 *		passarg - How to collect password if needed to decrypt file
 *		key - Location to store resulting key if found
 *		cert - Location to store resulting cert if found.
 *
 * Returns:	f one or more certificates are found in the file,
 *		and one or more keys are found, then the first
 *		certificate is used, and the keys are searched for a
 *		match.  If no key matches the cert, then only the cert
 *		is returned.  If no certs are found, but one or more
 *		keys are found, then the first key is returned.
 */
int
load_cert_and_key(PKG_ERR *err, FILE *incert,
    keystore_encoding_format_t format, char *passarg, EVP_PKEY **key,
    X509 **cert)
{
	X509 *tmpcert = NULL;
	EVP_PKEY *tmpkey = NULL;
	STACK_OF(EVP_PKEY)	*keys = NULL;
	STACK_OF(X509)		*certs = NULL;
	int i, ret = 0;
	keystore_passphrase_data	data;
	unsigned long crypto_err;

	if (key) *key = NULL;
	if (cert) *cert = NULL;

	switch (format) {
	case KEYSTORE_FORMAT_DER:
		/* first try to load a DER cert, which cannot contain a key */
		if ((tmpcert = d2i_X509_fp(incert, NULL)) == NULL) {
			log_msg(LOG_MSG_ERR, MSG_PARSE);
			ret = 1;
		}
		break;
	case KEYSTORE_FORMAT_PEM:
	default:
		data.err = err;
		set_passphrase_passarg(passarg);
		set_passphrase_prompt(gettext("Enter PEM passphrase:"));
		if (sunw_PEM_contents(incert, pkg_passphrase_cb,
		    &data, &keys, &certs) < 0) {
			/* print out openssl-generated PEM errors */
			while ((crypto_err = ERR_get_error()) != 0) {
				log_msg(LOG_MSG_ERR,
				    ERR_reason_error_string(crypto_err));
			}
			ret = 1;
			goto cleanup;
		}

		/* take the first cert in the file, if any */
		if (cert && (certs != NULL)) {
			if (sk_X509_num(certs) != 1) {
				log_msg(LOG_MSG_ERR, MSG_MULTIPLE_CERTS);
				ret = 1;
				goto cleanup;
			} else {
				tmpcert = sk_X509_value(certs, 0);
			}
		}

		if (key && (keys != NULL)) {
			if (tmpcert != NULL) {
				/*
				 * if we found a cert and some keys,
				 * only return the key that
				 * matches the cert
				 */
				for (i = 0; i < sk_EVP_PKEY_num(keys); i++) {
					if (X509_check_private_key(tmpcert,
					    sk_EVP_PKEY_value(keys, i))) {
						tmpkey =
						    sk_EVP_PKEY_value(keys, i);
						break;
					}
				}
			} else {
				if (sk_EVP_PKEY_num(keys) > 0) {
					tmpkey = sk_EVP_PKEY_value(keys, 0);
				}
			}
		}
		break;
	}

	/* set results */
	if (key && tmpkey) {
		*key = tmpkey;
		tmpkey = NULL;
	}

	if (cert && tmpcert) {
		*cert = tmpcert;
		tmpcert = NULL;
	}

cleanup:
	if (tmpcert != NULL) {
		X509_free(tmpcert);
	}
	if (tmpkey != NULL) {
		sunw_evp_pkey_free(tmpkey);
	}
	return (ret);
}

/*
 * Function:	load_all_certs
 * Description:	Loads alll certificates from a stream.
 * Parameters:	err	- Where to write errors to for underlying library calls
 *		incert - File to read certs and keys from
 *		format - The format of the file
 *		passarg - How to collect password if needed to decrypt file
 *		certs - Location to store resulting cert if found.
 *
 * Returns:	0 - success, all certs placed in ''certs'
 *		non-zero failure, errors in 'err'
 */
int
load_all_certs(PKG_ERR *err, FILE *incert,
    keystore_encoding_format_t format, char *passarg, STACK_OF(X509) **certs)
{
	X509 *tmpcert = NULL;
	STACK_OF(X509) *tmpcerts = NULL;
	int ret = 0;
	keystore_passphrase_data	data;
	unsigned long crypto_err;
	if (certs) *certs = NULL;

	switch (format) {
	case KEYSTORE_FORMAT_DER:
		/* first try to load a DER cert, which cannot contain a key */
		if ((tmpcert = d2i_X509_fp(incert, NULL)) == NULL) {
		    log_msg(LOG_MSG_ERR, MSG_PARSE);
			ret = 1;
			goto cleanup;
		}

		if ((tmpcerts = sk_X509_new_null()) == NULL) {
			log_msg(LOG_MSG_ERR, MSG_MEM);
			ret = 1;
			goto cleanup;
		}
		sk_X509_push(tmpcerts, tmpcert);
		break;
	case KEYSTORE_FORMAT_PEM:
	default:
		data.err = err;
		set_passphrase_prompt(MSG_PEM_PASSPROMPT);
		set_passphrase_passarg(passarg);
		if (sunw_PEM_contents(incert, pkg_passphrase_cb,
		    &data, NULL, &tmpcerts) < 0) {
			/* print out openssl-generated PEM errors */
			while ((crypto_err = ERR_get_error()) != 0) {
				log_msg(LOG_MSG_ERR,
				    ERR_reason_error_string(crypto_err));
			}
		}
		break;
	}

	/* set results */
	if (certs && tmpcerts) {
		*certs = tmpcerts;
		tmpcerts = NULL;
	}

cleanup:
	if (tmpcerts != NULL) {
		sk_X509_free(tmpcerts);
	}
	return (ret);
}
