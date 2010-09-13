/*
 * Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 1999.
 */
/*
 * ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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

/*
 * Copyright 2002, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <strings.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include <openssl/pkcs12.h>
#include <p12aux.h>
#include <auxutil.h>
#include <p12err.h>

/*
 * sunw_PKCS12_create() creates a pkcs#12 structure and given component parts.
 *
 * Given one or more of user private key, user cert and/or other (CA) certs,
 * return an encrypted PKCS12 structure containing them.
 *
 * Arguments:
 *   pass     - Pass phrase for the pkcs12 structure and private key (possibly
 *              empty) or NULL if there is none.  It will be used to encrypt
 *              both the private key(s) and as the pass phrase for the whole
 *              pkcs12 wad.
 *   pkeys    - Points to stack of private keys.
 *   certs    - Points to stack of client (public ke) certs
 *   cacerts  - Points to stack of 'certificate authority' certs (or trust
 *              anchors).
 *
 *   Note that any of these may be NULL.
 *
 * Returns:
 *   NULL     - An error occurred.
 *   != NULL  - Address of PKCS12 structure.  The user is responsible for
 *              freeing the memory when done.
 */
PKCS12 *
sunw_PKCS12_create(const char *pass, STACK_OF(EVP_PKEY) *pkeys,
    STACK_OF(X509) *certs, STACK_OF(X509) *cacerts)
{
	int nid_cert = NID_pbe_WithSHA1And40BitRC2_CBC;
	int nid_key = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
	STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
	STACK_OF(PKCS7) *safes = NULL;
	PKCS12_SAFEBAG *bag = NULL;
	PKCS8_PRIV_KEY_INFO *p8 = NULL;
	EVP_PKEY *pkey = NULL;
	PKCS12 *ret_p12 = NULL;
	PKCS12 *p12 = NULL;
	PKCS7 *authsafe = NULL;
	X509 *cert = NULL;
	uchar_t *str = NULL;
	int certs_there = 0;
	int keys_there = 0;
	int len;
	int i;

	if ((safes = sk_PKCS7_new_null()) == NULL) {
		SUNWerr(SUNW_F_PKCS12_CREATE, SUNW_R_MEMORY_FAILURE);
		return (NULL);
	}

	if ((bags = sk_PKCS12_SAFEBAG_new_null()) == NULL) {
		SUNWerr(SUNW_F_PKCS12_CREATE, SUNW_R_MEMORY_FAILURE);
		goto err_ret;
	}

	if (certs != NULL && sk_X509_num(certs) > 0) {

		for (i = 0; i < sk_X509_num(certs); i++) {
			cert = sk_X509_value(certs, i);

			/* Add user certificate */
			if ((bag = M_PKCS12_x5092certbag(cert)) == NULL) {
				SUNWerr(SUNW_F_PKCS12_CREATE, SUNW_R_CERT_ERR);
				goto err_ret;
			}
			if (cert->aux != NULL && cert->aux->alias != NULL &&
			    cert->aux->alias->type == V_ASN1_UTF8STRING) {
				str = utf82ascstr(cert->aux->alias);
				if (str == NULL) {
					/*
					 * Error already on stack
					 */
					goto err_ret;
				}
				if (PKCS12_add_friendlyname_asc(bag,
				    (char const *) str,
				    strlen((char const *) str)) == 0) {
					SUNWerr(SUNW_F_PKCS12_CREATE,
					    SUNW_R_ADD_ATTR_ERR);
					goto err_ret;
				}
			}
			if (cert->aux != NULL && cert->aux->keyid != NULL &&
			    cert->aux->keyid->type == V_ASN1_OCTET_STRING) {
				str = cert->aux->keyid->data;
				len = cert->aux->keyid->length;

				if (str != NULL &&
				    PKCS12_add_localkeyid(bag, str, len) == 0) {
					SUNWerr(SUNW_F_PKCS12_CREATE,
					    SUNW_R_ADD_ATTR_ERR);
					goto err_ret;
				}
			}
			if (sk_PKCS12_SAFEBAG_push(bags, bag) == 0) {
				SUNWerr(SUNW_F_PKCS12_CREATE,
				    SUNW_R_MEMORY_FAILURE);
				goto err_ret;
			}
			certs_there++;
			bag = NULL;
		}
	}

	if (cacerts != NULL && sk_X509_num(cacerts) > 0) {

		/* Put all certs in structure */
		for (i = 0; i < sk_X509_num(cacerts); i++) {
			cert = sk_X509_value(cacerts, i);
			if ((bag = M_PKCS12_x5092certbag(cert)) == NULL) {
				SUNWerr(SUNW_F_PKCS12_CREATE, SUNW_R_CERT_ERR);
				goto err_ret;
			}

			if (cert->aux != NULL && cert->aux->alias != NULL &&
			    cert->aux->alias->type == V_ASN1_UTF8STRING) {
				str = utf82ascstr(cert->aux->alias);
				if (str == NULL) {
					/*
					 * Error already on stack
					 */
					goto err_ret;
				}
				if (PKCS12_add_friendlyname_asc(
				    bag, (char const *) str,
				    strlen((char const *) str)) == 0) {
					SUNWerr(SUNW_F_PKCS12_CREATE,
					    SUNW_R_ADD_ATTR_ERR);
					goto err_ret;
				}
			}
			if (cert->aux != NULL && cert->aux->keyid != NULL &&
			    cert->aux->keyid->type == V_ASN1_OCTET_STRING) {
				str = cert->aux->keyid->data;
				len = cert->aux->keyid->length;

				if (str != NULL &&
				    PKCS12_add_localkeyid(bag, str, len) == 0) {
					SUNWerr(SUNW_F_PKCS12_CREATE,
					    SUNW_R_ADD_ATTR_ERR);
					goto err_ret;
				}
			}
			if (sk_PKCS12_SAFEBAG_push(bags, bag) == 0) {
				SUNWerr(SUNW_F_PKCS12_CREATE,
				    SUNW_R_MEMORY_FAILURE);
				goto err_ret;
			}
			certs_there++;
			bag = NULL;
		}
	}

	if (certs != NULL || cacerts != NULL && certs_there) {
		/* Turn certbags into encrypted authsafe */
		authsafe = PKCS12_pack_p7encdata(nid_cert, pass, -1,
		    NULL, 0, PKCS12_DEFAULT_ITER, bags);
		if (authsafe == NULL) {
			SUNWerr(SUNW_F_PKCS12_CREATE, SUNW_R_CERT_ERR);
			goto err_ret;
		}
		sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
		bags = NULL;

		if (sk_PKCS7_push(safes, authsafe) == 0) {
			SUNWerr(SUNW_F_PKCS12_CREATE, SUNW_R_MEMORY_FAILURE);
			goto err_ret;
		}
		authsafe = NULL;
	}

	if (pkeys != NULL && sk_EVP_PKEY_num(pkeys) > 0) {

		if (bags == NULL &&
		    (bags = sk_PKCS12_SAFEBAG_new_null()) == NULL) {
			SUNWerr(SUNW_F_PKCS12_CREATE, SUNW_R_MEMORY_FAILURE);
			goto err_ret;
		}

		for (i = 0; i < sk_EVP_PKEY_num(pkeys); i++) {

			pkey = sk_EVP_PKEY_value(pkeys, i);

			/* Make a shrouded key bag */
			if ((p8 = EVP_PKEY2PKCS8(pkey)) == NULL) {
				SUNWerr(SUNW_F_PKCS12_CREATE, SUNW_R_PKEY_ERR);
				goto err_ret;
			}

			bag = PKCS12_MAKE_SHKEYBAG(nid_key, pass, -1, NULL, 0,
			    PKCS12_DEFAULT_ITER, p8);
			if (bag == NULL) {
				SUNWerr(SUNW_F_PKCS12_CREATE,
				    SUNW_R_MAKE_BAG_ERR);
				goto err_ret;
			}
			PKCS8_PRIV_KEY_INFO_free(p8);
			p8 = NULL;

			len = sunw_get_pkey_fname(GETDO_COPY, pkey,
			    (char **)&str);
			if (str != NULL) {
				if (PKCS12_add_friendlyname_asc(bag,
				    (const char *)str, len) == 0) {
					SUNWerr(SUNW_F_PKCS12_CREATE,
					    SUNW_R_ADD_ATTR_ERR);
					goto err_ret;
				}
			}
			str = NULL;

			len = sunw_get_pkey_localkeyid(GETDO_COPY, pkey,
			    (char **)&str, &len);
			if (str != NULL) {
				if (PKCS12_add_localkeyid(bag, str, len) == 0) {
					SUNWerr(SUNW_F_PKCS12_CREATE,
					    SUNW_R_ADD_ATTR_ERR);
					goto err_ret;
				}
			}
			str = NULL;

			if (sk_PKCS12_SAFEBAG_push(bags, bag) == 0) {
				SUNWerr(SUNW_F_PKCS12_CREATE,
				    SUNW_R_MEMORY_FAILURE);
				goto err_ret;
			}
			keys_there++;
			bag = NULL;
		}

		if (keys_there) {
			/* Turn into unencrypted authsafe */
			authsafe = PKCS12_pack_p7data(bags);
			if (authsafe == NULL) {
				SUNWerr(SUNW_F_PKCS12_CREATE,
				    SUNW_R_PKCS12_CREATE_ERR);
				goto err_ret;
			}
			sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
			bags = NULL;

			if (sk_PKCS7_push(safes, authsafe) == 0) {
				SUNWerr(SUNW_F_PKCS12_CREATE,
				    SUNW_R_MEMORY_FAILURE);
			}
			authsafe = NULL;
		}
	}

	if (certs_there == 0 && keys_there == 0) {
		SUNWerr(SUNW_F_PKCS12_CREATE, SUNW_R_PKCS12_EMPTY_ERR);
		goto err_ret;
	}

	if ((p12 = PKCS12_init(NID_pkcs7_data)) == NULL) {
		SUNWerr(SUNW_F_PKCS12_CREATE, SUNW_R_PKCS12_CREATE_ERR);
		goto err_ret;
	}

	/*
	 * Note that safes is copied by the following.  Therefore, it needs
	 * to be freed whether or not the following succeeds.
	 */
	if (M_PKCS12_pack_authsafes(p12, safes) == 0) {
		SUNWerr(SUNW_F_PKCS12_CREATE, SUNW_R_PKCS12_CREATE_ERR);
		goto err_ret;
	}
	if (PKCS12_set_mac(p12, pass, -1, NULL, 0, 2048, NULL) == 0) {
		SUNWerr(SUNW_F_PKCS12_CREATE, SUNW_R_MAC_CREATE_FAILURE);
		goto err_ret;
	}

	ret_p12 = p12;
	p12 = NULL;

	/* Fallthrough is intentional */

err_ret:

	if (str != NULL)
		free(str);

	if (p8 != NULL)
		PKCS8_PRIV_KEY_INFO_free(p8);

	if (bag != NULL)
		PKCS12_SAFEBAG_free(bag);
	if (bags != NULL)
		sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
	if (authsafe != NULL)
		PKCS7_free(authsafe);
	if (safes != NULL)
		sk_PKCS7_pop_free(safes, PKCS7_free);
	if (p12 != NULL)
		PKCS12_free(p12);

	return (ret_p12);
}
