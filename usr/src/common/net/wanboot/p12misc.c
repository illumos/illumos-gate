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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2012, OmniTI Computer Consulting, Inc. All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

#include <openssl/pkcs12.h>
#include <p12aux.h>
#include <auxutil.h>
#include <p12err.h>

/*
 * sunw_cryto_init() does crypto-specific initialization.
 *
 * Arguments:
 *   None.
 *
 * Returns:
 *   None.
 */
void
sunw_crypto_init(void)
{
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ERR_load_SUNW_strings();
	(void) SSL_library_init();
}

/*
 * sunw_split_certs() - Given a list of certs and a list of private keys,
 *     moves certs which match one of the keys to a different stack.
 *
 * Arguments:
 *   allkeys  - Points to a stack of private keys to search.
 *   allcerts - Points to a stack of certs to be searched.
 *   keycerts - Points to address of a stack of certs with matching private
 *              keys.  They are moved from 'allcerts'.  This may not be NULL
 *              when called.  If *keycerts is NULL upon entry, a new stack will
 *              be allocated.  Otherwise, it must be a valid STACK_OF(509).
 *   nocerts  - Points to address of a stack for keys which have no matching
 *              certs.  Keys are moved from 'allkeys' here when they have no
 *              matching certs.  If this is NULL, matchless keys will be
 *              discarded.
 *
 *   Notes:  If an error occurs while moving certs, the cert being move may be
 *   lost.  'keycerts' may only contain part of the matching certs.  The number
 *   of certs successfully moved can be found by checking sk_X509_num(keycerts).
 *
 *   If there is a key which does not have a matching cert, it is moved to
 *   the list nocerts.
 *
 *   If all certs are removed from 'certs' and/or 'pkeys', it will be the
 *   caller's responsibility to free the empty stacks.
 *
 * Returns:
 *  <  0 - An error returned.  Call ERR_get_error() to get errors information.
 *         Where possible, memory has been freed.
 *  >= 0 - The number of certs moved from 'cert' to 'pkcerts'.
 */
int
sunw_split_certs(STACK_OF(EVP_PKEY) *allkeys, STACK_OF(X509) *allcerts,
    STACK_OF(X509) **keycerts, STACK_OF(EVP_PKEY) **nocerts)
{
	STACK_OF(X509) *matching;
	STACK_OF(EVP_PKEY) *nomatch;
	EVP_PKEY *tmpkey;
	X509 *tmpcert;
	int count = 0;
	int found;
	int res;
	int i;
	int k;

	*keycerts = NULL;
	if (nocerts != NULL)
		*nocerts = NULL;
	nomatch = NULL;

	if ((matching = sk_X509_new_null()) == NULL) {
		SUNWerr(SUNW_F_SPLIT_CERTS, SUNW_R_MEMORY_FAILURE);
		return (-1);
	}
	*keycerts = matching;

	k = 0;
	while (k < sk_EVP_PKEY_num(allkeys)) {
		found = 0;
		tmpkey = sk_EVP_PKEY_value(allkeys, k);

		for (i = 0; i < sk_X509_num(allcerts); i++) {
			tmpcert = sk_X509_value(allcerts, i);
			res = X509_check_private_key(tmpcert, tmpkey);
			if (res != 0) {
				count++;
				found = 1;
				tmpcert = sk_X509_delete(allcerts, i);
				if (sk_X509_push(matching, tmpcert) == 0) {
					X509_free(tmpcert);
					SUNWerr(SUNW_F_SPLIT_CERTS,
					    SUNW_R_MEMORY_FAILURE);
					return (-1);
				}
				break;
			}
		}
		if (found != 0) {
			/*
			 * Found a match - keep the key & check out the next
			 * one.
			 */
			k++;
		} else {
			/*
			 * No cert matching this key.  Move the key if
			 * possible or discard it.  Don't increment the
			 * index.
			 */
			if (nocerts == NULL) {
				tmpkey = sk_EVP_PKEY_delete(allkeys, k);
				sunw_evp_pkey_free(tmpkey);
			} else {
				if (*nocerts == NULL) {
					nomatch = sk_EVP_PKEY_new_null();
					if (nomatch == NULL) {
						SUNWerr(SUNW_F_SPLIT_CERTS,
						    SUNW_R_MEMORY_FAILURE);
						return (-1);
					}
					*nocerts = nomatch;
				}
				tmpkey = sk_EVP_PKEY_delete(allkeys, k);
				if (sk_EVP_PKEY_push(nomatch, tmpkey) == 0) {
					sunw_evp_pkey_free(tmpkey);
					SUNWerr(SUNW_F_SPLIT_CERTS,
					    SUNW_R_MEMORY_FAILURE);
					return (-1);
				}
			}
		}
	}

	return (count);
}

/*
 * sunw_evp_pkey_free() Given an EVP_PKEY structure, free any attributes
 *     that are attached.  Then free the EVP_PKEY itself.
 *
 *     This is a replacement for EVP_PKEY_free() for the sunw stuff.
 *     It should be used in places where EVP_PKEY_free would be used,
 *     including calls to sk_EVP_PKEY_pop_free().
 *
 * Arguments:
 *   pkey     - Entry which potentially has attributes to be freed.
 *
 * Returns:
 *   None.
 */
void
sunw_evp_pkey_free(EVP_PKEY *pkey)
{
	if (pkey != NULL) {
		if (pkey->attributes != NULL) {
			sk_X509_ATTRIBUTE_pop_free(pkey->attributes,
			    X509_ATTRIBUTE_free);
			pkey->attributes = NULL;
		}
		EVP_PKEY_free(pkey);
	}
}

/*
 * sunw_set_localkeyid() sets the localkeyid in a cert, a private key or
 *     both.  Any existing localkeyid will be discarded.
 *
 * Arguments:
 *   keyid_str- A byte string with the localkeyid to set
 *   keyid_len- Length of the keyid byte string.
 *   pkey     - Points to a private key to set the keyidstr in.
 *   cert     - Points to a cert to set the keyidstr in.
 *
 * Note that setting a keyid into a cert which will not be written out as
 * a PKCS12 cert is pointless since it will be lost.
 *
 * Returns:
 *   0        - Success.
 *   < 0      - An error occurred.  It was probably an error in allocating
 *              memory.  The error will be set in the error stack.  Call
 *              ERR_get_error() to get specific information.
 */
int
sunw_set_localkeyid(const char *keyid_str, int keyid_len, EVP_PKEY *pkey,
    X509 *cert)
{
	X509_ATTRIBUTE *attr = NULL;
	ASN1_STRING *str = NULL;
	ASN1_TYPE *keyid = NULL;
	int retval = -1;
	int i;

	if (cert != NULL) {
		if (X509_keyid_set1(cert, (uchar_t *)keyid_str, keyid_len)
		    == 0) {
			SUNWerr(SUNW_F_SET_LOCALKEYID, SUNW_R_SET_LKID_ERR);
			goto cleanup;
		}
	}
	if (pkey != NULL) {
		str = (ASN1_STRING *)M_ASN1_OCTET_STRING_new();
		if (str == NULL ||
		    M_ASN1_OCTET_STRING_set(str, keyid_str, keyid_len) == 0 ||
		    (keyid = ASN1_TYPE_new()) == NULL) {
			SUNWerr(SUNW_F_SET_LOCALKEYID, SUNW_R_MEMORY_FAILURE);
			goto cleanup;
		}

		ASN1_TYPE_set(keyid, V_ASN1_OCTET_STRING, str);
		str = NULL;

		attr = type2attrib(keyid, NID_localKeyID);
		if (attr == NULL) {
			/*
			 * Error already on stack
			 */
			goto cleanup;
		}
		keyid = NULL;

		if (pkey->attributes == NULL) {
			pkey->attributes = sk_X509_ATTRIBUTE_new_null();
			if (pkey->attributes == NULL) {
				SUNWerr(SUNW_F_SET_LOCALKEYID,
				    SUNW_R_MEMORY_FAILURE);
				goto cleanup;
			}
		} else {
			i = find_attr_by_nid(pkey->attributes, NID_localKeyID);
			if (i >= 0)
				sk_X509_ATTRIBUTE_delete(pkey->attributes, i);
		}
		if (sk_X509_ATTRIBUTE_push(pkey->attributes, attr) == 0) {
			SUNWerr(SUNW_F_SET_LOCALKEYID, SUNW_R_MEMORY_FAILURE);
			goto cleanup;
		}
		attr = NULL;
	}
	retval = 0;

cleanup:
	if (str != NULL)
		ASN1_STRING_free(str);
	if (keyid != NULL)
		ASN1_TYPE_free(keyid);
	if (attr != NULL)
		X509_ATTRIBUTE_free(attr);

	return (retval);
}

/*
 * sunw_get_pkey_localkeyid() gets the localkeyid from a private key.  It can
 *     optionally remove the value found.
 *
 * Arguments:
 *   dowhat   - What to do with the attributes (remove them or copy them).
 *   pkey     - Points to a private key to set the keyidstr in.
 *   keyid_str- Points to a location which will receive the pointer to
 *              a byte string containing the binary localkeyid.  Note that
 *              this is a copy, and the caller must free it.
 *   keyid_len- Length of keyid_str.
 *
 * Returns:
 *   >= 0     - The number of characters in the keyid returned.
 *   < 0      - An error occurred.  It was probably an error in allocating
 *              memory.  The error will be set in the error stack.  Call
 *              ERR_get_error() to get specific information.
 */
int
sunw_get_pkey_localkeyid(getdo_actions_t dowhat, EVP_PKEY *pkey,
    char **keyid_str, int *keyid_len)
{
	X509_ATTRIBUTE *attr = NULL;
	ASN1_OCTET_STRING *str = NULL;
	ASN1_TYPE *ty = NULL;
	int len = 0;
	int i;

	if (keyid_str != NULL)
		*keyid_str = NULL;
	if (keyid_len != NULL)
		*keyid_len = 0;

	if (pkey == NULL || pkey->attributes == NULL) {
		return (0);
	}

	if ((i = find_attr_by_nid(pkey->attributes, NID_localKeyID)) < 0) {
		return (0);
	}
	attr = sk_X509_ATTRIBUTE_value(pkey->attributes, i);

	if ((ty = attrib2type(attr)) == NULL ||
	    ty->type != V_ASN1_OCTET_STRING) {
		return (0);
	}

	if (dowhat == GETDO_DEL) {
		attr = sk_X509_ATTRIBUTE_delete(pkey->attributes, i);
		if (attr != NULL)
			X509_ATTRIBUTE_free(attr);
		return (0);
	}

	str = ty->value.octet_string;
	len = str->length;
	if ((*keyid_str = malloc(len)) == NULL) {
		SUNWerr(SUNW_F_GET_LOCALKEYID, SUNW_R_MEMORY_FAILURE);
		return (-1);
	}

	(void) memcpy(*keyid_str, str->data, len);
	*keyid_len = len;

	return (len);
}

/*
 * sunw_get_pkey_fname() gets the friendlyName from a private key.  It can
 *     optionally remove the value found.
 *
 * Arguments:
 *   dowhat   - What to do with the attributes (remove them or copy them).
 *   pkey     - Points to a private key to get the frientlyname from
 *   fname    - Points to a location which will receive the pointer to a
 *              byte string with the ASCII friendlyname
 *
 * Returns:
 *   >= 0     - The number of characters in the frienlyname returned.
 *   < 0      - An error occurred.  It was probably an error in allocating
 *              memory.  The error will be set in the error stack.  Call
 *              ERR_get_error() to get specific information.
 */
int
sunw_get_pkey_fname(getdo_actions_t dowhat, EVP_PKEY *pkey, char **fname)
{
	X509_ATTRIBUTE *attr = NULL;
	ASN1_BMPSTRING *str = NULL;
	ASN1_TYPE *ty = NULL;
	int len = 0;
	int i;

	if (fname != NULL)
		*fname = NULL;

	if (pkey == NULL || pkey->attributes == NULL) {
		return (0);
	}

	if ((i = find_attr_by_nid(pkey->attributes, NID_friendlyName)) < 0) {
		return (0);
	}
	attr = sk_X509_ATTRIBUTE_value(pkey->attributes, i);

	if ((ty = attrib2type(attr)) == NULL ||
	    ty->type != V_ASN1_BMPSTRING) {
		return (0);
	}

	if (dowhat == GETDO_DEL) {
		attr = sk_X509_ATTRIBUTE_delete(pkey->attributes, i);
		if (attr != NULL)
			X509_ATTRIBUTE_free(attr);
		return (0);
	}

	str = ty->value.bmpstring;
#if OPENSSL_VERSION_NUMBER < 0x10000000L
	*fname = uni2asc(str->data, str->length);
#else
	*fname = OPENSSL_uni2asc(str->data, str->length);
#endif
	if (*fname == NULL) {
		SUNWerr(SUNW_F_GET_PKEY_FNAME, SUNW_R_MEMORY_FAILURE);
		return (-1);
	}

	len = strlen(*fname);

	return (len);
}

/*
 * sunw_find_localkeyid() searches stacks of certs and private keys,
 *     and returns  the first matching cert/private key found.
 *
 * Look for a keyid in a stack of certs.  if 'certs' is NULL and 'pkeys' is
 * not NULL, search the list of private keys.  Move the matching cert to
 * 'matching_cert' and its matching private key to 'matching_pkey'.  If no
 * cert or keys match, no match occurred.
 *
 * Arguments:
 *   keyid_str- A byte string with the localkeyid to match
 *   keyid_len- Length of the keyid byte string.
 *   pkeys    - Points to a stack of private keys which match the certs.
 *              This may be NULL, in which case no keys are returned.
 *   certs    - Points to a stack of certs to search.  If NULL, search the
 *              stack of keys instead.
 *   matching_pkey
 *            - Pointer to receive address of first matching pkey found.
 *              'matching_pkey' must not be NULL; '*matching_pkey' will be
 *              reset.
 *   matching_cert
 *            - Pointer to receive address of first matching cert found.
 *              'matching_cert' must not be NULL; '*matching_cert' will be
 *              reset.
 *
 * Returns:
 *  <  0 - An error returned.  Call ERR_get_error() to get errors information.
 *         Where possible, memory has been freed.
 *  >= 0 - Objects were found and returned.  Which objects are indicated by
 *         which bits are set (FOUND_PKEY and/or FOUND_CERT).
 */
int
sunw_find_localkeyid(char *keyid_str, int len, STACK_OF(EVP_PKEY) *pkeys,
STACK_OF(X509) *certs, EVP_PKEY **matching_pkey, X509 **matching_cert)
{
	ASN1_STRING *cmpstr = NULL;
	EVP_PKEY *tmp_pkey = NULL;
	X509 *tmp_cert = NULL;
	int retval = 0;

	/* If NULL arguments, this is an error */
	if (keyid_str == NULL ||
	    (pkeys == NULL || certs == NULL) ||
	    (pkeys != NULL && matching_pkey == NULL) ||
	    (certs != NULL && matching_cert == NULL)) {
		SUNWerr(SUNW_F_FIND_LOCALKEYID, SUNW_R_INVALID_ARG);
		return (-1);
	}

	if (matching_pkey != NULL)
		*matching_pkey = NULL;
	if (matching_cert != NULL)
		*matching_cert = NULL;

	cmpstr = (ASN1_STRING *)M_ASN1_OCTET_STRING_new();
	if (cmpstr == NULL ||
	    M_ASN1_OCTET_STRING_set(cmpstr, keyid_str, len) == 0) {
		SUNWerr(SUNW_F_FIND_LOCALKEYID, SUNW_R_MEMORY_FAILURE);
		return (-1);
	}

	retval = find_attr(NID_localKeyID, cmpstr, pkeys, &tmp_pkey, certs,
	    &tmp_cert);
	if (retval == 0) {
		ASN1_STRING_free(cmpstr);
		return (retval);
	}

	if (matching_pkey != NULL)
		*matching_pkey = tmp_pkey;
	if (matching_cert != NULL)
		*matching_cert = tmp_cert;

	return (retval);
}

/*
 * sunw_find_fname() searches stacks of certs and private keys for one with
 *     a matching friendlyname and returns the first matching cert/private
 *     key found.
 *
 * Look for a friendlyname in a stack of certs.  if 'certs' is NULL and 'pkeys'
 * is not NULL, search the list of private keys.  Move the matching cert to
 * 'matching_cert' and its matching private key to 'matching_pkey'.  If no
 * cert or keys match, no match occurred.
 *
 * Arguments:
 *   fname    - Friendlyname to find (NULL-terminated ASCII string).
 *   pkeys    - Points to a stack of private keys which match the certs.
 *              This may be NULL, in which case no keys are returned.
 *   certs    - Points to a stack of certs to search.  If NULL, search the
 *              stack of keys instead.
 *   matching_pkey
 *            - Pointer to receive address of first matching pkey found.
 *   matching_cert
 *            - Pointer to receive address of first matching cert found.
 *
 * Returns:
 *  <  0 - An error returned.  Call ERR_get_error() to get errors information.
 *         Where possible, memory has been freed.
 *  >= 0 - Objects were found and returned.  Which objects are indicated by
 *         which bits are set (FOUND_PKEY and/or FOUND_CERT).
 */
int
sunw_find_fname(char *fname, STACK_OF(EVP_PKEY) *pkeys, STACK_OF(X509) *certs,
    EVP_PKEY **matching_pkey, X509 ** matching_cert)
{
	ASN1_STRING *cmpstr = NULL;
	EVP_PKEY *tmp_pkey = NULL;
	X509 *tmp_cert = NULL;
	int retval = 0;

	/* If NULL arguments, this is an error */
	if (fname == NULL ||
	    (pkeys == NULL || certs == NULL) ||
	    (pkeys != NULL && matching_pkey == NULL) ||
	    (certs != NULL && matching_cert == NULL)) {
		SUNWerr(SUNW_F_FIND_FNAME, SUNW_R_INVALID_ARG);
		return (-1);
	}

	if (matching_pkey != NULL)
		*matching_pkey = NULL;
	if (matching_cert != NULL)
		*matching_cert = NULL;

	cmpstr = (ASN1_STRING *)asc2bmpstring(fname, strlen(fname));
	if (cmpstr == NULL) {
		/*
		 * Error already on stack
		 */
		return (-1);
	}

	retval = find_attr(NID_friendlyName, cmpstr, pkeys, &tmp_pkey, certs,
	    &tmp_cert);
	if (retval == 0) {
		ASN1_STRING_free(cmpstr);
		return (retval);
	}

	if (matching_pkey != NULL)
		*matching_pkey = tmp_pkey;
	if (matching_cert != NULL)
		*matching_cert = tmp_cert;

	return (retval);
}

/*
 * sunw_print_times() formats and prints cert times to the given file.
 *
 * The label is printed on one line. One or both dates are printed on
 * the following line or two, each with it's own indented label in the
 * format:
 *
 *    label
 *      'not before' date: whatever
 *      'not after' date:  whatever
 *
 * Arguments:
 *   fp       - file pointer for file to write to.
 *   dowhat   - what field(s) to print.
 *   label    - Label to use.  If NULL, no line will be printed.
 *   cert     - Points to a client or CA certs to check
 *
 * Returns:
 *  <  0 - An error occured.
 *  >= 0 - Number of lines written.
 */
int
sunw_print_times(FILE *fp, prnt_actions_t dowhat, char *label, X509 *cert)
{
	int lines = 0;

	if (label != NULL) {
		(void) fprintf(fp, "%s\n", label);
		lines++;
	}

	if (dowhat == PRNT_NOT_BEFORE || dowhat == PRNT_BOTH) {
		(void) fprintf(fp, "'not before' date: ");
		(void) print_time(fp, X509_get_notBefore(cert));
		(void) fprintf(fp, "\n");
		lines++;
	}

	if (dowhat == PRNT_NOT_AFTER || dowhat == PRNT_BOTH) {
		(void) fprintf(fp, "'not after' date:  ");
		(void) print_time(fp, X509_get_notAfter(cert));
		(void) fprintf(fp, "\n");
		lines++;
	}
	return (lines);
}

/*
 * sunw_check_keys() compares the public key in the certificate and a
 *     private key to ensure that they match.
 *
 * Arguments:
 *   cert     - Points to a certificate.
 *   pkey     - Points to a private key.
 *
 * Returns:
 *  == 0 - These do not match.
 *  != 0 - The cert's public key and the private key match.
 */
int
sunw_check_keys(X509 *cert, EVP_PKEY *pkey)
{
	int retval = 0;

	if (pkey != NULL && cert != NULL)
		retval = X509_check_private_key(cert, pkey);

	return (retval);
}

/*
 * sunw_issuer_attrs - Given a cert, return the issuer-specific attributes
 *     as one ASCII string.
 *
 * Arguments:
 *   cert     - Cert to process
 *   buf      - If non-NULL, buffer to receive string.  If NULL, one will
 *              be allocated and its value will be returned to the caller.
 *   len      - If 'buff' is non-null, the buffer's length.
 *
 * This returns an ASCII string with all issuer-related attributes in one
 * string separated by '/' characters.  Each attribute begins with its name
 * and an equal sign.  Two attributes (ATTR1 and Attr2) would have the
 * following form:
 *
 *         ATTR1=attr_value/ATTR2=attr2_value
 *
 * Returns:
 *   != NULL  - Pointer to the ASCII string containing the issuer-related
 *              attributes.  If the 'buf' argument was NULL, this is a
 *              dynamically-allocated buffer and the caller will have the
 *              responsibility for freeing it.
 *   NULL     - Memory needed to be allocated but could not be.  Errors
 *              are set on the error stack.
 */
char *
sunw_issuer_attrs(X509 *cert, char *buf, int len)
{
	return (X509_NAME_oneline(X509_get_issuer_name(cert), buf, len));
}

/*
 * sunw_subject_attrs - Given a cert, return the subject-specific attributes
 *     as one ASCII string.
 *
 * Arguments:
 *   cert     - Cert to process
 *   buf      - If non-NULL, buffer to receive string.  If NULL, one will
 *              be allocated and its value will be returned to the caller.
 *   len      - If 'buff' is non-null, the buffer's length.
 *
 * This returns an ASCII string with all subject-related attributes in one
 * string separated by '/' characters.  Each attribute begins with its name
 * and an equal sign.  Two attributes (ATTR1 and Attr2) would have the
 * following form:
 *
 *         ATTR1=attr_value/ATTR2=attr2_value
 *
 * Returns:
 *   != NULL  - Pointer to the ASCII string containing the subject-related
 *              attributes.  If the 'buf' argument was NULL, this is a
 *              dynamically-allocated buffer and the caller will have the
 *              responsibility for freeing it.
 *   NULL     - Memory needed to be allocated but could not be.  Errors
 *              are set on the error stack.
 */
char *
sunw_subject_attrs(X509 *cert, char *buf, int len)
{
	return (X509_NAME_oneline(X509_get_subject_name(cert), buf, len));
}

/*
 * sunw_append_keys - Given two stacks of private keys, remove the keys from
 *      the second stack and append them to the first.  Both stacks must exist
 *      at time of call.
 *
 * Arguments:
 *   dst 	- the stack to receive the keys from 'src'
 *   src	- the stack whose keys are to be moved.
 *
 * Returns:
 *   -1  	- An error occurred.  The error status is set.
 *   >= 0       - The number of keys that were copied.
 */
int
sunw_append_keys(STACK_OF(EVP_PKEY) *dst, STACK_OF(EVP_PKEY) *src)
{
	EVP_PKEY *tmpk;
	int count = 0;

	while (sk_EVP_PKEY_num(src) > 0) {
		tmpk = sk_EVP_PKEY_delete(src, 0);
		if (sk_EVP_PKEY_push(dst, tmpk) == 0) {
			sunw_evp_pkey_free(tmpk);
			SUNWerr(SUNW_F_APPEND_KEYS, SUNW_R_MEMORY_FAILURE);
			return (-1);
		}
		count++;
	}

	return (count);
}
