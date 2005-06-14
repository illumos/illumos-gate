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
#include <stdlib.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include <openssl/pkcs12.h>
#include <p12aux.h>
#include <auxutil.h>
#include <p12err.h>

/*
 * Briefly, a note on the APIs provided by this module.
 *
 * The sunw_PKCS_parse, parse_pkcs12 and sunw_PKCS12_contents APIs
 * replace OpenSSL funcionality provided by PKCS12_parse and its
 * supporting routines.
 *
 * The APIs provided here provide more functionality:
 *
 * - sunw_PKCS12_parse provides:
 *
 *   earlier MAC processing than PKCS12_parse
 *
 *   treats the handling of the difference between CA certs and certs
 *   with matching private keys differently that PKCS12_parse does.  In
 *   PKCS12_parse, any cert which is not the one selected is assumed to be
 *   a CA cert.  In parse_pkcs12, certs which have matching private keys are
 *   not returned as part of the CA certs.
 *
 *   the matching of private keys and certs is done at this level, rather than
 *   at the lower levels which were used in the openssl implementation.  This
 *   is part of the changes introduced so that the parsing functions can
 *   return just a cert, just a private key, the stack of CA certs or any
 *   combination.
 *
 *   added DO_FIRST_PAIR, DO_LAST_PAIR and DO_UNMATCHING matchty support.
 *
 *   do a much better job of cleaning up.  Specifically, free the added
 *   attributes on the private key which was done by calling
 *   sunw_evp_pkey_free().
 *
 *   in sunw_PKCS12_contents, handle allocation of the stacks of certificates
 *   and private keys so that a) the original stacks are not changed unless
 *   the parsing was successful; b) it will either extend stacks passed in,
 *   or allocate new ones if none were supplied.
 *
 * - for parse_outer vs. parse_pk12() (from the openssl source base):
 *
 *   this calls lower levels with stacks of private keys and certs, rather
 *   that a cert, a private key and a stack for CA certs.
 *
 * - In the case of parse_all_bags vs. parse_bags, there is no real difference,
 *   other than use of stacks of private keys and certificates (as opposed
 *   to one cert, one private key and a stack of CA certificates).
 *
 * - Finally, for parse_one_bag vs. parse_bag:
 *
 *   got rid of the bugs the openssl matching of keys and certificates.
 *
 *   got rid of the requirement that there is one private key and a matching
 *   cert somewhere in the input.  This was done by moving the matching
 *   code to a higher level.
 *
 *   put any localKeyID and/or friendlyName attributes found in the structures
 *   returned, so that they can be used at higher levels for searching, etc.
 *
 *   added some error returns (like an error when there is an unsupported
 *   bag type, an unsupported certificate type or an unsupported key type)
 *
 *   Added cleanup before returning.
 */

static int parse_pkcs12(PKCS12 *, const char *, int, char *, int, char *,
    EVP_PKEY **, X509 **, STACK_OF(X509) **);

static int parse_outer(PKCS12 *, const char *, STACK_OF(EVP_PKEY) *,
    STACK_OF(X509) *);

static int parse_all_bags(STACK_OF(PKCS12_SAFEBAG) *, const char *,
    STACK_OF(EVP_PKEY) *, STACK_OF(X509) *);

static int parse_one_bag(PKCS12_SAFEBAG *, const char *, STACK_OF(EVP_PKEY) *,
    STACK_OF(X509) *);

static int sunw_PKCS12_contents(PKCS12 *p12, const char *pass,
    STACK_OF(EVP_PKEY) **pkey, STACK_OF(X509) **certs);

/*
 * sunw_PKCS12_parse - Parse a PKCS12 structure and break it into its parts.
 *
 * Parse and decrypt a PKCS#12 structure returning user key, user cert and/or
 * other (CA) certs. Note either ca should be NULL, *ca should be NULL,
 * or it should point to a valid STACK_OF(X509) structure. pkey and cert can
 * be passed uninitialized.
 *
 * Arguments:
 *   p12      - Structure with pkcs12 info to be parsed
 *   pass     - Pass phrase for the private key (possibly empty) or NULL if
 *              there is none.
 *   matchty  - Info about which certs/keys to return if many are in the file.
 *   keyid    - If private key localkeyids friendlynames are to match a
 *              predetermined value, the value to match. This value should
 *		be an octet string.
 *   keyid_len- Length of the keyid byte string.
 *   name_str - If friendlynames are to match a predetermined value, the value
 *		 to match. This value should be a NULL terminated string.
 *   pkey     - Points to location pointing to the private key returned.
 *   cert     - Points to locaiton which points to the client cert returned
 *   ca       - Points to location that points to a stack of 'certificate
 *               authority' certs/trust anchors.
 *
 * Match based on the value of 'matchty' and the contents of 'keyid'
 * and/or 'name_str', as appropriate.  Go through the lists of certs and
 * private keys which were taken from the pkcs12 structure, looking for
 * matches of the requested type.  This function only searches the lists of
 * matching private keys and client certificates.  Kinds of matches allowed,
 * and the order in which they will be checked, are:
 *
 *   1) Find the key and/or cert whose localkeyid attributes matches
 *      'keyid'.
 *   2) Find the key and/or cert whose friendlyname attributes matches
 *	'name_str'
 *   3) Return the first matching key/cert pair found.
 *   4) Return the last matching key/cert pair found.
 *   5) Return whatever cert and/or key are available, even unmatching.
 *
 *   Append to the CA list, the certs which do not have matching private
 *   keys and which were not selected.
 *
 * If none of the bits are set, no client certs or private keys will be
 * returned.  CA (aka trust anchor) certs can be.
 *
 * Notes: If #3 is selected, then #4 will never occur.  CA certs will be
 * selected after a cert/key pairs are isolated.
 *
 * Returns:
 *  <  0 - An error returned.  Call ERR_get_error() to get errors information.
 *         Where possible, memory has been freed.
 *  >= 0 - Objects were found and returned.  Which objects are indicated by
 *         which bits are set (FOUND_PKEY, FOUND_CERT, FOUND_CA_CERTS).
 */
int
sunw_PKCS12_parse(PKCS12 *p12, const char *pass, int matchty, char *keyid,
    int keyid_len, char *name_str, EVP_PKEY **pkey, X509 **cert,
    STACK_OF(X509) **ca)
{
	boolean_t ca_supplied;
	int retval = -1;

	/* If NULL PKCS12 structure, this is an error */
	if (p12 == NULL) {
		SUNWerr(SUNW_F_PKCS12_PARSE, SUNW_R_INVALID_ARG);
		return (-1);
	}

	/* Set up arguments....  These will be allocated if needed */
	if (pkey)
		*pkey = NULL;
	if (cert)
		*cert = NULL;

	/*
	 * If there is already a ca list, use it.  Otherwise, allocate one
	 * and free is later if an error occurs or whatever.)
	 */
	ca_supplied = (ca != NULL && *ca != NULL);
	if (ca != NULL && *ca == NULL) {
		if ((*ca = sk_X509_new_null()) == NULL) {
			SUNWerr(SUNW_F_PKCS12_PARSE, SUNW_R_MEMORY_FAILURE);
			return (-1);
		}
	}

	/*
	 * If password is zero length or NULL then try verifying both cases
	 * to determine which password is correct. The reason for this is that
	 * under PKCS#12 password based encryption no password and a zero
	 * length password are two different things. If the password has a
	 * non-zero length and is not NULL then call PKCS12_verify_mac() with
	 * a length of '-1' and let it use strlen() to figure out the length
	 * of the password.
	 */
	/* Check the mac */
	if (pass == NULL || *pass == '\0') {
		if (PKCS12_verify_mac(p12, NULL, 0))
			pass = NULL;
		else if (PKCS12_verify_mac(p12, "", 0))
			pass = "";
		else {
			SUNWerr(SUNW_F_PKCS12_PARSE,
			    SUNW_R_MAC_VERIFY_FAILURE);
			goto err;
		}
	} else if (PKCS12_verify_mac(p12, pass, -1) == 0) {
		SUNWerr(SUNW_F_PKCS12_PARSE, SUNW_R_MAC_VERIFY_FAILURE);
		goto err;
	}

	retval = parse_pkcs12(p12, pass, matchty, keyid, keyid_len,
	    name_str, pkey, cert, ca);
	if (retval < 0) {
		SUNWerr(SUNW_F_PKCS12_PARSE, SUNW_R_PKCS12_PARSE_ERR);
		goto err;
	}
	return (retval);

err:
	if (pkey && *pkey) {
		sunw_evp_pkey_free(*pkey);
	}
	if (cert && *cert)
		X509_free(*cert);
	if (ca_supplied == B_FALSE && ca != NULL)
		sk_X509_pop_free(*ca, X509_free);

	return (-1);

}

/*
 * parse_pkcs12 - Oversee parsing of the pkcs12 structure.  Get it
 *         parsed.  After that either return what's found directly, or
 *         do any required matching.
 *
 * Arguments:
 *   p12      - Structure with pkcs12 info to be parsed
 *   pass     - Pass phrase for the private key (possibly empty) or NULL if
 *              there is none.
 *   matchty  - Info about which certs/keys to return if many are in the file.
 *   keyid    - If private key localkeyids friendlynames are to match a
 *              predetermined value, the value to match. This value should
 *		be an octet string.
 *   keyid_len- Length of the keyid byte string.
 *   name_str - If friendlynames are to match a predetermined value, the value
 *		 to match. This value should be a NULL terminated string.
 *   pkey     - Points to location pointing to the private key returned.
 *   cert     - Points to locaiton which points to the client cert returned
 *   ca       - Points to location that points to a stack of 'certificate
 *              authority' certs/trust anchors.
 *
 *   Note about error codes:  This function is an internal function, and the
 *   place where it is called sets error codes.  Therefore only set an error
 *   code if it is something that is unique or if the function which detected
 *   the error doesn't set one.
 *
 * Returns:
 *   == -1 - An error occurred.  Call ERR_get_error() to get error information.
 *           Where possible, memory has been freed.
 *   == 0  - No matching returns were found.
 *    > 0  - This is the aithmetic 'or' of the FOUND_* bits that indicate which
 *           of the requested entries were found.
 */
static int
parse_pkcs12(PKCS12 *p12, const char *pass, int matchty, char *keyid,
    int kstr_len, char *name_str, EVP_PKEY **pkey, X509 **cert,
    STACK_OF(X509) **ca)
{
	STACK_OF(EVP_PKEY) *work_kl = NULL;	/* Head for private key list */
	STACK_OF(EVP_PKEY) *nocerts = NULL;	/* Head for alt. key list */
	STACK_OF(X509) *work_ca = NULL;		/* Head for cert list */
	STACK_OF(X509) *work_cl = NULL;
	int retval = 0;
	int n;

	retval = sunw_PKCS12_contents(p12, pass, &work_kl, &work_ca);
	if (retval < 0) {
		goto cleanup;
	} else if (retval == 0) {
		/*
		 * Not really an error here - its just that nothing was found.
		 */
		goto cleanup;
	}

	if (sk_EVP_PKEY_num(work_kl) > 0) {

		if (sunw_split_certs(work_kl, work_ca, &work_cl, &nocerts)
		    < 0) {
			goto cleanup;
		}
	}

	/*
	 * Go through the lists of certs and private keys which were
	 * returned, looking for matches of the appropriate type.  Do these
	 * in the order described above.
	 */
	if ((matchty & DO_FIND_KEYID) != 0) {

		if (keyid == NULL) {
			SUNWerr(SUNW_F_PKCS12_PARSE, SUNW_R_INVALID_ARG);
			retval = -1;
			goto cleanup;
		}

		/* See if string matches localkeyid's */
		retval = sunw_find_localkeyid(keyid, kstr_len,
		    work_kl, work_cl, pkey, cert);
		if (retval != 0) {
			if (retval == -1)
				goto cleanup;
			else
				goto last_part;
		}
	}
	if ((matchty & DO_FIND_FN) != 0) {

		if (name_str == NULL) {
			SUNWerr(SUNW_F_PKCS12_PARSE, SUNW_R_INVALID_ARG);
			retval = -1;
			goto cleanup;
		}

		/* See if string matches friendly names */
		retval = sunw_find_fname(name_str, work_kl, work_cl,
		    pkey, cert);
		if (retval != 0) {
			if (retval == -1)
				goto cleanup;
			else
				goto last_part;
		}
	}

	if (matchty & DO_FIRST_PAIR) {

		/* Find the first cert and private key and return them */
		retval = get_key_cert(0, work_kl, pkey, work_cl, cert);
		if (retval != 0) {
			if (retval == -1)
				goto cleanup;
			else
				goto last_part;
		}
	}

	if (matchty & DO_LAST_PAIR) {

		/*
		 * Find the last matching cert and private key and return
		 * them.  Since keys which don't have matching client certs
		 * are at the end of the list of keys, use the number of
		 * client certs to compute the position of the last private
		 * key which matches a client cert.
		 */
		n = sk_X509_num(work_cl) - 1;
		retval = get_key_cert(n, work_kl, pkey, work_cl, cert);
		if (retval != 0) {
			if (retval == -1)
				goto cleanup;
			else
				goto last_part;
		}
	}

	if (matchty & DO_UNMATCHING) {
		STACK_OF(EVP_PKEY) *tmpk;
		STACK_OF(X509) *tmpc;

		/* Find the first cert and private key and return them */
		tmpc = work_cl;
		if (work_cl == NULL || sk_X509_num(work_cl) == 0)
			tmpc = work_ca;
		tmpk = work_kl;
		if (work_kl == NULL || sk_EVP_PKEY_num(work_kl) == 0)
			tmpk = nocerts;
		retval = get_key_cert(0, tmpk, pkey, tmpc, cert);
		if (retval != 0) {
			if (retval == -1)
				goto cleanup;
			else
				goto last_part;
		}
	}

last_part:
	/* If no errors, terminate normally */
	if (retval != -1)
		retval |= set_results(NULL, NULL, NULL, NULL, ca, &work_ca,
		    NULL, NULL);
	if (retval >= 0) {
		goto clean_part;
	}

	/* Fallthrough is intentional in error cases. */
cleanup:
	if (pkey != NULL && *pkey != NULL) {
		sunw_evp_pkey_free(*pkey);
		*pkey = NULL;
	}
	if (cert != NULL && *cert != NULL) {
		X509_free(*cert);
		*cert = NULL;
	}

clean_part:

	if (work_kl != NULL) {
		sk_EVP_PKEY_pop_free(work_kl, sunw_evp_pkey_free);
	}
	if (work_ca != NULL)
		sk_X509_pop_free(work_ca, X509_free);
	if (work_cl != NULL)
		sk_X509_pop_free(work_cl, X509_free);

	return (retval);
}

/*
 * sunw_PKCS12_contents() parses a pkcs#12 structure and returns component
 *     parts found, without evaluation.
 *
 * Parse and decrypt a PKCS#12 structure returning any user keys and/or
 * various certs. Note these should either be NULL, *whatever should
 * be NULL, or it should point to a valid STACK_OF(X509) structure.
 *
 * Arguments:
 *   p12      - Structure with pkcs12 info to be parsed
 *   pass     - Pass phrase for the private key and entire pkcs12 wad (possibly
 *              empty) or NULL if there is none.
 *   pkeys    - Points to address of a stack of private keys to return.
 *   certs    - Points to address of a stack of client certs return.
 *
 *   Note:  The certs and keys being returned are in random order.
 *
 * Returns:
 *  <  0 - An error returned.  Call ERR_get_error() to get errors information.
 *         Where possible, memory has been freed.
 *  >= 0 - Objects were found and returned.  Which objects are indicated by
 *         which bits are set (FOUND_PKEY or FOUND_CERT)
 */
static int
sunw_PKCS12_contents(PKCS12 *p12, const char *pass, STACK_OF(EVP_PKEY) **pkey,
    STACK_OF(X509) **certs)
{
	STACK_OF(EVP_PKEY) *work_kl = NULL;
	STACK_OF(X509) *work_ca = NULL;
	int retval = -1;

	/*
	 * Allocate the working stacks for private key and for the
	 * ca certs.
	 */
	if ((work_kl = sk_EVP_PKEY_new_null()) == NULL) {
		SUNWerr(SUNW_F_PKCS12_CONTENTS, SUNW_R_MEMORY_FAILURE);
		goto cleanup;
	}

	if ((work_ca = sk_X509_new_null()) == NULL) {
		SUNWerr(SUNW_F_PKCS12_CONTENTS, SUNW_R_MEMORY_FAILURE);
		goto cleanup;
	}

	if (parse_outer(p12, pass, work_kl, work_ca) == 0) {
		/*
		 * Error already on stack
		 */
		goto cleanup;
	}

	/* on error, set_results() returns an error on the stack */
	retval = set_results(pkey, &work_kl, certs, &work_ca, NULL,
	    NULL, NULL, NULL);

cleanup:
	if (work_kl != NULL) {
		sk_EVP_PKEY_pop_free(work_kl, sunw_evp_pkey_free);
	}

	return (retval);
}

/*
 * parse_outer - Unpack the outer PKCS#12 structure and go through the
 *         individual bags.  Return stacks of certs, private keys found and
 *         CA certs found.
 *
 *   Note about error codes:  This function is an internal function, and the
 *   place where it is called sets error codes.
 *
 * Returns:
 *    0 - An error returned.  Call ERR_get_error() to get errors information.
 *        Where possible, memory has been freed.
 *    1 - PKCS12 data object was parsed and lists of certs and private keys
 *        were returned.
 */
static int
parse_outer(PKCS12 *p12, const char *pass, STACK_OF(EVP_PKEY) *kl,
    STACK_OF(X509) *cl)
{
	STACK_OF(PKCS12_SAFEBAG) *bags;
	STACK_OF(PKCS7) *asafes;
	int i, bagnid;
	PKCS7 *p7;

	if ((asafes = M_PKCS12_unpack_authsafes(p12)) == NULL)
		return (0);

	for (i = 0; i < sk_PKCS7_num(asafes); i++) {
		p7 = sk_PKCS7_value(asafes, i);
		bagnid = OBJ_obj2nid(p7->type);
		if (bagnid == NID_pkcs7_data) {
			bags = M_PKCS12_unpack_p7data(p7);
		} else if (bagnid == NID_pkcs7_encrypted) {
			/*
			 * A length of '-1' means strlen() can be used
			 * to determine the password length.
			 */
			bags = M_PKCS12_unpack_p7encdata(p7, pass, -1);
		} else {
			SUNWerr(SUNW_F_PARSE_OUTER, SUNW_R_BAD_BAGTYPE);
			return (0);
		}

		if (bags == NULL) {
			SUNWerr(SUNW_F_PARSE_OUTER, SUNW_R_PARSE_BAG_ERR);
			sk_PKCS7_pop_free(asafes, PKCS7_free);
			return (0);
		}
		if (parse_all_bags(bags, pass, kl, cl) == 0) {
			sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
			sk_PKCS7_pop_free(asafes, PKCS7_free);
			return (0);
		}
	}

	return (1);
}

/*
 * parse_all_bags - go through the stack of bags, parsing each.
 *
 *   Note about error codes:  This function is an internal function, and the
 *   place where it is called sets error codes.
 *
 * Returns:
 *    0 - An error returned.  Call ERR_get_error() to get errors information.
 *        Where possible, memory has been freed.
 *    1 - Stack of safebags was parsed and lists of certs and private keys
 *        were returned.
 */
static int
parse_all_bags(STACK_OF(PKCS12_SAFEBAG) *bags, const char *pass,
    STACK_OF(EVP_PKEY) *kl, STACK_OF(X509) *cl)
{
	int i;
	for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
		if (parse_one_bag(sk_PKCS12_SAFEBAG_value(bags, i),
		    pass, kl, cl) == 0)
			return (0);
	}
	return (1);
}

/*
 * parse_one_bag - Parse an individual bag
 *
 *   i = parse_one_bag(bag, pass, kl, cl);
 *
 * Arguments:
 *   bag	- pkcs12 safebag to parse.
 *   pass 	- password for use in decryption of shrouded keybag
 *   kl         - Stack of private keys found so far.  New private keys will
 *                be added here if found.
 *   cl         - Stack of certs found so far.  New certificates will be
 *                added here if found.
 *
 * Returns:
 *    0 - An error returned.  Call ERR_get_error() to get errors information.
 *        Where possible, memory has been freed.
 *    1 - one safebag was parsed. If it contained a cert or private key, it
 *        was added to the stack of certs or private keys found, respectively.
 *        localKeyId or friendlyName attributes are returned with the
 *        private key or certificate.
 */
static int
parse_one_bag(PKCS12_SAFEBAG *bag, const char *pass, STACK_OF(EVP_PKEY) *kl,
    STACK_OF(X509) *cl)
{
	X509_ATTRIBUTE *attr = NULL;
	ASN1_TYPE *keyid = NULL;
	ASN1_TYPE *fname = NULL;
	PKCS8_PRIV_KEY_INFO *p8;
	EVP_PKEY *pkey = NULL;
	X509 *x509 = NULL;
	uchar_t *data = NULL;
	char *str = NULL;
	int retval = 1;

	keyid = PKCS12_get_attr(bag, NID_localKeyID);
	fname = PKCS12_get_attr(bag, NID_friendlyName);

	switch (M_PKCS12_bag_type(bag)) {
	case NID_keyBag:
		if ((pkey = EVP_PKCS82PKEY(bag->value.keybag)) == NULL) {
			SUNWerr(SUNW_F_PARSE_ONE_BAG, SUNW_R_PARSE_BAG_ERR);
			retval = 0;
			break;
		}
		break;

	case NID_pkcs8ShroudedKeyBag:
		/*
		 * A length of '-1' means strlen() can be used
		 * to determine the password length.
		 */
		if ((p8 = M_PKCS12_decrypt_skey(bag, pass, -1)) == NULL) {
			SUNWerr(SUNW_F_PARSE_ONE_BAG, SUNW_R_PARSE_BAG_ERR);
			retval = 0;
			break;
		}
		pkey = EVP_PKCS82PKEY(p8);
		PKCS8_PRIV_KEY_INFO_free(p8);
		if (pkey == NULL) {
			SUNWerr(SUNW_F_PARSE_ONE_BAG, SUNW_R_PARSE_BAG_ERR);
			retval = 0;
		}
		break;

	case NID_certBag:
		if (M_PKCS12_cert_bag_type(bag) != NID_x509Certificate) {
			SUNWerr(SUNW_F_PARSE_ONE_BAG, SUNW_R_BAD_CERTTYPE);
			break;
		}
		if ((x509 = M_PKCS12_certbag2x509(bag)) == NULL) {
			SUNWerr(SUNW_F_PARSE_ONE_BAG,
			    SUNW_R_PARSE_CERT_ERR);
			retval = 0;
			break;
		}

		if (keyid != NULL) {
			if (keyid->type != V_ASN1_OCTET_STRING) {
				SUNWerr(SUNW_F_PARSE_ONE_BAG,
				    SUNW_R_BAD_LKID);
				retval = 0;
				break;
			}
			if (X509_keyid_set1(x509,
			    keyid->value.octet_string->data,
			    keyid->value.octet_string->length) == 0) {
				SUNWerr(SUNW_F_PARSE_ONE_BAG,
				    SUNW_R_SET_LKID_ERR);
				retval = 0;
				break;
			}
		}

		if (fname != NULL) {
			ASN1_STRING *tmpstr = NULL;
			int len;

			if (fname->type != V_ASN1_BMPSTRING) {
				SUNWerr(SUNW_F_PARSE_ONE_BAG,
				    SUNW_R_BAD_FNAME);
				retval = 0;
				break;
			}

			tmpstr = fname->value.asn1_string;
			len = ASN1_STRING_to_UTF8(&data, tmpstr);
			if (len < 0) {
				SUNWerr(SUNW_F_PARSE_ONE_BAG,
				    SUNW_R_SET_FNAME_ERR);
				retval = 0;
				break;
			}

			if (X509_alias_set1(x509, data, len) == 0) {
				SUNWerr(SUNW_F_PARSE_ONE_BAG,
				    SUNW_R_SET_FNAME_ERR);
				retval = 0;
				break;
			}
		}

		if (sk_X509_push(cl, x509) == 0) {
			SUNWerr(SUNW_F_PARSE_ONE_BAG, SUNW_R_MEMORY_FAILURE);
			retval = 0;
			break;
		}
		x509 = NULL;
		break;

	case NID_safeContentsBag:
		if (keyid != NULL)
			ASN1_TYPE_free(keyid);
		if (fname != NULL)
			ASN1_TYPE_free(fname);
		if (parse_all_bags(bag->value.safes, pass, kl, cl) == 0) {
			/*
			 * Error already on stack
			 */
			return (0);
		}
		return (1);

	default:
		if (keyid != NULL)
			ASN1_TYPE_free(keyid);
		if (fname != NULL)
			ASN1_TYPE_free(fname);
		SUNWerr(SUNW_F_PARSE_ONE_BAG, SUNW_R_BAD_BAGTYPE);
		return (0);
	}


	if (pkey != NULL) {
		if (retval != 0 && (keyid != NULL || fname != NULL) &&
		    pkey->attributes == NULL) {
			pkey->attributes = sk_X509_ATTRIBUTE_new_null();
			if (pkey->attributes == NULL) {
				SUNWerr(SUNW_F_PARSE_ONE_BAG,
				    SUNW_R_MEMORY_FAILURE);
				retval = 0;
			}
		}

		if (retval != 0 && keyid != NULL) {
			attr = type2attrib(keyid, NID_localKeyID);
			if (attr == NULL)
				/*
				 * Error already on stack
				 */
				retval = 0;
			else {
				keyid = NULL;
				if (sk_X509_ATTRIBUTE_push(pkey->attributes,
				    attr) == 0) {
					SUNWerr(SUNW_F_PARSE_ONE_BAG,
					    SUNW_R_MEMORY_FAILURE);
					retval = 0;
				} else {
					attr = NULL;
				}
			}
		}

		if (retval != 0 && fname != NULL) {
			attr = type2attrib(fname, NID_friendlyName);
			if (attr == NULL) {
				/*
				 * Error already on stack
				 */
				retval = 0;
			} else {
				fname = NULL;
				if (sk_X509_ATTRIBUTE_push(pkey->attributes,
				    attr) == 0) {
					SUNWerr(SUNW_F_PARSE_ONE_BAG,
					    SUNW_R_MEMORY_FAILURE);
					retval = 0;
				} else {
					attr = NULL;
				}
			}
		}

		/* Save the private key */
		if (retval != 0) {
			if (sk_EVP_PKEY_push(kl, pkey) == 0) {
				SUNWerr(SUNW_F_PARSE_ONE_BAG,
				    SUNW_R_MEMORY_FAILURE);
				retval = 0;
			} else {
				pkey = NULL;
			}
		}
	}

	if (pkey != NULL) {
		sunw_evp_pkey_free(pkey);
	}

	if (x509 != NULL)
		X509_free(x509);

	if (keyid != NULL)
		ASN1_TYPE_free(keyid);

	if (fname != NULL)
		ASN1_TYPE_free(fname);

	if (attr != NULL)
		X509_ATTRIBUTE_free(attr);

	if (data != NULL)
		OPENSSL_free(data);

	if (str != NULL)
		OPENSSL_free(str);

	return (retval);
}
