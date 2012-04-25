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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2012, OmniTI Computer Consulting, Inc. All rights reserved.
 */


#include <strings.h>
#include <stdlib.h>
#include <assert.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <openssl/pkcs12.h>
#include "p12lib.h"

/*
 * OpenSSL provides a framework for pushing error codes onto a stack.
 * When an error occurs, the consumer may use the framework to
 * pop the errors off the stack and provide a trace of where the
 * errors occurred.
 *
 * Our PKCS12 code plugs into this framework by calling
 * ERR_load_SUNW_strings(). To push an error (which by the way, consists
 * of a function code and an error code) onto the stack our PKCS12 code
 * calls SUNWerr().
 *
 * Consumers of our PKCS12 code can then call the OpenSSL error routines
 * when an error occurs and retrieve the stack of errors.
 */

#ifndef OPENSSL_NO_ERR

/* Function codes and their matching strings */
static ERR_STRING_DATA SUNW_str_functs[] = {
	{ ERR_PACK(0, SUNW_F_USE_X509CERT, 0),	   "sunw_use_x509cert" },
	{ ERR_PACK(0, SUNW_F_USE_PKEY, 0),	   "sunw_use_pkey" },
	{ ERR_PACK(0, SUNW_F_USE_TASTORE, 0),	   "sunw_use_tastore" },
	{ ERR_PACK(0, SUNW_F_USE_CERTFILE, 0),	   "sunw_p12_use_certfile" },
	{ ERR_PACK(0, SUNW_F_USE_KEYFILE, 0),	   "sunw_p12_use_keyfile" },
	{ ERR_PACK(0, SUNW_F_USE_TRUSTFILE, 0),	   "sunw_p12_use_trustfile" },
	{ ERR_PACK(0, SUNW_F_READ_FILE, 0),	   "p12_read_file" },
	{ ERR_PACK(0, SUNW_F_DOPARSE, 0),	   "p12_doparse" },
	{ ERR_PACK(0, SUNW_F_PKCS12_PARSE, 0),	   "sunw_PKCS12_parse" },
	{ ERR_PACK(0, SUNW_F_PKCS12_CONTENTS, 0),  "sunw_PKCS12_contents" },
	{ ERR_PACK(0, SUNW_F_PARSE_ONE_BAG, 0),	   "parse_one_bag" },
	{ ERR_PACK(0, SUNW_F_PKCS12_CREATE, 0),	   "sunw_PKCS12_create" },
	{ ERR_PACK(0, SUNW_F_SPLIT_CERTS, 0),	   "sunw_split_certs" },
	{ ERR_PACK(0, SUNW_F_FIND_LOCALKEYID, 0),  "sunw_find_localkeyid" },
	{ ERR_PACK(0, SUNW_F_SET_LOCALKEYID, 0),   "sunw_set_localkeyid" },
	{ ERR_PACK(0, SUNW_F_GET_LOCALKEYID, 0),   "sunw_get_localkeyid" },
	{ ERR_PACK(0, SUNW_F_SET_FNAME, 0),	   "sunw_set_fname" },
	{ ERR_PACK(0, SUNW_F_GET_PKEY_FNAME, 0),   "sunw_get_pkey_fname" },
	{ ERR_PACK(0, SUNW_F_APPEND_KEYS, 0),	   "sunw_append_keys" },
	{ ERR_PACK(0, SUNW_F_PEM_CONTENTS, 0),	   "sunw_PEM_contents" },
	{ ERR_PACK(0, SUNW_F_PEM_INFO, 0),	   "pem_info" },
	{ ERR_PACK(0, SUNW_F_ASC2BMPSTRING, 0),	   "asc2bmpstring" },
	{ ERR_PACK(0, SUNW_F_UTF82ASCSTR, 0),	   "utf82ascstr" },
	{ ERR_PACK(0, SUNW_F_FINDATTR, 0),	   "findattr" },
	{ ERR_PACK(0, SUNW_F_TYPE2ATTRIB, 0),	   "type2attrib" },
	{ ERR_PACK(0, SUNW_F_MOVE_CERTS, 0),	   "move_certs" },
	{ ERR_PACK(0, SUNW_F_FIND_FNAME, 0),	   "sunw_find_fname" },
	{ ERR_PACK(0, SUNW_F_PARSE_OUTER, 0),	   "parse_outer" },
	{ ERR_PACK(0, SUNW_F_CHECKFILE, 0),	   "checkfile" },
	{ 0, NULL }
};

/* Error codes and their matching strings */
static ERR_STRING_DATA SUNW_str_reasons[] = {
	{ SUNW_R_INVALID_ARG,		"invalid argument" },
	{ SUNW_R_MEMORY_FAILURE,	"memory failure" },
	{ SUNW_R_MAC_VERIFY_FAILURE,	"mac verify failure" },
	{ SUNW_R_MAC_CREATE_FAILURE,	"mac create failure" },
	{ SUNW_R_BAD_FILETYPE,		"bad file type" },
	{ SUNW_R_BAD_PKEY,		"bad or missing private key" },
	{ SUNW_R_BAD_PKEYTYPE,		"unsupported key type" },
	{ SUNW_R_PKEY_READ_ERR,		"unable to read private key" },
	{ SUNW_R_NO_TRUST_ANCHOR,	"no trust anchors found" },
	{ SUNW_R_READ_TRUST_ERR,	"unable to read trust anchor" },
	{ SUNW_R_ADD_TRUST_ERR,		"unable to add trust anchor" },
	{ SUNW_R_PKCS12_PARSE_ERR,	"PKCS12 parse error" },
	{ SUNW_R_PKCS12_CREATE_ERR,	"PKCS12 create error" },
	{ SUNW_R_BAD_CERTTYPE,		"unsupported certificate type" },
	{ SUNW_R_PARSE_CERT_ERR,	"error parsing PKCS12 certificate" },
	{ SUNW_R_PARSE_BAG_ERR,		"error parsing PKCS12 bag" },
	{ SUNW_R_MAKE_BAG_ERR,		"error making PKCS12 bag" },
	{ SUNW_R_BAD_LKID,		"bad localKeyID format" },
	{ SUNW_R_SET_LKID_ERR,		"error setting localKeyID" },
	{ SUNW_R_BAD_FNAME,		"bad friendlyName format" },
	{ SUNW_R_SET_FNAME_ERR,		"error setting friendlyName" },
	{ SUNW_R_BAD_TRUST,		"bad or missing trust anchor" },
	{ SUNW_R_BAD_BAGTYPE,		"unsupported bag type" },
	{ SUNW_R_CERT_ERR,		"certificate error" },
	{ SUNW_R_PKEY_ERR,		"private key error" },
	{ SUNW_R_READ_ERR,		"error reading file" },
	{ SUNW_R_ADD_ATTR_ERR,		"error adding attribute" },
	{ SUNW_R_STR_CONVERT_ERR,	"error converting string" },
	{ SUNW_R_PKCS12_EMPTY_ERR,	"empty PKCS12 structure" },
	{ SUNW_R_PASSWORD_ERR,		"bad password" },
	{ 0, NULL }
};

/*
 * The library name that our module will be known as. This name
 * may be retrieved via OpenSSLs error APIs.
 */
static ERR_STRING_DATA SUNW_lib_name[] = {
	{ 0,	SUNW_LIB_NAME },
	{ 0, NULL }
};
#endif

/*
 * The value of this variable (initialized by a call to
 * ERR_load_SUNW_strings()) is what identifies our errors
 * to OpenSSL as being ours.
 */
static int SUNW_lib_error_code = 0;

/* local routines */
static int	parse_pkcs12(PKCS12 *, const char *, int, char *, int, char *,
    EVP_PKEY **, X509 **, STACK_OF(X509) **);
static int	pem_info(FILE *, pem_password_cb, void *,
    STACK_OF(EVP_PKEY) **, STACK_OF(X509) **);

static int	parse_outer(PKCS12 *, const char *, STACK_OF(EVP_PKEY) *,
    STACK_OF(X509) *);

static int	parse_all_bags(STACK_OF(PKCS12_SAFEBAG) *, const char *,
    STACK_OF(EVP_PKEY) *, STACK_OF(X509) *);

static int	parse_one_bag(PKCS12_SAFEBAG *, const char *,
    STACK_OF(EVP_PKEY) *, STACK_OF(X509) *);

static X509_ATTRIBUTE	*type2attrib(ASN1_TYPE *, int);
static ASN1_TYPE	*attrib2type(X509_ATTRIBUTE *);
static uchar_t		*utf82ascstr(ASN1_UTF8STRING *);
static ASN1_BMPSTRING	*asc2bmpstring(const char *, int);
static int		find_attr_by_nid(STACK_OF(X509_ATTRIBUTE) *, int);
static int		find_attr(int, ASN1_STRING *, STACK_OF(EVP_PKEY) *,
    EVP_PKEY **, STACK_OF(X509) *, X509 **);

static chk_errs_t	check_time(chk_actions_t, X509 *);
static int		get_key_cert(int, STACK_OF(EVP_PKEY) *, EVP_PKEY **,
    STACK_OF(X509) *, X509 **cert);
static int		move_certs(STACK_OF(X509) *, STACK_OF(X509) *);
static int		sunw_append_keys(STACK_OF(EVP_PKEY) *,
    STACK_OF(EVP_PKEY) *);
static int		set_results(STACK_OF(EVP_PKEY) **,
    STACK_OF(EVP_PKEY) **, STACK_OF(X509) **, STACK_OF(X509) **,
    STACK_OF(X509) **, STACK_OF(X509) **,
    STACK_OF(EVP_PKEY) **, STACK_OF(EVP_PKEY) **);

/*
 * ----------------------------------------------------------------------------
 * Public routines
 * ----------------------------------------------------------------------------
 */

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
 * sunw_PEM_contents() parses a PEM file and returns component parts found
 *
 * Parse and decrypt a PEM file, returning any user keys and certs.
 *
 * There are some limits to this function.  It will ignore the following:
 * - certificates identified by "TRUSTED CERTIFICATE"
 * - CERTIFICATE REQUEST and NEW CERTIFICATE REQUEST records.
 * - X509 CRL
 * - DH PARAMETERS
 * - DSA PARAMETERS
 * - Any PUBLIC KEY
 * - PKCS7
 * - PRIVATE KEY or ENCRYPTED PRIVATE KEY (PKCS 8)
 *
 * Arguments:
 *   fp       - File pointer for file containing PEM data.
 *   pass     - Pass phrase for the private key or NULL if there is none.
 *   pkeys    - Points to address of a stack of private keys to return.
 *   certs    - Points to address of a stack of client certs to return.
 *
 *   The pointers to stacks should either be NULL or their contents should
 *   either be NULL or should point to a valid STACK_OF(X509) structure.
 *   If the stacks contain information, corresponding information from the
 *   file will be appended to the original contents.
 *
 *   Note:  Client certs and and their matching private keys will be in any
 *   order.
 *
 *   Certs which have no matching private key are assumed to be ca certs.
 *
 * Returns:
 *  <  0 - An error returned.  Call ERR_get_error() to get errors information.
 *         Where possible, memory has been freed.
 *  >= 0 - Objects were found and returned.  Which objects are indicated by
 *         which bits are set (FOUND_PKEY, FOUND_CERT)
 */
int sunw_PEM_contents(FILE *fp, pem_password_cb *cb, void *userdata,
    STACK_OF(EVP_PKEY) **pkey, STACK_OF(X509) **certs)
{
	STACK_OF(EVP_PKEY) *work_kl = NULL;
	STACK_OF(X509) *work_ca = NULL;
	int retval = -1;

	/*
	 * Allocate the working stacks for private key and for the
	 * ca certs.
	 */
	if ((work_kl = sk_EVP_PKEY_new_null()) == NULL) {
		SUNWerr(SUNW_F_PEM_CONTENTS, SUNW_R_MEMORY_FAILURE);
		goto cleanup;
	}

	if ((work_ca = sk_X509_new_null()) == NULL) {
		SUNWerr(SUNW_F_PEM_CONTENTS, SUNW_R_MEMORY_FAILURE);
		goto cleanup;
	}

	/* Error strings are set within the following. */
	if (pem_info(fp, cb, userdata, &work_kl, &work_ca) <= 0) {
		goto cleanup;
	}

	/* on error, set_results() returns an error on the stack */
	retval = set_results(pkey, &work_kl, certs, &work_ca, NULL, NULL, NULL,
	    NULL);
cleanup:
	if (work_kl != NULL) {
		sk_EVP_PKEY_pop_free(work_kl, sunw_evp_pkey_free);
	}
	if (work_ca != NULL)
		sk_X509_pop_free(work_ca, X509_free);

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
int
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
	    (pkeys == NULL && certs == NULL) ||
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
 * sunw_get_cert_fname() gets the fiendlyname from a cert.  It can
 *     optionally remove the value found.
 *
 * Arguments:
 *   dowhat   - What to do with the attributes (remove them or copy them).
 *   cert     - Points to a cert to get the friendlyName from.
 *   fname    - Points to a location which will receive the pointer to a
 *              byte string with the ASCII friendlyname
 *
 * Returns:
 *   >= 0     - The number of characters in the friendlyname returned.
 *   < 0      - An error occurred.  It was probably an error in allocating
 *              memory.  The error will be set in the error stack.  Call
 *              ERR_get_error() to get specific information.
 */
int
sunw_get_cert_fname(getdo_actions_t dowhat, X509 *cert, char **fname)
{
	int len;

	if (fname != NULL)
		*fname = NULL;

	if (cert == NULL || cert->aux == NULL || cert->aux->alias == NULL) {
		return (0);
	}

	if (dowhat == GETDO_DEL) {
		/* Delete the entry */
		ASN1_UTF8STRING_free(cert->aux->alias);
		cert->aux->alias = NULL;
		return (0);
	}

	*((uchar_t **)fname) = utf82ascstr(cert->aux->alias);
	if (*fname == NULL) {
		/*
		 * Error already on stack
		 */
		return (-1);
	}

	len = strlen(*fname);

	return (len);
}

/*
 * sunw_set_fname() sets the friendlyName in a cert, a private key or
 *     both.  Any existing friendlyname will be discarded.
 *
 * Arguments:
 *   ascname  - An ASCII string with the friendlyName to set
 *   pkey     - Points to a private key to set the fname in.
 *   cert     - Points to a cert to set the fname in.
 *
 * Note that setting a friendlyName into a cert which will not be written out
 * as a PKCS12 cert is pointless since it will be lost.
 *
 * Returns:
 *   0        - Success.
 *   <0       - An error occurred.  It was probably an error in allocating
 *              memory.  The error will be set in the error stack.  Call
 *              ERR_get_error() to get specific information.
 */
int
sunw_set_fname(const char *ascname, EVP_PKEY *pkey, X509 *cert)
{
	X509_ATTRIBUTE *attr = NULL;
	ASN1_BMPSTRING *str = NULL;
	ASN1_TYPE *fname = NULL;
	unsigned char *data = NULL;
	int retval = -1;
	int len;
	int i;

	str = asc2bmpstring(ascname, strlen(ascname));
	if (str == NULL) {
		/*
		 * Error already on stack
		 */
		return (-1);
	}

	if (cert != NULL) {
		if (cert->aux != NULL && cert->aux->alias != NULL) {
			ASN1_UTF8STRING_free(cert->aux->alias);
		}

		len = ASN1_STRING_to_UTF8(&data, str);
		i = -23;
		if (len <= 0 || (i = X509_alias_set1(cert, data, len)) == 0) {
			SUNWerr(SUNW_F_SET_FNAME, SUNW_R_SET_FNAME_ERR);
			goto cleanup;
		}
	}
	if (pkey != NULL) {
		if ((fname = ASN1_TYPE_new()) == NULL) {
			SUNWerr(SUNW_F_SET_FNAME, SUNW_R_MEMORY_FAILURE);
			goto cleanup;
		}

		ASN1_TYPE_set(fname, V_ASN1_BMPSTRING, str);
		str = NULL;

		attr = type2attrib(fname, NID_friendlyName);
		if (attr == NULL) {
			/*
			 * Error already on stack
			 */
			goto cleanup;
		}
		fname = NULL;

		if (pkey->attributes == NULL) {
			pkey->attributes = sk_X509_ATTRIBUTE_new_null();
			if (pkey->attributes == NULL) {
				SUNWerr(SUNW_F_SET_FNAME,
				    SUNW_R_MEMORY_FAILURE);
				goto cleanup;
			}
		} else if ((i = find_attr_by_nid(pkey->attributes,
		    NID_friendlyName)) >= 0) {
			(void) sk_X509_ATTRIBUTE_delete(pkey->attributes, i);
		}

		if (sk_X509_ATTRIBUTE_push(pkey->attributes, attr) == 0) {
			SUNWerr(SUNW_F_SET_FNAME, SUNW_R_MEMORY_FAILURE);
			goto cleanup;
		}

		attr = NULL;
	}
	retval = 0;

cleanup:
	if (data != NULL)
		OPENSSL_free(data);
	if (str != NULL)
		ASN1_BMPSTRING_free(str);
	if (fname != NULL)
		ASN1_TYPE_free(fname);
	if (attr != NULL)
		X509_ATTRIBUTE_free(attr);

	return (retval);
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
 * sunw_check_cert_times() compares the time fields in a certificate
 *
 * Compare the 'not before' and the 'not after' times in the cert
 * to the current time.  Return the results of the comparison (bad time formats,
 * cert not yet in force, cert expired or in range)
 *
 * Arguments:
 *   dowhat   - what field(s) to check.
 *   cert     - Points to a cert to check
 *
 * Returns:
 *   Results of the comparison.
 */
chk_errs_t
sunw_check_cert_times(chk_actions_t chkwhat, X509 *cert)
{
	return (check_time(chkwhat, cert));
}

/*
 * ----------------------------------------------------------------------------
 * Local routines
 * ----------------------------------------------------------------------------
 */


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

/*
 * This function uses the only function that reads PEM files, regardless of
 * the kinds of information included (private keys, public keys, cert requests,
 * certs).  Other interfaces that read files require that the application
 * specifically know what kinds of things to read next, and call different
 * interfaces for the different kinds of entities.
 *
 * There is only one aspect of this function that's a bit problematic.
 * If it finds an encrypted private key, it does not decrypt it.  It returns
 * the encrypted data and other information needed to decrypt it.  The caller
 * must do the decryption.  This function does the decoding.
 */
static int
pem_info(FILE *fp, pem_password_cb cb, void *userdata,
    STACK_OF(EVP_PKEY) **pkeys, STACK_OF(X509) **certs)
{
	STACK_OF(X509_INFO) *info;
	STACK_OF(EVP_PKEY) *work_kl;
	STACK_OF(X509) *work_cl;
	X509_INFO *x;
	int retval = 0;
	int i;

	info = PEM_X509_INFO_read(fp, NULL, cb, userdata);
	if (info == NULL) {
		SUNWerr(SUNW_F_PEM_INFO, SUNW_R_READ_ERR);
		return (-1);
	}

	/*
	 * Allocate the working stacks for private key(s) and for the cert(s).
	 */
	if ((work_kl = sk_EVP_PKEY_new_null()) == NULL) {
		SUNWerr(SUNW_F_PEM_INFO, SUNW_R_MEMORY_FAILURE);
		retval = -1;
		goto cleanup;
	}

	if ((work_cl = sk_X509_new_null()) == NULL) {
		SUNWerr(SUNW_F_PEM_INFO, SUNW_R_MEMORY_FAILURE);
		retval = -1;
		goto cleanup;
	}

	/*
	 * Go through the entries in the info structure.
	 */
	for (i = 0; i < sk_X509_INFO_num(info); i++) {
		x = sk_X509_INFO_value(info, i);
		if (x->x509) {
			if (sk_X509_push(work_cl, x->x509) == 0) {
				retval = -1;
				break;
			}
			x->x509 = NULL;
		}
		if (x->x_pkey != NULL && x->x_pkey->dec_pkey != NULL &&
		    (x->x_pkey->dec_pkey->type == EVP_PKEY_RSA ||
		    x->x_pkey->dec_pkey->type == EVP_PKEY_DSA)) {
			const uchar_t *p;

			/*
			 * If the key was encrypted, PEM_X509_INFO_read does
			 * not decrypt it.  If that is the case, the 'enc_pkey'
			 * field is set to point to the unencrypted key data.
			 * Go through the additional steps to decode it before
			 * going on.
			 */
			if (x->x_pkey->enc_pkey != NULL) {

				if (PEM_do_header(&x->enc_cipher,
				    (uchar_t *)x->enc_data,
				    (long *)&x->enc_len,
				    cb, userdata) == 0) {
					if (ERR_GET_REASON(ERR_peek_error()) ==
					    PEM_R_BAD_PASSWORD_READ) {
						SUNWerr(SUNW_F_PEM_INFO,
						    SUNW_R_PASSWORD_ERR);
					} else {
						SUNWerr(SUNW_F_PEM_INFO,
						    SUNW_R_PKEY_READ_ERR);
					}
					retval = -1;
					break;
				}
				if (x->x_pkey->dec_pkey->type == EVP_PKEY_RSA) {
					RSA **pp;

					pp = &(x->x_pkey->dec_pkey->pkey.rsa);
					p = (uchar_t *)x->enc_data;
					if (d2i_RSAPrivateKey(pp, &p,
					    x->enc_len) == NULL) {
						SUNWerr(SUNW_F_PEM_INFO,
						    SUNW_R_PKEY_READ_ERR);
						retval = -1;
						break;
					}
				} else {
					DSA **pp;

					pp = &(x->x_pkey->dec_pkey->pkey.dsa);
					p = (uchar_t *)x->enc_data;
					if (d2i_DSAPrivateKey(pp, &p,
					    x->enc_len) == NULL) {
						SUNWerr(SUNW_F_PEM_INFO,
						    SUNW_R_PKEY_READ_ERR);
						retval = -1;
						break;
					}
				}
			}

			/* Save the key. */
			retval = sk_EVP_PKEY_push(work_kl, x->x_pkey->dec_pkey);
			if (retval == 0) {
				retval = -1;
				break;
			}
			x->x_pkey->dec_pkey = NULL;
		} else if (x->x_pkey != NULL) {
			SUNWerr(SUNW_F_PEM_INFO, SUNW_R_BAD_PKEYTYPE);
			retval = -1;
			break;
		}
	}
	if (retval == -1)
		goto cleanup;

	/* If error occurs, then error already on stack */
	retval = set_results(pkeys, &work_kl, certs, &work_cl, NULL, NULL,
	    NULL, NULL);

cleanup:
	if (work_kl != NULL) {
		sk_EVP_PKEY_pop_free(work_kl, sunw_evp_pkey_free);
	}
	if (work_cl != NULL)
		sk_X509_pop_free(work_cl, X509_free);

	sk_X509_INFO_pop_free(info, X509_INFO_free);

	return (retval);
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
static int
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
		count ++;
	}

	return (count);
}

/*
 * move_certs - Given two stacks of certs, remove the certs from
 *      the second stack and append them to the first.
 *
 * Arguments:
 *   dst 	- the stack to receive the certs from 'src'
 *   src	- the stack whose certs are to be moved.
 *
 * Returns:
 *   -1  	- An error occurred.  The error status is set.
 *   >= 0       - The number of certs that were copied.
 */
static int
move_certs(STACK_OF(X509) *dst, STACK_OF(X509) *src)
{
	X509 *tmpc;
	int count = 0;

	while (sk_X509_num(src) > 0) {
		tmpc = sk_X509_delete(src, 0);
		if (sk_X509_push(dst, tmpc) == 0) {
			X509_free(tmpc);
			SUNWerr(SUNW_F_MOVE_CERTS, SUNW_R_MEMORY_FAILURE);
			return (-1);
		}
		count++;
	}

	return (count);
}

/*
 * get_key_cert - Get a cert and its matching key from the stacks of certs
 *      and keys.  They are removed from the stacks.
 *
 * Arguments:
 *   n        - Offset of the entries to return.
 *   kl       - Points to a stack of private keys that matches the list of
 *              certs below.
 *   pkey     - Points at location where the address of the matching private
 *              key will be stored.
 *   cl       - Points to a stack of client certs with matching private keys.
 *   cert     - Points to locaiton where the address of the matching client cert
 *              will be returned
 *
 * The assumption is that the stacks of keys and certs contain key/cert pairs,
 * with entries in the same order and hence at the same offset.  Provided
 * the key and cert selected match, each will be removed from its stack and
 * returned.
 *
 * A stack of certs can be passed in without a stack of private keys, and vise
 * versa.  In that case, the indicated key/cert will be returned.
 *
 * Returns:
 *     0 - No matches were found.
 *   > 0 - Bits set based on FOUND_* definitions, indicating what is returned.
 *         This can be FOUND_PKEY, FOUND_CERT or (FOUND_PKEY | FOUND_CERT).
 */
static int
get_key_cert(int n, STACK_OF(EVP_PKEY) *kl, EVP_PKEY **pkey, STACK_OF(X509) *cl,
    X509 **cert)
{
	int retval = 0;
	int nk;
	int nc;

	nk = (kl != NULL) ? sk_EVP_PKEY_num(kl) : 0;
	nc = (cl != NULL) ? sk_X509_num(cl) : 0;

	if (pkey != NULL && *pkey == NULL) {
		if (nk > 0 && n >= 0 || n < nk) {
			*pkey = sk_EVP_PKEY_delete(kl, n);
			if (*pkey != NULL)
				retval |= FOUND_PKEY;
		}
	}

	if (cert != NULL && *cert == NULL) {
		if (nc > 0 && n >= 0 && n < nc) {
			*cert = sk_X509_delete(cl, n);
			if (*cert != NULL)
				retval |= FOUND_CERT;
		}
	}

	return (retval);
}


/*
 * asc2bmpstring - Convert a regular C ASCII string to an ASn1_STRING in
 *         ASN1_BMPSTRING format.
 *
 * Arguments:
 *   str      - String to be convered.
 *   len      - Length of the string.
 *
 * Returns:
 *   == NULL  - An error occurred.  Error information (accessible by
 *              ERR_get_error()) is set.
 *   != NULL  - Points to an ASN1_BMPSTRING structure with the converted
 *              string as a value.
 */
static ASN1_BMPSTRING *
asc2bmpstring(const char *str, int len)
{
	ASN1_BMPSTRING *bmp = NULL;
	uchar_t *uni = NULL;
	int unilen;

	/* Convert the character to the bmp format. */
#if OPENSSL_VERSION_NUMBER < 0x10000000L
	if (asc2uni(str, len, &uni, &unilen) == 0) {
#else
	if (OPENSSL_asc2uni(str, len, &uni, &unilen) == 0) {
#endif
		SUNWerr(SUNW_F_ASC2BMPSTRING, SUNW_R_MEMORY_FAILURE);
		return (NULL);
	}

	/*
	 * Adjust for possible pair of NULL bytes at the end because
	 * asc2uni() returns a doubly null terminated string.
	 */
	if (uni[unilen - 1] == '\0' && uni[unilen - 2] == '\0')
		unilen -= 2;

	/* Construct comparison string with correct format */
	bmp = M_ASN1_BMPSTRING_new();
	if (bmp == NULL) {
		SUNWerr(SUNW_F_ASC2BMPSTRING, SUNW_R_MEMORY_FAILURE);
		OPENSSL_free(uni);
		return (NULL);
	}

	bmp->data = uni;
	bmp->length = unilen;

	return (bmp);
}

/*
 * utf82ascstr - Convert a UTF8STRING string to a regular C ASCII string.
 *         This goes through an intermediate step with a ASN1_STRING type of
 *         IA5STRING (International Alphabet 5, which is the same as ASCII).
 *
 * Arguments:
 *   str      - UTF8STRING to be converted.
 *
 * Returns:
 *   == NULL  - An error occurred.  Error information (accessible by
 *              ERR_get_error()) is set.
 *   != NULL  - Points to a NULL-termianted ASCII string.  The caller must
 *              free it.
 */
static uchar_t *
utf82ascstr(ASN1_UTF8STRING *ustr)
{
	ASN1_STRING tmpstr;
	ASN1_STRING *astr = &tmpstr;
	uchar_t *retstr = NULL;
	int mbflag;
	int ret;

	if (ustr == NULL || ustr->type != V_ASN1_UTF8STRING) {
		SUNWerr(SUNW_F_UTF82ASCSTR, SUNW_R_INVALID_ARG);
		return (NULL);
	}

	mbflag = MBSTRING_ASC;
	tmpstr.data = NULL;
	tmpstr.length = 0;

	ret = ASN1_mbstring_copy(&astr, ustr->data, ustr->length, mbflag,
	    B_ASN1_IA5STRING);
	if (ret < 0) {
		SUNWerr(SUNW_F_UTF82ASCSTR, SUNW_R_STR_CONVERT_ERR);
		return (NULL);
	}

	retstr = OPENSSL_malloc(astr->length + 1);
	if (retstr == NULL) {
		SUNWerr(SUNW_F_UTF82ASCSTR, SUNW_R_MEMORY_FAILURE);
		return (NULL);
	}

	(void) memcpy(retstr, astr->data, astr->length);
	retstr[astr->length] = '\0';
	OPENSSL_free(astr->data);

	return (retstr);
}


/*
 * type2attrib - Given a ASN1_TYPE, return a X509_ATTRIBUTE of the type
 *     specified by the given NID.
 *
 * Arguments:
 *   ty       - Type structure to be made into an attribute
 *   nid      - NID of the attribute
 *
 * Returns:
 *   NULL	An error occurred.
 *   != NULL	An X509_ATTRIBUTE structure.
 */
X509_ATTRIBUTE *
type2attrib(ASN1_TYPE *ty, int nid)
{
	X509_ATTRIBUTE *a;

	if ((a = X509_ATTRIBUTE_new()) == NULL ||
	    (a->value.set = sk_ASN1_TYPE_new_null()) == NULL ||
	    sk_ASN1_TYPE_push(a->value.set, ty) == 0) {
		if (a != NULL)
			X509_ATTRIBUTE_free(a);
			SUNWerr(SUNW_F_TYPE2ATTRIB, SUNW_R_MEMORY_FAILURE);
		return (NULL);
	}
	a->single = 0;
	a->object = OBJ_nid2obj(nid);

	return (a);
}

/*
 * attrib2type - Given a X509_ATTRIBUTE, return pointer to the ASN1_TYPE
 *     component
 *
 * Arguments:
 *   attr     - Attribute structure containing a type.
 *
 * Returns:
 *   NULL	An error occurred.
 *   != NULL	An ASN1_TYPE structure.
 */
static ASN1_TYPE *
attrib2type(X509_ATTRIBUTE *attr)
{
	ASN1_TYPE *ty = NULL;

	if (attr == NULL || attr->single == 1)
		return (NULL);

	if (sk_ASN1_TYPE_num(attr->value.set) > 0)
		ty = sk_ASN1_TYPE_value(attr->value.set, 0);

	return (ty);
}

/*
 * find_attr_by_nid - Given a ASN1_TYPE, return the offset of a X509_ATTRIBUTE
 *     of the type specified by the given NID.
 *
 * Arguments:
 *   attrs    - Stack of attributes to search
 *   nid      - NID of the attribute being searched for
 *
 * Returns:
 *   -1 	None found
 *   != -1	Offset of the matching attribute.
 */
static int
find_attr_by_nid(STACK_OF(X509_ATTRIBUTE) *attrs, int nid)
{
	X509_ATTRIBUTE *a;
	int i;

	if (attrs == NULL)
		return (-1);

	for (i = 0; i < sk_X509_ATTRIBUTE_num(attrs); i++) {
		a = sk_X509_ATTRIBUTE_value(attrs, i);
		if (OBJ_obj2nid(a->object) == nid)
			return (i);
	}
	return (-1);
}

/*
 * Called by our PKCS12 code to read our function and error codes
 * into memory so that the OpenSSL framework can retrieve them.
 */
void
ERR_load_SUNW_strings(void)
{
	assert(SUNW_lib_error_code == 0);
#ifndef OPENSSL_NO_ERR
	/*
	 * Have OpenSSL provide us with a unique ID.
	 */
	SUNW_lib_error_code = ERR_get_next_error_library();

	ERR_load_strings(SUNW_lib_error_code, SUNW_str_functs);
	ERR_load_strings(SUNW_lib_error_code, SUNW_str_reasons);

	SUNW_lib_name->error = ERR_PACK(SUNW_lib_error_code, 0, 0);
	ERR_load_strings(0, SUNW_lib_name);
#endif
}

/*
 * The SUNWerr macro resolves to this routine. So when we need
 * to push an error, this routine does it for us. Notice that
 * the SUNWerr macro provides a filename and line #.
 */
void
ERR_SUNW_error(int function, int reason, char *file, int line)
{
	assert(SUNW_lib_error_code != 0);
#ifndef OPENSSL_NO_ERR
	ERR_PUT_error(SUNW_lib_error_code, function, reason, file, line);
#endif
}

/*
 * check_time - Given an indication of the which time(s) to check, check
 *      that time or those times against the current time and return the
 *      relationship.
 *
 * Arguments:
 *   chkwhat    - What kind of check to do.
 *   cert	- The cert to check.
 *
 * Returns:
 *   CHKERR_* values.
 */
static chk_errs_t
check_time(chk_actions_t chkwhat, X509 *cert)
{
	int i;

	if (chkwhat == CHK_NOT_BEFORE || chkwhat == CHK_BOTH) {
		i = X509_cmp_time(X509_get_notBefore(cert), NULL);
		if (i == 0)
			return (CHKERR_TIME_BEFORE_BAD);
		if (i > 0)
			return (CHKERR_TIME_IS_BEFORE);

		/* The current time is after the 'not before' time */
	}

	if (chkwhat == CHK_NOT_AFTER || chkwhat == CHK_BOTH) {
		i = X509_cmp_time(X509_get_notAfter(cert), NULL);
		if (i == 0)
			return (CHKERR_TIME_AFTER_BAD);
		if (i < 0)
			return (CHKERR_TIME_HAS_EXPIRED);
	}

	return (CHKERR_TIME_OK);
}

/*
 * find_attr - Look for a given attribute of the type associated with the NID.
 *
 * Arguments:
 *   nid      - NID for the attribute to be found (either NID_friendlyName or
 *              NID_locakKeyId)
 *   str      - ASN1_STRING-type structure containing the value to be found,
 *              FriendlyName expects a ASN1_BMPSTRING and localKeyID uses a
 *              ASN1_STRING.
 *   kl       - Points to a stack of private keys.
 *   pkey     - Points at a location where the address of the matching private
 *              key will be stored.
 *   cl       - Points to a stack of client certs with matching private keys.
 *   cert     - Points to locaiton where the address of the matching client cert
 *              will be returned
 *
 * This function is designed to process lists of certs and private keys.
 * This is made complex because these the attributes are stored differently
 * for certs and for keys.  For certs, only a few attributes are retained.
 * FriendlyName is stored in the aux structure, under the name 'alias'.
 * LocalKeyId is also stored in the aux structure, under the name 'keyid'.
 * A pkey structure has a stack of attributes.
 *
 * The basic approach is:
 *   - If there there is no stack of certs but a stack of private keys exists,
 *     search the stack of keys for a match. Alternately, if there is a stack
 *     of certs and no private keys, search the certs.
 *
 *   - If there are both certs and keys, assume that the matching certs and
 *     keys are in their respective stacks, with matching entries in the same
 *     order.  Search for the name or keyid in the stack of certs.  If it is
 *     not found, then this function returns 0 (nothing found).
 *
 *   - Once a cert is found, verify that the key actually matches by
 *     comparing the private key with the public key (in the cert).
 *     If they don't match, return an error.
 *
 *   A pointer to cert and/or pkey which matches the name or keyid is stored
 *   in the return arguments.
 *
 * Returns:
 *     0 - No matches were found.
 *   > 0 - Bits set based on FOUND_* definitions, indicating what was found.
 *         This can be FOUND_PKEY, FOUND_CERT or (FOUND_PKEY | FOUND_CERT).
 */
static int
find_attr(int nid, ASN1_STRING *str, STACK_OF(EVP_PKEY) *kl, EVP_PKEY **pkey,
    STACK_OF(X509) *cl, X509 **cert)
{
	ASN1_UTF8STRING *ustr = NULL;
	ASN1_STRING *s;
	ASN1_TYPE *t;
	EVP_PKEY *p;
	uchar_t *fname = NULL;
	X509 *x;
	int found = 0;
	int chkcerts;
	int len;
	int res;
	int c = -1;
	int k = -1;

	chkcerts = (cert != NULL || pkey != NULL) && cl != NULL;
	if (chkcerts && nid == NID_friendlyName &&
	    str->type == V_ASN1_BMPSTRING) {
		ustr = ASN1_UTF8STRING_new();
		if (ustr == NULL) {
			SUNWerr(SUNW_F_FINDATTR, SUNW_R_MEMORY_FAILURE);
			return (0);
		}
		len = ASN1_STRING_to_UTF8(&fname, str);
		if (fname == NULL) {
			ASN1_UTF8STRING_free(ustr);
			SUNWerr(SUNW_F_FINDATTR, SUNW_R_STR_CONVERT_ERR);
			return (0);
		}

		if (ASN1_STRING_set(ustr, fname, len) == 0) {
			ASN1_UTF8STRING_free(ustr);
			OPENSSL_free(fname);
			SUNWerr(SUNW_F_FINDATTR, SUNW_R_MEMORY_FAILURE);
			return (0);
		}
	}

	if (chkcerts) {
		for (c = 0; c < sk_X509_num(cl); c++) {
			res = -1;
			x = sk_X509_value(cl, c);
			if (nid == NID_friendlyName && ustr != NULL) {
				if (x->aux == NULL || x->aux->alias == NULL)
					continue;
				s = x->aux->alias;
				if (s != NULL && s->type == ustr->type &&
				    s->data != NULL) {
					res = ASN1_STRING_cmp(s, ustr);
				}
			} else {
				if (x->aux == NULL || x->aux->keyid == NULL)
					continue;
				s = x->aux->keyid;
				if (s != NULL && s->type == str->type &&
				    s->data != NULL) {
					res = ASN1_STRING_cmp(s, str);
				}
			}
			if (res == 0) {
				if (cert != NULL)
					*cert = sk_X509_delete(cl, c);
				found = FOUND_CERT;
				break;
			}
		}
		if (ustr != NULL) {
			ASN1_UTF8STRING_free(ustr);
			OPENSSL_free(fname);
		}
	}

	if (pkey != NULL && kl != NULL) {
		/*
		 * Looking for pkey to match a cert?  If so, assume that
		 * lists of certs and their matching pkeys are in the same
		 * order.  Call X509_check_private_key() to verify this
		 * assumption.
		 */
		if (found != 0 && cert != NULL) {
			k = c;
			p = sk_EVP_PKEY_value(kl, k);
			if (X509_check_private_key(x, p) != 0) {
				if (pkey != NULL)
					*pkey = sk_EVP_PKEY_delete(kl, k);
				found |= FOUND_PKEY;
			}
		} else if (cert == NULL) {
			for (k = 0; k < sk_EVP_PKEY_num(kl); k++) {
				p = sk_EVP_PKEY_value(kl, k);
				if (p == NULL || p->attributes == NULL)
					continue;

				t = PKCS12_get_attr_gen(p->attributes, nid);
				if (t != NULL || ASN1_STRING_cmp(str,
				    t->value.asn1_string) == 0)
					continue;

				found |= FOUND_PKEY;
				if (pkey != NULL)
					*pkey = sk_EVP_PKEY_delete(kl, k);
				break;
			}
		}
	}

	return (found);
}

/*
 * set_results - Given two pointers to stacks of private keys, certs or CA
 *     CA certs, either copy the second stack to the first, or append the
 *     contents of the second to the first.
 *
 * Arguments:
 *   pkeys    - Points to stack of pkeys
 *   work_kl  - Points to working stack of pkeys
 *   certs    - Points to stack of certs
 *   work_cl  - Points to working stack of certs
 *   cacerts  - Points to stack of CA certs
 *   work_ca  - Points to working stack of CA certs
 *   xtrakeys - Points to stack of unmatcned pkeys
 *   work_xl  - Points to working stack of unmatcned pkeys
 *
 *   The arguments are in pairs.  The first of each pair points to a stack
 *   of keys or certs.  The second of the pair points at a 'working stack'
 *   of the same type of entities.   Actions taken are as follows:
 *
 *   - If either the first or second argument is NULL, or if there are no
 *     members in the second stack, there is nothing to do.
 *   - If the first argument points to a pointer which is NULL, then there
 *     is no existing stack for the first argument.  Copy the stack pointer
 *     from the second argument to the first argument and NULL out the stack
 *     pointer for the second.
 *   - Otherwise, go through the elements of the second stack, removing each
 *     and adding it to the first stack.
 *
 * Returns:
 *   == -1 - An error occurred.  Call ERR_get_error() to get error information.
 *   == 0  - No matching returns were found.
 *    > 0  - This is the arithmetic 'or' of the FOUND_* bits that indicate which
 *           of the requested entries were manipulated.
 */
static int
set_results(STACK_OF(EVP_PKEY) **pkeys, STACK_OF(EVP_PKEY) **work_kl,
    STACK_OF(X509) **certs, STACK_OF(X509) **work_cl,
    STACK_OF(X509) **cacerts, STACK_OF(X509) **work_ca,
    STACK_OF(EVP_PKEY) **xtrakeys, STACK_OF(EVP_PKEY) **work_xl)
{
	int retval = 0;

	if (pkeys != NULL && work_kl != NULL && *work_kl != NULL &&
	    sk_EVP_PKEY_num(*work_kl) > 0) {
		if (*pkeys == NULL) {
			*pkeys = *work_kl;
			*work_kl = NULL;
		} else {
			if (sunw_append_keys(*pkeys, *work_kl) < 0) {
				return (-1);
			}
		}
		retval |= FOUND_PKEY;
	}
	if (certs != NULL && work_cl != NULL && *work_cl != NULL &&
	    sk_X509_num(*work_cl) > 0) {
		if (*certs == NULL) {
			*certs = *work_cl;
			*work_cl = NULL;
		} else {
			if (move_certs(*certs, *work_cl) < 0) {
				return (-1);
			}
		}
		retval |= FOUND_CERT;
	}

	if (cacerts != NULL && work_ca != NULL && *work_ca != NULL &&
	    sk_X509_num(*work_ca) > 0) {
		if (*cacerts == NULL) {
			*cacerts = *work_ca;
			*work_ca = NULL;
		} else {
			if (move_certs(*cacerts, *work_ca) < 0) {
				return (-1);
			}
		}
		retval |= FOUND_CA_CERTS;
	}

	if (xtrakeys != NULL && work_xl != NULL && *work_xl != NULL &&
	    sk_EVP_PKEY_num(*work_xl) > 0) {
		if (*xtrakeys == NULL) {
			*xtrakeys = *work_xl;
			*work_xl = NULL;
		} else {
			if (sunw_append_keys(*xtrakeys, *work_xl) < 0) {
				return (-1);
			}
		}
		retval |= FOUND_XPKEY;
	}

	return (retval);
}
