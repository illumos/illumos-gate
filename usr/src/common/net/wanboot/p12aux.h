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
 * Copyright 2002, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2015 by Delphix. All rights reserved.
 */

#ifndef	_P12AUX_H
#define	_P12AUX_H

#include <openssl/pkcs12.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * I really hate to do this.  It's pretty gross, but go ahead and use the
 * macros and functions already defined to provide new EVP_PKEY-specific
 * macros, for use within this file only.
 *
 * My apologies.
 */
/* LINTED */
DECLARE_STACK_OF(EVP_PKEY);

#define	sk_EVP_PKEY_new_null() SKM_sk_new_null(EVP_PKEY)
#define	sk_EVP_PKEY_free(st) SKM_sk_free(EVP_PKEY, (st))
#define	sk_EVP_PKEY_num(st) SKM_sk_num(EVP_PKEY, (st))
#define	sk_EVP_PKEY_value(st, i) SKM_sk_value(EVP_PKEY, (st), (i))
#define	sk_EVP_PKEY_push(st, val) SKM_sk_push(EVP_PKEY, (st), (val))
#define	sk_EVP_PKEY_find(st, val) SKM_sk_find(EVP_PKEY, (st), (val))
#define	sk_EVP_PKEY_delete(st, i) SKM_sk_delete(EVP_PKEY, (st), (i))
#define	sk_EVP_PKEY_delete_ptr(st, ptr) SKM_sk_delete_ptr(EVP_PKEY, (st), (ptr))
#define	sk_EVP_PKEY_insert(st, val, i) SKM_sk_insert(EVP_PKEY, (st), (val), (i))
#define	sk_EVP_PKEY_pop_free(st, free_func) SKM_sk_pop_free(EVP_PKEY, (st), \
	    (free_func))
#define	sk_EVP_PKEY_pop(st) SKM_sk_pop(EVP_PKEY, (st))

/*
 * This type indicates what to do with an attribute being returned.
 */
typedef enum {
	GETDO_COPY = 1,		/* Simply return the value of the attribute */
	GETDO_DEL		/* Delete the attribute at the same time. */
} getdo_actions_t;

/*
 * The following is used to call the sunw_print_times function which is
 * described at the bottom of the page.
 */
typedef enum {
	PRNT_NOT_BEFORE = 1,	/* Print 'not before' date */
	PRNT_NOT_AFTER,		/* Print 'not after' date */
	PRNT_BOTH		/* Prints both dates */
} prnt_actions_t;

/*
 * For sunw_pkcs12_parse, the following are values for bits that indicate
 * various types of searches/matching to do. Any of these values can be
 * OR'd together. However, the order in which an attempt will be made
 * to satisfy them is the order in which they are listed below. The
 * exception is DO_NONE. It should not be OR'd with any other value.
 */
#define	DO_NONE		0x00	/* Don't even try to match */
#define	DO_FIND_KEYID	0x01	/* 1st cert, key with matching localkeyid */
#define	DO_FIND_FN	0x02	/* 1st cert, key with matching friendlyname */
#define	DO_FIRST_PAIR	0x04	/* Return first matching cert/key pair found */
#define	DO_LAST_PAIR	0x08	/* Return last matching cert/key pair found */
#define	DO_UNMATCHING	0x10	/* Return first cert and/or key */

/* Bits returned, which indicate what values were found. */
#define	FOUND_PKEY	0x01	/* Found one or more private key */
#define	FOUND_CERT	0x02	/* Found one or more client certificate */
#define	FOUND_CA_CERTS	0x04	/* Added at least one cert to the CA list */
#define	FOUND_XPKEY	0x08	/* Found at least one private key which does */
				/* not match a certificate in the certs list */

/*
 * sunw_cryto_init() does crypto-specific initialization.
 *
 * Arguments:
 *   None.
 *
 * Returns:
 *   None.
 */
void sunw_crypto_init(void);

/*
 * sunw_PKCS12_parse() parses a pkcs#12 structure and returns component parts.
 *
 * Parse and decrypt a PKCS#12 structure returning user key, user cert and/or
 * other (CA) certs. Note either ca should be NULL, *ca should be NULL,
 * or it should point to a valid STACK_OF(X509) structure. pkey and cert can
 * be passed uninitialized.
 *
 * Arguments:
 *   p12      - Structure with pkcs12 info to be parsed
 *   pass     - Pass phrase for the private key and entire pkcs12 wad (possibly
 *              empty) or NULL if there is none.
 *   matchty  - Info about which certs/keys to return if many are in the file.
 *   keyid_str- If private key localkeyids are to match a predetermined value,
 *              the value to match.
 *   keyid_len- Length of the keyid byte string.
 *   name_str - If friendlynames are to match a predetermined value, the value
 *              to match.
 *   pkey     - Points to location pointing to the private key returned.
 *   cert     - Points to locaiton which points to the client cert returned
 *   ca       - Points to location that points to a stack of 'certificate
 *              authority' certs (possibly including trust anchors).
 *
 * Match based on the value of 'matchty' and the contents of 'keyid_str'
 * and/or 'name_str', as appropriate.  Go through the lists of certs and
 * private keys which were taken from the pkcs12 structure, looking for
 * matches of the requested type.  This function only searches the lists of
 * matching private keys and client certificates.  Kinds of matches allowed,
 * and the order in which they will be checked, are:
 *
 *   1) Find the key and/or cert whose localkeyid attributes matches 'cmpstr'
 *   2) Find the key and/or cert whose friendlyname attributes matches 'cmpstr'
 *   3) Return the first matching key/cert pair found.
 *   4) Return the last matching key/cert pair found.
 *   5) Return whatever cert and/or key are available, even unmatching.
 *
 *   Append the certs which do not have matching private keys and which were
 *   not selected to the CA list.
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
int sunw_PKCS12_parse(PKCS12 *, const char *, int, char *, int, char *,
    EVP_PKEY **, X509 **, STACK_OF(X509) **);


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
 *   pkey     - Points to stack of private keys.
 *   cert     - Points to stack of client (public ke) certs
 *   ca       - Points to stack of 'certificate authority' certs (or trust
 *              anchors).
 *
 *   Note that any of these may be NULL.
 *
 * Returns:
 *   NULL     - An error occurred.
 *   != NULL  - Address of PKCS12 structure.  The user is responsible for
 *              freeing the memory when done.
 */
PKCS12 *sunw_PKCS12_create(const char *, STACK_OF(EVP_PKEY) *, STACK_OF(X509) *,
    STACK_OF(X509) *);


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
int sunw_split_certs(STACK_OF(EVP_PKEY) *, STACK_OF(X509) *, STACK_OF(X509) **,
    STACK_OF(EVP_PKEY) **);

/*
 * sunw_evp_pkey_free() Given an EVP_PKEY structure, free any attributes
 *     that are attached.  Then free the EVP_PKEY itself.
 *
 *     This is the replacement for EVP_PKEY_free() for the sunw stuff.
 *     It should be used in places where EVP_PKEY_free would be used,
 *     including calls to sk_EVP_PKEY_pop_free().
 *
 * Arguments:
 *   pkey     - Entry which potentially has attributes to be freed.
 *
 * Returns:
 *   None.
 */
void sunw_evp_pkey_free(EVP_PKEY *);

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
int sunw_set_localkeyid(const char *, int, EVP_PKEY *, X509 *);


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
int sunw_get_pkey_localkeyid(getdo_actions_t, EVP_PKEY *, char **, int *);


/*
 * sunw_get_pkey_fname() gets the friendlyName from a private key.  It can
 *     optionally remove the value found.
 *
 * Arguments:
 *   dowhat   - What to do with the attributes (remove them or just return
 *              them).
 *   pkey     - Points to a private key to get the keyid from
 *   fname    - Points to a location which will receive the pointer to a
 *              byte string with the ASCII friendlyname
 *
 * Returns:
 *   >= 0     - The number of characters in the keyid returned.
 *   < 0      - An error occurred.  It was probably an error in allocating
 *              memory.  The error will be set in the error stack.  Call
 *              ERR_get_error() to get specific information.
 */
int sunw_get_pkey_fname(getdo_actions_t, EVP_PKEY *, char **);


/*
 * sunw_find_localkeyid() searches stacks of certs and private keys, and
 *     returns the first matching cert/private key found.
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
int sunw_find_localkeyid(char *, int, STACK_OF(EVP_PKEY) *, STACK_OF(X509) *,
    EVP_PKEY **, X509 **);


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
int sunw_find_fname(char *, STACK_OF(EVP_PKEY) *, STACK_OF(X509) *, EVP_PKEY **,
    X509 **);


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
 *   cert     - Points to a client or CA cert to check
 *
 * Returns:
 *  <  0 - An error occured.
 *  >= 0 - Number of lines written.
 */
int sunw_print_times(FILE *, prnt_actions_t, char *, X509 *);


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
int sunw_check_keys(X509 *, EVP_PKEY *);


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
char *sunw_issuer_attrs(X509 *cert, char *buf, int len);


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
char *sunw_subject_attrs(X509 *cert, char *buf, int len);

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
int sunw_append_keys(STACK_OF(EVP_PKEY) *, STACK_OF(EVP_PKEY) *);


#ifdef	__cplusplus
}
#endif

#endif	/* _P12AUX_H */
