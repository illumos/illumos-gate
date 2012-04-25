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
 *
 * All of the functions included here are internal to the pkcs12 functions
 * in this library.  None of these are exposed.
 */

/*
 * Copyright (c) 2012, OmniTI Computer Consulting, Inc. All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include <openssl/pkcs12.h>
#include <p12aux.h>
#include <auxutil.h>
#include <p12err.h>

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
ASN1_BMPSTRING *
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
uchar_t *
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
int
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
int
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
int
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
int
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
ASN1_TYPE *
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
int
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
 * print_time - Given an ASN1_TIME, print one or both of the times.
 *
 * Arguments:
 *   fp         - File to write to
 *   t          - The time to format and print.
 *
 * Returns:
 *   0          - Error occurred while opening or writing.
 *   > 0        - Success.
 */
int
print_time(FILE *fp, ASN1_TIME *t)
{
	BIO *bp;
	int ret = 1;

	if ((bp = BIO_new(BIO_s_file())) == NULL) {
		return (0);
	}

	(void) BIO_set_fp(bp, fp, BIO_NOCLOSE);
	ret = ASN1_TIME_print(bp, t);
	(void) BIO_free(bp);

	return (ret);
}
