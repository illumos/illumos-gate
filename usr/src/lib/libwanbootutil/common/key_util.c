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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <strings.h>
#include <stdarg.h>
#include <errno.h>
#include <libintl.h>
#include <sys/wanboot_impl.h>

#include "key_xdr.h"
#include "key_util.h"

/*
 * Size of 'empty' pkcs12 key file (with no key in it) plus 1
 * This is the minimum length for our RSA keys, because we
 * only use RSA keys that are stored in PKCS12 format.
 */
#define	PKCS12_MIN_LEN	76

/*
 *  Program name to be used by wbku_printerr()
 */
static const char *wbku_pname = NULL;

/*
 * Note: must be kept in sync with codes in <key_util.h>
 */
static char *wbku_retmsgs[WBKU_NRET] = {
/* 0 WBKU_SUCCESS */		"Success",
/* 1 WBKU_INTERNAL_ERR */	"Internal error",
/* 2 WBKU_WRITE_ERR */		"Keystore write error",
/* 3 WBKU_NOKEY */		"Key does not exist in keystore",
/* 4 WBKU_BAD_KEYTYPE */	"Invalid keytype specified"
};

/*
 * Initialize library for calls to wbku_printerr().
 */
void
wbku_errinit(const char *arg0)
{
	wbku_pname = strrchr(arg0, '/');

	if (wbku_pname == NULL)
		wbku_pname = arg0;
	else
		wbku_pname++;
}

/*
 * Print an error message to standard error and optionally
 * append a system error.
 */
/*PRINTFLIKE1*/
void
wbku_printerr(const char *format, ...)
{
	int err = errno;
	va_list	ap;

	if (wbku_pname != NULL)
		(void) fprintf(stderr, "%s: ", wbku_pname);

	/*
	 * Note that gettext() is used in order to obtain the
	 * message from the consumer's domain.
	 */
	va_start(ap, format);
	(void) vfprintf(stderr, gettext(format), ap);
	va_end(ap);

	if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, ": %s\n", strerror(err));
}

/*
 * Return the appropriate message for a given WBKU return code.
 */
const char *
wbku_retmsg(wbku_retcode_t retcode)
{
	if ((retcode < WBKU_SUCCESS) || (retcode >= WBKU_NRET))
		return (dgettext(TEXT_DOMAIN, "<unknown code>"));

	return (dgettext(TEXT_DOMAIN, wbku_retmsgs[retcode]));
}

/*
 * This routine is a simple helper routine that initializes a
 * wbku_key_attr_t object.
 */
static void
wbku_keyattr_init(wbku_key_attr_t *attr, wbku_key_type_t type, uint_t atype,
    uint_t len, uint_t minlen, uint_t maxlen,
    char *str, char *oid, boolean_t (*keycheck)(const uint8_t *))
{
	attr->ka_type = type;
	attr->ka_atype = atype;
	attr->ka_len = len;
	attr->ka_minlen = minlen;
	attr->ka_maxlen = maxlen;
	attr->ka_str = str;
	attr->ka_oid = oid;
	attr->ka_keycheck = keycheck;
}


/*
 * This routine is used to build a key attribute structure of the type
 * defined by 'str' and 'flag'. This structure, 'attr', is the common
 * structure used by the utilities that defines the attributes of a
 * specific key type.
 *
 * Returns:
 *	WBKU_SUCCESS or WBKU_BAD_KEYTYPE.
 */
wbku_retcode_t
wbku_str_to_keyattr(const char *str, wbku_key_attr_t *attr, uint_t flag)
{
	if (str == NULL)
		return (WBKU_BAD_KEYTYPE);

	if (flag & WBKU_ENCR_KEY) {
		if (strcmp(str, WBKU_KW_3DES) == 0) {
			wbku_keyattr_init(attr, WBKU_KEY_3DES,
			    WBKU_ENCR_KEY, DES3_KEY_SIZE, DES3_KEY_SIZE,
			    DES3_KEY_SIZE, "3DES", WBKU_DES3_OID,
			    des3_keycheck);
			return (WBKU_SUCCESS);
		}
		if (strcmp(str, WBKU_KW_AES_128) == 0) {
			wbku_keyattr_init(attr, WBKU_KEY_AES_128,
			    WBKU_ENCR_KEY, AES_128_KEY_SIZE, AES_128_KEY_SIZE,
			    AES_128_KEY_SIZE, "AES", WBKU_AES_128_OID, NULL);
			return (WBKU_SUCCESS);
		}
		if (strcmp(str, WBKU_KW_RSA) == 0) {
			wbku_keyattr_init(attr, WBKU_KEY_RSA,
			    WBKU_ENCR_KEY, 0, PKCS12_MIN_LEN,
			    WBKU_MAX_KEYLEN, "RSA", WBKU_RSA_OID, NULL);
			return (WBKU_SUCCESS);
		}
	}
	if (flag & WBKU_HASH_KEY) {
		if (strcmp(str, WBKU_KW_HMAC_SHA1) == 0) {
			wbku_keyattr_init(attr, WBKU_KEY_HMAC_SHA1,
			    WBKU_HASH_KEY, WANBOOT_HMAC_KEY_SIZE,
			    WANBOOT_HMAC_KEY_SIZE, WANBOOT_HMAC_KEY_SIZE,
			    "HMAC/SHA1", WBKU_HMAC_SHA1_OID, NULL);
			return (WBKU_SUCCESS);
		}
	}
	return (WBKU_BAD_KEYTYPE);
}

/*
 * This routine is used to search a key file (whose handle, fp, has been
 * initialized by the caller) for the key of type 'ka'. The search is further
 * constrained by the 'master' argument which is used to signify that the
 * key being searched for is the master key.
 *
 * This routine may be used for a number of purposes:
 *  - Check for the existence of key of type foo.
 *  - Get the value for the key of type foo.
 *  - Return the file position of the key of type foo.
 *
 * To faciliate the uses above, both 'ppos' and 'ekey' will only be
 * returned if they are not NULL pointers.
 *
 * Returns:
 *	WBKU_SUCCESS, WBKU_INTERNAL_ERR or WBKU_NOKEY.
 */
wbku_retcode_t
wbku_find_key(FILE *fp, fpos_t *ppos, wbku_key_attr_t *ka, uint8_t *ekey,
    boolean_t master)
{
	fpos_t pos;
	XDR xdrs;
	wbku_key keyobj;
	int keyno;
	int ret;

	/*
	 * Always, start at the beginning.
	 */
	rewind(fp);

	/*
	 * Initialize the XDR stream.
	 */
	xdrs.x_ops = NULL;
	xdrstdio_create(&xdrs, fp, XDR_DECODE);
	if (xdrs.x_ops == NULL) {
		return (WBKU_INTERNAL_ERR);
	}

	/*
	 * The XDR routines may examine the content of the keyobj
	 * structure to determine whether or not to provide memory
	 * resources. Since XDR does not provide an init routine
	 * for XDR generated objects, it seems that the safest thing
	 * to do is to bzero() the object as a means of initialization.
	 */
	bzero(&keyobj, sizeof (keyobj));

	/*
	 * Read a key and check to see if matches the criteria.
	 */
	for (keyno = 0; !feof(fp); keyno++) {

		/*
		 * Returning the file position is conditional.
		 */
		if (ppos != NULL) {
			if (fgetpos(fp, &pos) != 0) {
				ret = WBKU_INTERNAL_ERR;
				break;
			}
		}

		/*
		 * Read the key. Unfortuantely, XDR does not provide
		 * the ability to tell an EOF from some other IO error.
		 * Therefore, a faliure to read is assumed to be EOF.
		 */
		if (!xdr_wbku_key(&xdrs, &keyobj)) {
			ret = WBKU_NOKEY;
			break;
		}

		/*
		 * Check this key against the criteria.
		 */
		if ((strcmp(keyobj.wk_oid, ka->ka_oid) == 0) &&
		    (keyobj.wk_master == master)) {

			ka->ka_len = keyobj.wk_key_len;

			/*
			 * Conditionally return the key value and file
			 * position.
			 */
			if (ekey != NULL) {
				(void) memcpy(ekey, keyobj.wk_key_val,
				    ka->ka_len);
			}
			if (ppos != NULL) {
				*ppos = pos;
			}

			xdr_free(xdr_wbku_key, (char *)&keyobj);
			ret = WBKU_SUCCESS;
			break;
		}
		xdr_free(xdr_wbku_key, (char *)&keyobj);
	}

	xdr_destroy(&xdrs);
	return (ret);
}

/*
 * This routine writes a key object to the key file at the location
 * specified by the caller.
 *
 * Returns:
 *	WBKU_SUCCESS, WBKU_INTERNAL_ERR or WBKU_WRITE_ERR.
 */
wbku_retcode_t
wbku_write_key(FILE *fp, const fpos_t *ppos, const wbku_key_attr_t *ka,
    uint8_t *rand_key, boolean_t master)
{
	XDR xdrs;
	wbku_key keyobj;

	/*
	 * Set the file position as specified by the caller.
	 */
	if (fsetpos(fp, ppos) != 0) {
		return (WBKU_INTERNAL_ERR);
	}

	/*
	 * Initialize the XDR stream.
	 */
	xdrs.x_ops = NULL;
	xdrstdio_create(&xdrs, fp, XDR_ENCODE);
	if (xdrs.x_ops == NULL) {
		return (WBKU_INTERNAL_ERR);
	}

	/*
	 * Build the key object.
	 */
	keyobj.wk_master = master;
	keyobj.wk_oid = ka->ka_oid;
	keyobj.wk_key_len = ka->ka_len;
	keyobj.wk_key_val = (char *)rand_key;

	/*
	 * Write it.
	 */
	if (!xdr_wbku_key(&xdrs, &keyobj)) {
		xdr_free(xdr_wbku_key, (char *)&keyobj);
		xdr_destroy(&xdrs);
		return (WBKU_WRITE_ERR);
	}

	/*
	 * Free the stream and return success.
	 */
	xdr_destroy(&xdrs);
	return (WBKU_SUCCESS);
}

/*
 * This routine reads the contents of one keystore file and copies it to
 * another, omitting the key of the type defined by 'ka'.
 *
 * Returns:
 *	WBKU_SUCCESS, WBKU_INTERNAL_ERR or WBKU_WRITE_ERR.
 */
wbku_retcode_t
wbku_delete_key(FILE *from_fp, FILE *to_fp, const wbku_key_attr_t *ka)
{
	XDR from_xdrs;
	XDR to_xdrs;
	wbku_key keyobj;
	int keyno;
	int ret;

	/*
	 * Always, start at the beginning.
	 */
	rewind(from_fp);
	rewind(to_fp);

	/*
	 * Initialize the XDR streams.
	 */
	from_xdrs.x_ops = NULL;
	xdrstdio_create(&from_xdrs, from_fp, XDR_DECODE);
	if (from_xdrs.x_ops == NULL) {
		return (WBKU_INTERNAL_ERR);
	}

	to_xdrs.x_ops = NULL;
	xdrstdio_create(&to_xdrs, to_fp, XDR_ENCODE);
	if (to_xdrs.x_ops == NULL) {
		xdr_destroy(&from_xdrs);
		return (WBKU_INTERNAL_ERR);
	}

	/*
	 * The XDR routines may examine the content of the keyobj
	 * structure to determine whether or not to provide memory
	 * resources. Since XDR does not provide an init routine
	 * for XDR generated objects, it seems that the safest thing
	 * to do is to bzero() the object as a means of initialization.
	 */
	bzero(&keyobj, sizeof (keyobj));

	/*
	 * Read a key and check to see if matches the criteria.
	 */
	ret = WBKU_SUCCESS;
	for (keyno = 0; !feof(from_fp); keyno++) {

		/*
		 * Read the key. Unfortuantely, XDR does not provide
		 * the ability to tell an EOF from some other IO error.
		 * Therefore, a faliure to read is assumed to be EOF.
		 */
		if (!xdr_wbku_key(&from_xdrs, &keyobj)) {
			break;
		}

		/*
		 * If this isn't the key to skip, then write it.
		 */
		if (strcmp(keyobj.wk_oid, ka->ka_oid) != 0) {
			/*
			 * Write this to the copy.
			 */
			if (!xdr_wbku_key(&to_xdrs, &keyobj)) {
				xdr_free(xdr_wbku_key, (char *)&keyobj);
				ret = WBKU_WRITE_ERR;
				break;
			}

		}

		xdr_free(xdr_wbku_key, (char *)&keyobj);
	}

	xdr_destroy(&from_xdrs);
	xdr_destroy(&to_xdrs);

	return (ret);
}
