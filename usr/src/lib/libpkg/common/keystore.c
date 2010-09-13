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
 * Module:	keystore.c
 * Description:	This module contains the structure definitions for processing
 *		package keystore files.
 */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <libintl.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/safestack.h>
#include <openssl/stack.h>
#include "p12lib.h"
#include "pkgerr.h"
#include "keystore.h"
#include "pkglib.h"
#include "pkglibmsgs.h"

typedef struct keystore_t {
	boolean_t		dirty;
	boolean_t		new;
	char			*path;
	char			*passphrase;
	/* truststore handles */
	int			cafd;
	STACK_OF(X509)		*cacerts;
	char			*capath;

	/* user certificate handles */
	STACK_OF(X509)		*clcerts;
	char			*clpath;

	/* private key handles */
	STACK_OF(EVP_PKEY)	*pkeys;
	char			*keypath;
} keystore_t;

/* local routines */
static keystore_t	*new_keystore(void);
static void		free_keystore(keystore_t *);
static boolean_t	verify_keystore_integrity(PKG_ERR *, keystore_t *);
static boolean_t	check_password(PKCS12 *, char *);
static boolean_t	resolve_paths(PKG_ERR *, char *, char *,
    long, keystore_t *);
static boolean_t	lock_keystore(PKG_ERR *, long, keystore_t *);

static boolean_t	unlock_keystore(PKG_ERR *, keystore_t *);
static boolean_t	read_keystore(PKG_ERR *, keystore_t *,
    keystore_passphrase_cb);
static boolean_t	write_keystore(PKG_ERR *, keystore_t *,
    keystore_passphrase_cb);
static boolean_t	write_keystore_file(PKG_ERR *, char *, PKCS12 *);
static boolean_t	clear_keystore_file(PKG_ERR *, char *);
static PKCS12		*read_keystore_file(PKG_ERR *, char *);
static char		*get_time_string(ASN1_TIME *);

/* locking routines */
static boolean_t	restore_keystore_file(PKG_ERR *, char *);
static int		file_lock(int, int, int);
static int		file_unlock(int);
static boolean_t	file_lock_test(int, int);
static boolean_t	file_empty(char *);
static boolean_t	get_keystore_passwd(PKG_ERR *err, PKCS12 *p12,
    keystore_passphrase_cb cb, keystore_t *keystore);
static boolean_t	wait_restore(int, char *, char *, char *);

#define	KEYSTORE_PERMS	(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

/* wait on other keystore access for 1 minute before giving up */
#define	LOCK_TIMEOUT	60

/*
 * print_certs  - prints certificates out of a keystore, to a file.
 *
 * Arguments:
 * err - Error object to append errors to
 * keystore - Keystore on which to operate
 * alias - Name of certificate to print, NULL means print all
 * format - Format in which to print certificates
 * outfile - Where to print certificates
 *
 * Returns:
 *   0 - Success
 *   non-zero - Failure, errors added to err
 */
int
print_certs(PKG_ERR *err, keystore_handle_t keystore_h, char *alias,
    keystore_encoding_format_t format, FILE *outfile)
{
	int		i;
	X509		*cert;
	char		*fname = NULL;
	boolean_t	found = B_FALSE;
	keystore_t	*keystore = keystore_h;

	if (keystore->clcerts != NULL) {
		/* print out each client cert */
		for (i = 0; i < sk_X509_num(keystore->clcerts); i++) {
			cert = sk_X509_value(keystore->clcerts, i);
			(void) sunw_get_cert_fname(GETDO_COPY, cert,
			    &fname);

			if (fname == NULL) {
				/* no name recorded, keystore is corrupt */
				pkgerr_add(err, PKGERR_CORRUPT,
				    gettext(ERR_KEYSTORE_NO_ALIAS),
				    get_subject_display_name(cert));
				return (1);
			}

			if ((alias != NULL) && (!streq(alias, fname))) {
				/* name does not match, skip it */
				(void) OPENSSL_free(fname);
				fname = NULL;
				continue;
			} else {
				found = B_TRUE;
				(void) print_cert(err, cert, format,
				    fname, B_FALSE, outfile);
				(void) OPENSSL_free(fname);
				fname = NULL;
			}
		}
	}

	if (fname != NULL) {
	    (void) OPENSSL_free(fname);
	    fname = NULL;
	}

	if (keystore->cacerts != NULL) {
		/* print out each trusted cert */
		for (i = 0; i < sk_X509_num(keystore->cacerts); i++) {
			cert = sk_X509_value(keystore->cacerts, i);
			(void) sunw_get_cert_fname(GETDO_COPY,
			    cert, &fname);

			if (fname == NULL) {
				/* no name recorded, keystore is corrupt */
				pkgerr_add(err, PKGERR_CORRUPT,
				    gettext(ERR_KEYSTORE_NO_ALIAS),
				    get_subject_display_name(cert));
				return (1);
			}

			if ((alias != NULL) && (!streq(alias, fname))) {
				/* name does not match, skip it */
				(void) OPENSSL_free(fname);
				fname = NULL;
				continue;
			} else {
				found = B_TRUE;
				(void) print_cert(err, cert, format,
				    fname, B_TRUE, outfile);
				(void) OPENSSL_free(fname);
				fname = NULL;
			}
		}
	}

	if (fname != NULL) {
	    (void) OPENSSL_free(fname);
	    fname = NULL;
	}

	if (found) {
		return (0);
	} else {
		/* no certs printed */
		if (alias != NULL) {
			pkgerr_add(err, PKGERR_NOALIASMATCH,
			    gettext(ERR_KEYSTORE_NOCERT),
			    alias, keystore->path);
		} else {
			pkgerr_add(err, PKGERR_NOPUBKEY,
			    gettext(ERR_KEYSTORE_NOPUBCERTS),
			    keystore->path);
			pkgerr_add(err, PKGERR_NOCACERT,
			    gettext(ERR_KEYSTORE_NOCACERTS),
			    keystore->path);
		}
		return (1);
	}
}

/*
 * print_cert  - prints a single certificate, to a file
 *
 * Arguments:
 * err - Error object to append errors to
 * x - The certificate to print
 * alias - Name of certificate to print
 * format - Format in which to print certificate
 * outfile - Where to print certificate
 *
 * Returns:
 *   0 - Success
 *   non-zero - Failure, errors added to err
 */
int print_cert(PKG_ERR *err, X509 *x,
    keystore_encoding_format_t format, char *alias, boolean_t is_trusted,
    FILE *outfile)
{

	char *vdb_str;
	char *vda_str;
	char vd_str[ATTR_MAX];
	int ret = 0;
	char *cn_str, *icn_str, *typ_str;
	char *tmp;
	char *md5_fp;
	char *sha1_fp;
	int len;

	/* need to localize the word "Fingerprint", hence these pointers */
	char md5_label[ATTR_MAX];
	char sha1_label[ATTR_MAX];

	if (is_trusted) {
		typ_str = gettext(MSG_KEYSTORE_TRUSTED);
	} else {
		typ_str = gettext(MSG_KEYSTORE_UNTRUSTED);
	}

	if ((cn_str = get_subject_display_name(x)) == NULL) {
		cn_str = gettext(MSG_KEYSTORE_UNKNOWN);
	}

	if ((icn_str = get_issuer_display_name(x)) == NULL) {
		icn_str = gettext(MSG_KEYSTORE_UNKNOWN);
	}

	vdb_str = xstrdup(get_time_string(X509_get_notBefore(x)));
	vda_str = xstrdup(get_time_string(X509_get_notAfter(x)));
	if (((len = snprintf(vd_str, ATTR_MAX, "<%s> - <%s>",
	    vdb_str, vda_str)) < 0) || (len >= ATTR_MAX)) {
		pkgerr_add(err, PKGERR_WEB, gettext(ERR_LEN), vdb_str);
		ret = 1;
		goto cleanup;
	}

	if ((tmp = get_fingerprint(x, EVP_md5())) == NULL) {
		md5_fp = gettext(MSG_KEYSTORE_UNKNOWN);
	} else {
		/*
		 * make a copy, otherwise the next call to get_fingerprint
		 * will overwrite this one
		 */
		md5_fp = xstrdup(tmp);
	}

	if ((tmp = get_fingerprint(x, EVP_sha1())) == NULL) {
		sha1_fp = gettext(MSG_KEYSTORE_UNKNOWN);
	} else {
		sha1_fp = xstrdup(tmp);
	}

	(void) snprintf(md5_label, ATTR_MAX, "%s %s",
	    OBJ_nid2sn(EVP_MD_type(EVP_md5())),
	    /* i18n: 14 characters max */
	    gettext(MSG_KEYSTORE_FP));

	(void) snprintf(sha1_label, ATTR_MAX, "%s %s",
	    OBJ_nid2sn(EVP_MD_type(EVP_sha1())),
	    /* i18n: 14 characters max */
	    gettext(MSG_KEYSTORE_FP));

	switch (format) {
	case KEYSTORE_FORMAT_PEM:
		(void) PEM_write_X509(outfile, x);
		break;
	case KEYSTORE_FORMAT_DER:
		(void) i2d_X509_fp(outfile, x);
		break;
	case KEYSTORE_FORMAT_TEXT:
		(void) fprintf(outfile, "%18s: %s\n",
		    /* i18n: 18 characters max */
		    gettext(MSG_KEYSTORE_AL), alias);
		(void) fprintf(outfile, "%18s: %s\n",
		    /* i18n: 18 characters max */
		    gettext(MSG_KEYSTORE_CN), cn_str);
		(void) fprintf(outfile, "%18s: %s\n",
		    /* i18n: 18 characters max */
		    gettext(MSG_KEYSTORE_TY), typ_str);
		(void) fprintf(outfile, "%18s: %s\n",
		    /* i18n: 18 characters max */
		    gettext(MSG_KEYSTORE_IN), icn_str);
		(void) fprintf(outfile, "%18s: %s\n",
		    /* i18n: 18 characters max */
		    gettext(MSG_KEYSTORE_VD), vd_str);
		(void) fprintf(outfile, "%18s: %s\n", md5_label, md5_fp);
		(void) fprintf(outfile, "%18s: %s\n", sha1_label, sha1_fp);
		(void) fprintf(outfile, "\n");
		break;
	default:
		pkgerr_add(err, PKGERR_INTERNAL,
		    gettext(ERR_KEYSTORE_INTERNAL),
		    __FILE__, __LINE__);
		ret = 1;
		goto cleanup;
	}

cleanup:
	if (md5_fp != NULL)
		free(md5_fp);
	if (sha1_fp != NULL)
		free(sha1_fp);
	if (vda_str != NULL)
		free(vda_str);
	if (vdb_str != NULL)
		free(vdb_str);
	return (ret);
}

/*
 * open_keystore - Initialize new keystore object for
 * impending access.
 *
 * Arguments:
 * err - Error object to append errors to
 * keystore_file - Base filename or directory of keystore
 * app - Application making request
 * passwd - Password used to decrypt keystore
 * flags - Control flags used to control access mode and behavior
 * result - Resulting keystore object stored here on success
 *
 * Returns:
 *   0 - Success - result contains a pointer to the opened keystore
 *   non-zero - Failure, errors added to err
 */
int
open_keystore(PKG_ERR *err, char *keystore_file, char *app,
    keystore_passphrase_cb cb, long flags, keystore_handle_t *result)
{
	int ret = 0;
	keystore_t	*tmpstore;

	tmpstore = new_keystore();

	tmpstore->dirty = B_FALSE;
	tmpstore->new = B_FALSE;
	tmpstore->path = xstrdup(keystore_file);

	if (!resolve_paths(err, keystore_file, app, flags, tmpstore)) {
		/* unable to determine keystore paths */
		pkgerr_add(err, PKGERR_CORRUPT, gettext(ERR_KEYSTORE_REPAIR),
		    keystore_file);
		ret = 1;
		goto cleanup;
	}

	if (!verify_keystore_integrity(err, tmpstore)) {
		/* unable to repair keystore */
		pkgerr_add(err, PKGERR_CORRUPT, gettext(ERR_KEYSTORE_REPAIR),
		    keystore_file);
		ret = 1;
		goto cleanup;
	}

	if (!lock_keystore(err, flags, tmpstore)) {
		pkgerr_add(err, PKGERR_LOCKED, gettext(ERR_KEYSTORE_LOCKED),
		    keystore_file);
		ret = 1;
		goto cleanup;
	}

	/* now that we have locked the keystore, go ahead and read it */
	if (!read_keystore(err, tmpstore, cb)) {
		pkgerr_add(err, PKGERR_READ, gettext(ERR_PARSE),
		    keystore_file);
		ret = 1;
		goto cleanup;
	}

	*result = tmpstore;
	tmpstore = NULL;

cleanup:
	if (tmpstore != NULL)
		free_keystore(tmpstore);
	return (ret);
}

/*
 * new_keystore - Allocates and initializes a Keystore object
 *
 * Arguments:
 * NONE
 *
 * Returns:
 *   NULL - out of memory
 *   otherwise, returns a pointer to the newly allocated object,
 *   which should be freed with free_keystore() when no longer
 *   needed.
 */
static keystore_t
*new_keystore(void)
{
	keystore_t *tmpstore;

	if ((tmpstore = (keystore_t *)malloc(sizeof (keystore_t))) == NULL) {
		return (NULL);
	}
	tmpstore->dirty = B_FALSE;
	tmpstore->new = B_FALSE;
	tmpstore->path = NULL;
	tmpstore->passphrase = NULL;
	tmpstore->cafd = -1;
	tmpstore->cacerts = NULL;
	tmpstore->capath = NULL;
	tmpstore->clcerts = NULL;
	tmpstore->clpath = NULL;
	tmpstore->pkeys = NULL;
	tmpstore->keypath = NULL;

	return (tmpstore);
}

/*
 * free_keystore - Deallocates a Keystore object
 *
 * Arguments:
 * keystore - The keystore to deallocate
 *
 * Returns:
 *   NONE
 */
static void
free_keystore(keystore_t *keystore)
{
	if (keystore->path != NULL)
		free(keystore->path);
	if (keystore->capath != NULL)
		free(keystore->capath);
	if (keystore->passphrase != NULL)
		free(keystore->passphrase);
	if (keystore->clpath != NULL)
		free(keystore->clpath);
	if (keystore->keypath != NULL)
		free(keystore->keypath);

	if (keystore->pkeys != NULL) {
		sk_EVP_PKEY_pop_free(keystore->pkeys,
		    sunw_evp_pkey_free);
	}
	if (keystore->clcerts != NULL)
		sk_X509_free(keystore->clcerts);
	if (keystore->cacerts != NULL)
		sk_X509_free(keystore->cacerts);
	free(keystore);
}

/*
 * close_keystore - Writes keystore to disk if needed, then
 * unlocks and closes keystore.
 *
 * Arguments:
 * err - Error object to append errors to
 * keystore - Keystore which should be closed
 * passwd - Password used to encrypt keystore
 *
 * Returns:
 *   0 - Success - keystore is committed to disk, and unlocked
 *   non-zero - Failure, errors added to err
 */
int
close_keystore(PKG_ERR *err, keystore_handle_t keystore_h,
    keystore_passphrase_cb cb)
{
	int ret = 0;
	keystore_t *keystore = keystore_h;

	if (keystore->dirty) {
		/* write out the keystore first */
		if (!write_keystore(err, keystore, cb)) {
			pkgerr_add(err, PKGERR_WRITE,
			    gettext(ERR_KEYSTORE_WRITE),
			    keystore->path);
			ret = 1;
			goto cleanup;
		}
	}

	if (!unlock_keystore(err, keystore)) {
		pkgerr_add(err, PKGERR_UNLOCK, gettext(ERR_KEYSTORE_UNLOCK),
		    keystore->path);
		ret = 1;
		goto cleanup;
	}

	free_keystore(keystore);
cleanup:
	return (ret);
}

/*
 * merge_ca_cert - Adds a trusted certificate (trust anchor) to a keystore.
 * certificate checked for validity dates and non-duplicity.
 *
 * Arguments:
 * err - Error object to add errors to
 * cacert - Certificate which to merge into keystore
 * keystore - The keystore into which the certificate is merged
 *
 * Returns:
 *   0 - Success - Certificate passes validity, and
 *		is merged into keystore
 * non-zero - Failure, errors recorded in err
 */
int
merge_ca_cert(PKG_ERR *err, X509 *cacert, keystore_handle_t keystore_h)
{

	int		ret = 0;
	X509		*existing = NULL;
	char		*fname;
	keystore_t	*keystore = keystore_h;

	/* check validity dates */
	if (check_cert(err, cacert) != 0) {
		ret = 1;
		goto cleanup;
	}

	/* create the certificate's friendlyName */
	fname = get_subject_display_name(cacert);

	if (sunw_set_fname(fname, NULL, cacert) != 0) {
		pkgerr_add(err, PKGERR_NOMEM, gettext(ERR_MEM));
		ret = 1;
		goto cleanup;
	}

	/* merge certificate into the keystore */
	if (keystore->cacerts == NULL) {
		/* no existing truststore, so make a new one */
		if ((keystore->cacerts = sk_X509_new_null()) == NULL) {
			pkgerr_add(err, PKGERR_NOMEM, gettext(ERR_MEM));
			ret = 1;
			goto cleanup;
		}
	} else {
		/* existing truststore, make sure there's no duplicate */
		if (sunw_find_fname(fname, NULL, keystore->cacerts,
		    NULL, &existing) < 0) {
			pkgerr_add(err, PKGERR_INTERNAL,
			    gettext(ERR_KEYSTORE_INTERNAL),
			    __FILE__, __LINE__);
			ERR_print_errors_fp(stderr);
			ret = 1;
			goto cleanup;
			/* could not search properly! */
		}
		if (existing != NULL) {
			/* whoops, found one already */
			pkgerr_add(err, PKGERR_DUPLICATE,
			    gettext(ERR_KEYSTORE_DUPLICATECERT), fname);
			ret = 1;
			goto cleanup;
		}
	}

	(void) sk_X509_push(keystore->cacerts, cacert);
	keystore->dirty = B_TRUE;
cleanup:
	if (existing != NULL)
		X509_free(existing);
	return (ret);
}

/*
 * find_key_cert_pair - Searches a keystore for a matching
 * public key certificate and private key, given an alias.
 *
 * Arguments:
 * err - Error object to add errors to
 * ks - Keystore to search
 * alias - Name to used to match certificate's alias
 * key - Resulting key is placed here
 * cert - Resulting cert is placed here
 *
 * Returns:
 *   0 - Success - Matching cert/key pair placed in key and cert.
 * non-zero - Failure, errors recorded in err
 */
int
find_key_cert_pair(PKG_ERR *err, keystore_handle_t ks_h, char *alias,
    EVP_PKEY **key, X509 **cert)
{
	X509		*tmpcert = NULL;
	EVP_PKEY	*tmpkey = NULL;
	int		ret = 0;
	int		items_found;
	keystore_t	*ks = ks_h;

	if (key == NULL || cert == NULL) {
		pkgerr_add(err, PKGERR_NOPUBKEY,
		    gettext(ERR_KEYSTORE_NOPUBCERTS), ks->path);
		ret = 1;
		goto cleanup;
	}

	if (ks->clcerts == NULL) {
		/* no public certs */
		pkgerr_add(err, PKGERR_NOPUBKEY,
		    gettext(ERR_KEYSTORE_NOCERTS), ks->path);
		ret = 1;
		goto cleanup;
	}
	if (ks->pkeys == NULL) {
		/* no private keys */
		pkgerr_add(err, PKGERR_NOPRIVKEY,
		    gettext(ERR_KEYSTORE_NOKEYS), ks->path);
		ret = 1;
		goto cleanup;
	}

	/* try the easy case first */
	if ((sk_EVP_PKEY_num(ks->pkeys) == 1) &&
	    (sk_X509_num(ks->clcerts) == 1)) {
		tmpkey = sk_EVP_PKEY_value(ks->pkeys, 0);
		tmpcert = sk_X509_value(ks->clcerts, 0);
		if (sunw_check_keys(tmpcert, tmpkey)) {
			/*
			 * only one private key and public key cert, and they
			 * match, so use them
			 */
			*key = tmpkey;
			tmpkey = NULL;
			*cert = tmpcert;
			tmpcert = NULL;
			goto cleanup;
		}
	}

	/* Attempt to find the right pair given the alias */
	items_found = sunw_find_fname(alias, ks->pkeys, ks->clcerts,
	    &tmpkey, &tmpcert);

	if ((items_found < 0) ||
	    (items_found & (FOUND_PKEY | FOUND_CERT)) == 0) {
		/* no key/cert pair found. bail. */
		pkgerr_add(err, PKGERR_BADALIAS,
		    gettext(ERR_KEYSTORE_NOMATCH), alias);
		ret = 1;
		goto cleanup;
	}

	/* success */
	*key = tmpkey;
	tmpkey = NULL;
	*cert = tmpcert;
	tmpcert = NULL;

cleanup:

	if (tmpcert != NULL)
		(void) X509_free(tmpcert);

	if (tmpkey != NULL)
		sunw_evp_pkey_free(tmpkey);

	return (ret);
}

/*
 * find_ca_certs - Searches a keystore for trusted certificates
 *
 * Arguments:
 * err - Error object to add errors to
 * ks - Keystore to search
 * cacerts - resulting set of trusted certs are placed here
 *
 * Returns:
 *   0 - Success - trusted cert list returned in cacerts
 * non-zero - Failure, errors recorded in err
 */
int
find_ca_certs(PKG_ERR *err, keystore_handle_t ks_h, STACK_OF(X509) **cacerts)
{

	keystore_t	*ks = ks_h;

	/* easy */
	if (cacerts == NULL) {
		pkgerr_add(err, PKGERR_INTERNAL,
		    gettext(ERR_KEYSTORE_INTERNAL), __FILE__, __LINE__);
		return (1);
	}

	*cacerts = ks->cacerts;
	return (0);
}

/*
 * find_cl_certs - Searches a keystore for user certificates
 *
 * Arguments:
 * err - Error object to add errors to
 * ks - Keystore to search
 * cacerts - resulting set of user certs are placed here
 *
 * No matching of any kind is performed.
 * Returns:
 *   0 - Success - trusted cert list returned in cacerts
 * non-zero - Failure, errors recorded in err
 */
/* ARGSUSED */
int
find_cl_certs(PKG_ERR *err, keystore_handle_t ks_h, STACK_OF(X509) **clcerts)
{
	keystore_t	*ks = ks_h;

	/* easy */
	*clcerts = ks->clcerts;
	return (0);
}


/*
 * merge_cert_and_key - Adds a user certificate and matching
 * private key to a keystore.
 * certificate checked for validity dates and non-duplicity.
 *
 * Arguments:
 * err - Error object to add errors to
 * cert - Certificate which to merge into keystore
 * key - matching private key to 'cert'
 * alias - Name which to store the cert and key under
 * keystore - The keystore into which the certificate is merged
 *
 * Returns:
 *   0 - Success - Certificate passes validity, and
 *		is merged into keystore, along with key
 * non-zero - Failure, errors recorded in err
 */
int
merge_cert_and_key(PKG_ERR *err, X509 *cert, EVP_PKEY *key, char *alias,
    keystore_handle_t keystore_h)
{
	X509		*existingcert = NULL;
	EVP_PKEY	*existingkey = NULL;
	int		ret = 0;
	keystore_t	*keystore = keystore_h;

	/* check validity dates */
	if (check_cert(err, cert) != 0) {
		ret = 1;
		goto cleanup;
	}

	/* set the friendlyName of the key and cert to the supplied alias */
	if (sunw_set_fname(alias, key, cert) != 0) {
		pkgerr_add(err, PKGERR_NOMEM, gettext(ERR_MEM));
		ret = 1;
		goto cleanup;
	}

	/* merge certificate and key into the keystore */
	if (keystore->clcerts == NULL) {
		/* no existing truststore, so make a new one */
		if ((keystore->clcerts = sk_X509_new_null()) == NULL) {
			pkgerr_add(err, PKGERR_NOMEM, gettext(ERR_MEM));
			ret = 1;
			goto cleanup;
		}
	} else {
		/* existing certstore, make sure there's no duplicate */
		if (sunw_find_fname(alias, NULL, keystore->clcerts,
		    NULL, &existingcert) < 0) {
			pkgerr_add(err, PKGERR_INTERNAL,
			    gettext(ERR_KEYSTORE_INTERNAL),
			    __FILE__, __LINE__);
			ERR_print_errors_fp(stderr);
			ret = 1;
			goto cleanup;
			/* could not search properly! */
		}
		if (existingcert != NULL) {
			/* whoops, found one already */
			pkgerr_add(err, PKGERR_DUPLICATE,
			    gettext(ERR_KEYSTORE_DUPLICATECERT), alias);
			ret = 1;
			goto cleanup;
		}
	}

	if (keystore->pkeys == NULL) {
		/* no existing keystore, so make a new one */
		if ((keystore->pkeys = sk_EVP_PKEY_new_null()) == NULL) {
			pkgerr_add(err, PKGERR_NOMEM, gettext(ERR_MEM));
			ret = 1;
			goto cleanup;
		}
	} else {
		/* existing keystore, so make sure there's no duplicate entry */
		if (sunw_find_fname(alias, keystore->pkeys, NULL,
		    &existingkey, NULL) < 0) {
			pkgerr_add(err, PKGERR_INTERNAL,
			    gettext(ERR_KEYSTORE_INTERNAL),
			    __FILE__, __LINE__);
			ERR_print_errors_fp(stderr);
			ret = 1;
			goto cleanup;
			/* could not search properly! */
		}
		if (existingkey != NULL) {
			/* whoops, found one already */
			pkgerr_add(err, PKGERR_DUPLICATE,
			    gettext(ERR_KEYSTORE_DUPLICATEKEY), alias);
			ret = 1;
			goto cleanup;
		}
	}

	(void) sk_X509_push(keystore->clcerts, cert);
	(void) sk_EVP_PKEY_push(keystore->pkeys, key);
	keystore->dirty = B_TRUE;
cleanup:
	if (existingcert != NULL)
		(void) X509_free(existingcert);
	if (existingkey != NULL)
		(void) sunw_evp_pkey_free(existingkey);
	return (ret);
}

/*
 * delete_cert_and_keys - Deletes one or more certificates
 *  and matching private keys from a keystore.
 *
 * Arguments:
 * err - Error object to add errors to
 * ks - The keystore from which certs and keys are deleted
 * alias - Name which to search for certificates and keys
 *	to delete
 *
 * Returns:
 *   0 - Success - All trusted certs which match 'alias'
 *		are deleted.  All user certificates
 *		which match 'alias' are deleted, along
 *		with the matching private key.
 * non-zero - Failure, errors recorded in err
 */
int
delete_cert_and_keys(PKG_ERR *err, keystore_handle_t ks_h, char *alias)
{
	X509		*existingcert;
	EVP_PKEY	*existingkey;
	int		i;
	char		*fname = NULL;
	boolean_t	found = B_FALSE;
	keystore_t	*ks = ks_h;

	/* delete any and all client certs with the supplied name */
	if (ks->clcerts != NULL) {
		for (i = 0; i < sk_X509_num(ks->clcerts); i++) {
			existingcert = sk_X509_value(ks->clcerts, i);
			if (sunw_get_cert_fname(GETDO_COPY,
			    existingcert, &fname) >= 0) {
				if (streq(fname, alias)) {
					/* match, so nuke it */
					existingcert =
					    sk_X509_delete(ks->clcerts, i);
					X509_free(existingcert);
					existingcert = NULL;
					found = B_TRUE;
				}
				(void) OPENSSL_free(fname);
				fname = NULL;
			}
		}
		if (sk_X509_num(ks->clcerts) <= 0) {
			/* we deleted all the client certs */
			sk_X509_free(ks->clcerts);
			ks->clcerts = NULL;
		}
	}

	/* and now the private keys */
	if (ks->pkeys != NULL) {
		for (i = 0; i < sk_EVP_PKEY_num(ks->pkeys); i++) {
			existingkey = sk_EVP_PKEY_value(ks->pkeys, i);
			if (sunw_get_pkey_fname(GETDO_COPY,
			    existingkey, &fname) >= 0) {
				if (streq(fname, alias)) {
					/* match, so nuke it */
					existingkey =
					    sk_EVP_PKEY_delete(ks->pkeys, i);
					sunw_evp_pkey_free(existingkey);
					existingkey = NULL;
					found = B_TRUE;
				}
				(void) OPENSSL_free(fname);
				fname = NULL;
			}
		}
		if (sk_EVP_PKEY_num(ks->pkeys) <= 0) {
			/* we deleted all the private keys */
			sk_EVP_PKEY_free(ks->pkeys);
			ks->pkeys = NULL;
		}
	}

	/* finally, remove any trust anchors that match */

	if (ks->cacerts != NULL) {
		for (i = 0; i < sk_X509_num(ks->cacerts); i++) {
			existingcert = sk_X509_value(ks->cacerts, i);
			if (sunw_get_cert_fname(GETDO_COPY,
			    existingcert, &fname) >= 0) {
				if (streq(fname, alias)) {
					/* match, so nuke it */
					existingcert =
					    sk_X509_delete(ks->cacerts, i);
					X509_free(existingcert);
					existingcert = NULL;
					found = B_TRUE;
				}
				(void) OPENSSL_free(fname);
				fname = NULL;
			}
		}
		if (sk_X509_num(ks->cacerts) <= 0) {
			/* we deleted all the CA certs */
			sk_X509_free(ks->cacerts);
			ks->cacerts = NULL;
		}
	}

	if (found) {
		ks->dirty = B_TRUE;
		return (0);
	} else {
		/* no certs or keys deleted */
		pkgerr_add(err, PKGERR_NOALIASMATCH,
		    gettext(ERR_KEYSTORE_NOCERTKEY),
		    alias, ks->path);
		return (1);
	}
}

/*
 * check_cert - Checks certificate validity.  This routine
 * checks that the current time falls within the period
 * of validity for the cert.
 *
 * Arguments:
 * err - Error object to add errors to
 * cert - The certificate to check
 *
 * Returns:
 *   0 - Success - Certificate checks out
 * non-zero - Failure, errors and reasons recorded in err
 */
int
check_cert(PKG_ERR *err, X509 *cert)
{
	char			currtimestr[ATTR_MAX];
	time_t			currtime;
	char			*r, *before_str, *after_str;
	/* get current time */
	if ((currtime = time(NULL)) == (time_t)-1) {
		pkgerr_add(err, PKGERR_TIME, gettext(ERR_CURR_TIME));
		return (1);
	}

	(void) strlcpy(currtimestr, ctime(&currtime), ATTR_MAX);

	/* trim whitespace from end of time string */
	for (r = (currtimestr + strlen(currtimestr) - 1); isspace(*r); r--) {
		*r = '\0';
	}
	/* check  validity of cert */
	switch (sunw_check_cert_times(CHK_BOTH, cert)) {
	case CHKERR_TIME_OK:
		/* Current time meets requested checks */
		break;
	case CHKERR_TIME_BEFORE_BAD:
		/* 'not before' field is invalid */
	case CHKERR_TIME_AFTER_BAD:
		/* 'not after' field is invalid */
		pkgerr_add(err, PKGERR_TIME, gettext(ERR_CERT_TIME_BAD));
		return (1);
	case CHKERR_TIME_IS_BEFORE:
		/* Current time is before 'not before' */
	case CHKERR_TIME_HAS_EXPIRED:
		/*
		 * Ignore expiration time since the trust cert used to
		 * verify the certs used to sign Sun patches is already
		 * expired. Once the patches get resigned with the new
		 * cert we will check expiration against the time the
		 * patch was signed and not the time it is installed.
		 */
		return (0);
	default:
		pkgerr_add(err, PKGERR_INTERNAL,
		    gettext(ERR_KEYSTORE_INTERNAL),
		    __FILE__, __LINE__);
		return (1);
	}

	/* all checks ok */
	return (0);
}

/*
 * check_cert - Checks certificate validity.  This routine
 * checks everything that check_cert checks, and additionally
 * verifies that the private key and corresponding public
 * key are indeed a pair.
 *
 * Arguments:
 * err - Error object to add errors to
 * cert - The certificate to check
 * key - the key to check
 * Returns:
 *   0 - Success - Certificate checks out
 * non-zero - Failure, errors and reasons recorded in err
 */
int
check_cert_and_key(PKG_ERR *err, X509 *cert, EVP_PKEY *key)
{

	/* check validity dates */
	if (check_cert(err, cert) != 0) {
		return (1);
	}

	/* check key pair match */
	if (sunw_check_keys(cert, key) == 0) {
		pkgerr_add(err, PKGERR_VERIFY, gettext(ERR_MISMATCHED_KEYS),
		    get_subject_display_name(cert));
		return (1);
	}

	/* all checks OK */
	return (0);
}

/* ------------------ private functions ---------------------- */

/*
 * verify_keystore_integrity - Searches for the remnants
 * of a failed or aborted keystore modification, and
 * cleans up the files, retstores the keystore to a known
 * state.
 *
 * Arguments:
 * err - Error object to add errors to
 * keystore_file - Base directory or filename of keystore
 * app - Application making request
 *
 * Returns:
 *   0 - Success - Keystore is restored, or untouched in the
 *		case that cleanup was unnecessary
 * non-zero - Failure, errors and reasons recorded in err
 */
static boolean_t
verify_keystore_integrity(PKG_ERR *err, keystore_t *keystore)
{
	if (keystore->capath != NULL) {
		if (!restore_keystore_file(err, keystore->capath)) {
			return (B_FALSE);
		}
	}
	if (keystore->clpath != NULL) {
		if (!restore_keystore_file(err, keystore->clpath)) {
			return (B_FALSE);
		}
	}
	if (keystore->keypath != NULL) {
		if (!restore_keystore_file(err, keystore->keypath)) {
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}

/*
 * restore_keystore_file - restores a keystore file to
 * a known state.
 *
 * Keystore files can possibly be corrupted by a variety
 * of error conditions during reading/writing.  This
 * routine, along with write_keystore_file, tries to
 * maintain keystore integrity by writing the files
 * out in a particular order, minimizing the time period
 * that the keystore is in an indeterminate state.
 *
 * With the current implementation, there are some failures
 * that are wholly unrecoverable, such as disk corruption.
 * These routines attempt to minimize the risk, but not
 * eliminate it.  When better, atomic operations are available
 * (such as a trued atabase with commit, rollback, and
 * guaranteed atomicity), this implementation should use that.
 *
 * Arguments:
 * err - Error object to add errors to
 * keystore_file - keystore file path to restore.
 *
 * Returns:
 *   0 - Success - Keystore file is restored, or untouched in the
 *		case that cleanup was unnecessary
 * non-zero - Failure, errors and reasons recorded in err
 */
/* ARGSUSED */
static boolean_t
restore_keystore_file(PKG_ERR *err, char *keystore_file)
{
	char	newpath[MAXPATHLEN];
	char	backuppath[MAXPATHLEN];
	int	newfd;
	struct stat buf;
	int len;

	if (((len = snprintf(newpath, MAXPATHLEN, "%s.new",
	    keystore_file)) < 0) ||
	    (len >= ATTR_MAX)) {
		pkgerr_add(err, PKGERR_WEB, gettext(ERR_LEN), keystore_file);
		return (B_FALSE);
	}

	if (((len = snprintf(backuppath, MAXPATHLEN, "%s.bak",
	    keystore_file)) < 0) ||
	    (len >= ATTR_MAX)) {
		pkgerr_add(err, PKGERR_WEB, gettext(ERR_LEN), keystore_file);
		return (B_FALSE);
	}

	if ((newfd = open(newpath, O_RDWR|O_NONBLOCK, 0)) != -1) {
		if (fstat(newfd, &buf) != -1) {
			if (S_ISREG(buf.st_mode)) {
				/*
				 * restore the file, waiting on it
				 * to be free for locking, or for
				 * it to disappear
				 */
				if (!wait_restore(newfd, keystore_file,
				    newpath, backuppath)) {
					pkgerr_add(err, PKGERR_WRITE,
					    gettext(ERR_WRITE),
					    newpath, strerror(errno));
					(void) close(newfd);
					return (B_FALSE);
				} else {
					return (B_TRUE);
				}
			} else {
				/* "new" file is not a regular file */
				pkgerr_add(err, PKGERR_WRITE,
				    gettext(ERR_NOT_REG), newpath);
				(void) close(newfd);
				return (B_FALSE);
			}
		} else {
			/* couldn't stat "new" file */
			pkgerr_add(err, PKGERR_WRITE,
			    gettext(ERR_WRITE), newpath,
			    strerror(errno));
			(void) close(newfd);
			return (B_FALSE);
		}
	} else {
		/* "new" file doesn't exist */
		return (B_TRUE);
	}
}

static boolean_t
wait_restore(int newfd, char *keystore_file,
    char *origpath, char *backuppath)
{
	struct stat buf;
	FILE *newstream;
	PKCS12 *p12;

	(void) alarm(LOCK_TIMEOUT);
	if (file_lock(newfd, F_WRLCK, 1) == -1) {
		/* could not lock file */
		(void) alarm(0);
		return (B_FALSE);
	}
	(void) alarm(0);

	if (fstat(newfd, &buf) != -1) {
		if (S_ISREG(buf.st_mode)) {
			/*
			 * The new file still
			 * exists, with no
			 * owner.  It must be
			 * the result of an
			 * aborted update.
			 */
			newstream = fdopen(newfd, "r");
			if ((p12 =
			    d2i_PKCS12_fp(newstream,
				NULL)) != NULL) {
				/*
				 * The file
				 * appears
				 * complete.
				 * Replace the
				 * exsisting
				 * keystore
				 * file with
				 * this one
				 */
				(void) rename(keystore_file, backuppath);
				(void) rename(origpath, keystore_file);
				PKCS12_free(p12);
			} else {
				/* The file is not complete.  Remove it */
				(void) remove(origpath);
			}
			/* remove backup file */
			(void) remove(backuppath);
			(void) fclose(newstream);
			(void) close(newfd);
			return (B_TRUE);
		} else {
			/*
			 * new file exists, but is not a
			 * regular file
			 */
			(void) close(newfd);
			return (B_FALSE);
		}
	} else {
		/*
		 * could not stat file.  Unless
		 * the reason was that the file
		 * is now gone, this is an error
		 */
		if (errno != ENOENT) {
			(void) close(newfd);
			return (B_FALSE);
		}
		/*
		 * otherwise, file is gone.  The process
		 * that held the lock must have
		 * successfully cleaned up and
		 * exited with a valid keystore
		 * state
		 */
		(void) close(newfd);
		return (B_TRUE);
	}
}

/*
 * resolve_paths - figure out if we are dealing with a single-file
 * or multi-file keystore
 *
 * The flags tell resolve_paths how to behave:
 *
 * KEYSTORE_PATH_SOFT
 * If the keystore file does not exist at <base>/<app> then
 * use <base> as the path to the keystore.  This can be used,
 * for example, to access an app-specific keystore iff it
 * exists, otherwise revert back to an app-generic keystore.
 *
 * KEYSTORE_PATH_HARD
 * Always use the keystore located at <keystore_path>/<app>.
 * In read/write mode, if the files do not exist, then
 * they will be created.  This is used to avoid falling
 * back to an app-generic keystore path when the app-specific
 * one does not exist.
 *
 * Arguments:
 * err - Error object to add errors to
 * keystore_file - base keystore file path to lock
 * app - Application making requests
 * flags - Control flags (see above description)
 * keystore - object which is being locked
 *
 * Returns:
 *   B_TRUE - Success - Keystore file is locked, paths to
 *		appropriate files placed in keystore.
 *   B_FALSE - Failure, errors and reasons recorded in err
 */
static boolean_t
resolve_paths(PKG_ERR *err, char *keystore_file, char *app,
    long flags, keystore_t *keystore)
{
	char			storepath[PATH_MAX];
	struct stat		buf;
	boolean_t		multi = B_FALSE;
	int			fd1, fd2, len;

	/*
	 * figure out whether we are dealing with a single-file keystore
	 * or a multi-file keystore
	 */
	if (app != NULL) {
		if (((len = snprintf(storepath, PATH_MAX, "%s/%s",
		    keystore_file, app)) < 0) ||
		    (len >= ATTR_MAX)) {
			pkgerr_add(err, PKGERR_WEB, gettext(ERR_LEN),
			    keystore_file);
			return (B_FALSE);
		}

		if (((fd1 = open(storepath, O_NONBLOCK|O_RDONLY)) == -1) ||
		    (fstat(fd1, &buf) == -1) ||
		    !S_ISDIR(buf.st_mode)) {
			/*
			 * app-specific does not exist
			 * fallback to app-generic, if flags say we can
			 */
			if ((flags & KEYSTORE_PATH_MASK) ==
			    KEYSTORE_PATH_SOFT) {

				if (((fd2 = open(keystore_file,
				    O_NONBLOCK|O_RDONLY)) != -1) &&
				    (fstat(fd2, &buf) != -1)) {
					if (S_ISDIR(buf.st_mode)) {
						/*
						 * app-generic dir
						 * exists, so use it
						 * as a multi-file
						 * keystore
						 */
						multi = B_TRUE;
						app = NULL;
					} else if (S_ISREG(buf.st_mode)) {
						/*
						 * app-generic file exists, so
						 * use it as a single file ks
						 */
						multi = B_FALSE;
						app = NULL;
					}
				}
			}
		}
		if (fd1 != -1)
			(void) close(fd1);
		if (fd2 != -1)
			(void) close(fd2);
	} else {
		if (((fd1 = open(keystore_file,
		    O_NONBLOCK|O_RDONLY)) != -1) &&
		    (fstat(fd1, &buf) != -1) &&
		    S_ISDIR(buf.st_mode)) {
			/*
			 * app-generic dir exists, so use
			 * it as a multi-file keystore
			 */
			multi = B_TRUE;
		}
		if (fd1 != -1)
			(void) close(fd1);
	}

	if (app != NULL) {
		/* app-specific keystore */
		(void) snprintf(storepath, PATH_MAX, "%s/%s/%s",
		    keystore_file, app, TRUSTSTORE);
		keystore->capath = xstrdup(storepath);
		(void) snprintf(storepath, PATH_MAX, "%s/%s/%s",
		    keystore_file, app, CERTSTORE);
		keystore->clpath = xstrdup(storepath);
		(void) snprintf(storepath, PATH_MAX, "%s/%s/%s",
		    keystore_file, app, KEYSTORE);
		keystore->keypath = xstrdup(storepath);
	} else {
		/* app-generic keystore */
		if (!multi) {
			/* single-file app-generic keystore */
			keystore->capath = xstrdup(keystore_file);
			keystore->keypath = NULL;
			keystore->clpath = NULL;
		} else {
			/* multi-file app-generic keystore */
			(void) snprintf(storepath, PATH_MAX, "%s/%s",
			    keystore_file, TRUSTSTORE);
			keystore->capath = xstrdup(storepath);
			(void) snprintf(storepath, PATH_MAX, "%s/%s",
			    keystore_file, CERTSTORE);
			keystore->clpath = xstrdup(storepath);
			(void) snprintf(storepath, PATH_MAX, "%s/%s",
			    keystore_file, KEYSTORE);
			keystore->keypath = xstrdup(storepath);
		}
	}

	return (B_TRUE);
}

/*
 * lock_keystore - Locks a keystore for shared (read-only)
 * or exclusive (read-write) access.
 *
 * The flags tell lock_keystore how to behave:
 *
 * KEYSTORE_ACCESS_READONLY
 * opens keystore read-only.  Attempts to modify results in an error
 *
 * KEYSTORE_ACCESS_READWRITE
 * opens keystore read-write
 *
 * KEYSTORE_PATH_SOFT
 * If the keystore file does not exist at <base>/<app> then
 * use <base> as the path to the keystore.  This can be used,
 * for example, to access an app-specific keystore iff it
 * exists, otherwise revert back to an app-generic keystore.
 *
 * KEYSTORE_PATH_HARD
 * Always use the keystore located at <keystore_path>/<app>.
 * In read/write mode, if the files do not exist, then
 * they will be created.  This is used to avoid falling
 * back to an app-generic keystore path when the app-specific
 * one does not exist.
 *
 * Arguments:
 * err - Error object to add errors to
 * flags - Control flags (see above description)
 * keystore - object which is being locked
 *
 * Returns:
 *   0 - Success - Keystore file is locked, paths to
 *		appropriate files placed in keystore.
 * non-zero - Failure, errors and reasons recorded in err
 */
static boolean_t
lock_keystore(PKG_ERR *err, long flags, keystore_t *keystore)
{
	boolean_t		ret = B_TRUE;
	struct stat		buf;

	switch (flags & KEYSTORE_ACCESS_MASK) {
	case KEYSTORE_ACCESS_READONLY:
		if ((keystore->cafd =
		    open(keystore->capath, O_NONBLOCK|O_RDONLY)) == -1) {
			if (errno == ENOENT) {
				/*
				 * no keystore.  try to create an
				 * empty one so we can lock on it and
				 * prevent others from gaining
				 * exclusive access.  It will be
				 * deleted when the keystore is closed.
				 */
				if ((keystore->cafd =
				    open(keystore->capath,
					O_NONBLOCK|O_RDWR|O_CREAT|O_EXCL,
					S_IRUSR|S_IWUSR)) == -1) {
					pkgerr_add(err, PKGERR_READ,
					    gettext(ERR_NO_KEYSTORE),
					    keystore->capath);
					ret = B_FALSE;
					goto cleanup;
				}
			} else {
				pkgerr_add(err, PKGERR_READ,
				    gettext(ERR_KEYSTORE_OPEN),
				    keystore->capath, strerror(errno));
				ret = B_FALSE;
				goto cleanup;
			}
		}
		if (fstat(keystore->cafd, &buf) != -1) {
			if (S_ISREG(buf.st_mode)) {
				if (file_lock(keystore->cafd, F_RDLCK,
				    0) == -1) {
					pkgerr_add(err, PKGERR_LOCKED,
					    gettext(ERR_KEYSTORE_LOCKED_READ),
					    keystore->capath);
					ret = B_FALSE;
					goto cleanup;
				}
			} else {
				/* ca file not a regular file! */
				pkgerr_add(err, PKGERR_READ,
				    gettext(ERR_NOT_REG),
				    keystore->capath);
				ret = B_FALSE;
				goto cleanup;
			}
		} else {
			pkgerr_add(err, PKGERR_READ,
			    gettext(ERR_KEYSTORE_OPEN),
			    keystore->capath, strerror(errno));
			ret = B_FALSE;
			goto cleanup;
		}
		break;
	case KEYSTORE_ACCESS_READWRITE:

		if ((keystore->cafd = open(keystore->capath,
		    O_RDWR|O_NONBLOCK)) == -1) {
			/* does not exist.  try to create an empty one */
			if (errno == ENOENT) {
				if ((keystore->cafd =
				    open(keystore->capath,
					O_NONBLOCK|O_RDWR|O_CREAT|O_EXCL,
					S_IRUSR|S_IWUSR)) == -1) {
					pkgerr_add(err, PKGERR_READ,
					    gettext(ERR_KEYSTORE_WRITE),
					    keystore->capath);
					ret = B_FALSE;
					goto cleanup;
				}
			} else {
				pkgerr_add(err, PKGERR_READ,
				    gettext(ERR_KEYSTORE_OPEN),
				    keystore->capath, strerror(errno));
				ret = B_FALSE;
				goto cleanup;
			}
		}
		if (fstat(keystore->cafd, &buf) != -1) {
			if (S_ISREG(buf.st_mode)) {
				if (file_lock(keystore->cafd, F_WRLCK,
				    0) == -1) {
					pkgerr_add(err, PKGERR_LOCKED,
					    gettext(ERR_KEYSTORE_LOCKED),
					    keystore->capath);
					ret = B_FALSE;
					goto cleanup;
				}
			} else {
				/* ca file not a regular file! */
				pkgerr_add(err, PKGERR_READ,
				    gettext(ERR_NOT_REG),
				    keystore->capath);
				ret = B_FALSE;
				goto cleanup;
			}
		} else {
			pkgerr_add(err, PKGERR_READ,
			    gettext(ERR_KEYSTORE_OPEN),
			    keystore->capath, strerror(errno));
			ret = B_FALSE;
			goto cleanup;
		}

		break;
	default:
		pkgerr_add(err, PKGERR_INTERNAL,
		    gettext(ERR_KEYSTORE_INTERNAL),
		    __FILE__, __LINE__);
		ret = B_FALSE;
		goto cleanup;
	}

cleanup:
	if (!ret) {
		if (keystore->cafd > 0) {
			(void) file_unlock(keystore->cafd);
			(void) close(keystore->cafd);
			keystore->cafd = -1;
		}

		if (keystore->capath != NULL)
			free(keystore->capath);
		if (keystore->clpath != NULL)
			free(keystore->clpath);
		if (keystore->keypath != NULL)
			free(keystore->keypath);
		keystore->capath = NULL;
		keystore->clpath = NULL;
		keystore->keypath = NULL;
	}

	return (ret);
}

/*
 * unlock_keystore - Unocks a keystore
 *
 * Arguments:
 * err - Error object to add errors to
 * keystore - keystore object to unlock
 * Returns:
 *   0 - Success - Keystore files are unlocked, files are closed,
 * non-zero - Failure, errors and reasons recorded in err
 */
/* ARGSUSED */
static boolean_t
unlock_keystore(PKG_ERR *err, keystore_t *keystore)
{

	/*
	 * Release lock on the CA file.
	 * Delete file if it is empty
	 */
	if (file_empty(keystore->capath)) {
		(void) remove(keystore->capath);
	}

	(void) file_unlock(keystore->cafd);
	(void) close(keystore->cafd);
	return (B_TRUE);
}

/*
 * read_keystore - Reads keystore files of disk, parses
 * into internal structures.
 *
 * Arguments:
 * err - Error object to add errors to
 * keystore - keystore object to read into
 * cb - callback to get password, if required
 * Returns:
 *   0 - Success - Keystore files are read, and placed
 * into keystore structure.
 * non-zero - Failure, errors and reasons recorded in err
 */
static boolean_t
read_keystore(PKG_ERR *err, keystore_t *keystore, keystore_passphrase_cb cb)
{
	boolean_t	ret = B_TRUE;
	PKCS12		*p12 = NULL;
	boolean_t	ca_empty;
	boolean_t	have_passwd = B_FALSE;
	boolean_t	cl_empty = B_TRUE;
	boolean_t	key_empty = B_TRUE;

	ca_empty = file_empty(keystore->capath);

	if (keystore->clpath != NULL)
		cl_empty = file_empty(keystore->clpath);
	if (keystore->keypath != NULL)
		key_empty = file_empty(keystore->keypath);

	if (ca_empty && cl_empty && key_empty) {
	    keystore->new = B_TRUE;
	}

	if (!ca_empty) {
		/* first read the ca file */
		if ((p12 = read_keystore_file(err,
		    keystore->capath)) == NULL) {
			pkgerr_add(err, PKGERR_CORRUPT,
			    gettext(ERR_KEYSTORE_CORRUPT), keystore->capath);
			ret = B_FALSE;
			goto cleanup;
		}

		/* Get password, using callback if necessary */
		if (!have_passwd) {
			if (!get_keystore_passwd(err, p12, cb, keystore)) {
				ret = B_FALSE;
				goto cleanup;
			}
			have_passwd = B_TRUE;
		}

		/* decrypt and parse keystore file */
		if (sunw_PKCS12_contents(p12, keystore->passphrase,
		    &keystore->pkeys, &keystore->cacerts) < 0) {
			/* could not parse the contents */
			pkgerr_add(err, PKGERR_CORRUPT,
			    gettext(ERR_KEYSTORE_CORRUPT), keystore->capath);
			ret = B_FALSE;
			goto cleanup;
		}

		PKCS12_free(p12);
		p12 = NULL;
	} else {

		/*
		 * truststore is empty, so we don't have any trusted
		 * certs
		 */
		keystore->cacerts = NULL;
	}

	/*
	 * if there is no cl file or key file, use the cl's and key's found
	 * in the ca file
	 */
	if (keystore->clpath == NULL && !ca_empty) {
		if (sunw_split_certs(keystore->pkeys, keystore->cacerts,
		    &keystore->clcerts, NULL) < 0) {
			pkgerr_add(err, PKGERR_CORRUPT,
			    gettext(ERR_KEYSTORE_CORRUPT), keystore->capath);
			ret = B_FALSE;
			goto cleanup;
		}
	} else {
		/*
		 * files are in separate files.  read keys out of the keystore
		 * certs out of the certstore, if they are not empty
		 */
		if (!cl_empty) {
			if ((p12 = read_keystore_file(err,
			    keystore->clpath)) == NULL) {
				pkgerr_add(err, PKGERR_CORRUPT,
				    gettext(ERR_KEYSTORE_CORRUPT),
				    keystore->clpath);
				ret = B_FALSE;
				goto cleanup;
			}

			/* Get password, using callback if necessary */
			if (!have_passwd) {
				if (!get_keystore_passwd(err, p12, cb,
				    keystore)) {
					ret = B_FALSE;
					goto cleanup;
				}
				have_passwd = B_TRUE;
			}

			if (check_password(p12,
			    keystore->passphrase) == B_FALSE) {
				/*
				 * password in client cert file
				 * is different than
				 * the one in the other files!
				 */
				pkgerr_add(err, PKGERR_BADPASS,
				    gettext(ERR_MISMATCHPASS),
				    keystore->clpath,
				    keystore->capath, keystore->path);
				ret = B_FALSE;
				goto cleanup;
			}

			if (sunw_PKCS12_contents(p12, keystore->passphrase,
			    NULL, &keystore->clcerts) < 0) {
				/* could not parse the contents */
				pkgerr_add(err, PKGERR_CORRUPT,
				    gettext(ERR_KEYSTORE_CORRUPT),
				    keystore->clpath);
				ret = B_FALSE;
				goto cleanup;
			}

			PKCS12_free(p12);
			p12 = NULL;
		} else {
			keystore->clcerts = NULL;
		}

		if (!key_empty) {
			if ((p12 = read_keystore_file(err,
			    keystore->keypath)) == NULL) {
				pkgerr_add(err, PKGERR_CORRUPT,
				    gettext(ERR_KEYSTORE_CORRUPT),
				    keystore->keypath);
				ret = B_FALSE;
				goto cleanup;
			}

			/* Get password, using callback if necessary */
			if (!have_passwd) {
				if (!get_keystore_passwd(err, p12, cb,
				    keystore)) {
					ret = B_FALSE;
					goto cleanup;
				}
				have_passwd = B_TRUE;
			}

			if (check_password(p12,
			    keystore->passphrase) == B_FALSE) {
				pkgerr_add(err, PKGERR_BADPASS,
				    gettext(ERR_MISMATCHPASS),
				    keystore->keypath,
				    keystore->capath, keystore->path);
				ret = B_FALSE;
				goto cleanup;
			}

			if (sunw_PKCS12_contents(p12, keystore->passphrase,
			    &keystore->pkeys, NULL) < 0) {
				/* could not parse the contents */
				pkgerr_add(err, PKGERR_CORRUPT,
				    gettext(ERR_KEYSTORE_CORRUPT),
				    keystore->keypath);
				ret = B_FALSE;
				goto cleanup;
			}

			PKCS12_free(p12);
			p12 = NULL;
		} else {
			keystore->pkeys = NULL;
		}
	}

cleanup:
	if (p12 != NULL)
		PKCS12_free(p12);
	return (ret);
}

/*
 * get_keystore_password - retrieves pasword used to
 * decrypt PKCS12 structure.
 *
 * Arguments:
 * err - Error object to add errors to
 * p12 - PKCS12 structure which returned password should
 * decrypt
 * cb - callback to collect password.
 * keystore - The keystore in which the PKCS12 structure
 * will eventually populate.
 * Returns:
 *   B_TRUE - success.
 *     keystore password is set in keystore->passphrase.
 *   B_FALSE - failure, errors logged
 */
static boolean_t
get_keystore_passwd(PKG_ERR *err, PKCS12 *p12, keystore_passphrase_cb cb,
    keystore_t *keystore)
{
	char				*passwd;
	char				passbuf[KEYSTORE_PASS_MAX + 1];
	keystore_passphrase_data	data;

	/* see if no password is the right password */
	if (check_password(p12, "") == B_TRUE) {
		passwd = "";
	} else if (check_password(p12, NULL) == B_TRUE) {
		passwd = NULL;
	} else {
		/* oops, it's encrypted.  get password */
		data.err = err;
		if (cb(passbuf, KEYSTORE_PASS_MAX, 0,
		    &data) == -1) {
			/* could not get password */
			return (B_FALSE);
		}

		if (check_password(p12, passbuf) == B_FALSE) {
				/* wrong password */
			pkgerr_add(err, PKGERR_BADPASS,
			    gettext(ERR_BADPASS));
			return (B_FALSE);
		}

		/*
		 * make copy of password buffer, since it
		 * goes away upon return
		 */
		passwd = xstrdup(passbuf);
	}
	keystore->passphrase = passwd;
	return (B_TRUE);
}

/*
 * write_keystore - Writes keystore files to disk
 *
 * Arguments:
 * err - Error object to add errors to
 * keystore - keystore object to write from
 * passwd - password used to encrypt keystore
 * Returns:
 *   0 - Success - Keystore contents are written out to
 *   the same locations as read from
 * non-zero - Failure, errors and reasons recorded in err
 */
static boolean_t
write_keystore(PKG_ERR *err, keystore_t *keystore,
    keystore_passphrase_cb cb)
{
	PKCS12	*p12 = NULL;
	boolean_t ret = B_TRUE;
	keystore_passphrase_data data;
	char		passbuf[KEYSTORE_PASS_MAX + 1];

	if (keystore->capath != NULL && keystore->clpath == NULL &&
	    keystore->keypath == NULL) {

		/*
		 * keystore is a file.
		 * just write out a single file
		 */
		if ((keystore->pkeys == NULL) &&
		    (keystore->clcerts == NULL) &&
		    (keystore->cacerts == NULL)) {
			if (!clear_keystore_file(err, keystore->capath)) {
				/*
				 * no keys or certs to write out, so
				 * blank the ca file.  we do not
				 * delete it since it is used as a
				 * lock by lock_keystore() in
				 * subsequent invocations
				 */
				pkgerr_add(err, PKGERR_WRITE,
				    gettext(ERR_KEYSTORE_WRITE),
				    keystore->capath);
				ret = B_FALSE;
				goto cleanup;
			}
		} else {
			/*
			 * if the keystore is being created for the first time,
			 * prompt for a passphrase for encryption
			 */
			if (keystore->new) {
				data.err = err;
				if (cb(passbuf, KEYSTORE_PASS_MAX,
				    1, &data) == -1) {
					ret = B_FALSE;
					goto cleanup;
				}
			} else {
				/*
				 * use the one used when the keystore
				 * was read
				 */
				strlcpy(passbuf, keystore->passphrase,
				    KEYSTORE_PASS_MAX);
			}

			p12 = sunw_PKCS12_create(passbuf, keystore->pkeys,
			    keystore->clcerts, keystore->cacerts);

			if (p12 == NULL) {
				pkgerr_add(err, PKGERR_WRITE,
				    gettext(ERR_KEYSTORE_FORM),
				    keystore->capath);
				ret = B_FALSE;
				goto cleanup;
			}

			if (!write_keystore_file(err, keystore->capath, p12)) {
				pkgerr_add(err, PKGERR_WRITE,
				    gettext(ERR_KEYSTORE_WRITE),
				    keystore->capath);
				ret = B_FALSE;
				goto cleanup;
			}
		}

	} else {
		/* files are seprate. Do one at a time */

		/*
		 * if the keystore is being created for the first time,
		 * prompt for a passphrase for encryption
		 */
		if (keystore->new && ((keystore->pkeys != NULL) ||
		    (keystore->clcerts != NULL) ||
		    (keystore->cacerts != NULL))) {
			data.err = err;
			if (cb(passbuf, KEYSTORE_PASS_MAX,
			    1, &data) == -1) {
				ret = B_FALSE;
				goto cleanup;
			}
		} else {
			/* use the one used when the keystore was read */
			strlcpy(passbuf, keystore->passphrase,
			    KEYSTORE_PASS_MAX);
		}

		/* do private keys first */
		if (keystore->pkeys != NULL) {
			p12 = sunw_PKCS12_create(passbuf, keystore->pkeys,
			    NULL, NULL);

			if (p12 == NULL) {
				pkgerr_add(err, PKGERR_WRITE,
				    gettext(ERR_KEYSTORE_FORM),
				    keystore->keypath);
				ret = B_FALSE;
				goto cleanup;
			}

			if (!write_keystore_file(err, keystore->keypath,
			    p12)) {
				pkgerr_add(err, PKGERR_WRITE,
				    gettext(ERR_KEYSTORE_WRITE),
				    keystore->keypath);
				ret = B_FALSE;
				goto cleanup;
			}

			PKCS12_free(p12);
		} else {
			if ((remove(keystore->keypath) != 0) &&
			    (errno != ENOENT)) {
				pkgerr_add(err, PKGERR_WRITE,
				    gettext(ERR_KEYSTORE_REMOVE),
				    keystore->keypath);
				ret = B_FALSE;
				goto cleanup;
			}
		}

		/* do user certs next */
		if (keystore->clcerts != NULL) {
			p12 = sunw_PKCS12_create(passbuf, NULL,
			    keystore->clcerts, NULL);

			if (p12 == NULL) {
				pkgerr_add(err, PKGERR_WRITE,
				    gettext(ERR_KEYSTORE_FORM),
				    keystore->clpath);
				ret = B_FALSE;
				goto cleanup;
			}

			if (!write_keystore_file(err, keystore->clpath, p12)) {
				pkgerr_add(err, PKGERR_WRITE,
				    gettext(ERR_KEYSTORE_WRITE),
				    keystore->clpath);
				ret = B_FALSE;
				goto cleanup;
			}

			PKCS12_free(p12);
		} else {
			if ((remove(keystore->clpath) != 0) &&
			    (errno != ENOENT)) {
				pkgerr_add(err, PKGERR_WRITE,
				    gettext(ERR_KEYSTORE_REMOVE),
				    keystore->clpath);
				ret = B_FALSE;
				goto cleanup;
			}
		}


		/* finally do CA cert file */
		if (keystore->cacerts != NULL) {
			p12 = sunw_PKCS12_create(passbuf, NULL,
			    NULL, keystore->cacerts);

			if (p12 == NULL) {
				pkgerr_add(err, PKGERR_WRITE,
				    gettext(ERR_KEYSTORE_FORM),
				    keystore->capath);
				ret = B_FALSE;
				goto cleanup;
			}

			if (!write_keystore_file(err, keystore->capath, p12)) {
				pkgerr_add(err, PKGERR_WRITE,
				    gettext(ERR_KEYSTORE_WRITE),
				    keystore->capath);
				ret = B_FALSE;
				goto cleanup;
			}

			PKCS12_free(p12);
			p12 = NULL;
		} else {
			/*
			 * nothing to write out, so truncate the file
			 * (it will be deleted during close_keystore)
			 */
			if (!clear_keystore_file(err, keystore->capath)) {
				pkgerr_add(err, PKGERR_WRITE,
				    gettext(ERR_KEYSTORE_WRITE),
				    keystore->capath);
				ret = B_FALSE;
				goto cleanup;
			}
		}
	}

cleanup:
	if (p12 != NULL)
		PKCS12_free(p12);

	return (ret);
}

/*
 * clear_keystore_file - Clears (zeros out) a keystore file.
 *
 * Arguments:
 * err - Error object to add errors to
 * dest - Path of keystore file to zero out.
 * Returns:
 *   0 - Success - Keystore file is truncated to zero length
 * non-zero - Failure, errors and reasons recorded in err
 */
static boolean_t
clear_keystore_file(PKG_ERR *err, char *dest)
{
	int fd;
	struct stat buf;

	fd = open(dest, O_RDWR|O_NONBLOCK);
	if (fd == -1) {
		/* can't open for writing */
		pkgerr_add(err, PKGERR_WRITE, gettext(MSG_OPEN),
		    errno);
		return (B_FALSE);
	}

	if ((fstat(fd, &buf) == -1) || !S_ISREG(buf.st_mode)) {
		/* not a regular file */
		(void) close(fd);
		pkgerr_add(err, PKGERR_WRITE, gettext(ERR_NOT_REG),
		    dest);
		return (B_FALSE);
	}

	if (ftruncate(fd, 0) == -1) {
		(void) close(fd);
		pkgerr_add(err, PKGERR_WRITE, gettext(ERR_WRITE),
		    dest, strerror(errno));
		return (B_FALSE);
	}

	(void) close(fd);
	return (B_TRUE);
}

/*
 * write_keystore_file - Writes keystore file to disk.
 *
 * Keystore files can possibly be corrupted by a variety
 * of error conditions during reading/writing.  This
 * routine, along with restore_keystore_file, tries to
 * maintain keystore integity by writing the files
 * out in a particular order, minimizing the time period
 * that the keystore is in an indeterminate state.
 *
 * With the current implementation, there are some failures
 * that are wholly unrecoverable, such as disk corruption.
 * These routines attempt to minimize the risk, but not
 * eliminate it.  When better, atomic operations are available
 * (such as a true database with commit, rollback, and
 * guaranteed atomicity), this implementation should use that.
 *
 *
 * Arguments:
 * err - Error object to add errors to
 * dest - Destination filename
 * contents - Contents to write to the file
 * Returns:
 *   0 - Success - Keystore contents are written out to
 *   the destination.
 * non-zero - Failure, errors and reasons recorded in err
 */
static boolean_t
write_keystore_file(PKG_ERR *err, char *dest, PKCS12 *contents)
{
	FILE	*newfile = NULL;
	boolean_t	ret = B_TRUE;
	char	newpath[MAXPATHLEN];
	char	backuppath[MAXPATHLEN];
	struct stat buf;
	int fd;

	(void) snprintf(newpath, MAXPATHLEN, "%s.new", dest);
	(void) snprintf(backuppath, MAXPATHLEN, "%s.bak", dest);

	if ((fd = open(newpath, O_CREAT|O_EXCL|O_WRONLY|O_NONBLOCK,
	    S_IRUSR|S_IWUSR)) == -1) {
		pkgerr_add(err, PKGERR_READ, gettext(ERR_KEYSTORE_OPEN),
		    newpath, strerror(errno));
		ret = B_FALSE;
		goto cleanup;
	}

	if (fstat(fd, &buf) == -1) {
		pkgerr_add(err, PKGERR_READ, gettext(ERR_KEYSTORE_OPEN),
		    newpath, strerror(errno));
		ret = B_FALSE;
		goto cleanup;
	}

	if (!S_ISREG(buf.st_mode)) {
		pkgerr_add(err, PKGERR_READ, gettext(ERR_NOT_REG),
		    newpath);
		ret = B_FALSE;
		goto cleanup;
	}

	if ((newfile = fdopen(fd, "w")) == NULL) {
		pkgerr_add(err, PKGERR_READ, gettext(ERR_KEYSTORE_OPEN),
		    newpath, strerror(errno));
		ret = B_FALSE;
		goto cleanup;
	}

	if (i2d_PKCS12_fp(newfile, contents) == 0) {
		pkgerr_add(err, PKGERR_WRITE, gettext(ERR_KEYSTORE_WRITE),
		    newpath);
		ret = B_FALSE;
		goto cleanup;
	}

	/* flush, then close */
	(void) fflush(newfile);
	(void) fclose(newfile);
	newfile = NULL;

	/* now back up the original file */
	(void) rename(dest, backuppath);

	/* put new one in its place */
	(void) rename(newpath, dest);

	/* remove backup */
	(void) remove(backuppath);

cleanup:
	if (newfile != NULL)
		(void) fclose(newfile);
	if (fd != -1)
		(void) close(fd);

	return (ret);
}

/*
 * read_keystore_file - Reads single keystore file
 * off disk in PKCS12 format.
 *
 * Arguments:
 * err - Error object to add errors to
 * file - File path to read
 * Returns:
 *   PKCS12 contents of file, or NULL if an error occurred.
 *   errors recorded in 'err'.
 */
static PKCS12
*read_keystore_file(PKG_ERR *err, char *file)
{
	int fd;
	struct stat buf;
	FILE *newfile;
	PKCS12 *p12 = NULL;

	if ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		pkgerr_add(err, PKGERR_READ, gettext(ERR_KEYSTORE_OPEN),
		    file, strerror(errno));
		goto cleanup;
	}

	if (fstat(fd, &buf) == -1) {
		pkgerr_add(err, PKGERR_READ, gettext(ERR_KEYSTORE_OPEN),
		    file, strerror(errno));
		goto cleanup;
	}

	if (!S_ISREG(buf.st_mode)) {
		pkgerr_add(err, PKGERR_READ, gettext(ERR_NOT_REG),
		    file);
		goto cleanup;
	}

	if ((newfile = fdopen(fd, "r")) == NULL) {
		pkgerr_add(err, PKGERR_READ, gettext(ERR_KEYSTORE_OPEN),
		    file, strerror(errno));
		goto cleanup;
	}

	if ((p12 = d2i_PKCS12_fp(newfile, NULL)) == NULL) {
		pkgerr_add(err, PKGERR_CORRUPT,
		    gettext(ERR_KEYSTORE_CORRUPT), file);
		goto cleanup;
	}

cleanup:
	if (newfile != NULL)
		(void) fclose(newfile);
	if (fd != -1)
		(void) close(fd);

	return (p12);
}


/*
 * Locks the specified file.
 */
static int
file_lock(int fd, int type, int wait)
{
	struct flock lock;

	lock.l_type = type;
	lock.l_start = 0;
	lock.l_whence = SEEK_SET;
	lock.l_len = 0;

	if (!wait) {
		if (file_lock_test(fd, type)) {
			/*
			 * The caller would have to wait to get the
			 * lock on this file.
			 */
			return (-1);
		}
	}

	return (fcntl(fd, F_SETLKW, &lock));
}

/*
 * Returns FALSE if the file is not locked; TRUE
 * otherwise.
 */
static boolean_t
file_lock_test(int fd, int type)
{
	struct flock lock;

	lock.l_type = type;
	lock.l_start = 0;
	lock.l_whence = SEEK_SET;
	lock.l_len = 0;

	if (fcntl(fd, F_GETLK, &lock) != -1) {
		if (lock.l_type != F_UNLCK) {
			/*
			 * The caller would have to wait to get the
			 * lock on this file.
			 */
			return (B_TRUE);
		}
	}

	/*
	 * The file is not locked.
	 */
	return (B_FALSE);
}

/*
 * Unlocks the specified file.
 */
static int
file_unlock(int fd)
{
	struct flock lock;

	lock.l_type = F_UNLCK;
	lock.l_start = 0;
	lock.l_whence = SEEK_SET;
	lock.l_len = 0;

	return (fcntl(fd, F_SETLK, &lock));
}

/*
 * Determines if file has a length of 0 or not
 */
static boolean_t
file_empty(char *path)
{
	struct stat	buf;

	/* file is empty if size = 0 or it doesn't exist */
	if (lstat(path, &buf) == 0) {
		if (buf.st_size == 0) {
			return (B_TRUE);
		}
	} else {
		if (errno == ENOENT) {
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * Name:		get_time_string
 * Description:	Generates a human-readable string from an ASN1_TIME
 *
 * Arguments:	intime - The time to convert
 *
 * Returns :	A pointer to a static string representing the passed-in time.
 */
static char
*get_time_string(ASN1_TIME *intime)
{

	static char	time[ATTR_MAX];
	BIO		*mem;
	char	*p;

	if (intime == NULL) {
		return (NULL);
	}
	if ((mem = BIO_new(BIO_s_mem())) == NULL) {
		return (NULL);
	}

	if (ASN1_TIME_print(mem, intime) == 0) {
		(void) BIO_free(mem);
		return (NULL);
	}

	if (BIO_gets(mem, time, ATTR_MAX) <= 0) {
		(void) BIO_free(mem);
		return (NULL);
	}

	(void) BIO_free(mem);

	/* trim the end of the string */
	for (p = time + strlen(time) - 1; isspace(*p); p--) {
		*p = '\0';
	}

	return (time);
}

/*
 * check_password - do various password checks to see if the current password
 *                  will work or we need to prompt for a new one.
 *
 * Arguments:
 *   pass   - password to check
 *
 * Returns:
 *   B_TRUE  - Password is OK.
 *   B_FALSE - Password not valid.
 */
static boolean_t
check_password(PKCS12 *p12, char *pass)
{
	boolean_t ret = B_TRUE;

	/*
	 * If password is zero length or NULL then try verifying both cases
	 * to determine which password is correct. The reason for this is that
	 * under PKCS#12 password based encryption no password and a zero
	 * length password are two different things...
	 */

	/* Check the mac */
	if (pass == NULL || *pass == '\0') {
		if (PKCS12_verify_mac(p12, NULL, 0) == 0 &&
		    PKCS12_verify_mac(p12, "", 0) == 0)
			ret = B_FALSE;
	} else if (PKCS12_verify_mac(p12, pass, -1) == 0) {
		ret = B_FALSE;
	}
	return (ret);
}
