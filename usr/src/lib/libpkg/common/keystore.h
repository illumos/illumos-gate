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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _KEYSTORE_H
#define	_KEYSTORE_H


/*
 * Module:	keystore.h
 * Description:	This module contains the structure definitions for processing
 *		package keystore files.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/evp.h>
#include <openssl/x509.h>
#include "pkgerr.h"

/* keystore structures */

/* this opaque type represents a keystore */
typedef void *keystore_handle_t;

/* flags passed to open_keystore */

/* opens keystore read-only.  Attempts to modify results in an error */
#define	KEYSTORE_ACCESS_READONLY	0x00000001L

/* opens keystore read-write */
#define	KEYSTORE_ACCESS_READWRITE	0x00000002L

/*
 * tells open_keystore to fall back to app-generic paths in the case that
 * the app-specific paths do not exist.
 */
#define	KEYSTORE_PATH_SOFT		0x00000010L

/*
 * tells open_keystore to use the app-specific paths no matter what,
 * failing if they cannot be used for any reason.
 */
#define	KEYSTORE_PATH_HARD		0x00000020L

/* masks off various types of flags */
#define	KEYSTORE_ACCESS_MASK		0x0000000FL
#define	KEYSTORE_PATH_MASK		0x000000F0L

/* default is read-only, soft */
#define	KEYSTORE_DFLT_FLAGS \
		(KEYSTORE_ACCESS_READONLY|KEYSTORE_PATH_SOFT)

/*
 * possible encoding formats used by the library, used
 * by print_cert
 */
typedef enum {
	KEYSTORE_FORMAT_PEM,
	KEYSTORE_FORMAT_DER,
	KEYSTORE_FORMAT_TEXT
} keystore_encoding_format_t;

/*
 * structure passed back to password callback for determining how
 * to prompt for passphrase, and where to record errors
 */
typedef struct {
	PKG_ERR	*err;
} keystore_passphrase_data;


/* max length of a passphrase.  One could use a short story! */
#define	KEYSTORE_PASS_MAX	1024

/* callback for collecting passphrase when open_keystore() is called */
typedef int keystore_passphrase_cb(char *, int, int, void *);

/* names of the individual files within the keystore path */
#define	TRUSTSTORE		"truststore"
#define	KEYSTORE		"keystore"
#define	CERTSTORE		"certstore"

/* keystore.c */
extern int		open_keystore(PKG_ERR *, char *, char *,
    keystore_passphrase_cb, long flags, keystore_handle_t *);

extern int		print_certs(PKG_ERR *, keystore_handle_t, char *,
    keystore_encoding_format_t, FILE *);

extern int		check_cert(PKG_ERR *, X509 *);

extern int		check_cert_and_key(PKG_ERR *, X509 *, EVP_PKEY *);

extern int		print_cert(PKG_ERR *, X509 *,
    keystore_encoding_format_t, char *, boolean_t, FILE *);

extern int		close_keystore(PKG_ERR *, keystore_handle_t,
    keystore_passphrase_cb);

extern int		merge_ca_cert(PKG_ERR *, X509 *, keystore_handle_t);
extern int		merge_cert_and_key(PKG_ERR *, X509 *, EVP_PKEY *,
    char *, keystore_handle_t);

extern int		delete_cert_and_keys(PKG_ERR *, keystore_handle_t,
    char *);

extern int		find_key_cert_pair(PKG_ERR *, keystore_handle_t,
    char *, EVP_PKEY **, X509 **);

extern int		find_ca_certs(PKG_ERR *, keystore_handle_t,
    STACK_OF(X509) **);

extern int		find_cl_certs(PKG_ERR *, keystore_handle_t,
    STACK_OF(X509) **);

#ifdef __cplusplus
}
#endif

#endif /* _KEYSTORE_H */
