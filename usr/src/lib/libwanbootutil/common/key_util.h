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

#ifndef	_KEY_UTIL_H
#define	_KEY_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Key algorithms */
typedef enum {
	WBKU_KEY_3DES,
	WBKU_KEY_AES_128,
	WBKU_KEY_HMAC_SHA1,
	WBKU_KEY_RSA,
	WBKU_KEY_UNKNOWN
} wbku_key_type_t;

/* Algorithm keywords */
#define	WBKU_KW_3DES		"3des"
#define	WBKU_KW_AES_128		"aes"
#define	WBKU_KW_HMAC_SHA1	"sha1"
#define	WBKU_KW_RSA		"rsa"

/* Algorithm types */
#define	WBKU_ENCR_KEY	(uint_t)0x1
#define	WBKU_HASH_KEY	(uint_t)0x2
#define	WBKU_ANY_KEY	(WBKU_ENCR_KEY | WBKU_HASH_KEY)

/* Return codes */
typedef enum {
	WBKU_SUCCESS,
	WBKU_INTERNAL_ERR,
	WBKU_WRITE_ERR,
	WBKU_NOKEY,
	WBKU_BAD_KEYTYPE
} wbku_retcode_t;

#define	WBKU_NRET		(WBKU_BAD_KEYTYPE + 1)

/* The master key file location. */
#define	MASTER_KEY_FILE	"/etc/netboot/keystore"

/* The root directory for all client keys */
#define	CLIENT_KEY_DIR	"/etc/netboot"

/* The structure that defines the attributes of a particular key type */
typedef struct key_attr {
	wbku_key_type_t ka_type; /* key type */
	uint_t ka_atype;	/* key algorithm type */
	uint_t ka_len;		/* length of the current key */
	uint_t ka_minlen;	/* shortest allowable key value */
	uint_t ka_maxlen;	/* maximum allowable key length */
	char *ka_str;		/* key string identifier */
	char *ka_oid;		/* key algorithm oid */
	boolean_t (*ka_keycheck)(const uint8_t *); /* keycheck function */
} wbku_key_attr_t;

extern void wbku_errinit(const char *);
extern void wbku_printerr(const char *, ...);
extern const char *wbku_retmsg(wbku_retcode_t);
extern wbku_retcode_t wbku_str_to_keyattr(const char *, wbku_key_attr_t *,
    uint_t);
extern wbku_retcode_t wbku_find_key(FILE *, fpos_t *, wbku_key_attr_t *,
    uint8_t *, boolean_t);
extern wbku_retcode_t wbku_write_key(FILE *, const fpos_t *,
    const wbku_key_attr_t *, uint8_t *, boolean_t);
extern wbku_retcode_t wbku_delete_key(FILE *, FILE *, const wbku_key_attr_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _KEY_UTIL_H */
