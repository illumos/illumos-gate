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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_KEYSERV_CACHE_H
#define	_KEYSERV_CACHE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* uid_t, size_t, caddr_t, u_int, etc. */
#include <sys/types.h>
/* des_block, keylen_t, algtype_t */
#include <rpc/key_prot.h>

struct dhkey {
	u_short	length;	/* Length in bytes */
	u_char	key[1];	/* Binary data; allocated to correct length */
};

/* Round up to multiple of four */
#define	ALIGN4(addr)		(4 * (((addr)+3)/4))
/* Round up to multiple of eight */
#define	ALIGN8(addr)		(8 * (((addr)+7)/8))

/* Convert key length in bits to bytes */
#define	KEYLEN(keylen)		(((keylen)+7)/8)

/* Bytes to allocate for struct dhkey holding key of specified length (bits) */
#define	DHKEYALLOC(keylen)	ALIGN4(sizeof (struct dhkey) + KEYLEN(keylen))
/* Bytes used for a struct dhkey (already allocated */
#define	DHKEYSIZE(dhkey_ptr)	ALIGN4(sizeof (struct dhkey) + \
				(dhkey_ptr)->length)

struct cachekey3_list {
	keybuf3			*public;
	keybuf3			*secret;
	int			refcnt;
	deskeyarray		deskey;
	struct cachekey3_list	*next;
};

#define	CACHEKEY3_LIST_SIZE(keylen)	(sizeof (struct cachekey3_list) + \
					2*sizeof (keybuf3) + \
					2*(ALIGN4(2*KEYLEN(keylen)+1)) + \
					3*sizeof (des_block))

int			create_cache_file(keylen_t keylen, algtype_t algtype,
					int sizespec);

int			cache_insert(keylen_t keylen, algtype_t algtype,
					uid_t uid,
					deskeyarray common, des_block key,
					keybuf3 *public,
					keybuf3 *secret);

struct cachekey3_list	*cache_retrieve(keylen_t keylen, algtype_t algtype,
					uid_t uid,
					keybuf3 *public, des_block key);

int			cache_remove(keylen_t keylen, algtype_t algtype,
					uid_t uid,
					keybuf3 *public);

void			print_cache(keylen_t keylen, algtype_t algtype);

#ifdef	__cplusplus
}
#endif

#endif /* _KEYSERV_CACHE_H */
