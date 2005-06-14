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
 *	npd_cache.h
 *
 *	Copyright (c) 1994, 2001 Sun Microsystems Inc
 *	All Rights Reserved.
 */

#ifndef _NPD_CACHE_H
#define	_NPD_CACHE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpcsvc/nis.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * cache for useful information
 */
struct	update_item {
	NIS_HASH_ITEM	ul_item;	/* generic tag */
	bool_t		ul_sameuser;	/* changing their own passwd */
	char		*ul_user;	/* username */
	char		*ul_domain;	/* domainname */
	ulong_t		ul_rval;	/* random value */
	ulong_t		ul_ident;	/* identifier */
	des_block	ul_key;		/* session key */
	char		*ul_oldpass;	/* old clear passwd */
	int		ul_attempt;	/* failed attempts per session */
	ulong_t		ul_expire;	/* expiration time */
};


bool_t find_upd_item(nis_name principal, struct	update_item **upd);
void free_upd_item(struct update_item *upd);
struct update_item *__npd_item_by_key(int key);
int add_upd_item(nis_name principal, char *user, bool_t sameuser, char *domain,
	ulong_t ident, ulong_t rval, des_block *key, char *pass);
void __npd_print_entry(char *prin);
int __npd_hash_key(nis_name name);

#ifdef	__cplusplus
}
#endif

#endif	/* _NPD_CACHE_H */
