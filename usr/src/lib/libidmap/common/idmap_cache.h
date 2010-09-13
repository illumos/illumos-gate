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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Windows to Solaris Identity Mapping
 * This header file contains cache definitions.
 */

#ifndef _IDMAP_CACHE_H
#define	_IDMAP_CACHE_H


#include <sys/avl.h>
#include "idmap.h"

#ifdef	__cplusplus
extern "C" {
#endif

void
idmap_cache_create();

void
idmap_cache_purge();


idmap_stat
idmap_cache_lookup_uidbysid(const char *sid_prefix, idmap_rid_t rid,
			uid_t *uid);

idmap_stat
idmap_cache_lookup_gidbysid(const char *sid_prefix, idmap_rid_t rid,
			gid_t *gid);

idmap_stat
idmap_cache_lookup_pidbysid(const char *sid_prefix, idmap_rid_t rid,
			uid_t *pid, int *is_user);

idmap_stat
idmap_cache_lookup_sidbyuid(char **sid_prefix, idmap_rid_t *rid,
			uid_t uid);

idmap_stat
idmap_cache_lookup_sidbygid(char **sid_prefix, idmap_rid_t *rid,
			gid_t gid);

idmap_stat
idmap_cache_lookup_winnamebyuid(char **winname, char **windomain, uid_t uid);

idmap_stat
idmap_cache_lookup_winnamebygid(char **winname, char **windomain, gid_t gid);

idmap_stat
idmap_cache_lookup_uidbywinname(const char *winname, const char *windomain,
			uid_t *uid);

idmap_stat
idmap_cache_lookup_gidbywinname(const char *winname, const char *windomain,
			gid_t *gid);

void
idmap_cache_add_sid2uid(const char *sid_prefix, idmap_rid_t rid, uid_t uid,
			int direction);

void
idmap_cache_add_sid2gid(const char *sid_prefix, idmap_rid_t rid, gid_t gid,
			int direction);

void
idmap_cache_add_sid2pid(const char *sid_prefix, idmap_rid_t rid, uid_t pid,
			int is_user, int direction);

void
idmap_cache_add_winname2uid(const char *winname, const char *windomain,
			uid_t uid, int direction);

void
idmap_cache_add_winname2gid(const char *winname, const char *windomain,
			gid_t gid, int direction);

void
idmap_cache_get_data(size_t *uidbysid, size_t *gidbysid, size_t *pidbysid,
			size_t *sidbyuid, size_t *sidbygid,
			size_t *winnamebyuid, size_t *winnamebygid,
			size_t *uidbywinname, size_t *gidbywinname);


#ifdef	__cplusplus
}
#endif

#endif	/* _IDMAP_CACHE_H */
