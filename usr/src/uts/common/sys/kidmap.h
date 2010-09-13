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
 * Windows to Solaris Identity Mapping kernel API
 * This header defines an API to map Windows SIDs to
 * Solaris UID and GIDs and versa visa.
 */

#ifndef	_SYS_KIDMAP_H
#define	_SYS_KIDMAP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/idmap.h>
#include <sys/door.h>
#include <sys/zone.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Opaque get handle */
typedef struct idmap_get_handle idmap_get_handle_t;

/* Return status */
typedef	int32_t idmap_stat;

/*
 * In all the routines a Windows SID is handled as a
 * string SID prefix plus a RID. For example
 *
 * S-1-5-5-12-34-568 will be passed as SID prefix
 * S-1-5-5-12-34 and RID 568
 *
 * Certain routines returns pointers to a SID prefix string.
 * These strings are stored internally and should not be modified
 * or freed.
 */


/*
 * The following routines are simple get ID mapping routines.
 */


idmap_stat
kidmap_getuidbysid(zone_t *zone, const char *sid_prefix, uint32_t rid,
		uid_t *uid);

idmap_stat
kidmap_getgidbysid(zone_t *zone, const char *sid_prefix, uint32_t rid,
		gid_t *gid);

idmap_stat
kidmap_getpidbysid(zone_t *zone, const char *sid_prefix, uint32_t rid,
		uid_t *pid, int *is_user);

idmap_stat
kidmap_getsidbyuid(zone_t *zone, uid_t uid, const char **sid_prefix,
		uint32_t *rid);

idmap_stat
kidmap_getsidbygid(zone_t *zone, gid_t gid, const char **sid_prefix,
		uint32_t *rid);



/*
 * The following routines provide a batch interface for mapping IDs.
 */

/*
 * Create a batch "get mapping" handle for batch mappings.
 */
idmap_get_handle_t *
kidmap_get_create(zone_t *zone);

/*
 * These routines queue the request to the "get mapping" handle
 */

idmap_stat
kidmap_batch_getuidbysid(idmap_get_handle_t *get_handle,
		const char *sid_prefix, uint32_t rid,
		uid_t *uid, idmap_stat *stat);

idmap_stat
kidmap_batch_getgidbysid(idmap_get_handle_t *get_handle,
		const char *sid_prefix, uint32_t rid,
		gid_t *gid, idmap_stat *stat);

idmap_stat
kidmap_batch_getpidbysid(idmap_get_handle_t *get_handle,
		const char *sid_prefix, uint32_t rid,
		uid_t *pid, int *is_user, idmap_stat *stat);

idmap_stat
kidmap_batch_getsidbyuid(idmap_get_handle_t *get_handle, uid_t uid,
		const char **sid_prefix, uint32_t *rid, idmap_stat *stat);

idmap_stat
kidmap_batch_getsidbygid(idmap_get_handle_t *get_handle, gid_t gid,
		const char **sid_prefix, uint32_t *rid, idmap_stat *stat);

/*
 * Process the queued "get mapping" requests. The results (i.e.
 * status and identity) will be available in the data areas
 * provided by individual requests.
 */
idmap_stat
kidmap_get_mappings(idmap_get_handle_t *get_handle);

/*
 * Destroy the "get mapping" handle
 */
void
kidmap_get_destroy(idmap_get_handle_t *get_handle);

/*
 * Functions that do the hard part of door registration/unregistration
 * for the idmap_reg()/idmap_unreg() syscalls
 */
int idmap_reg_dh(zone_t *zone, door_handle_t dh);
int idmap_unreg_dh(zone_t *zone, door_handle_t dh);

/*
 * Function needed by allocids() to ensure only the daemon that owns
 * the door gets ephemeral IDS
 */
door_handle_t idmap_get_door(zone_t *zone);

/*
 * Function used by system call allocids() to purge the
 * ID mapping cache
 */
void idmap_purge_cache(zone_t *zone);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_KIDMAP_H */
