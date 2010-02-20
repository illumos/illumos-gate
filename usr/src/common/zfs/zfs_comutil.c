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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file is intended for functions that ought to be common between user
 * land (libzfs) and the kernel. When many common routines need to be shared
 * then a separate file should to be created.
 */

#if defined(_KERNEL)
#include <sys/systm.h>
#else
#include <string.h>
#endif

#include <sys/types.h>
#include <sys/fs/zfs.h>
#include <sys/int_limits.h>
#include <sys/nvpair.h>

/*
 * Are there allocatable vdevs?
 */
boolean_t
zfs_allocatable_devs(nvlist_t *nv)
{
	uint64_t is_log;
	uint_t c;
	nvlist_t **child;
	uint_t children;

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) != 0) {
		return (B_FALSE);
	}
	for (c = 0; c < children; c++) {
		is_log = 0;
		(void) nvlist_lookup_uint64(child[c], ZPOOL_CONFIG_IS_LOG,
		    &is_log);
		if (!is_log)
			return (B_TRUE);
	}
	return (B_FALSE);
}

void
zpool_get_rewind_policy(nvlist_t *nvl, zpool_rewind_policy_t *zrpp)
{
	nvlist_t *policy;
	nvpair_t *elem;
	char *nm;

	/* Defaults */
	zrpp->zrp_request = ZPOOL_NO_REWIND;
	zrpp->zrp_maxmeta = 0;
	zrpp->zrp_maxdata = UINT64_MAX;
	zrpp->zrp_txg = UINT64_MAX;

	if (nvl == NULL)
		return;

	elem = NULL;
	while ((elem = nvlist_next_nvpair(nvl, elem)) != NULL) {
		nm = nvpair_name(elem);
		if (strcmp(nm, ZPOOL_REWIND_POLICY) == 0) {
			if (nvpair_value_nvlist(elem, &policy) == 0)
				zpool_get_rewind_policy(policy, zrpp);
			return;
		} else if (strcmp(nm, ZPOOL_REWIND_REQUEST) == 0) {
			if (nvpair_value_uint32(elem, &zrpp->zrp_request) == 0)
				if (zrpp->zrp_request & ~ZPOOL_REWIND_POLICIES)
					zrpp->zrp_request = ZPOOL_NO_REWIND;
		} else if (strcmp(nm, ZPOOL_REWIND_REQUEST_TXG) == 0) {
			(void) nvpair_value_uint64(elem, &zrpp->zrp_txg);
		} else if (strcmp(nm, ZPOOL_REWIND_META_THRESH) == 0) {
			(void) nvpair_value_uint64(elem, &zrpp->zrp_maxmeta);
		} else if (strcmp(nm, ZPOOL_REWIND_DATA_THRESH) == 0) {
			(void) nvpair_value_uint64(elem, &zrpp->zrp_maxdata);
		}
	}
	if (zrpp->zrp_request == 0)
		zrpp->zrp_request = ZPOOL_NO_REWIND;
}
