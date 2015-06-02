/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Joyent, Inc.
 */

/*
 * Lookup functions for various file paths used by ipmgmtd.  This mechanism
 * primarily exists to account for a native root prefix when run within a
 * branded zone (e.g. "/native").
 */

#include <stdio.h>
#include <zone.h>
#include "ipmgmt_impl.h"

#define	IPADM_PERM_DIR		"/etc/ipadm"
#define	IPADM_TMPFS_DIR		"/etc/svc/volatile/ipadm"

typedef struct ipadm_path_ent {
	ipadm_path_t ipe_id;
	const char *ipe_path;
} ipadm_path_ent_t;

static ipadm_path_ent_t ipadm_paths[] = {
	/*
	 * A temporary directory created in the SMF volatile filesystem.
	 */
	{ IPADM_PATH_TMPFS_DIR,		IPADM_TMPFS_DIR },

	/*
	 * This file captures the in-memory copy of list `aobjmap' on disk.
	 * This allows the system to recover in the event that the daemon
	 * crashes or is restarted.
	 */
	{ IPADM_PATH_ADDROBJ_MAP_DB,	IPADM_TMPFS_DIR "/aobjmap.conf" },

	/*
	 * The permanent data store for ipadm.
	 */
	{ IPADM_PATH_DB,		IPADM_PERM_DIR "/ipadm.conf" },

	/*
	 * A temporary copy of the ipadm configuration created, if needed, to
	 * service write requests early in boot.  This file is merged with the
	 * permanent data store once it is available for writes.
	 */
	{ IPADM_PATH_VOL_DB,		IPADM_TMPFS_DIR "/ipadm.conf" },

	{ 0,				NULL }
};

/*
 * Load one of the paths used by ipadm into the provided string buffer.
 * Prepends the native system prefix (e.g. "/native") if one is in effect,
 * such as when running within a branded zone.
 */
void
ipmgmt_path(ipadm_path_t ip, char *buf, size_t bufsz)
{
	int i;

	for (i = 0; ipadm_paths[i].ipe_path != NULL; i++) {
		if (ipadm_paths[i].ipe_id == ip) {
			const char *zroot = zone_get_nroot();

			(void) snprintf(buf, bufsz, "%s%s", zroot != NULL ?
			    zroot : "", ipadm_paths[i].ipe_path);

			return;
		}
	}

	abort();
}
