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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <regex.h>
#include <devfsadm.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/mkdev.h>
#include <sys/fs/zfs.h>

/* zfs and zvol name info */

#define	ZVOL_LINK_RE_DEVICES	"zvol/r?dsk/.*/.*$"

static int zfs(di_minor_t minor, di_node_t node);

/*
 * devfs create callback register
 */
static devfsadm_create_t zfs_create_cbt[] = {
	{ "pseudo", "ddi_pseudo", ZFS_DRIVER,
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, zfs,
	},
};
DEVFSADM_CREATE_INIT_V0(zfs_create_cbt);

/*
 * devfs cleanup register
 */
static devfsadm_remove_t zfs_remove_cbt[] = {
	{ "pseudo", ZVOL_LINK_RE_DEVICES, RM_HOT | RM_POST,
	    ILEVEL_0, devfsadm_rm_all },
};
DEVFSADM_REMOVE_INIT_V0(zfs_remove_cbt);

/*
 * For the zfs control node:
 *	/dev/zfs -> /devices/pseudo/zfs@0:zfs
 * For zvols:
 *	/dev/zvol/dsk/<pool>/<dataset> -> /devices/pseudo/zfs@0:1
 *	/dev/zvol/rdsk/<pool>/<dataset> -> /devices/pseudo/zfs@0:1,raw
 */
static int
zfs(di_minor_t minor, di_node_t node)
{
	dev_t	dev;
	int	err;
	char mn[MAXNAMELEN + 1];
	char blkname[MAXNAMELEN + 1];
	char rawname[MAXNAMELEN + 1];
	char path[PATH_MAX + 1];
	char *name;

	(void) strcpy(mn, di_minor_name(minor));

	if (strcmp(mn, ZFS_DRIVER) == 0) {
		(void) devfsadm_mklink(ZFS_DRIVER, node, minor, 0);
	} else {
		dev = di_minor_devt(minor);
		err = di_prop_lookup_strings(dev, node, ZVOL_PROP_NAME, &name);
		if (err < 0) {
			/* property not defined so can't do anything */
			return (DEVFSADM_CONTINUE);
		}
		(void) snprintf(blkname, sizeof (blkname), "%dc",
		    (int)minor(dev));
		(void) snprintf(rawname, sizeof (rawname), "%dc,raw",
		    (int)minor(dev));

		/*
		 * This is where the actual public name gets constructed.
		 * Change the snprintf format to change the public
		 * path that gets constructed.
		 */
		if (strcmp(mn, blkname) == 0) {
			(void) snprintf(path, sizeof (path), "%s/%s",
			    ZVOL_DEV_DIR, name);
		} else if (strcmp(mn, rawname) == 0) {
			(void) snprintf(path, sizeof (path), "%s/%s",
			    ZVOL_RDEV_DIR, name);
		} else {
			return (DEVFSADM_CONTINUE);
		}

		(void) devfsadm_mklink(path, node, minor, 0);
	}
	return (DEVFSADM_CONTINUE);
}
