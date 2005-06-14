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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
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

#define	MD_LINK_RE_DEVICES	"^md/r?dsk/d[0-9]+$"
#define	MD_LINK_RE_SHARED	"^md/shared/[0-9]+/r?dsk/d[0-9]+$"
#define	MD_LINK_RE_ADMIN	"^md/admin"

/*
 * The devfsadm link module require the next section to
 * be defined in order to know what and when to call functions
 * in the module on device creation and removal.
 */

/* setup for device creation */

static int md_create(di_minor_t minor, di_node_t node);

static devfsadm_create_t md_cbt[] = {
	{ "pseudo", "ddi_pseudo", "md",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, md_create,
	},
};

DEVFSADM_CREATE_INIT_V0(md_cbt);

/*
 * remove devices - always allow disks to be dynamically removed. Only allow
 *		    admin device to be removed at reboot.
 */

static devfsadm_remove_t md_remove_cbt[] = {
	{"pseudo", MD_LINK_RE_DEVICES, RM_ALWAYS | RM_PRE | RM_HOT,
	    ILEVEL_0, devfsadm_rm_all},
	{"pseudo", MD_LINK_RE_SHARED, RM_ALWAYS | RM_PRE | RM_HOT,
	    ILEVEL_0, devfsadm_rm_all},
	{"pseudo", MD_LINK_RE_ADMIN, RM_ALWAYS | RM_PRE,
	    ILEVEL_0, devfsadm_rm_all},
};

DEVFSADM_REMOVE_INIT_V0(md_remove_cbt);


/*
 * For the admin device:
 *	/dev/md/admin -> /devices/pseudo/md@0:admin
 *
 * For each other device
 *	/dev/md/dsk/dN -> /devices/pseudo/md@0:0,N,blk
 *	/dev/md/rdsk/dN -> /devices/pseudo/md@0:0,N,raw
 *	/dev/md/shared/M/dsk/dN /devices/pseudo/md@0:M,N,blk
 *	/dev/md/shared/M/rdsk/dN /devices/pseudo/md@0:M,N,raw
 */
static int
md_create(di_minor_t minor, di_node_t node)
{
	char mn[MAXNAMELEN + 1];
	char path[PATH_MAX + 1];
	int set = -1, mdev = -1, ret;
	char *type, *dir;

	(void) strcpy(mn, di_minor_name(minor));

	/*
	 * Check whether we are being requested to setup the admin
	 * device link or one of the metadevice links. They need
	 * to be treated differently.
	 */

	if (strcmp(mn, "admin") == 0) {
		/* there is only one admin link and always in /dev/md/admin */
		(void) devfsadm_mklink("md/admin", node, minor, 0);
	} else {
		/*
		 * Extract out the minor components and create the
		 * appropriate links. The node looks like:
		 * md@<set>,<mdev>,<type>
		 * where the <set> number is the named diskset,
		 * <mdev> is the metadevice number, and <type>
		 * is the trailing "blk" or "raw" indication.
		 *
		 * NOTE: when <set> is non-zero, we need to create
		 * under the "shared" directory entry instead of linking
		 * into the top level dsk/rdsk directories.
		 */
		ret = sscanf(mn, "%d,%d,", &set, &mdev);
		if (ret == 2 && (type = strrchr(mn, ',')) != NULL) {
			type ++;
			if (strcmp(type, "blk") == 0) {
				dir = "dsk";
			} else {
				dir = "rdsk";
			}
			if (set == 0) {
				/* this is a simple md */
				(void) snprintf(path, sizeof (path),
					"md/%s/d%d", dir, mdev);
			} else {
				/* this is a shared md */
				(void) snprintf(path, sizeof (path),
					"md/shared/%d/%s/d%d",
					set, dir, mdev);
			}
			(void) devfsadm_mklink(path, node, minor, 0);
		}
	}
	return (DEVFSADM_CONTINUE);
}
