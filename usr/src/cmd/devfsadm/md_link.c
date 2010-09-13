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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <meta.h>
#include <regex.h>
#include <devfsadm.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/mkdev.h>
#include <sdssc.h>

#define	MD_LINK_RE_DEVICES	"^md/r?dsk/.+$"
#define	MD_LINK_RE_SHARED	"^md/shared/[0-9]+/r?dsk/.+$"
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
 * minor_fini - module cleanup routine
 */
int
minor_fini(void)
{
	metarpccloseall();
	return (DEVFSADM_SUCCESS);
}

/*
 * For the admin device:
 *	/dev/md/admin -> /devices/pseudo/md@0:admin
 *
 * For metadevice:
 *	/dev/md/dsk/foobar --> /devices/pseudo/md@0:0,100,blk
 *	/dev/md/rdsk/foobar --> /devices/pseudo/md@0:0,100,raw
 *
 * Where 'foobar' is user specified arbitrary name and '100'
 * is the minor number returned by MD_IOCMAKE_DEV ioctl
 *
 */
static int
md_create(di_minor_t minor, di_node_t node)
{
	char mn[MAXNAMELEN + 1];
	char path[PATH_MAX + 1];
	char set_path[PATH_MAX +1];
	char sym_path[PATH_MAX + 1];
	int set = -1, ret;
	char *type, *dir;
	char *device_name;
	dev_t minor_devt = di_minor_devt(minor);
	int key;
	mdsetname_t	*sp = NULL;
	md_error_t ep;

	/*
	 * Initialize sdssc entry points. Don't worry about the return
	 * value here since the interface functions will get initialized
	 * correctly regardless.
	 */
	(void) sdssc_bind_library();

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
		ret = sscanf(mn, "%d,", &set);
		if (ret == 1 && (type = strrchr(mn, ',')) != NULL) {
			type++;
			if (strcmp(type, "blk") == 0) {
				dir = "dsk";
			} else {
				dir = "rdsk";
			}

			(void) memset(&ep, '\0', sizeof (ep));
			if ((device_name = meta_getnmentbydev(set,
			    MD_SIDEWILD, minor_devt, NULL, NULL,
			    &key, &ep)) == NULL) {
				(void) close_admin(&ep);
				return (DEVFSADM_CONTINUE);
			}

			if (set == 0) {
				/* this is a simple md */
				(void) snprintf(path, sizeof (path),
				    "md/%s/%s", dir, basename(device_name));
			} else {
				/* this is a shared md */
				(void) snprintf(path, sizeof (path),
				    "md/shared/%d/%s/%s", set, dir,
				    basename(device_name));

				/*
				 * flush the caches so the next call to
				 * metasetnosetname will get us the
				 * updated cache.
				 */
				metaflushnames(0);
				if ((sp = metasetnosetname(set, &ep))
				    != NULL) {
					(void) snprintf(set_path,
					    sizeof (set_path), "md/shared/%d",
					    sp->setno);
					(void) snprintf(sym_path,
					    sizeof (sym_path), "md/%s",
					    sp->setname);
				}
			}
			(void) devfsadm_mklink(path, node, minor, 0);
			Free(device_name);

			if (sp != NULL) {
				(void) devfsadm_secondary_link(sym_path,
				    set_path, 0);
			}
		}
	}

	(void) close_admin(&ep);
	return (DEVFSADM_CONTINUE);
}
