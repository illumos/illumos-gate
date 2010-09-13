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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <regex.h>
#include <devfsadm.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <sys/ramdisk.h>

static int ramdisk(di_minor_t di_minor, di_node_t node);

/*
 * devfs create callback register
 */
static devfsadm_create_t ramdisk_create_cbt[] = {
	{ "pseudo", "ddi_pseudo", RD_DRIVER_NAME,
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, ramdisk,
	},
};
DEVFSADM_CREATE_INIT_V0(ramdisk_create_cbt);

/*
 * devfs cleanup register
 */
#define	RAMDISK_LINK_RE	"^r?ramdisk/.+$"

static devfsadm_remove_t ramdisk_remove_cbt[] = {
	{ "pseudo", RAMDISK_LINK_RE, RM_ALWAYS | RM_PRE | RM_HOT,
	    ILEVEL_0, devfsadm_rm_all},
};
DEVFSADM_REMOVE_INIT_V0(ramdisk_remove_cbt);

static char *debug_mid = "ramdisk_mid";

int
minor_init(void)
{
	devfsadm_print(debug_mid, "ramdisk_link: minor_init\n");
	return (DEVFSADM_SUCCESS);
}

int
minor_fini(void)
{
	devfsadm_print(debug_mid, "ramdisk_link: minor_fini\n");
	return (DEVFSADM_SUCCESS);
}

/*
 * This function is called for every ramdisk minor node.
 * Calls enumerate to assign a logical ramdisk id, and then
 * devfsadm_mklink to make the link.
 *
 * For pseudo ramdisk devices:
 *
 *	/dev/ramdiskctl      -> /devices/pseudo/ramdisk@0:ctl
 *	/dev/ramdisk/<name>  -> /devices/pseudo/ramdisk@0:<name>
 *	/dev/rramdisk/<name> -> /devices/pseudo/ramdisk@0:<name>,raw
 *
 * For OBP-created ramdisk devices:
 *
 *	/dev/ramdisk/<name>  -> /devices/ramdisk-<name>:a
 *	/dev/rramdisk/<name> -> /devices/ramdisk-<name>:a,raw
 */
static int
ramdisk(di_minor_t di_minor, di_node_t node)
{
	char	*name;
	char	devnm[MAXNAMELEN + 1];
	char	path[PATH_MAX];

	/*
	 * If this is an OBP-created ramdisk use the node name, having first
	 * stripped the "ramdisk-" prefix.  For pseudo ramdisks use the minor
	 * name, having first stripped any ",raw" suffix.
	 */
	if (di_nodeid(node) == DI_PROM_NODEID) {
		RD_STRIP_PREFIX(name, di_node_name(node));
		(void) strlcpy(devnm, name, sizeof (devnm));
	} else {
		(void) strlcpy(devnm, di_minor_name(di_minor), sizeof (devnm));
		RD_STRIP_SUFFIX(devnm);
	}

	if (strcmp(devnm, RD_CTL_NODE) == 0) {
		(void) devfsadm_mklink(RD_CTL_NAME, node, di_minor, 0);
	} else {
		/*
		 * Make the link in /dev/ramdisk or /dev/rramdisk.
		 */
		(void) snprintf(path, sizeof (path), "%s/%s",
		    di_minor_spectype(di_minor) == S_IFBLK ?
		    RD_BLOCK_NAME : RD_CHAR_NAME, devnm);
		(void) devfsadm_mklink(path, node, di_minor, 0);
	}

	return (DEVFSADM_CONTINUE);
}
