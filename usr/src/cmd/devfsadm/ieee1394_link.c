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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <devfsadm.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

static int ieee1394_process(di_minor_t minor, di_node_t node);

static devfsadm_create_t ieee1394_cbt[] = {
	{ "ieee1394", "ddi_ctl:devctl", "hci1394",
		TYPE_EXACT | DRV_EXACT, ILEVEL_0, ieee1394_process
	},
};

static char *debug_mid = "ieee1394_mid";

DEVFSADM_CREATE_INIT_V0(ieee1394_cbt);

#define	IEEE1394_LINK_RE "^1394/hba[0-9]+$"

static devfsadm_remove_t ieee1394_remove_cbt[] = {
	{ "ieee1394", IEEE1394_LINK_RE, RM_HOT | RM_POST,
		ILEVEL_0, devfsadm_rm_all
	},
};

DEVFSADM_REMOVE_INIT_V0(ieee1394_remove_cbt);

int
minor_init(void)
{
	devfsadm_print(debug_mid, "ieee1394_link: minor_init\n");
	return (DEVFSADM_SUCCESS);
}

int
minor_fini(void)
{
	devfsadm_print(debug_mid, "ieee1394_link: minor_fini\n");
	return (DEVFSADM_SUCCESS);
}

/*
 * This function is called for every ieee1394 minor node.
 * Calls enumerate to assign a logical ieee1394 id, and then
 * devfsadm_mklink to make the link.
 */
static int
ieee1394_process(di_minor_t minor, di_node_t node)
{
	char *buf, *devfspath;
	char l_path[PATH_MAX], p_path[PATH_MAX];
	devfsadm_enumerate_t re[] = {"^1394/hba([0-9]+)$", 1, MATCH_ALL};

	devfspath = di_devfs_path(node);

	devfsadm_print(debug_mid,
		"ieee1394_process: path %s\n", devfspath);

	(void) snprintf(p_path, sizeof (p_path), "%s:%s",
		devfspath, di_minor_name(minor));
	di_devfs_path_free(devfspath);

	/*
	 *  Build the physical path from the components. Find the logical
	 *  ieee1394 HBA id, and stuff it in buf
	 */
	if (devfsadm_enumerate_int(p_path, 0, &buf, re, 1)) {
		devfsadm_print(debug_mid, "ieee1394_process: exit/continue\n");
		return (DEVFSADM_CONTINUE);
	}
	devfsadm_print(debug_mid, "ieee1394_process: p_path=%s buf=%s\n",
					p_path, buf);

	(void) snprintf(l_path, sizeof (l_path), "1394/hba%s", buf);

	free(buf);

	devfsadm_print(debug_mid, "mklink %s %s\n", l_path, p_path);

	(void) devfsadm_mklink(l_path, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}
