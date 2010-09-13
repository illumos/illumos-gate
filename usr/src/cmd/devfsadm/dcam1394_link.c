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

#include "devfsadm.h"
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#define	DCAM_RE_STRING_LEN	64

#define	DCAM_STR_LINK_RE	"^dcam([0-9]+)$"
#define	DCAM_CTL_LINK_RE	"^dcamctl([0-9]+)$"

static int dcam1394_process(di_minor_t minor, di_node_t node);

static devfsadm_create_t dcam1394_cbt[] = {
	{
		"firewire",
		NULL,
		"dcam",
		DRV_RE,
		ILEVEL_0,
		dcam1394_process
	}
};

static char *debug_mid = "dcam1394_mid";

DEVFSADM_CREATE_INIT_V0(dcam1394_cbt);


static devfsadm_remove_t dcam1394_remove_cbt[] = {
	{
		"firewire",
		DCAM_STR_LINK_RE,
		RM_PRE | RM_HOT | RM_ALWAYS,
		ILEVEL_0,
		devfsadm_rm_all
	},
	{
		"firewire",
		DCAM_CTL_LINK_RE,
		RM_PRE | RM_HOT | RM_ALWAYS,
		ILEVEL_0,
		devfsadm_rm_all
	}
};

DEVFSADM_REMOVE_INIT_V0(dcam1394_remove_cbt);

int
minor_init(void)
{
	devfsadm_print(debug_mid, "dcam1394_link: minor_init\n");
	return (DEVFSADM_SUCCESS);
}

int
minor_fini(void)
{
	devfsadm_print(debug_mid, "dcam1394_link: minor_fini\n");
	return (DEVFSADM_SUCCESS);
}


/*
 * This function is called for every dcam1394 minor node.
 * Calls enumerate to assign a logical dcam1394 id, and then
 * devfsadm_mklink to make the link.
 */
static int
dcam1394_process(di_minor_t minor, di_node_t node)
{
	char m_name[PATH_MAX], restring0[DCAM_RE_STRING_LEN];
	char l_path[PATH_MAX], p_path[PATH_MAX], *buf, *devfspath;
	devfsadm_enumerate_t re[1];

	(void) strcpy(m_name, di_minor_name(minor));

	if (strcmp(di_driver_name(node), "dcam1394") != 0) {
	    return (DEVFSADM_CONTINUE);
	}

	if (strncmp(m_name, "dcamctl", 7) == 0) {
		(void) snprintf(restring0, DCAM_RE_STRING_LEN,
				DCAM_CTL_LINK_RE);
	} else if (strncmp(m_name, "dcam", 4) == 0) {
		(void) snprintf(restring0, DCAM_RE_STRING_LEN,
				DCAM_STR_LINK_RE);
	} else {
		return (DEVFSADM_CONTINUE);
	}

	re[0].re	= restring0;
	re[0].subexp	= 1;
	re[0].flags	= MATCH_ALL;

	devfsadm_print(debug_mid,
	    "dcam1394_process: path %s\n", di_devfs_path(node));

	(void) strcpy(p_path, devfspath = di_devfs_path(node));
	(void) strcat(p_path, ":");
	(void) strcat(p_path, di_minor_name(minor));
	di_devfs_path_free(devfspath);

	/*
	 * Build the physical path from the components, omitting
	 * minor name field.  Find the logical dcam1394 id, and
	 * stuff it in buf.
	 */
	if (devfsadm_enumerate_int(p_path, 0, &buf, re, 1)) {
		devfsadm_print(debug_mid,
		    "dcam1394_process: exit/continue\n");
		return (DEVFSADM_CONTINUE);
	}

	devfsadm_print(debug_mid, "dcam1394_process: p_path=%s buf=%s\n",
	    p_path, buf);

	if (strncmp(di_minor_name(minor), "dcamctl", 7) == 0)
		(void) snprintf(l_path, PATH_MAX, "dcamctl%s", buf);
	else
		(void) snprintf(l_path, PATH_MAX, "dcam%s", buf);

	(void) devfsadm_mklink(l_path, node, minor, 0);

	free(buf);

	return (DEVFSADM_CONTINUE);
}
