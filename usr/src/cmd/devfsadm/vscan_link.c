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

#include <devfsadm.h>
#include <strings.h>
#include <stdio.h>
#include <sys/vscan.h>

static int vscan(di_minor_t minor, di_node_t node);

static devfsadm_create_t vscan_create_cbt[] = {
	{ "pseudo", "ddi_pseudo", "vscan",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, vscan },
};
DEVFSADM_CREATE_INIT_V0(vscan_create_cbt);

static devfsadm_remove_t vscan_remove_cbt[] = {
	{ "vscan", "^vscan/vscan[0-9]+$", RM_HOT | RM_POST,
		ILEVEL_0, devfsadm_rm_all
	}
};
DEVFSADM_REMOVE_INIT_V0(vscan_remove_cbt);

static int
vscan(di_minor_t minor, di_node_t node)
{
	char *mname = di_minor_name(minor);
	char path[MAXPATHLEN];

	(void) snprintf(path, sizeof (path), "vscan/%s", mname);
	(void) devfsadm_mklink(path, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}
