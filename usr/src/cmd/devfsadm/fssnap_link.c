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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <regex.h>
#include <devfsadm.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/fssnap_if.h>


static int fssnap(di_minor_t minor, di_node_t node);

static devfsadm_create_t fssnap_cbt[] = {
	{ "pseudo", "ddi_pseudo", SNAP_NAME,
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, fssnap,
	},
};

DEVFSADM_CREATE_INIT_V0(fssnap_cbt);

/*
 * For the master device:
 *	/dev/fssnapctl -> /devices/pseudo/fssnap@0:ctl
 * For each other device
 *	/dev/fssnap/1 -> /devices/pseudo/fssnap@0:1
 *	/dev/rfssnap/1 -> /devices/pseudo/fssnap@0:1,raw
 */
static int
fssnap(di_minor_t minor, di_node_t node)
{
	dev_t	dev;
	char mn[MAXNAMELEN + 1];
	char blkname[MAXNAMELEN + 1];
	char rawname[MAXNAMELEN + 1];
	char path[PATH_MAX + 1];

	(void) strcpy(mn, di_minor_name(minor));

	if (strcmp(mn, "ctl") == 0) {
		(void) devfsadm_mklink(SNAP_CTL_NAME, node, minor, 0);
	} else {
		dev = di_minor_devt(minor);
		(void) snprintf(blkname, sizeof (blkname), "%d",
		    (int)minor(dev));
		(void) snprintf(rawname, sizeof (rawname), "%d,raw",
		    (int)minor(dev));

		if (strcmp(mn, blkname) == 0) {
			(void) snprintf(path, sizeof (path), "%s/%s",
			    SNAP_BLOCK_NAME, blkname);
		} else if (strcmp(mn, rawname) == 0) {
			(void) snprintf(path, sizeof (path), "%s/%s",
			    SNAP_CHAR_NAME, blkname);
		} else {
			return (DEVFSADM_CONTINUE);
		}

		(void) devfsadm_mklink(path, node, minor, 0);
	}
	return (DEVFSADM_CONTINUE);
}
