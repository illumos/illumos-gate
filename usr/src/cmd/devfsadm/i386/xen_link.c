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

#include <regex.h>
#include <devfsadm.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/privcmd_impl.h>
#include <sys/domcaps_impl.h>
#include <sys/balloon.h>

/*
 * Handle miscellaneous children of xendev
 */
static int devxen(di_minor_t, di_node_t);
static int xdt(di_minor_t minor, di_node_t node);

static devfsadm_create_t xen_cbt[] = {
	{ "xendev", DDI_PSEUDO, "xenbus",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, devxen,
	},
	{ "xendev", DDI_PSEUDO, PRIVCMD_DRIVER_NAME,
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, devxen,
	},
	{ "xendev", DDI_PSEUDO, "evtchn",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, devxen,
	},
	{ "xendev", DDI_PSEUDO, DOMCAPS_DRIVER_NAME,
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, devxen,
	},
	{ "xendev", DDI_PSEUDO, BALLOON_DRIVER_NAME,
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, devxen,
	},
	{ "pseudo", DDI_PSEUDO, "xdt",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, xdt
	},
};

DEVFSADM_CREATE_INIT_V0(xen_cbt);

static devfsadm_remove_t xen_remove_cbt[] = {
	{ "xendev", "^" "xen/xenbus" "$", RM_ALWAYS | RM_PRE | RM_HOT,
	    ILEVEL_0, devfsadm_rm_all
	},
	{ "xendev", "^" PRIVCMD_PATHNAME "$", RM_ALWAYS | RM_PRE | RM_HOT,
	    ILEVEL_0, devfsadm_rm_all
	},
	{ "xendev", "^" "xen/evtchn" "$", RM_ALWAYS | RM_PRE | RM_HOT,
	    ILEVEL_0, devfsadm_rm_all
	},
	{ "xendev", "^" DOMCAPS_PATHNAME "$", RM_ALWAYS | RM_PRE | RM_HOT,
	    ILEVEL_0, devfsadm_rm_all
	},
	{ "xendev", "^" BALLOON_PATHNAME "$", RM_ALWAYS | RM_PRE | RM_HOT,
	    ILEVEL_0, devfsadm_rm_all
	},
};

DEVFSADM_REMOVE_INIT_V0(xen_remove_cbt);

/*
 * /dev/xen/<foo>	->	/devices/xendev/<whatever>:<foo>
 */
static int
devxen(di_minor_t minor, di_node_t node)
{
	char buf[256];

	(void) snprintf(buf, sizeof (buf), "xen/%s", di_minor_name(minor));
	(void) devfsadm_mklink(buf, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}

static int
xdt(di_minor_t minor, di_node_t node)
{
	char *mname = di_minor_name(minor);
	char path[MAXPATHLEN];

	(void) snprintf(path, sizeof (path), "dtrace/provider/%s", mname);
	(void) devfsadm_mklink(path, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}
