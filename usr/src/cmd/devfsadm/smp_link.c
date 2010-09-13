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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <devfsadm.h>
#include <strings.h>
#include <stdlib.h>
#include <limits.h>
#include <bsm/devalloc.h>

#define	SMP_LINK_RE	"^smp/expd[0-9]+$"
#define	SMP_CLASS	"sas"
#define	SMP_DRV_NAME	"smp"

static int smp_callback(di_minor_t minor, di_node_t node);

static devfsadm_create_t smp_create_cbt[] = {
	{ SMP_CLASS, "ddi_sas_smp", SMP_DRV_NAME,
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, smp_callback
	}
};

DEVFSADM_CREATE_INIT_V0(smp_create_cbt);

/*
 * HOT auto cleanup of smp links not desired.
 */
static devfsadm_remove_t smp_remove_cbt[] = {
	{ SMP_CLASS, SMP_LINK_RE, RM_PRE,
		ILEVEL_0, devfsadm_rm_all
	}
};

DEVFSADM_REMOVE_INIT_V0(smp_remove_cbt);

/*
 * Create link for expander devices as form
 * dev/smp/expd0 -> ../../devices/pci@0,0/.../smp@w5001636000005aff:smp
 */
static int
smp_callback(di_minor_t minor, di_node_t node)
{
	char l_path[PATH_MAX + 1];
	char *buf;
	char *mn;
	char *devfspath;
	devfsadm_enumerate_t rules[1] = {"smp/expd([0-9]+)", 1, MATCH_ADDR};

	mn = di_minor_name(minor);

	devfspath = di_devfs_path(node);

	(void) strcpy(l_path, devfspath);
	(void) strcat(l_path, ":");
	(void) strcat(l_path, mn);

	di_devfs_path_free(devfspath);

	if (devfsadm_enumerate_int(l_path, 0, &buf, rules, 1)) {
		return (DEVFSADM_CONTINUE);
	}

	(void) strcpy(l_path, "smp/expd");
	(void) strcat(l_path, buf);
	free(buf);

	(void) devfsadm_mklink(l_path, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}
