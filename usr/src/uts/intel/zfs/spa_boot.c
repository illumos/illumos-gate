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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

#include <sys/zio.h>
#include <sys/spa.h>
#include <sys/sunddi.h>
#include <sys/x86_archext.h>

extern int zfs_deadman_enabled;

char *
spa_get_bootprop(char *propname)
{
	char *value;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, propname, &value) != DDI_SUCCESS)
		return (NULL);
	return (value);
}

void
spa_free_bootprop(char *value)
{
	ddi_prop_free(value);
}

void
spa_arch_init(void)
{
	/*
	 * Configure the default settings for the zfs deadman unless
	 * overriden by /etc/system.
	 */
	if (zfs_deadman_enabled == -1) {
		/*
		 * Disable the zfs deadman logic on VMware deployments.
		 */
		if (get_hwenv() == HW_VMWARE)
			zfs_deadman_enabled = 0;
		else
			zfs_deadman_enabled = 1;
	}
}
