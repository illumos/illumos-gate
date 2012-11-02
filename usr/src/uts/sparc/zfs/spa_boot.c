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
#include <sys/bootconf.h>

extern int zfs_deadman_enabled;

char *
spa_get_bootprop(char *propname)
{
	int proplen;
	char *value;

	proplen = BOP_GETPROPLEN(bootops, propname);
	if (proplen <= 0)
		return (NULL);

	value = kmem_zalloc(proplen, KM_SLEEP);
	if (BOP_GETPROP(bootops, propname, value) == -1) {
		kmem_free(value, proplen);
		return (NULL);
	}

	return (value);
}

void
spa_free_bootprop(char *propname)
{
	kmem_free(propname, strlen(propname) + 1);
}

void
spa_arch_init(void)
{
	/*
	 * The deadman is disabled by default on sparc.
	 */
	if (zfs_deadman_enabled == -1)
		zfs_deadman_enabled = 0;
}
