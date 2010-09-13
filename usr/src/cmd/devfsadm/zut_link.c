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

#include <regex.h>
#include <devfsadm.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/mkdev.h>
#include <sys/fs/zut.h>

/* zfs unit test driver */

static int zut(di_minor_t minor, di_node_t node);

/*
 * devfs create callback register
 */
static devfsadm_create_t zut_create_cbt[] = {
	{ "pseudo", "ddi_pseudo", ZUT_DRIVER,
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, zut,
	},
};
DEVFSADM_CREATE_INIT_V0(zut_create_cbt);

/*
 * For the zut control node:
 *	/dev/zut -> /devices/pseudo/zut@0:zut
 */
static int
zut(di_minor_t minor, di_node_t node)
{
	if (strcmp(di_minor_name(minor), ZUT_DRIVER) == 0)
		(void) devfsadm_mklink(ZUT_DRIVER, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}
