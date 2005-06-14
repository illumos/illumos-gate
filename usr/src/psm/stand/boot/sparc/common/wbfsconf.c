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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/boothsfs.h>
#include <sys/bootufs.h>
#include <sys/bootvfs.h>

struct boot_fs_ops *boot_fsw[] = {
	&boot_ufs_ops,
	&boot_hsfs_ops
};

int boot_nfsw = sizeof (boot_fsw) / sizeof (boot_fsw[0]);

char *systype;

static char *ufsname = "ufs";
static char *hsfsname = "hsfs";

int
determine_fstype_and_mountroot(char *path)
{
	set_default_fs(ufsname);
	if (mountroot(path) == VFS_SUCCESS) {
		systype = ufsname;
		return (VFS_SUCCESS);
	}

	set_default_fs(hsfsname);
	if (mountroot(path) == VFS_SUCCESS) {
		systype = hsfsname;
		return (VFS_SUCCESS);
	}
	clr_default_fs();

	return (VFS_FAILURE);
}
