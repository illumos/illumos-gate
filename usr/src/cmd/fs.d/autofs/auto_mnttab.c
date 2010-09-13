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
 *	auto_mnttab.c
 *
 *	Copyright (c) 1988-1999 Sun Microsystems Inc
 *	All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/mnttab.h>
#include <sys/mkdev.h>
#include "automount.h"

static mutex_t mnttab_lock = DEFAULTMUTEX;

/*
 * XXX - Serialize calls to fsgetmntlist, so that threads can get consistent
 * snapshots of the in-kernel mnttab.  This function should be removed
 * once getextmntent is made MT-safe and callers can invoke fsgetmntlist
 * directly.
 */
struct mntlist *
getmntlist()
{
	struct mntlist *mntl;

	(void) mutex_lock(&mnttab_lock);
	mntl = fsgetmntlist();
	(void) mutex_unlock(&mnttab_lock);
	return (mntl);
}

/*
 * Return device number from extmnttab struct
 */
dev_t
get_devid(mnt)
	struct extmnttab *mnt;
{
	return (makedev(mnt->mnt_major, mnt->mnt_minor));
}
