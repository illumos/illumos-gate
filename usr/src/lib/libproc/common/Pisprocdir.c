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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "Pcontrol.h"

/*
 * Return TRUE iff dir is the /proc directory.
 */
int
Pisprocdir(struct ps_prochandle *Pr, const char *dir)
{
	char path[PATH_MAX];
	struct stat statb;
	struct statvfs statvfsb;

	if (*dir == '/')
		(void) snprintf(path, sizeof (path), "%s/%d/root%s",
		    procfs_path, (int)Pr->pid, dir);
	else
		(void) snprintf(path, sizeof (path), "%s/%d/cwd/%s",
		    procfs_path, (int)Pr->pid, dir);

	/*
	 * We can't compare the statb.st_fstype string to "proc" because
	 * a loop-back mount of /proc would show "lofs" instead of "proc".
	 * Instead we use the statvfs() f_basetype string.
	 */
	return (stat(path, &statb) == 0 &&
	    statvfs(path, &statvfsb) == 0 &&
	    (statb.st_mode & S_IFMT) == S_IFDIR &&
	    statb.st_ino == 2 &&
	    strcmp(statvfsb.f_basetype, "proc") == 0);
}
