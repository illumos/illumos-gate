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

#pragma weak _settaskid = settaskid
#pragma weak _gettaskid = gettaskid
#pragma weak _getprojid = getprojid

#include "lint.h"
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/task.h>
#include <errno.h>
#include <project.h>

taskid_t
settaskid(projid_t project, uint_t flags)
{
	taskid_t newtaskid;

	while ((newtaskid = syscall(SYS_tasksys, 0, project, flags, NULL, 0))
	    == -1 && errno == EINTR)
		continue;

	return (newtaskid);
}

taskid_t
gettaskid(void)
{
	return ((taskid_t)syscall(SYS_tasksys, 1, 0, 0, NULL, 0));
}

projid_t
getprojid(void)
{
	return ((projid_t)syscall(SYS_tasksys, 2, 0, 0, NULL, 0));
}
