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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak settaskid = _settaskid
#pragma weak gettaskid = _gettaskid
#pragma weak getprojid = _getprojid

#include "synonyms.h"
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
	    == -1 && errno == EINTR);

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
