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

#pragma weak _getpgrp = getpgrp
#pragma weak _setpgrp = setpgrp
#pragma weak _getsid = getsid
#pragma weak _setsid = setsid
#pragma weak _getpgid = getpgid
#pragma weak _setpgid = setpgid

#include "lint.h"
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>

pid_t
getpgrp(void)
{
	return ((pid_t)syscall(SYS_pgrpsys, 0));
}

pid_t
setpgrp(void)
{
	return ((pid_t)syscall(SYS_pgrpsys, 1));
}

pid_t
getsid(pid_t pid)
{
	return ((pid_t)syscall(SYS_pgrpsys, 2, pid));
}

pid_t
setsid(void)
{
	return ((pid_t)syscall(SYS_pgrpsys, 3));
}

pid_t
getpgid(pid_t pid)
{
	return ((pid_t)syscall(SYS_pgrpsys, 4, pid));
}

int
setpgid(pid_t pid, pid_t pgid)
{
	return (syscall(SYS_pgrpsys, 5, pid, pgid));
}
