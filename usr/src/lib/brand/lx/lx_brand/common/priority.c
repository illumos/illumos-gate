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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <errno.h>
#include <sys/types.h>
#include <sys/lx_debug.h>
#include <sys/lx_misc.h>
#include <sys/lx_syscall.h>
#include <sys/lx_types.h>
#include <sys/resource.h>
#include <sys/lx_misc.h>

long
lx_getpriority(uintptr_t p1, uintptr_t p2)
{
	int	which = (int)p1;
	id_t	who  = (id_t)p2;
	int	ret;

	/*
	 * The only valid values for 'which' are positive integers, and unlike
	 * Solaris, linux doesn't support anything past PRIO_USER.
	 */
	if (which < 0 || which > PRIO_USER)
		return (-EINVAL);

	lx_debug("\tgetpriority(%d, %d)", which, who);

	errno = 0;

	if ((which == PRIO_PROCESS) && (who == 1))
		who = zoneinit_pid;

	ret = getpriority(which, who);
	if (ret == -1 && errno != 0) {
		/*
		 * Linux does not return EINVAL for invalid 'who' values, it
		 * returns ESRCH instead. We already validated 'which' above.
		 */
		if (errno == EINVAL)
			errno = ESRCH;
		return (-errno);
	}

	/*
	 * The return value of the getpriority syscall is biased by 20 to avoid
	 * returning negative values when successful.
	 */
	return (20 - ret);
}

long
lx_setpriority(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int which = (int)p1;
	id_t who  = (id_t)p2;
	int prio  = (int)p3;
	int rval;

	if (which > PRIO_USER)
		return (-EINVAL);

	lx_debug("\tsetpriority(%d, %d, %d)", which, who, prio);

	if ((which == PRIO_PROCESS) && (who == 1))
		who = zoneinit_pid;

	rval = setpriority(which, who, prio);

	return ((rval == -1) ? -errno : rval);
}
