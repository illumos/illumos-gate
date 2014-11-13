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

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/lx_misc.h>
#include <sys/lx_syscall.h>

long
lx_getpgrp(void)
{
	int ret;

	ret = getpgrp();

	/*
	 * If the pgrp is that of the init process, return the value Linux
	 * expects.
	 */
	if (ret == zoneinit_pid)
		return (LX_INIT_PGID);

	return ((ret == -1) ? -errno : ret);
}

long
lx_getpgid(uintptr_t p1)
{
	pid_t spid;
	int pid = (int)p1;
	int ret;

	if (pid < 0)
		return (-ESRCH);

	/*
	 * If the supplied pid matches that of the init process, return
	 * the pgid Linux expects.
	 */
	if (pid == zoneinit_pid)
		return (LX_INIT_PGID);

	if ((ret = lx_lpid_to_spid(pid, &spid)) < 0)
		return (ret);

	ret = getpgid(spid);

	/*
	 * If the pgid is that of the init process, return the value Linux
	 * expects.
	 */
	if (ret == zoneinit_pid)
		return (LX_INIT_PGID);

	return ((ret == -1) ? -errno : ret);
}

long
lx_setpgid(uintptr_t p1, uintptr_t p2)
{
	pid_t pid = (pid_t)p1;
	pid_t pgid = (pid_t)p2;
	pid_t spid, spgid;
	int ret;

	if (pid < 0)
		return (-ESRCH);

	if (pgid < 0)
		return (-EINVAL);

	if ((ret = lx_lpid_to_spid(pid, &spid)) < 0)
		return (ret);

	if (pgid == 0)
		spgid = spid;
	else if ((ret = lx_lpid_to_spid(pgid, &spgid)) < 0)
		return (ret);

	ret = setpgid(spid, spgid);

	if (ret != 0 && errno == EPERM) {
		/*
		 * On Linux, calling setpgid with a desired pgid that is equal
		 * to the current pgid of the process, no error is emitted.
		 * This differs slightly from illumos which will return EPERM.
		 *
		 * To emulate the Linux behavior, we check specifically for
		 * matching pgids if an EPERM is encountered.
		 */
		if (spgid == getpgid(spid))
			return (0);
		else
			return (-EPERM);
	}

	return ((ret == 0) ? 0 : -errno);
}

long
lx_getsid(uintptr_t p1)
{
	pid_t spid;
	int pid = (int)p1;
	int ret;

	if (pid < 0)
		return (-ESRCH);

	/*
	 * If the supplied matches that of the init process, return the value
	 * Linux expects.
	 */
	if (pid == zoneinit_pid)
		return (LX_INIT_SID);

	if ((ret = lx_lpid_to_spid(pid, &spid)) < 0)
		return (ret);

	ret = getsid(spid);

	/*
	 * If the sid is that of the init process, return the value Linux
	 * expects.
	 */
	if (ret == zoneinit_pid)
		return (LX_INIT_SID);

	return ((ret == -1) ? -errno : ret);
}

long
lx_setsid(void)
{
	int ret;

	ret = setsid();

	/*
	 * If the pgid is that of the init process, return the value Linux
	 * expects.
	 */
	if (ret == zoneinit_pid)
		return (LX_INIT_SID);

	return ((ret == -1) ? -errno : ret);
}
