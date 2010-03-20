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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * UID/SID mapping system call entries.
 */

#include "lint.h"
#include <sys/sid.h>
#include <sys/syscall.h>


int
allocids(int flag, int nuids, uid_t *suid, int ngids, gid_t *sgid)
{
	sysret_t rv;
	int e;

	e = __systemcall(&rv, SYS_sidsys, SIDSYS_ALLOC_IDS, flag, nuids, ngids);

	if (e != 0) {
		(void) __set_errno(e);
		return (-1);
	}

	if (suid != NULL)
		*suid = (uid_t)rv.sys_rval1;
	if (sgid != NULL)
		*sgid = (gid_t)rv.sys_rval2;

	return (0);
}

int
__idmap_reg(int fd)
{
	return (syscall(SYS_sidsys, SIDSYS_IDMAP_REG, fd));
}

int
__idmap_unreg(int fd)
{
	return (syscall(SYS_sidsys, SIDSYS_IDMAP_UNREG, fd));
}

int
__idmap_flush_kcache(void)
{
	return (syscall(SYS_sidsys, SIDSYS_IDMAP_FLUSH_KCACHE));
}
