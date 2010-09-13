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
 * Copyright (c) 1997-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include "libproc.h"

/*
 * mmap() system call -- executed by subject process
 */
void *
pr_mmap(struct ps_prochandle *Pr,
	void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
	sysret_t rval;			/* return value from mmap() */
	argdes_t argd[6];		/* arg descriptors for mmap() */
	argdes_t *adp;
	int error;

	if (Pr == NULL)		/* no subject process */
		return (mmap(addr, len, prot, flags, fd, off));

	adp = &argd[0];		/* addr argument */
	adp->arg_value = (long)addr;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* len argument */
	adp->arg_value = (long)len;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* prot argument */
	adp->arg_value = (long)prot;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* flags argument */
	adp->arg_value = (long)(_MAP_NEW|flags);
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* fd argument */
	adp->arg_value = (long)fd;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* off argument */
	adp->arg_value = (long)off;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, SYS_mmap, 6, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return ((void *)(-1));
	}
	return ((void *)rval.sys_rval1);
}

/*
 * munmap() system call -- executed by subject process
 */
int
pr_munmap(struct ps_prochandle *Pr, void *addr, size_t len)
{
	sysret_t rval;			/* return value from munmap() */
	argdes_t argd[2];		/* arg descriptors for munmap() */
	argdes_t *adp;
	int error;

	if (Pr == NULL)		/* no subject process */
		return (munmap(addr, len));

	adp = &argd[0];		/* addr argument */
	adp->arg_value = (long)addr;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* len argument */
	adp->arg_value = (long)len;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, SYS_munmap, 2, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return (-1);
	}
	return (rval.sys_rval1);
}

/*
 * zmap() -- convenience function; mmap(MAP_ANON) executed by subject process.
 */
void *
pr_zmap(struct ps_prochandle *Pr, void *addr, size_t len, int prot, int flags)
{
	return (pr_mmap(Pr, addr, len, prot, flags | MAP_ANON, -1, (off_t)0));
}
