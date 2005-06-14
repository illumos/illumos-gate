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
 * Copyright (c) 1998-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/isa_defs.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include "libproc.h"

#ifdef _LP64
static void
statvfs_32_to_n(statvfs32_t *src, statvfs_t *dest)
{
	dest->f_bsize = src->f_bsize;
	dest->f_frsize = src->f_frsize;
	dest->f_blocks = src->f_blocks;
	dest->f_bfree = src->f_bfree;
	dest->f_bavail = src->f_bavail;
	dest->f_files = src->f_files;
	dest->f_ffree = src->f_ffree;
	dest->f_favail = src->f_favail;
	dest->f_fsid = src->f_fsid;
	(void) memcpy(dest->f_basetype, src->f_basetype,
		sizeof (dest->f_basetype));
	dest->f_flag = src->f_flag;
	dest->f_namemax = src->f_namemax;
	(void) memcpy(dest->f_fstr, src->f_fstr,
		sizeof (dest->f_fstr));
}
#endif	/* _LP64 */

/*
 * statvfs() system call -- executed by subject process
 */
int
pr_statvfs(struct ps_prochandle *Pr, const char *path, statvfs_t *buf)
{
	sysret_t rval;			/* return value from statvfs() */
	argdes_t argd[2];		/* arg descriptors for statvfs() */
	argdes_t *adp = &argd[0];	/* first argument */
	int error;
#ifdef _LP64
	statvfs32_t statvfs32;
#endif	/* _LP64 */

	if (Pr == NULL)		/* no subject process */
		return (statvfs(path, buf));

	adp->arg_value = 0;
	adp->arg_object = (void *)path;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = strlen(path)+1;
	adp++;			/* move to buffer argument */

	adp->arg_value = 0;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_OUTPUT;
#ifdef _LP64
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32) {
		adp->arg_object = &statvfs32;
		adp->arg_size = sizeof (statvfs32);
	} else {
		adp->arg_object = buf;
		adp->arg_size = sizeof (*buf);
	}
#else	/* _LP64 */
	adp->arg_object = buf;
	adp->arg_size = sizeof (*buf);
#endif	/* _LP64 */

	error = Psyscall(Pr, &rval, SYS_statvfs, 2, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return (-1);
	}
#ifdef _LP64
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32)
		statvfs_32_to_n(&statvfs32, buf);
#endif	/* _LP64 */
	return (0);
}

/*
 * fstatvfs() system call -- executed by subject process
 */
int
pr_fstatvfs(struct ps_prochandle *Pr, int fd, statvfs_t *buf)
{
	sysret_t rval;			/* return value from fstatvfs() */
	argdes_t argd[2];		/* arg descriptors for fstatvfs() */
	argdes_t *adp = &argd[0];	/* first argument */
	int error;
#ifdef _LP64
	statvfs32_t statvfs32;
#endif	/* _LP64 */

	if (Pr == NULL)		/* no subject process */
		return (fstatvfs(fd, buf));

	adp->arg_value = fd;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;			/* move to buffer argument */

	adp->arg_value = 0;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_OUTPUT;
#ifdef _LP64
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32) {
		adp->arg_object = &statvfs32;
		adp->arg_size = sizeof (statvfs32);
	} else {
		adp->arg_object = buf;
		adp->arg_size = sizeof (*buf);
	}
#else	/* _LP64 */
	adp->arg_object = buf;
	adp->arg_size = sizeof (*buf);
#endif	/* _LP64 */

	error = Psyscall(Pr, &rval, SYS_fstatvfs, 2, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return (-1);
	}
#ifdef _LP64
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32)
		statvfs_32_to_n(&statvfs32, buf);
#endif	/* _LP64 */
	return (0);
}
