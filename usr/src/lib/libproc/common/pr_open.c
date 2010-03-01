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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include "libproc.h"

/*
 * open() system call -- executed by subject process.
 */
int
pr_open(struct ps_prochandle *Pr, const char *filename, int flags, mode_t mode)
{
	sysret_t rval;			/* return value from openat() */
	argdes_t argd[4];		/* arg descriptors for openat() */
	argdes_t *adp;
	int error;

	if (Pr == NULL)		/* no subject process */
		return (open(filename, flags, mode));

	adp = &argd[0];		/* AT_FDCWD argument */
	adp->arg_value = AT_FDCWD;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* filename argument */
	adp->arg_value = 0;
	adp->arg_object = (void *)filename;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = strlen(filename)+1;

	adp++;			/* flags argument */
	adp->arg_value = (long)flags;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* mode argument */
	adp->arg_value = (long)mode;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, SYS_openat, 4, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return (-1);
	}
	return (rval.sys_rval1);
}

/*
 * creat() system call -- executed by subject process.
 */
int
pr_creat(struct ps_prochandle *Pr, const char *filename, mode_t mode)
{
	sysret_t rval;			/* return value from openat() */
	argdes_t argd[4];		/* arg descriptors for openat() */
	argdes_t *adp;
	int error;

	if (Pr == NULL)		/* no subject process */
		return (creat(filename, mode));

	adp = &argd[0];		/* AT_FDCWD argument */
	adp->arg_value = AT_FDCWD;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* filename argument */
	adp->arg_value = 0;
	adp->arg_object = (void *)filename;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = strlen(filename)+1;

	adp++;			/* flags argument */
	adp->arg_value = (O_WRONLY | O_CREAT | O_TRUNC);
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* mode argument */
	adp->arg_value = (long)mode;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, SYS_openat, 4, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return (-1);
	}
	return (rval.sys_rval1);
}

/*
 * close() system call -- executed by subject process.
 */
int
pr_close(struct ps_prochandle *Pr, int fd)
{
	sysret_t rval;			/* return value from close() */
	argdes_t argd[1];		/* arg descriptors for close() */
	argdes_t *adp;
	int error;

	if (Pr == NULL)		/* no subject process */
		return (close(fd));

	adp = &argd[0];		/* fd argument */
	adp->arg_value = (int)fd;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, SYS_close, 1, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return (-1);
	}
	return (rval.sys_rval1);
}

/*
 * access() system call -- executed by subject process.
 */
int
pr_access(struct ps_prochandle *Pr, const char *path, int amode)
{
	sysret_t rval;			/* return from access() */
	argdes_t argd[4];		/* arg descriptors for access() */
	argdes_t *adp;
	int err;

	if (Pr == NULL)		/* no subject process */
		return (access(path, amode));

	adp = &argd[0];		/* directory fd argument */
	adp->arg_value = AT_FDCWD;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* path argument */
	adp->arg_value = 0;
	adp->arg_object = (void *)path;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = strlen(path) + 1;

	adp++;			/* amode argument */
	adp->arg_value = (long)amode;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* flag argument */
	adp->arg_value = 0;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	err = Psyscall(Pr, &rval, SYS_faccessat, 4, &argd[0]);

	if (err) {
		errno = (err > 0) ? err : ENOSYS;
		return (-1);
	}

	return (rval.sys_rval1);
}
