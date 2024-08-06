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

#include <sys/isa_defs.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include "libproc.h"

/*
 * fcntl() system call -- executed by subject process.
 */
int
pr_fcntl(struct ps_prochandle *Pr, int fd, int cmd, void *argp, void *argp1)
{
	sysret_t rval;			/* return value from fcntl() */
	argdes_t argd[4];		/* arg descriptors for fcntl() */
	argdes_t *adp;
	int error;

	if (Pr == NULL)		/* no subject process */
		return (fcntl(fd, cmd, argp));

	adp = &argd[0];		/* file descriptor argument */
	adp->arg_value = fd;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* cmd argument */
#ifdef _LP64
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32) {
		/*
		 * Guilty knowledge of the large file compilation environment
		 */
		switch (cmd) {
		case F_GETLK:
			cmd = 33;
			break;
		case F_SETLK:
			cmd = 34;
			break;
		case F_SETLKW:
			cmd = 35;
			break;
		case F_FREESP:
			cmd = 27;
			break;
		}
	}
#endif	/* _LP64 */
	adp->arg_value = cmd;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* argp argument */
	if (argp == NULL) {
		adp->arg_value = 0;
		adp->arg_object = NULL;
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = 0;
	} else {
		adp->arg_value = 0;
		adp->arg_object = argp;
		adp->arg_type = AT_BYREF;
		adp->arg_inout = AI_INOUT;
		switch (cmd) {
		case F_GETLK:
		case F_SETLK:
		case F_SETLKW:
		case F_ALLOCSP:
		case F_FREESP:
			adp->arg_size = sizeof (struct flock);
			break;
#ifdef _LP64
		case 33:
		case 34:
		case 35:
		case 27:
			adp->arg_size = sizeof (struct flock64_32);
#else	/* _LP64 */
		case F_GETLK64:
		case F_SETLK64:
		case F_SETLKW64:
		case F_FREESP64:
			adp->arg_size = sizeof (struct flock64);
#endif	/* _LP64 */
			break;
		case F_SHARE:
		case F_UNSHARE:
			adp->arg_size = sizeof (struct fshare);
			break;
		default:
			adp->arg_value = (long)argp;
			adp->arg_object = NULL;
			adp->arg_type = AT_BYVAL;
			adp->arg_inout = AI_INPUT;
			adp->arg_size = 0;
			break;
		}
	}

	adp++;			/* argp1 argument */
	adp->arg_value = (intptr_t)argp1;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, SYS_fcntl, 4, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return (-1);
	}
	return (rval.sys_rval1);
}
