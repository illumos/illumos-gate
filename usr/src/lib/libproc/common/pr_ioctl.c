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
#include <sys/types.h>
#include "libproc.h"

/*
 * ioctl() system call -- executed by subject process.
 */
int
pr_ioctl(struct ps_prochandle *Pr, int fd, int code, void *buf, size_t size)
{
	sysret_t rval;			/* return value from ioctl() */
	argdes_t argd[3];		/* arg descriptors for ioctl() */
	argdes_t *adp = &argd[0];	/* first argument */
	int error;

	if (Pr == NULL)		/* no subject process */
		return (ioctl(fd, code, buf));

	adp->arg_value = fd;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;			/* move to code argument */

	adp->arg_value = code;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;			/* move to buffer argument */

	if (size == 0) {
		adp->arg_value = (long)buf;
		adp->arg_object = NULL;
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = 0;
	} else {
		adp->arg_value = 0;
		adp->arg_object = buf;
		adp->arg_type = AT_BYREF;
		adp->arg_inout = AI_INOUT;
		adp->arg_size = size;
	}

	error = Psyscall(Pr, &rval, SYS_ioctl, 3, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return (-1);
	}
	return (rval.sys_rval1);
}
