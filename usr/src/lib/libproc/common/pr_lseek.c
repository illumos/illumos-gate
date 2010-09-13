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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "libproc.h"

typedef union {
	offset_t	full;		/* full 64 bit offset value */
	uint32_t	half[2];	/* two 32-bit halves */
} offsets_t;

/*
 * lseek() system call -- executed by subject process.
 */
off_t
pr_lseek(struct ps_prochandle *Pr, int filedes, off_t offset, int whence)
{
	int syscall;		/* SYS_lseek or SYS_llseek */
	int nargs;		/* 3 or 4, depending on syscall */
	offsets_t off;
	sysret_t rval;		/* return value from lseek() */
	argdes_t argd[4];	/* arg descriptors for lseek() */
	argdes_t *adp;
	int error;

	if (Pr == NULL)
		return (lseek(filedes, offset, whence));

	adp = &argd[0];		/* filedes argument */
	adp->arg_value = filedes;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* offset argument */
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_NATIVE) {
		syscall = SYS_lseek;
		nargs = 3;
		adp->arg_value = offset;
		adp->arg_object = NULL;
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = 0;
	} else {
		syscall = SYS_llseek;
		nargs = 4;
		off.full = offset;
		adp->arg_value = off.half[0];	/* first 32 bits */
		adp->arg_object = NULL;
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = 0;
		adp++;
		adp->arg_value = off.half[1];	/* second 32 bits */
		adp->arg_object = NULL;
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = 0;
	}

	adp++;			/* whence argument */
	adp->arg_value = whence;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, syscall, nargs, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return ((off_t)(-1));
	}

	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_NATIVE)
		offset = rval.sys_rval1;
	else {
		off.half[0] = (uint32_t)rval.sys_rval1;
		off.half[1] = (uint32_t)rval.sys_rval2;
		offset = (off_t)off.full;
	}

	return (offset);
}

/*
 * llseek() system call -- executed by subject process.
 */
offset_t
pr_llseek(struct ps_prochandle *Pr, int filedes, offset_t offset, int whence)
{
	int syscall;		/* SYS_lseek or SYS_llseek */
	int nargs;		/* 3 or 4, depending on syscall */
	offsets_t off;
	sysret_t rval;		/* return value from llseek() */
	argdes_t argd[4];	/* arg descriptors for llseek() */
	argdes_t *adp;
	int error;

	if (Pr == NULL)
		return (llseek(filedes, offset, whence));

	adp = &argd[0];		/* filedes argument */
	adp->arg_value = filedes;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* offset argument */
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_LP64) {
		syscall = SYS_lseek;
		nargs = 3;
		adp->arg_value = offset;
		adp->arg_object = NULL;
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = 0;
	} else {
		syscall = SYS_llseek;
		nargs = 4;
		off.full = offset;
		adp->arg_value = off.half[0];	/* first 32 bits */
		adp->arg_object = NULL;
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = 0;
		adp++;
		adp->arg_value = off.half[1];	/* second 32 bits */
		adp->arg_object = NULL;
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = 0;
	}

	adp++;			/* whence argument */
	adp->arg_value = whence;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, syscall, nargs, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return ((offset_t)(-1));
	}

	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_LP64)
		offset = rval.sys_rval1;
	else {
		off.half[0] = (uint32_t)rval.sys_rval1;
		off.half[1] = (uint32_t)rval.sys_rval2;
		offset = off.full;
	}

	return (offset);
}
