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

#include <sys/isa_defs.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "libproc.h"

/*
 * getitimer() system call -- executed by victim process.
 */
int
pr_getitimer(struct ps_prochandle *Pr, int which, struct itimerval *itv)
{
	sysret_t rval;		/* return value from getitimer() */
	argdes_t argd[2];	/* arg descriptors for getitimer() */
	argdes_t *adp;
	int error;
#ifdef _LP64
	int victim32 = (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32);
	struct itimerval32 itimerval32;
#endif

	if (Pr == NULL)		/* no victim process */
		return (getitimer(which, itv));

	adp = &argd[0];		/* which argument */
	adp->arg_value = which;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_object = NULL;
	adp->arg_size = 0;

	adp++;			/* itv argument */
	adp->arg_value = 0;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_OUTPUT;
#ifdef _LP64
	if (victim32) {
		adp->arg_object = &itimerval32;
		adp->arg_size = sizeof (itimerval32);
	} else {
		adp->arg_object = itv;
		adp->arg_size = sizeof (*itv);
	}
#else	/* _LP64 */
	adp->arg_object = itv;
	adp->arg_size = sizeof (*itv);
#endif	/* _LP64 */

	error = Psyscall(Pr, &rval, SYS_getitimer, 2, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return (-1);
	}
#ifdef _LP64
	if (victim32) {
		ITIMERVAL32_TO_ITIMERVAL(itv, &itimerval32);
	}
#endif	/* _LP64 */
	return (rval.sys_rval1);
}

/*
 * setitimer() system call -- executed by victim process.
 */
int
pr_setitimer(struct ps_prochandle *Pr,
	int which, const struct itimerval *itv, struct itimerval *oitv)
{
	sysret_t rval;		/* return value from setitimer() */
	argdes_t argd[3];	/* arg descriptors for setitimer() */
	argdes_t *adp;
	int error;
#ifdef _LP64
	int victim32 = (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32);
	struct itimerval32 itimerval32;
	struct itimerval32 oitimerval32;
#endif	/* _LP64 */

	if (Pr == NULL)		/* no victim process */
		return (setitimer(which, (struct itimerval *)itv, oitv));

	adp = &argd[0];		/* which argument */
	adp->arg_value = which;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_object = NULL;
	adp->arg_size = 0;

	adp++;			/* itv argument */
	adp->arg_value = 0;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_INPUT;
#ifdef _LP64
	if (victim32) {
		ITIMERVAL_TO_ITIMERVAL32(&itimerval32, itv);
		adp->arg_object = (void *)&itimerval32;
		adp->arg_size = sizeof (itimerval32);
	} else {
		adp->arg_object = (void *)itv;
		adp->arg_size = sizeof (*itv);
	}
#else	/* _LP64 */
	adp->arg_object = (void *)itv;
	adp->arg_size = sizeof (*itv);
#endif	/* _LP64 */

	adp++;			/* oitv argument */
	adp->arg_value = 0;
	if (oitv == NULL) {
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_INPUT;
		adp->arg_object = NULL;
		adp->arg_size = 0;
	} else {
		adp->arg_type = AT_BYREF;
		adp->arg_inout = AI_OUTPUT;
#ifdef _LP64
		if (victim32) {
			adp->arg_object = (void *)&oitimerval32;
			adp->arg_size = sizeof (oitimerval32);
		} else {
			adp->arg_object = oitv;
			adp->arg_size = sizeof (*oitv);
		}
#else	/* _LP64 */
		adp->arg_object = oitv;
		adp->arg_size = sizeof (*oitv);
#endif	/* _LP64 */
	}

	error = Psyscall(Pr, &rval, SYS_setitimer, 3, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return (-1);
	}
#ifdef _LP64
	if (victim32 && oitv != NULL) {
		ITIMERVAL32_TO_ITIMERVAL(oitv, &oitimerval32);
	}
#endif	/* _LP64 */
	return (rval.sys_rval1);
}
