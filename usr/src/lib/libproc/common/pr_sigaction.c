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
 * Copyright 1997-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/isa_defs.h>

#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <memory.h>
#include <errno.h>

#include "P32ton.h"
#include "libproc.h"

/*
 * sigaction() system call -- executed by subject process.
 */
int
pr_sigaction(struct ps_prochandle *Pr,
	int sig, const struct sigaction *act, struct sigaction *oact)
{
	sysret_t rval;			/* return value from sigaction() */
	argdes_t argd[3];		/* arg descriptors for sigaction() */
	argdes_t *adp;
	int error;
#ifdef _LP64
	struct sigaction32 act32;
	struct sigaction32 oact32;
#endif	/* _LP64 */

	if (Pr == NULL)		/* no subject process */
		return (sigaction(sig, act, oact));

	adp = &argd[0];		/* sig argument */
	adp->arg_value = sig;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* act argument */
	adp->arg_value = 0;
	if (act == NULL) {
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_INPUT;
		adp->arg_object = NULL;
		adp->arg_size = 0;
	} else {
		adp->arg_type = AT_BYREF;
		adp->arg_inout = AI_INPUT;
#ifdef _LP64
		if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32) {
			sigaction_n_to_32(act, &act32);
			adp->arg_object = &act32;
			adp->arg_size = sizeof (act32);
		} else {
			adp->arg_object = (void *)act;
			adp->arg_size = sizeof (*act);
		}
#else	/* _LP64 */
		adp->arg_object = (void *)act;
		adp->arg_size = sizeof (*act);
#endif	/* _LP64 */
	}

	adp++;			/* oact argument */
	adp->arg_value = 0;
	if (oact == NULL) {
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_INPUT;
		adp->arg_object = NULL;
		adp->arg_size = 0;
	} else {
		adp->arg_type = AT_BYREF;
		adp->arg_inout = AI_OUTPUT;
#ifdef _LP64
		if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32) {
			adp->arg_object = &oact32;
			adp->arg_size = sizeof (oact32);
		} else {
			adp->arg_object = oact;
			adp->arg_size = sizeof (*oact);
		}
#else	/* _LP64 */
		adp->arg_object = oact;
		adp->arg_size = sizeof (*oact);
#endif	/* _LP64 */
	}

	error = Psyscall(Pr, &rval, SYS_sigaction, 3, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return (-1);
	}
#ifdef _LP64
	if (oact != NULL && Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32)
		sigaction_32_to_n(&oact32, oact);
#endif	/* _LP64 */
	return (rval.sys_rval1);
}
