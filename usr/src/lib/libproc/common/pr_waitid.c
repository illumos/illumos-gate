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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/isa_defs.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "P32ton.h"
#include "libproc.h"

/*
 * waitid() system call -- executed by subject process
 */
int
pr_waitid(struct ps_prochandle *Pr,
    idtype_t idtype, id_t id, siginfo_t *infop, int options)
{
	sysret_t rval;			/* return value from waitid() */
	argdes_t argd[4];		/* arg descriptors for waitid() */
	argdes_t *adp;
	int error;
#ifdef _LP64
	siginfo32_t siginfo32;
#endif	/* _LP64 */

	if (Pr == NULL)		/* no subject process */
		return (waitid(idtype, id, infop, options));

	adp = &argd[0];		/* idtype argument */
	adp->arg_value = idtype;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* id argument */
	adp->arg_value = id;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* infop argument */
	adp->arg_value = 0;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_OUTPUT;
#ifdef _LP64
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32) {
		adp->arg_object = &siginfo32;
		adp->arg_size = sizeof (siginfo32);
	} else {
		adp->arg_object = infop;
		adp->arg_size = sizeof (*infop);
	}
#else	/* _LP64 */
	adp->arg_object = infop;
	adp->arg_size = sizeof (*infop);
#endif	/* _LP64 */

	adp++;			/* options argument */
	adp->arg_value = options;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, SYS_waitid, 4, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return (-1);
	}
#ifdef _LP64
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32)
		siginfo_32_to_n(&siginfo32, infop);
#endif	/* _LP64 */
	return (0);
}
