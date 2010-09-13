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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/procset.h>
#include <sys/processor.h>
#include <sys/pset.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "libproc.h"

int
pr_processor_bind(struct ps_prochandle *Pr, idtype_t idtype, id_t id,
    int processorid, int *obind)
{
	sysret_t rval;			/* return value */
	argdes_t argd[4];		/* arg descriptors */
	argdes_t *adp = &argd[0];	/* first argument */
	int error;

	if (Pr == NULL)		/* no subject process */
		return (processor_bind(idtype, id, processorid, obind));

	adp->arg_value = idtype;	/* idtype */
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;

	adp->arg_value = id;		/* id */
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;

	adp->arg_value = processorid;	/* processorid */
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;

	if (obind == NULL) {
		adp->arg_value = 0;	/* obind */
		adp->arg_object = NULL;
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = 0;
	} else {
		adp->arg_value = 0;
		adp->arg_object = obind;
		adp->arg_type = AT_BYREF;
		adp->arg_inout = AI_INOUT;
		adp->arg_size = sizeof (int);
	}

	error = Psyscall(Pr, &rval, SYS_processor_bind, 4, &argd[0]);

	if (error) {
		errno = (error < 0)? ENOSYS : error;
		return (-1);
	}
	return (rval.sys_rval1);
}
