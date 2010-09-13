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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	_LARGEFILE64_SOURCE

#include <sys/task.h>
#include <sys/types.h>

#include <zone.h>
#include <errno.h>
#include <project.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include "libproc.h"

zoneid_t
pr_getzoneid(struct ps_prochandle *Pr)
{
	sysret_t rval;
	argdes_t argd[2];
	argdes_t *adp;
	int error;

	if (Pr == NULL)		/* no subject process */
		return (getzoneid());

	adp = &argd[0];
	adp->arg_value = 6;	/* switch for zone_lookup in zone */
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp = &argd[1];
	adp->arg_value = 0;	/* arguement for zone_lookup in zone */
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, SYS_zone, 2, &argd[0]);

	if (error) {
		errno = (error > 0) ? error : ENOSYS;
		return (-1);
	}
	return (rval.sys_rval1);
}

projid_t
pr_getprojid(struct ps_prochandle *Pr)
{
	sysret_t rval;
	argdes_t argd[1];
	argdes_t *adp;
	int error;

	if (Pr == NULL)		/* no subject process */
		return (getprojid());

	adp = &argd[0];
	adp->arg_value = 2;	/* switch for getprojid in tasksys */
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, SYS_tasksys, 1, &argd[0]);

	if (error) {
		errno = (error > 0) ? error : ENOSYS;
		return (-1);
	}
	return (rval.sys_rval1);
}

taskid_t
pr_gettaskid(struct ps_prochandle *Pr)
{
	sysret_t rval;
	argdes_t argd[1];
	argdes_t *adp;
	int error;

	if (Pr == NULL)		/* no subject process */
		return (gettaskid());

	adp = &argd[0];
	adp->arg_value = 1;	/* switch for gettaskid in tasksys */
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, SYS_tasksys, 1, &argd[0]);

	if (error) {
		errno = (error > 0) ? error : ENOSYS;
		return (-1);
	}
	return (rval.sys_rval1);
}

taskid_t
pr_settaskid(struct ps_prochandle *Pr, projid_t project, int flags)
{
	sysret_t rval;
	argdes_t argd[3];
	argdes_t *adp;
	int error;

	if (Pr == NULL)		/* No subject process */
		return (settaskid(project, flags));

	adp = &argd[0];
	adp->arg_value = 0;	/* switch for settaskid in tasksys */
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;
	adp->arg_value = project;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = sizeof (project);

	adp++;
	adp->arg_value = flags;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, SYS_tasksys, 3, &argd[0]);

	if (error) {
		errno = (error > 0) ? error : ENOSYS;
		return (-1);
	}
	return (rval.sys_rval1);
}
