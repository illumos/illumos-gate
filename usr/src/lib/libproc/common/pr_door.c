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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <door.h>
#include "libproc.h"

/*
 * door() system calls -- executed by subject process
 */

int
pr_door_info(struct ps_prochandle *Pr, int did, door_info_t *di)
{
	sysret_t rval;			/* return value from door_info() */
	argdes_t argd[6];		/* arg descriptors for door_info() */
	argdes_t *adp = &argd[0];	/* first argument */
	int error;

	if (Pr == NULL)		/* no subject process */
		return (door_info(did, di));

	adp->arg_value = did;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;			/* move to door_info_t argument */

	adp->arg_value = 0;
	adp->arg_object = di;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_OUTPUT;
	adp->arg_size = sizeof (door_info_t);
	adp++;			/* move to unused argument */

	adp->arg_value = 0;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;			/* move to unused argument */

	adp->arg_value = 0;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;			/* move to unused argument */

	adp->arg_value = 0;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;			/* move to subcode argument */

	adp->arg_value = DOOR_INFO;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, SYS_door, 6, &argd[0]);

	if (error) {
		errno = (error < 0)? ENOSYS : error;
		return (-1);
	}
	return (0);
}
