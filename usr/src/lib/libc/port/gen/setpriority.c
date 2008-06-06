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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/procset.h>
#include <sys/priocntl.h>
#include <limits.h>
#include <errno.h>
#include <priv.h>

static idtype_t
prio_to_idtype(int which)
{
	switch (which) {

	case PRIO_PROCESS:
		return (P_PID);

	case PRIO_PGRP:
		return (P_PGID);

	case PRIO_USER:
		return (P_UID);

	case PRIO_GROUP:
		return (P_GID);

	case PRIO_SESSION:
		return (P_SID);

	case PRIO_LWP:
		return (P_LWPID);

	case PRIO_TASK:
		return (P_TASKID);

	case PRIO_PROJECT:
		return (P_PROJID);

	case PRIO_ZONE:
		return (P_ZONEID);

	case PRIO_CONTRACT:
		return (P_CTID);

	default:
		return (-1);
	}
}

static int
old_idtype(int which)
{
	switch (which) {
	case PRIO_PROCESS:
	case PRIO_PGRP:
	case PRIO_USER:
		return (1);
	default:
		return (0);
	}
}

int
getpriority(int which, id_t who)
{
	id_t id;
	idtype_t idtype;
	pcnice_t pcnice;

	if ((idtype = prio_to_idtype(which)) == -1) {
		errno = EINVAL;
		return (-1);
	}

	if (who < 0) {
		if (old_idtype(which)) {
			errno = EINVAL;
			return (-1);
		} else if (who != P_MYID) {
			errno = EINVAL;
			return (-1);
		}
	}

	/*
	 * The POSIX standard requires that a 0 value for the who argument
	 * should specify the current process, process group, or user.
	 * For all other id types we can treat zero as normal id value.
	 */
	if (who == 0 && old_idtype(which))
		id = P_MYID;
	else
		id = who;

	pcnice.pc_val = 0;
	pcnice.pc_op = PC_GETNICE;

	if (priocntl(idtype, id, PC_DONICE, &pcnice) == -1)
		return (-1);
	else
		return (pcnice.pc_val);
}

int
setpriority(int which, id_t who, int prio)
{
	id_t id;
	idtype_t idtype;
	pcnice_t pcnice;
	int ret;

	if ((idtype = prio_to_idtype(which)) == -1) {
		errno = EINVAL;
		return (-1);
	}

	if (who < 0) {
		if (old_idtype(which)) {
			errno = EINVAL;
			return (-1);
		} else if (who != P_MYID) {
			errno = EINVAL;
			return (-1);
		}
	}

	if (who == 0 && old_idtype(which))
		id = P_MYID;
	else
		id = who;

	if (prio > NZERO - 1)
		prio = NZERO - 1;
	else if (prio < -NZERO)
		prio = -NZERO;

	pcnice.pc_val = prio;
	pcnice.pc_op = PC_SETNICE;

	ret = priocntl(idtype, id, PC_DONICE, &pcnice);

	if (ret != 0 && errno == EPERM) {
		pcnice_t	gpcnice = { 0, PC_GETNICE };
		priv_set_t	*pset = NULL;

		/*
		 * The priocntl PC_DONICE subcommand returns EPERM if we lack
		 * sufficient privileges to carry out the operation, but
		 * setpriority(3C) may need to return EACCES.  We can't just
		 * change EPERM to EACCES, because there are other conditions
		 * which legitimately cause EPERM (such as an euid/ruid mismatch
		 * between the current process and the target.).
		 *
		 * setpriority(3C) must return EACCES if we lack the privilege
		 * checked for below and we are trying to increase the process
		 * priority (by lowering the numeric value of its priority).
		 */
		if (priocntl(idtype, id, PC_DONICE, &gpcnice) == 0 &&
		    prio < gpcnice.pc_val) {
			if ((pset = priv_allocset()) != NULL &&
			    getppriv(PRIV_EFFECTIVE, pset) == 0 &&
			    !priv_ismember(pset, "proc_priocntl"))
				errno = EACCES;
			if (pset != NULL)
				priv_freeset(pset);
		}
	}

	return (ret);
}
