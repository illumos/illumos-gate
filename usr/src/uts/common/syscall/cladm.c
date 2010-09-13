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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/cladm.h>

/*
 * cladm(2) cluster administation system call.
 */
int
cladm(int fac, int cmd, void *arg)
{
	int error = 0;
	int copyout_bootflags;

	switch (fac) {
	case CL_INITIALIZE:
		if (cmd != CL_GET_BOOTFLAG) {
			error = EINVAL;
			break;
		}

		/*
		 * The CLUSTER_INSTALLING and CLUSTER_DCS_ENABLED bootflags are
		 * internal flags. We do not want to expose these to the user
		 * level.
		 */
		copyout_bootflags = (cluster_bootflags &
		    ~(CLUSTER_INSTALLING | CLUSTER_DCS_ENABLED));
		if (copyout(&copyout_bootflags, arg, sizeof (int))) {
			error = EFAULT;
		}
		break;

	case CL_CONFIG:
		/*
		 * We handle CL_NODEID here so that the node number
		 * can be returned if the system is configured as part
		 * of a cluster but not booted as part of the cluster.
		 */
		if (cmd == CL_NODEID) {
			nodeid_t nid;

			/* return error if not configured as a cluster */
			if (!(cluster_bootflags & CLUSTER_CONFIGURED)) {
				error = ENOSYS;
				break;
			}

			nid = clconf_get_nodeid();
			error = copyout(&nid, arg, sizeof (nid));
			break;
		}
		/* FALLTHROUGH */

	default:
		if ((cluster_bootflags & (CLUSTER_CONFIGURED|CLUSTER_BOOTED)) !=
		    (CLUSTER_CONFIGURED|CLUSTER_BOOTED)) {
			error = EINVAL;
			break;
		}
		error = cladmin(fac, cmd, arg);
		/*
		 * error will be -1 if the cladm module cannot be loaded;
		 * otherwise, it is the errno value returned
		 * (see {i86,sparc}/ml/modstubs.s).
		 */
		if (error < 0)
			error = ENOSYS;
		break;
	}

	return (error ? set_errno(error) : 0);
}
