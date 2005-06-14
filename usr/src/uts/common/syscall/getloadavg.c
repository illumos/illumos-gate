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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/loadavg.h>
#include <sys/zone.h>
#include <sys/pool_pset.h>

/*
 * Extract elements of the raw avenrun array from the kernel for the
 * implementation of getloadavg(3c)
 */
int
getloadavg(int *buf, int nelem)
{
	int *loadbuf = &avenrun[0];
	int loadavg[LOADAVG_NSTATS];
	int error;

	if (nelem < 0)
		return (set_errno(EINVAL));
	if (nelem > LOADAVG_NSTATS)
		nelem = LOADAVG_NSTATS;

	if (!INGLOBALZONE(curproc)) {
		mutex_enter(&cpu_lock);
		if (pool_pset_enabled()) {
			psetid_t psetid = zone_pset_get(curproc->p_zone);

			error = cpupart_get_loadavg(psetid, &loadavg[0], nelem);
			ASSERT(error == 0);	/* pset isn't going anywhere */
			loadbuf = &loadavg[0];
		}
		mutex_exit(&cpu_lock);
	}

	error = copyout(loadbuf, buf, nelem * sizeof (avenrun[0]));
	if (error)
		return (set_errno(EFAULT));
	return (nelem);
}
