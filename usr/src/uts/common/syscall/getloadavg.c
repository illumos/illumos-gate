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
 * Copyright 2011 Joyent, Inc.  All rights reserved.
 */

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
	int error;

	if (nelem < 0)
		return (set_errno(EINVAL));
	if (nelem > LOADAVG_NSTATS)
		nelem = LOADAVG_NSTATS;

	if (!INGLOBALZONE(curproc)) {
		loadbuf = &curproc->p_zone->zone_avenrun[0];
	}

	error = copyout(loadbuf, buf, nelem * sizeof (avenrun[0]));
	if (error)
		return (set_errno(EFAULT));
	return (nelem);
}
