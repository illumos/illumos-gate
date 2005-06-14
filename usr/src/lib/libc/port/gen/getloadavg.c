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

#pragma weak getloadavg = _getloadavg

#include "synonyms.h"
#include <sys/types.h>
#include <sys/param.h>
#include <sys/syscall.h>
#include <sys/loadavg.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * getloadavg -- get the time averaged run queues from the system
 */
int
getloadavg(double loadavg[], int nelem)
{
	int i, buf[LOADAVG_NSTATS];

	if (nelem > LOADAVG_NSTATS)
		nelem = LOADAVG_NSTATS;

	if ((nelem = __getloadavg(buf, nelem)) == -1)
		return (-1);

	for (i = 0; i < nelem; i++)
		loadavg[i] = (double)buf[i] / FSCALE;

	return (nelem);
}
