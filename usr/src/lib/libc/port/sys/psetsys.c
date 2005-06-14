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

#pragma weak pset_create = _pset_create
#pragma weak pset_destroy = _pset_destroy
#pragma weak pset_assign = _pset_assign
#pragma weak pset_info = _pset_info
#pragma weak pset_bind = _pset_bind
#pragma weak pset_getloadavg = _pset_getloadavg
#pragma weak pset_list = _pset_list
#pragma weak pset_setattr = _pset_setattr
#pragma weak pset_getattr = _pset_getattr

#include "synonyms.h"
#include <sys/types.h>
#include <sys/procset.h>
#include <sys/processor.h>
#include <sys/pset.h>
#include <sys/param.h>
#include <sys/loadavg.h>

int _pset(int, ...);

/* subcode wrappers for _pset system call */

int
pset_create(psetid_t *npset)
{
	return (_pset(PSET_CREATE, npset));
}

int
pset_destroy(psetid_t pset)
{
	return (_pset(PSET_DESTROY, pset));
}

int
pset_assign(psetid_t pset, processorid_t cpu, psetid_t *opset)
{
	return (_pset(PSET_ASSIGN, pset, cpu, opset));
}

int
pset_assign_forced(psetid_t pset, processorid_t cpu, psetid_t *opset)
{
	return (_pset(PSET_ASSIGN_FORCED, pset, cpu, opset));
}

int
pset_info(psetid_t pset, int *type, uint_t *numcpus, processorid_t *cpulist)
{
	return (_pset(PSET_INFO, pset, type, numcpus, cpulist));
}

int
pset_bind(psetid_t pset, idtype_t idtype, id_t id, psetid_t *opset)
{
	return (_pset(PSET_BIND, pset, idtype, id, opset));
}

/*
 * Get the per-processor-set load average.
 */
int
pset_getloadavg(psetid_t pset, double loadavg[], int nelem)
{
	int i, buf[LOADAVG_NSTATS];

	if (nelem > LOADAVG_NSTATS)
		nelem = LOADAVG_NSTATS;

	if (_pset(PSET_GETLOADAVG, pset, buf, nelem) == -1)
		return (-1);

	for (i = 0; i < nelem; i++)
		loadavg[i] = (double)buf[i] / FSCALE;

	return (nelem);
}

int
pset_list(psetid_t *psetlist, uint_t *numpsets)
{
	return (_pset(PSET_LIST, psetlist, numpsets));
}

int
pset_setattr(psetid_t pset, uint_t attr)
{
	return (_pset(PSET_SETATTR, pset, attr));
}

int
pset_getattr(psetid_t pset, uint_t *attr)
{
	return (_pset(PSET_GETATTR, pset, attr));
}
