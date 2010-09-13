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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/promimpl.h>

int
prom_stopcpu_bycpuid(int cpuid)
{
	cell_t ci[5];

	ci[0] = p1275_ptr2cell("SUNW,stop-cpu-by-cpuid"); /* Service name */
	ci[1] = (cell_t)1;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #result cells */
	ci[3] = p1275_int2cell(cpuid);		/* Arg1: cpuid to stop */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();

	return (p1275_cell2int(ci[4]));
}


int
prom_startcpu(pnode_t node, caddr_t pc, int arg)
{
	cell_t ci[6];

	ci[0] = p1275_ptr2cell("SUNW,start-cpu");	/* Service name */
	ci[1] = (cell_t)3;			/* #argument cells */
	ci[2] = (cell_t)0;			/* #result cells */
	ci[3] = p1275_dnode2cell(node);		/* Arg1: nodeid to start */
	ci[4] = p1275_ptr2cell(pc);		/* Arg2: pc */
	ci[5] = p1275_int2cell(arg);		/* Arg3: cpuid */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();

	return (0);
}

int
prom_startcpu_bycpuid(int cpuid, caddr_t pc, int arg)
{
	cell_t ci[7];

	ci[0] = p1275_ptr2cell("SUNW,start-cpu-by-cpuid");  /* Service name */
	ci[1] = (cell_t)3;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #result cells */
	ci[3] = p1275_int2cell(cpuid);		/* Arg1: cpuid to start */
	ci[4] = p1275_ptr2cell(pc);		/* Arg2: pc */
	ci[5] = p1275_int2cell(arg);		/* Arg3: cpuid */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();

	return (p1275_cell2int(ci[6]));
}

int
prom_wakeupcpu(pnode_t node)
{
	cell_t ci[5];
	int	rv;

	ci[0] = p1275_ptr2cell("SUNW,wakeup-cpu");	/* Service name */
	ci[1] = (cell_t)1;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #result cells */
	ci[3] = p1275_dnode2cell(node);		/* Arg1: nodeid to wakeup */

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	if (rv != 0)
		return (rv);
	else
		return (p1275_cell2int(ci[4]));	/* Res1: Catch result */
}

int
prom_cpuoff(pnode_t node)
{
	cell_t ci[5];
	int rv;

	ci[0] = p1275_ptr2cell("SUNW,park-cpu");
	ci[1] = (cell_t)1;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #return cells */
	ci[3] = p1275_dnode2cell(node);

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	if (rv != 0)
		return (-1);

	return (p1275_cell2int(ci[4]));
}

int
prom_hotaddcpu(int cpuid)
{
	cell_t ci[5];

	ci[0] = p1275_ptr2cell("SUNW,hotadd-cpu-by-cpuid"); /* Service name */
	ci[1] = (cell_t)1;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #result cells */
	ci[3] = p1275_int2cell(cpuid);		/* Arg1: cpuid to start */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();

	return (p1275_cell2int(ci[4]));
}

int
prom_hotremovecpu(int cpuid)
{
	cell_t ci[5];

	ci[0] = p1275_ptr2cell("SUNW,hotremove-cpu-by-cpuid"); /* Service */
	ci[1] = (cell_t)1;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #result cells */
	ci[3] = p1275_int2cell(cpuid);		/* Arg1: cpuid to start */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();

	return (p1275_cell2int(ci[4]));
}
