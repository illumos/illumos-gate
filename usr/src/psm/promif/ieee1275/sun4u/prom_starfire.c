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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/promimpl.h>

/*
 * This file contains the implementations of all Starfire-specific
 * promif routines.
 */

/*
 * Probe all of the devices on a board. The board number is
 * computed from cpuid. All of the cpus on the board are
 * brought into OBP's slave idle loop but are not started.
 * Returns zero for success and non-zero for failure.
 */
int
prom_starfire_add_brd(uint_t cpuid)
{
	cell_t	ci[5];
	int	rv;

	ci[0] = p1275_ptr2cell("SUNW,UE10000,add-brd");	/* name */
	ci[1] = (cell_t)1;				/* #argument cells */
	ci[2] = (cell_t)1;				/* #result cells */
	ci[3] = p1275_uint2cell(cpuid);

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	return ((rv) ? -1 : p1275_cell2int(ci[4]));
}

/*
 * Prune the device tree nodes for all devices on the board
 * represented by brdnum. Returns zero for success and non-zero
 * for failure.
 */
int
prom_starfire_rm_brd(uint_t brdnum)
{
	cell_t	ci[5];
	int	rv;

	ci[0] = p1275_ptr2cell("SUNW,UE10000,rm-brd");	/* name */
	ci[1] = (cell_t)1;				/* #argument cells */
	ci[2] = (cell_t)1;				/* #result cells */
	ci[3] = p1275_uint2cell(brdnum);

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	return ((rv) ? -1 : p1275_cell2int(ci[4]));
}

/*
 * Prepare firmware internal state for the inclusion of the
 * cpu represented by cpuid. This operation has no effect on
 * the cpu hardware or behavior in the client.
 */
void
prom_starfire_add_cpu(uint_t cpuid)
{
	cell_t	ci[4];

	ci[0] = p1275_ptr2cell("SUNW,UE10000,add-cpu");	/* name */
	ci[1] = (cell_t)1;				/* #argument cells */
	ci[2] = (cell_t)0;				/* #result cells */
	ci[3] = p1275_uint2cell(cpuid);

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();
}

/*
 * Prepare firmware internal state for the departure of the cpu
 * represented by cpuid.
 */
void
prom_starfire_rm_cpu(uint_t cpuid)
{
	cell_t	ci[4];

	ci[0] = p1275_ptr2cell("SUNW,UE10000,rm-cpu");	/* name */
	ci[1] = (cell_t)1;				/* #argument cells */
	ci[2] = (cell_t)0;				/* #result cells */
	ci[3] = p1275_uint2cell(cpuid);

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();
}

/*
 * Mark the cpu represented by cpuid as cpu0. Returns zero for
 * success and non-zero for failure.
 */
int
prom_starfire_move_cpu0(uint_t cpuid)
{
	cell_t	ci[5];
	int	rv;

	ci[0] = p1275_ptr2cell("SUNW,UE10000,move-cpu0"); /* name */
	ci[1] = (cell_t)1;				  /* #argument cells */
	ci[2] = (cell_t)1;				  /* #result cells */
	ci[3] = p1275_uint2cell(cpuid);

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	return ((rv) ? -1 : p1275_cell2int(ci[4]));
}

/*
 * Perform initialization steps required for the console before
 * moving cpu0. The console uses the bootbus SRAM of cpu0 for both
 * input and output. The offsets of the console buffers are initialized
 * for the bootbus SRAM of the new cpu0 represented by cpuid.
 */
void
prom_starfire_init_console(uint_t cpuid)
{
	cell_t	ci[4];

	ci[0] = p1275_ptr2cell("SUNW,UE10000,init-console"); /* name */
	ci[1] = (cell_t)1;				 /* #argument cells */
	ci[2] = (cell_t)0;				 /* #result cells */
	ci[3] = p1275_uint2cell(cpuid);

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();
}
