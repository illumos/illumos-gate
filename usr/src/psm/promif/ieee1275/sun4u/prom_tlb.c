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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/promif.h>
#include <sys/promimpl.h>

/*
 * prom_itlb_load, prom_dtlb_load:
 *
 * Manage the Spitfire TLB. Returns 0 if successful, -1 otherwise.
 * Flush the address in context zero mapped by tte_data and virt,
 * and load the {i,d} tlb entry index with tte_data and virt.
 */

int
prom_itlb_load(int index, unsigned long long tte_data, caddr_t virt)
{
	cell_t ci[9];
	int rv;
	ihandle_t immu = prom_mmu_ihandle();

	if ((immu == (ihandle_t)-1))
		return (-1);

	ci[0] = p1275_ptr2cell("call-method");	/* Service name */
	ci[1] = (cell_t)5;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #result cells */
	ci[3] = p1275_ptr2cell("SUNW,itlb-load"); /* Arg1: method name */
	ci[4] = p1275_ihandle2cell(immu);	/* Arg2: mmu ihandle */
	ci[5] = p1275_ptr2cell(virt);		/* Arg3: SA1: virt */
	ci[6] = (cell_t)tte_data;		/* Arg4: SA2: tte_data */
	ci[7] = p1275_int2cell(index);		/* Arg5: SA3: index */

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	if (rv != 0)
		return (-1);
	if (ci[8] != 0)				/* Res1: Catch result */
		return (-1);
	return (0);
}

int
prom_dtlb_load(int index, unsigned long long tte_data, caddr_t virt)
{
	cell_t ci[9];
	int rv;
	ihandle_t immu = prom_mmu_ihandle();

	if ((immu == (ihandle_t)-1))
		return (-1);

	ci[0] = p1275_ptr2cell("call-method");	/* Service name */
	ci[1] = (cell_t)5;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #result cells */
	ci[3] = p1275_ptr2cell("SUNW,dtlb-load"); /* Arg1: method name */
	ci[4] = p1275_ihandle2cell(immu);	/* Arg2: mmu ihandle */
	ci[5] = p1275_ptr2cell(virt);		/* Arg3: SA1: virt */
	ci[6] = (cell_t)tte_data;		/* Arg4: SA2: tte_data */
	ci[7] = p1275_int2cell(index);		/* Arg5: SA3: index */

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	if (rv != 0)
		return (-1);
	if (ci[8] != 0)				/* Res1: Catch result */
		return (-1);
	return (0);
}
