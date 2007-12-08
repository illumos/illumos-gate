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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains platform-dependent MMU support routines,
 * suitable for mmu methods with 2-cell physical addresses.
 * Use of these routines makes the caller platform-dependent,
 * since the caller assumes knowledge of the physical layout of
 * the machines address space.  Generic programs should use the
 * standard client interface memory allocators.
 */

#include <sys/promif.h>
#include <sys/promimpl.h>

ihandle_t
prom_mmu_ihandle(void)
{
	static ihandle_t immu;

	if (immu != (ihandle_t)0)
		return (immu);

	if (prom_getproplen(prom_chosennode(), "mmu") != sizeof (ihandle_t))
		return (immu = (ihandle_t)-1);

	(void) prom_getprop(prom_chosennode(), "mmu", (caddr_t)(&immu));
	return (immu);
}

/*
 * prom_map_phys:
 *
 * Create an MMU mapping for a given physical address to a given virtual
 * address. The given resources are assumed to be owned by the caller,
 * and are *not* removed from any free lists.
 *
 * This routine is suitable for mapping a 2-cell physical address.
 */

int
prom_map_phys(int mode, size_t size, caddr_t virt, unsigned long long physaddr)
{
	cell_t ci[11];
	int rv;
	ihandle_t immu = prom_mmu_ihandle();

	if ((immu == (ihandle_t)-1))
		return (-1);

	ci[0] = p1275_ptr2cell("call-method");	/* Service name */
	ci[1] = (cell_t)7;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #result cells */
	ci[3] = p1275_ptr2cell("map");		/* Arg1: method name */
	ci[4] = p1275_ihandle2cell(immu);	/* Arg2: mmu ihandle */
	ci[5] = p1275_int2cell(mode);		/* Arg3: SA1: mode */
	ci[6] = p1275_size2cell(size);		/* Arg4: SA2: size */
	ci[7] = p1275_ptr2cell(virt);		/* Arg5: SA3: virt */
	ci[8] = p1275_ull2cell_high(physaddr);	/* Arg6: SA4: phys.hi */
	ci[9] = p1275_ull2cell_low(physaddr);	/* Arg7: SA5: phys.low */

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	if (rv != 0)
		return (-1);
	if (ci[10] != 0)			/* Res1: Catch result */
		return (-1);
	return (0);
}

void
prom_unmap_phys(size_t size, caddr_t virt)
{
	(void) prom_unmap_virt(size, virt);
}

/*
 * Allocate aligned or unaligned virtual address space, unmapped.
 */
caddr_t
prom_allocate_virt(uint_t align, size_t size)
{
	cell_t ci[9];
	int rv;
	ihandle_t immu = prom_mmu_ihandle();

	if ((immu == (ihandle_t)-1))
		return ((caddr_t)-1);

	if (align == 0)
		align = 1;

	ci[0] = p1275_ptr2cell("call-method");	/* Service name */
	ci[1] = (cell_t)4;			/* #argument cells */
	ci[2] = (cell_t)2;			/* #result cells */
	ci[3] = p1275_ptr2cell("claim");	/* Arg1: Method name */
	ci[4] = p1275_ihandle2cell(immu);	/* Arg2: mmu ihandle */
	ci[5] = p1275_uint2cell(align);		/* Arg3: SA1: align */
	ci[6] = p1275_size2cell(size);		/* Arg4: SA2: size */

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	if (rv != 0)
		return ((caddr_t)-1);
	if (ci[7] != 0)				/* Res1: Catch result */
		return ((caddr_t)-1);
	return (p1275_cell2ptr(ci[8]));		/* Res2: SR1: base */
}

/*
 * Claim a region of virtual address space, unmapped.
 */
caddr_t
prom_claim_virt(size_t size, caddr_t virt)
{
	cell_t ci[10];
	int rv;
	ihandle_t immu = prom_mmu_ihandle();

	if ((immu == (ihandle_t)-1))
		return ((caddr_t)-1);

	ci[0] = p1275_ptr2cell("call-method");	/* Service name */
	ci[1] = (cell_t)5;			/* #argument cells */
	ci[2] = (cell_t)2;			/* #result cells */
	ci[3] = p1275_ptr2cell("claim");	/* Arg1: Method name */
	ci[4] = p1275_ihandle2cell(immu);	/* Arg2: mmu ihandle */
	ci[5] = (cell_t)0;			/* Arg3: align */
	ci[6] = p1275_size2cell(size);		/* Arg4: length */
	ci[7] = p1275_ptr2cell(virt);		/* Arg5: virt */

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	if (rv != 0)
		return ((caddr_t)-1);
	if (ci[8] != 0)				/* Res1: Catch result */
		return ((caddr_t)-1);
	return (p1275_cell2ptr(ci[9]));		/* Res2: base */
}

/*
 * Free virtual address resource (no unmapping is done).
 */
void
prom_free_virt(size_t size, caddr_t virt)
{
	cell_t ci[7];
	ihandle_t immu = prom_mmu_ihandle();

	if ((immu == (ihandle_t)-1))
		return;

	ci[0] = p1275_ptr2cell("call-method");	/* Service name */
	ci[1] = (cell_t)4;			/* #argument cells */
	ci[2] = (cell_t)0;			/* #return cells */
	ci[3] = p1275_ptr2cell("release");	/* Arg1: Method name */
	ci[4] = p1275_ihandle2cell(immu);	/* Arg2: mmu ihandle */
	ci[5] = p1275_size2cell(size);		/* Arg3: length */
	ci[6] = p1275_ptr2cell(virt);		/* Arg4: virt */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();
}

/*
 * Un-map virtual address. Does not free underlying resources.
 */
void
prom_unmap_virt(size_t size, caddr_t virt)
{
	cell_t ci[7];
	ihandle_t immu = prom_mmu_ihandle();

	if ((immu == (ihandle_t)-1))
		return;

	ci[0] = p1275_ptr2cell("call-method");	/* Service name */
	ci[1] = (cell_t)4;			/* #argument cells */
	ci[2] = (cell_t)0;			/* #result cells */
	ci[3] = p1275_ptr2cell("unmap");	/* Arg1: Method name */
	ci[4] = p1275_ihandle2cell(immu);	/* Arg2: mmu ihandle */
	ci[5] = p1275_size2cell(size);		/* Arg3: SA1: size */
	ci[6] = p1275_ptr2cell(virt);		/* Arg4: SA2: virt */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();
}

static pnode_t
prom_mmu_phandle(void)
{
	static pnode_t pmmu = 0;

	if (pmmu == (pnode_t)0)  {
		ihandle_t ih;

		if ((ih = prom_mmu_ihandle()) == (ihandle_t)-1)
			prom_panic("Can't get mmu ihandle");
		pmmu = prom_getphandle(ih);
	}
	return (pmmu);
}


int
prom_virt_avail_len(void)
{
	return (prom_getproplen(prom_mmu_phandle(), "available"));
}

int
prom_virt_avail(caddr_t prop)
{
	return (prom_getprop(prom_mmu_phandle(), "available", prop));
}

/*
 * Translate virtual address to physical address.
 * Returns 0: Success; Non-zero: failure.
 * Returns *phys_hi, *phys_lo and *mode only if successful.
 */
int
prom_translate_virt(caddr_t virt, int *valid,
		unsigned long long *physaddr, int *mode)
{
	cell_t ci[11];
	int rv;
	ihandle_t immu = prom_mmu_ihandle();

	*valid = 0;

	if ((immu == (ihandle_t)-1))
		return (-1);

	ci[0] = p1275_ptr2cell("call-method");	/* Service name */
	ci[1] = (cell_t)3;			/* #argument cells */
	ci[2] = (cell_t)5;			/* #result cells */
	ci[3] = p1275_ptr2cell("translate");	/* Arg1: Method name */
	ci[4] = p1275_ihandle2cell(immu);	/* Arg2: mmu ihandle */
	ci[5] = p1275_ptr2cell(virt);		/* Arg3: virt */
	ci[6] = 0;				/* Res1: catch-resule */
	ci[7] = 0;				/* Res2: sr1: valid */

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	if (rv == -1)				/* Did the call fail ? */
		return (-1);
	if (ci[6] != 0)				/* Catch result */
		return (-1);

	if (p1275_cell2int(ci[7]) != -1)	/* Valid results ? */
		return (0);

	*mode = p1275_cell2int(ci[8]);		/* Res3: sr2: mode, if valid */
	*physaddr = p1275_cells2ull(ci[9], ci[10]);
				/* Res4: sr3: phys-hi ... Res5: sr4: phys-lo */
	*valid = -1;				/* Indicate valid result */
	return (0);
}

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
