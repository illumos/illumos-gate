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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif_impl.h>
#include <sys/machsystm.h>
#include <sys/hypervisor_api.h>
#include <sys/lpad.h>

extern int (*prom_cif_handler)(void *);
extern int cif_cpu_mp_ready;

int
promif_set_mmfsa_traptable(void *p)
{
	cell_t		*ci = (cell_t *)p;
	uint64_t	rtba;
	caddr_t		tba;
	uint64_t	mmfsa_ra;
	int		rv, ret;

	ASSERT(ci[1] == 2);

	/*
	 * We use the same trap table for the rtba as well.
	 */
	rtba = va_to_pa(p1275_cell2ptr(ci[3]));

	/*
	 * if cif_cpu_mp_ready is not set the prom is still
	 * setting the mmfsa and trap table. Set the rtba
	 * after the prom cif call.
	 */
	if (!cif_cpu_mp_ready) {
		ret = (*prom_cif_handler)(p);
		if ((rv = hv_cpu_set_rtba(&rtba)) != H_EOK)
			panic("hv_cpu_set_rtba failed: %d\n", rv);
		return (ret);
	}

	tba = p1275_cell2ptr(ci[3]);
	mmfsa_ra = (uint64_t)p1275_cell2ptr(ci[4]);

	if (tba != (caddr_t)KERNELBASE)
		return (-1);

	(void) set_tba(tba);

	if ((rv = hv_mmu_fault_area_conf(&mmfsa_ra)) != H_EOK) {
		panic("hv_mmu_fault_area_conf failed: %d\n", rv);
	}

	if ((rv = hv_cpu_set_rtba(&rtba)) != H_EOK) {
		panic("hv_cpu_set_rtba failed: %d\n", rv);
	}

	return (0);
}

int
promif_start_cpu(void *p)
{
	cell_t		*ci = (cell_t *)p;
	int		cpuid;
	caddr_t		pc;
	int		arg;
	uint64_t	rtba = 0;
	int		rv;
	uint64_t	*lpp;

	ASSERT(ci[1] == 3);

	cpuid = p1275_cell2int(ci[3]);
	pc = p1275_cell2ptr(ci[4]);
	arg = p1275_cell2int(ci[5]);

	if (!cif_cpu_mp_ready)
		return ((*prom_cif_handler)(p));

	rtba = va_to_pa(&trap_table);

	lpp = lpad_setup(cpuid, (uint64_t)pc, (uint64_t)arg);

	ASSERT(lpp);

	pc = (caddr_t)lpp;

	rv = hv_cpu_start(cpuid, va_to_pa(pc), rtba, cpuid);

	if (rv != H_EOK) {
		panic("promif_start_cpu: failed to start cpu %d (%d)\n",
		    cpuid, rv);
	}

	ci[6] = p1275_int2cell(rv);

	return (0);
}
