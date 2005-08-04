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

#include <sys/machsystm.h>
#include <sys/vm.h>
#include <sys/cpu.h>
#include <sys/intreg.h>
#include <sys/machcpuvar.h>
#include <sys/machparam.h>
#include <vm/hat_sfmmu.h>
#include <vm/seg_kmem.h>
#include <sys/error.h>
#include <sys/hypervisor_api.h>
#include <sys/types.h>
#include <sys/kstat.h>
#ifdef MACH_DESC_DEBUG
#include <sys/promif.h>		/* for prom_printf */
#endif
#include <sys/sysmacros.h>
#include <sys/mach_descrip.h>

/*
 * Basic code to pull in the machine description from the Hypervisor
 * An equivalent to this should really be available from mlsetup
 * for really early info, but for the time being we are content to
 * invoke this from startup_end once the VM system has been initialised.
 * To do this we use the intrq allocator which means that
 * this function should be called after intrq_init();
 * We try and do this early enough however that it is useful to other
 * components within the kernel.
 * Also, user-level entities can grab the machine description via
 * kstat and/or the mdesc device driver.
 */


machine_descrip_t machine_descrip;


#ifdef MACH_DESC_DEBUG
#define	MDP(ARGS)	prom_printf ARGS
static void
dump_buf(uint8_t *bufp, int size)
{
	int i;
	for (i = 0; i < size; i += 16) {
		int j;
		prom_printf("0x%04x :", i);
		for (j = 0; j < 16 && (i+j) < size; j++)
			prom_printf(" %02x", bufp[i+j]);
		prom_printf("\n");
	}
}
#else
#define	MDP(x)
#endif





void
mach_descrip_init(void)
{
	uint64_t md_size, ret;

	MDP(("MD: Requesting buffer size\n"));

	md_size = 0LL;
	(void) hv_mach_desc((uint64_t)0, &md_size);
	MDP(("MD: buffer size is %d\n", md_size));

	/*
	 * Align allocated space to nearest page contig_mem_alloc_align
	 * requires a Power of 2 alignment
	 */
	machine_descrip.space = P2ROUNDUP(md_size, PAGESIZE);
	MDP(("MD: allocated space is %d\n", machine_descrip.space));
	machine_descrip.va = contig_mem_alloc_align(machine_descrip.space,
	    PAGESIZE);
	if (machine_descrip.va == NULL)
		cmn_err(CE_PANIC, "Allocation for machine description failed");

	MDP(("MD: allocated va = 0x%p (size 0x%llx)\n",
		machine_descrip.va, machine_descrip.space));

	machine_descrip.pa = va_to_pa(machine_descrip.va);

	MDP(("MD: allocated pa = 0x%llx\n", machine_descrip.pa));

	ret = hv_mach_desc(machine_descrip.pa, &md_size);
	MDP(("MD: HV return code = %ld\n", ret));

	if (ret != H_EOK) {
		MDP(("MD: Failed with code %ld from HV\n", ret));

		machine_descrip.size = 0;

	} else {
		MDP(("MD: Grabbed %d bytes from HV\n", md_size));
#ifdef	MACH_DESC_DEBUG
		dump_buf((uint8_t *)machine_descrip.va, md_size);
#endif	/* MACH_DESC_DEBUG */

		machine_descrip.size = md_size;

			/*
			 * Allocate the kstat to get at the data
			 */
		machine_descrip.ksp = kstat_create("unix", 0, "machdesc",
		    "misc",
		    KSTAT_TYPE_RAW,
		    (uint_t)machine_descrip.size,
		    KSTAT_FLAG_VIRTUAL);

		if (machine_descrip.ksp == NULL) {
			cmn_err(CE_PANIC,
			    "Failed to create kstat for machine description");
		} else {
			machine_descrip.ksp->ks_data = machine_descrip.va;
			kstat_install(machine_descrip.ksp);
		}
	}
}
