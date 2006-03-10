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

#include <sys/machsystm.h>
#include <sys/archsystm.h>
#include <sys/vm.h>
#include <sys/cpu.h>
#include <sys/atomic.h>
#include <sys/reboot.h>
#include <sys/kdi.h>
#include <sys/bootconf.h>
#include <sys/memlist_plat.h>
#include <sys/memlist_impl.h>
#include <sys/prom_plat.h>
#include <sys/prom_isa.h>
#include <sys/autoconf.h>
#include <sys/intreg.h>
#include <sys/ivintr.h>
#include <sys/fpu/fpusystm.h>
#include <sys/iommutsb.h>
#include <vm/vm_dep.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kpm.h>
#include <vm/seg_map.h>
#include <vm/seg_kp.h>
#include <sys/sysconf.h>
#include <vm/hat_sfmmu.h>
#include <sys/kobj.h>
#include <sys/sun4asi.h>
#include <sys/clconf.h>
#include <sys/platform_module.h>
#include <sys/panic.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/clock.h>
#include <sys/fpras_impl.h>
#include <sys/prom_debug.h>
#include <sys/traptrace.h>
#include <sys/memnode.h>
#include <sys/mem_cage.h>

/*
 * fpRAS implementation structures.
 */
struct fpras_chkfn *fpras_chkfnaddrs[FPRAS_NCOPYOPS];
struct fpras_chkfngrp *fpras_chkfngrps;
struct fpras_chkfngrp *fpras_chkfngrps_base;
int fpras_frequency = -1;
int64_t fpras_interval = -1;

void
setup_trap_table(void)
{
	intr_init(CPU);			/* init interrupt request free list */
	setwstate(WSTATE_KERN);
	prom_set_traptable(&trap_table);
}

void
mach_fpras()
{
	if (fpras_implemented && !fpras_disable) {
		int i;
		struct fpras_chkfngrp *fcgp;
		size_t chkfngrpsallocsz;

		/*
		 * Note that we size off of NCPU and setup for
		 * all those possibilities regardless of whether
		 * the cpu id is present or not.  We do this so that
		 * we don't have any construction or destruction
		 * activity to perform at DR time, and it's not
		 * costly in memory.  We require block alignment.
		 */
		chkfngrpsallocsz = NCPU * sizeof (struct fpras_chkfngrp);
		fpras_chkfngrps_base = kmem_alloc(chkfngrpsallocsz, KM_SLEEP);
		if (IS_P2ALIGNED((uintptr_t)fpras_chkfngrps_base, 64)) {
			fpras_chkfngrps = fpras_chkfngrps_base;
		} else {
			kmem_free(fpras_chkfngrps_base, chkfngrpsallocsz);
			chkfngrpsallocsz += 64;
			fpras_chkfngrps_base = kmem_alloc(chkfngrpsallocsz,
			    KM_SLEEP);
			fpras_chkfngrps = (struct fpras_chkfngrp *)
			    P2ROUNDUP((uintptr_t)fpras_chkfngrps_base, 64);
		}

		/*
		 * Copy our check function into place for each copy operation
		 * and each cpu id.
		 */
		fcgp = &fpras_chkfngrps[0];
		for (i = 0; i < FPRAS_NCOPYOPS; ++i)
			bcopy((void *)fpras_chkfn_type1, &fcgp->fpras_fn[i],
			    sizeof (struct fpras_chkfn));
		for (i = 1; i < NCPU; ++i)
			*(&fpras_chkfngrps[i]) = *fcgp;

		/*
		 * At definition fpras_frequency is set to -1, and it will
		 * still have that value unless changed in /etc/system (not
		 * strictly supported, but not preventable).  The following
		 * both sets the default and sanity checks anything from
		 * /etc/system.
		 */
		if (fpras_frequency < 0)
			fpras_frequency = FPRAS_DEFAULT_FREQUENCY;

		/*
		 * Now calculate fpras_interval.  When fpras_interval
		 * becomes non-negative fpras checks will commence
		 * (copies before this point in boot will bypass fpras).
		 * Our stores of instructions must be visible; no need
		 * to flush as they're never been executed before.
		 */
		membar_producer();
		fpras_interval = (fpras_frequency == 0) ?
		    0 : sys_tick_freq / fpras_frequency;
	}
}

void
mach_hw_copy_limit(void)
{
	if (!fpu_exists) {
		use_hw_bcopy = 0;
		hw_copy_limit_1 = 0;
		hw_copy_limit_2 = 0;
		hw_copy_limit_4 = 0;
		hw_copy_limit_8 = 0;
		use_hw_bzero = 0;
	}
}

void
load_tod_module()
{
	/*
	 * Load tod driver module for the tod part found on this system.
	 * Recompute the cpu frequency/delays based on tod as tod part
	 * tends to keep time more accurately.
	 */
	if (tod_module_name == NULL || modload("tod", tod_module_name) == -1)
		halt("Can't load tod module");
}

void
mach_memscrub(void)
{
	/*
	 * Startup memory scrubber, if not running fpu emulation code.
	 */

	if (fpu_exists) {
		if (memscrub_init()) {
			cmn_err(CE_WARN,
			    "Memory scrubber failed to initialize");
		}
	}
}

void
mach_cpu_halt_idle()
{
	/* no suport for halting idle CPU */
}

/*ARGSUSED*/
void
cpu_intrq_setup(struct cpu *cp)
{
	/* Interrupt mondo queues not applicable to sun4u */
}

/*ARGSUSED*/
void
cpu_intrq_register(struct cpu *cp)
{
	/* Interrupt/error queues not applicable to sun4u */
}

/*ARGSUSED*/
void
mach_htraptrace_setup(int cpuid)
{
	/* Setup hypervisor traptrace buffer, not applicable to sun4u */
}

/*ARGSUSED*/
void
mach_htraptrace_configure(int cpuid)
{
	/* enable/ disable hypervisor traptracing, not applicable to sun4u */
}

/*ARGSUSED*/
void
mach_htraptrace_init(void)
{
	/* allocate hypervisor traptrace buffer, not applicable to sun4u */
}

/*ARGSUSED*/
void
mach_htraptrace_cleanup(int cpuid)
{
	/* cleanup hypervisor traptrace buffer, not applicable to sun4u */
}

void
mach_descrip_init(void)
{
	/* Obtain Machine description - only for sun4v */
}

void
hsvc_setup(void)
{
	/* Setup hypervisor services, not applicable to sun4u */
}

/*
 * Return true if the machine we're running on is a Positron.
 * (Positron is an unsupported developers platform.)
 */
int
iam_positron(void)
{
	char model[32];
	const char proto_model[] = "SUNW,501-2732";
	pnode_t root = prom_rootnode();

	if (prom_getproplen(root, "model") != sizeof (proto_model))
		return (0);

	(void) prom_getprop(root, "model", model);
	if (strcmp(model, proto_model) == 0)
		return (1);
	return (0);
}

/*
 * Find a physically contiguous area of twice the largest ecache size
 * to be used while doing displacement flush of ecaches.
 */
uint64_t
ecache_flush_address(void)
{
	struct memlist *pmem;
	uint64_t flush_size;
	uint64_t ret_val;

	flush_size = ecache_size * 2;
	for (pmem = phys_install; pmem; pmem = pmem->next) {
		ret_val = P2ROUNDUP(pmem->address, ecache_size);
		if (ret_val + flush_size <= pmem->address + pmem->size)
			return (ret_val);
	}
	return ((uint64_t)-1);
}

/*
 * Called with the memlist lock held to say that phys_install has
 * changed.
 */
void
phys_install_has_changed(void)
{
	/*
	 * Get the new address into a temporary just in case panicking
	 * involves use of ecache_flushaddr.
	 */
	uint64_t new_addr;

	new_addr = ecache_flush_address();
	if (new_addr == (uint64_t)-1) {
		cmn_err(CE_PANIC,
		    "ecache_flush_address(): failed, ecache_size=%x",
		    ecache_size);
		/*NOTREACHED*/
	}
	ecache_flushaddr = new_addr;
	membar_producer();
}
