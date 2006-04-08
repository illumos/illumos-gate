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

#include <sys/types.h>
#include <sys/machsystm.h>
#include <sys/x_call.h>
#include <sys/cmp.h>
#include <sys/debug.h>
#include <sys/chip.h>
#include <sys/cheetahregs.h>

/*
 * Note: We assume that chipid == portid.  This is not necessarily true.
 * We buried it down here in the implementation, and not in the
 * interfaces, so that we can change it later.
 */

/*
 * pre-alloc'ed because this is used early in boot (before the memory
 * allocator is available).
 */
static cpuset_t chips[MAX_CPU_CHIPID];

/*
 * Returns 1 if cpuid is CMP-capable, 0 otherwise.
 */
int
cmp_cpu_is_cmp(processorid_t cpuid)
{
	chipid_t chipid;

	/* N.B. We're assuming that the cpunode[].portid is still intact */
	chipid = cpunodes[cpuid].portid;
	return (!CPUSET_ISNULL(chips[chipid]));
}

/*
 * Indicate that this core (cpuid) resides on the chip indicated by chipid.
 * Called during boot and DR add.
 */
void
cmp_add_cpu(chipid_t chipid, processorid_t cpuid)
{
	CPUSET_ADD(chips[chipid], cpuid);
}

/*
 * Indicate that this core (cpuid) is being DR removed.
 */
void
cmp_delete_cpu(processorid_t cpuid)
{
	chipid_t chipid;

	/* N.B. We're assuming that the cpunode[].portid is still intact */
	chipid = cpunodes[cpuid].portid;
	CPUSET_DEL(chips[chipid], cpuid);
}

/*
 * Called when cpuid is being onlined or offlined.  If the offlined
 * processor is CMP-capable then current target of the CMP Error Steering
 * Register is set to either the lowest numbered on-line sibling core, if
 * one exists, or else to this core.
 */
/* ARGSUSED */
void
cmp_error_resteer(processorid_t cpuid)
{
#ifndef	_CMP_NO_ERROR_STEERING
	cpuset_t mycores;
	cpu_t *cpu;
	chipid_t chipid;
	int i;

	if (!cmp_cpu_is_cmp(cpuid))
	    return;

	ASSERT(MUTEX_HELD(&cpu_lock));
	chipid = cpunodes[cpuid].portid;
	mycores = chips[chipid];

	/* Look for an online sibling core */
	for (i = 0; i < NCPU; i++) {
		if (i == cpuid)
			continue;

		if (CPU_IN_SET(mycores, i) &&
		    (cpu = cpu_get(i)) != NULL && cpu_is_active(cpu)) {
			/* Found one, reset error steering  */
			xc_one(i, (xcfunc_t *)set_cmp_error_steering, 0, 0);
			break;
		}
	}

	/* No online sibling cores, point to this core.  */
	if (i == NCPU) {
		xc_one(cpuid, (xcfunc_t *)set_cmp_error_steering, 0, 0);
	}
#else
	/* Not all CMP's support (e.g. Olympus-C by Fujitsu) error steering */
	return;
#endif /* _CMP_NO_ERROR_STEERING */
}

chipid_t
cmp_cpu_to_chip(processorid_t cpuid)
{
	if (!cmp_cpu_is_cmp(cpuid)) {
		/* This CPU is not a CMP, so by definition chipid==cpuid */
		ASSERT(cpuid < MAX_CPU_CHIPID && CPUSET_ISNULL(chips[cpuid]));
		return (cpuid);
	}

	/* N.B. We're assuming that the cpunode[].portid is still intact */
	return (cpunodes[cpuid].portid);
}

/*
 * Return a chip "id" for the given cpu_t
 * cpu_t's residing on the same physical processor
 * should map to the same "id"
 */
chipid_t
chip_plat_get_chipid(cpu_t *cp)
{
	return (cmp_cpu_to_chip(cp->cpu_id));
}

/*
 * Return the "core id" for the given cpu_t
 * The "core id" space spans uniquely across all
 * cpu chips.
 */
id_t
chip_plat_get_coreid(cpu_t *cp)
{
	int impl;

	impl = cpunodes[cp->cpu_id].implementation;

	if (IS_OLYMPUS_C(impl)) {
		/*
		 * Currently only Fujitsu Olympus-c processor supports
		 * multi-stranded cores. Return the cpu_id with
		 * the strand bit masked out.
		 */
		return ((id_t)((uint_t)cp->cpu_id & ~(0x1)));
	} else {
		return (cp->cpu_id);
	}
}

void
chip_plat_define_chip(cpu_t *cp, chip_def_t *cd)
{
	int	impl;

	/*
	 * Define the chip's type
	 */
	impl = cpunodes[cp->cpu_id].implementation;

	if (IS_JAGUAR(impl)) {
		cd->chipd_type = CHIP_CMP_SPLIT_CACHE;
	} else if (IS_PANTHER(impl) || IS_OLYMPUS_C(impl)) {
		cd->chipd_type = CHIP_CMP_SHARED_CACHE;
	} else {
		cd->chipd_type = CHIP_DEFAULT;
	}

	/*
	 * Define any needed adjustment of rechoose_interval
	 * For now, all chips use the default. This
	 * will change with future processors.
	 */
	cd->chipd_rechoose_adj = 0;
}
