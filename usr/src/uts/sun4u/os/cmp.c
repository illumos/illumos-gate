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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/machsystm.h>
#include <sys/x_call.h>
#include <sys/cmp.h>
#include <sys/cmt.h>
#include <sys/debug.h>
#include <sys/disp.h>
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

/* ARGSUSED */
int
pg_plat_hw_shared(cpu_t *cp, pghw_type_t hw)
{
	int impl;

	impl = cpunodes[cp->cpu_id].implementation;

	switch (hw) {
	case PGHW_IPIPE:
		if ((IS_OLYMPUS_C(impl)) || (IS_JUPITER(impl)))
			return (1);
		break;
	case PGHW_CHIP:
		if (IS_JAGUAR(impl) || IS_PANTHER(impl) ||
		    IS_OLYMPUS_C(impl) || IS_JUPITER(impl))
			return (1);
		break;
	case PGHW_CACHE:
		if (IS_PANTHER(impl) || IS_OLYMPUS_C(impl) || IS_JUPITER(impl))
			return (1);
		break;
	}
	return (0);
}

int
pg_plat_cpus_share(cpu_t *cpu_a, cpu_t *cpu_b, pghw_type_t hw)
{
	int impl;

	impl = cpunodes[cpu_a->cpu_id].implementation;

	switch (hw) {
	case PGHW_IPIPE:
	case PGHW_CHIP:
		return (pg_plat_hw_instance_id(cpu_a, hw) ==
		    pg_plat_hw_instance_id(cpu_b, hw));
	case PGHW_CACHE:
		if ((IS_PANTHER(impl) || IS_OLYMPUS_C(impl) ||
		    IS_JUPITER(impl)) && pg_plat_cpus_share(cpu_a,
		    cpu_b, PGHW_CHIP)) {
			return (1);
		} else {
			return (0);
		}
	}
	return (0);
}

id_t
pg_plat_hw_instance_id(cpu_t *cpu, pghw_type_t hw)
{
	int impl;

	impl = cpunodes[cpu->cpu_id].implementation;

	switch (hw) {
	case PGHW_IPIPE:
		if (IS_OLYMPUS_C(impl) || IS_JUPITER(impl)) {
			/*
			 * Currently only Fujitsu Olympus-C (SPARC64-VI) and
			 * Jupiter (SPARC64-VII) processors support
			 * multi-stranded cores. Return the cpu_id with the
			 * strand bit masked out.
			 */
			return ((id_t)((uint_t)cpu->cpu_id & ~(0x1)));
		} else {
			return (cpu->cpu_id);
		}
	case PGHW_CHIP:
		return (cmp_cpu_to_chip(cpu->cpu_id));
	case PGHW_CACHE:
		if (IS_PANTHER(impl) ||
		    IS_OLYMPUS_C(impl) || IS_JUPITER(impl))
			return (pg_plat_hw_instance_id(cpu, PGHW_CHIP));
		else
			return (cpu->cpu_id);
	default:
		return (-1);
	}
}

/*
 * Rank the relative importance of optimizing for hw1 or hw2
 */
pghw_type_t
pg_plat_hw_rank(pghw_type_t hw1, pghw_type_t hw2)
{
	int i;
	int rank1 = 0;
	int rank2 = 0;

	static pghw_type_t hw_hier[] = {
		PGHW_IPIPE,
		PGHW_CHIP,
		PGHW_CACHE,
		PGHW_NUM_COMPONENTS
	};

	for (i = 0; hw_hier[i] != PGHW_NUM_COMPONENTS; i++) {
		if (hw_hier[i] == hw1)
			rank1 = i;
		if (hw_hier[i] == hw2)
			rank2 = i;
	}

	if (rank1 > rank2)
		return (hw1);
	else
		return (hw2);
}

/*
 * Override the default CMT dispatcher policy for the specified
 * hardware sharing relationship
 */
/* ARGSUSED */
pg_cmt_policy_t
pg_plat_cmt_policy(pghw_type_t hw)
{
	/* Accept the default polices */
	return (CMT_NO_POLICY);
}

id_t
pg_plat_get_core_id(cpu_t *cp)
{
	return (pg_plat_hw_instance_id(cp, PGHW_IPIPE));
}

void
cmp_set_nosteal_interval(void)
{
	/* Set the nosteal interval (used by disp_getbest()) to 100us */
	nosteal_nsec = 100000UL;
}
/*
 * Return 1 if CMT load balancing policies should be
 * implemented across instances of the specified hardware
 * sharing relationship.
 */
int
pg_cmt_load_bal_hw(pghw_type_t hw)
{
	if (hw == PGHW_IPIPE ||
	    hw == PGHW_FPU ||
	    hw == PGHW_CHIP)
		return (1);
	else
		return (0);
}
/*
 * Return 1 if thread affinity polices should be implemented
 * for instances of the specifed hardware sharing relationship.
 */
int
pg_cmt_affinity_hw(pghw_type_t hw)
{
	if (hw == PGHW_CACHE)
		return (1);
	else
		return (0);
}
