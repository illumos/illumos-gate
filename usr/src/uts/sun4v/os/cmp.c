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
#include <sys/cmp.h>
#include <sys/cmt.h>

/*
 * Note: For now assume the chip ID as 0 for all the cpus until additional
 * information is available via machine description table
 */

/*
 * Returns 1 if cpuid is CMP-capable, 0 otherwise.
 */
/*ARGSUSED*/
int
cmp_cpu_is_cmp(processorid_t cpuid)
{
	return (0);
}

/*
 * Indicate that this core (cpuid) resides on the chip indicated by chipid.
 * Called during boot and DR add.
 */
/*ARGSUSED*/
void
cmp_add_cpu(chipid_t chipid, processorid_t cpuid)
{
}

/*
 * Indicate that this core (cpuid) is being DR removed.
 */
/*ARGSUSED*/
void
cmp_delete_cpu(processorid_t cpuid)
{
}

/*
 * Called when cpuid is being onlined or offlined.  If the offlined
 * processor is CMP-capable then current target of the CMP Error Steering
 * Register is set to either the lowest numbered on-line sibling core, if
 * one exists, or else to this core.
 */
/*ARGSUSED*/
void
cmp_error_resteer(processorid_t cpuid)
{
}

/*
 * Return 0, shortterm workaround until MD table is updated
 * to provide cpu-chip mapping
 */

/*ARGSUSED*/
chipid_t
cmp_cpu_to_chip(processorid_t cpuid)
{
	return (cpu[cpuid]->cpu_m.cpu_chip);
}

/*ARGSUSED*/
int
pg_plat_hw_shared(cpu_t *cp, pghw_type_t hw)
{
	switch (hw) {
	case PGHW_IPIPE:
		return (1);
	case PGHW_FPU:
		return (1);
	case PGHW_MPIPE:
		return (1);
	}
	return (0);
}

int
pg_plat_cpus_share(cpu_t *cpu_a, cpu_t *cpu_b, pghw_type_t hw)
{
	if (pg_plat_hw_shared(cpu_a, hw) == 0 ||
	    pg_plat_hw_shared(cpu_b, hw) == 0)
		return (0);

	return (pg_plat_hw_instance_id(cpu_a, hw) ==
	    pg_plat_hw_instance_id(cpu_b, hw));
}

id_t
pg_plat_hw_instance_id(cpu_t *cpu, pghw_type_t hw)
{
	switch (hw) {
	case PGHW_IPIPE:
		return (cpu->cpu_m.cpu_ipipe);
	case PGHW_CHIP:
		return (cpu->cpu_m.cpu_chip);
	case PGHW_MPIPE:
		return (cpu->cpu_m.cpu_mpipe);
	case PGHW_FPU:
		return (cpu->cpu_m.cpu_fpu);
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
		PGHW_FPU,
		PGHW_MPIPE,
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
	/* Accept the default policies */
	return (CMT_NO_POLICY);
}

id_t
pg_plat_get_core_id(cpu_t *cpu)
{
	return (cpu->cpu_m.cpu_core);
}

void
cmp_set_nosteal_interval(void)
{
	nosteal_nsec = 0;
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
	    hw == PGHW_MPIPE)
		return (1);
	else
		return (0);
}
/*
 * Return 1 if thread affinity policies should be implemented
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
