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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/machsystm.h>
#include <sys/cmp.h>
#include <sys/chip.h>

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
	return (0);
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

/*ARGSUSED*/
void
chip_plat_define_chip(cpu_t *cp, chip_def_t *cd)
{
	cd->chipd_type = CHIP_CMT;

	/*
	 * Define any needed adjustment of rechoose_interval
	 * For now, all chips use the default. This
	 * will change with future processors.
	 */
	cd->chipd_rechoose_adj = 0;
	cd->chipd_nosteal = 0;
}

/*
 * Return a pipeline "id" for the given cpu_t
 * cpu_t's sharing the same instruction pipeline
 * should map to the same "id"
 */

id_t
chip_plat_get_coreid(cpu_t *cp)
{
	return (cp->cpu_m.cpu_ipipe);
}
