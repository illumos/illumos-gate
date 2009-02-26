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

/*
 * CPU power management driver support for sun4u.
 */
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cpupm.h>
#include <sys/cpudrv_mach.h>
#include <sys/machsystm.h>

/*
 * Change CPU speed.
 */
int
cpudrv_change_speed(cpudrv_devstate_t *cpudsp, cpudrv_pm_spd_t *new_spd)
{
	xc_one(cpudsp->cpu_id, (xcfunc_t *)cpu_change_speed, \
	    (uint64_t)new_spd->speed, 0);
	return (DDI_SUCCESS);
}

/*
 * Determine the cpu_id for the CPU device.
 */
boolean_t
cpudrv_get_cpu_id(dev_info_t *dip,  processorid_t *cpu_id)
{
	return (dip_to_cpu_id(dip, cpu_id) == DDI_SUCCESS);
}

/*
 * A noop for this machine type.
 */
boolean_t
cpudrv_power_ready(void)
{
	return (B_TRUE);
}

/*
 * A noop for this machine type.
 */
/* ARGSUSED */
boolean_t
cpudrv_is_governor_thread(cpudrv_pm_t *cpupm)
{
	return (B_FALSE);
}

/*
 * A noop for this machine type.
 */
/*ARGSUSED*/
boolean_t
cpudrv_mach_init(cpudrv_devstate_t *cpudsp)
{
	return (B_TRUE);
}

/*
 * On SPARC all instances support power management unless attach fails.
 * In the case of attach failure, cpudrv_enabled will be false.
 */
/*ARGSUSED*/
boolean_t
cpudrv_is_enabled(cpudrv_devstate_t *cpudsp)
{
	return (cpudrv_enabled);
}

void
cpudrv_set_supp_freqs(cpudrv_devstate_t *cpudsp)
{
	int		*speeds;
	uint_t		nspeeds;

	CPUDRV_GET_SPEEDS(cpudsp, speeds, nspeeds);
	if (nspeeds == 0)
		return;
	cpupm_set_supp_freqs(cpudsp->cp, speeds, nspeeds);
	CPUDRV_FREE_SPEEDS(speeds, nspeeds);
}
