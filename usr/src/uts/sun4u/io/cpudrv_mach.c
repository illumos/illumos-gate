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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * CPU power management driver support for sun4u.
 */
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cpudrv_mach.h>
#include <sys/machsystm.h>

boolean_t cpudrv_enabled = B_TRUE;

/*
 * Change CPU speed.
 */
int
cpudrv_pm_change_speed(cpudrv_devstate_t *cpudsp, cpudrv_pm_spd_t *new_spd)
{
	xc_one(cpudsp->cpu_id, (xcfunc_t *)cpu_change_speed, \
	    (uint64_t)new_spd->speed, 0);
	return (DDI_SUCCESS);
}

/*
 * Determine the cpu_id for the CPU device.
 */
boolean_t
cpudrv_pm_get_cpu_id(dev_info_t *dip,  processorid_t *cpu_id)
{
	return (dip_to_cpu_id(dip, cpu_id) == DDI_SUCCESS);
}

/*
 * A noop for this machine type.
 */
boolean_t
cpudrv_pm_power_ready(void)
{
	return (B_TRUE);
}

/*
 * A noop for this machine type.
 */
/* ARGSUSED */
boolean_t
cpudrv_pm_is_governor_thread(cpudrv_pm_t *cpupm)
{
	return (B_FALSE);
}

/*
 * A noop for this machine type.
 */
/*ARGSUSED*/
boolean_t
cpudrv_mach_pm_init(cpudrv_devstate_t *cpudsp)
{
	return (B_TRUE);
}

/*
 * A noop for this machine type.
 */
/*ARGSUSED*/
void
cpudrv_mach_pm_free(cpudrv_devstate_t *cpudsp)
{
}

/*
 * On SPARC all instances support power management unless attach fails.
 * In the case of attach failure, cpupm_enabled will be false.
 */
boolean_t
cpudrv_pm_enabled()
{
	return (B_TRUE);
}
