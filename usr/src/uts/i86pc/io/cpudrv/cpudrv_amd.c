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
 * AMD specific CPU power management support.
 */

#include <sys/x86_archext.h>
#include <sys/cpudrv_mach.h>
#include <sys/cpu_acpi.h>
#include <sys/pwrnow.h>

boolean_t
cpudrv_amd_init(cpudrv_devstate_t *cpudsp)
{
	cpudrv_mach_state_t *mach_state = cpudsp->mach_state;

	/* AMD? */
	if (x86_vendor != X86_VENDOR_AMD)
		return (B_FALSE);

	/*
	 * If we support PowerNow! on this processor, then set the
	 * correct pstate_ops for the processor.
	 */
	mach_state->cpupm_pstate_ops = pwrnow_supported() ? &pwrnow_ops : NULL;

	return (B_TRUE);
}
