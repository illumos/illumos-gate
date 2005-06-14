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
#include <sys/cpu_module.h>
#include <sys/dtrace.h>
#include <sys/cpu_sgnblk_defs.h>

/*
 * Useful for disabling MP bring-up for an MP capable kernel
 * (a kernel that was built with MP defined)
 */
int use_mp = 1;			/* set to come up mp */

/*
 * Init CPU info - get CPU type info for processor_info system call.
 */
void
init_cpu_info(struct cpu *cp)
{
	processor_info_t *pi = &cp->cpu_type_info;
	int cpuid = cp->cpu_id;
	struct cpu_node *cpunode = &cpunodes[cpuid];
	char buf[CPU_IDSTRLEN];

	cp->cpu_fpowner = NULL;		/* not used for V9 */

	/*
	 * Get clock-frequency property from cpunodes[] for the CPU.
	 */
	pi->pi_clock = (cpunode->clock_freq + 500000) / 1000000;

	(void) strcpy(pi->pi_processor_type, "sparcv9");
	(void) strcpy(pi->pi_fputypes, "sparcv9");

	(void) snprintf(buf, sizeof (buf),
	    "%s (cpuid %d clock %d MHz)",
	    cpunode->name, cpunode->cpuid, pi->pi_clock);

	cp->cpu_idstr = kmem_alloc(strlen(buf) + 1, KM_SLEEP);
	(void) strcpy(cp->cpu_idstr, buf);

	cmn_err(CE_CONT, "?cpu%d: %s\n", cpuid, cp->cpu_idstr);

	cp->cpu_brandstr = kmem_alloc(strlen(cpunode->name) + 1, KM_SLEEP);
	(void) strcpy(cp->cpu_brandstr, cpunode->name);

	/*
	 * StarFire requires the signature block stuff setup here
	 */
	CPU_SGN_MAPIN(cpuid);
	if (cpuid == cpu0.cpu_id) {
		/*
		 * cpu0 starts out running.  Other cpus are
		 * still in OBP land and we will leave them
		 * alone for now.
		 */
		CPU_SIGNATURE(OS_SIG, SIGST_RUN, SIGSUBST_NULL, cpuid);
#ifdef	lint
		cpuid = cpuid;
#endif	/* lint */
	}
}

/* ARGSUSED */
/*
 * Routine used to cleanup a CPU that has been powered off.  This will
 * destroy all per-cpu information related to this cpu.
 */
int
mp_cpu_unconfigure(int cpuid)
{
	return (0);
}

/* ARGSUSED */
int
mp_find_cpu(dev_info_t *dip, void *arg)
{
	return (0);
}

/* ARGSUSED */
/*
 * Routine used to setup a newly inserted CPU in preparation for starting
 * it running code.
 */
int
mp_cpu_configure(int cpuid)
{
	return (0);
}
