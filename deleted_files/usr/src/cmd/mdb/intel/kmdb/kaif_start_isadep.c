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

/*
 * The Intel-specific interface to the main CPU-control loops
 */

#include <sys/types.h>
#include <sys/trap.h>
#include <sys/segments.h>
#include <ia32/sys/psw.h>

#include <kmdb/kaif.h>
#include <kmdb/kaif_regs.h>
#include <kmdb/kaif_start.h>
#include <kmdb/kmdb_dpi_impl.h>
#include <kmdb/kmdb_kdi.h>
#include <mdb/mdb.h>

/*
 * We receive all breakpoints and single step traps.  Some of them,
 * including those from userland and those induced by DTrace providers,
 * are intended for the kernel, and must be processed there.  We adopt
 * this ours-until-proven-otherwise position due to the painful
 * consequences of sending the kernel an unexpected breakpoint or
 * single step.  Unless someone can prove to us that the kernel is
 * prepared to handle the trap, we'll assume there's a problem and will
 * give the user a chance to debug it.
 */
static int
kaif_trap_pass(kaif_cpusave_t *cpusave)
{
	kreg_t tt = cpusave->krs_gregs->kregs[KREG_TRAPNO];
	kreg_t pc = cpusave->krs_gregs->kregs[KREG_PC];
	kreg_t cs = cpusave->krs_gregs->kregs[KREG_CS];

	if (tt != T_BPTFLT && tt != T_SGLSTP)
		return (0);

	if (USERMODE(cs))
		return (1);

	if (tt == T_BPTFLT && kmdb_kdi_dtrace_get_state() ==
	    KDI_DTSTATE_DTRACE_ACTIVE)
		return (1);

	/*
	 * See the comments in the kernel's T_SGLSTP handler for why we need to
	 * do this.
	 */
	if (tt == T_SGLSTP &&
	    (pc == kaif_sys_sysenter || pc == kaif_brand_sys_sysenter))
		return (1);

	return (0);
}

/*
 * State has been saved, and all CPUs are on the CPU-specific stacks.  All
 * CPUs enter here, and head off to the slave spin loop or into the debugger
 * as appropriate.  This routine also handles the various flavors of resume.
 *
 * Returns 1 for the master CPU if there's work to be done by the driver, 0
 * otherwise.
 */
int
kaif_debugger_entry(kaif_cpusave_t *cpusave)
{
	if (kaif_trap_pass(cpusave)) {
		cpusave->krs_cpu_state = KAIF_CPU_STATE_NONE;
		return (KAIF_CPU_CMD_PASS_TO_KERNEL);
	}

	/*
	 * BPTFLT gives us control with %eip set to the instruction *after*
	 * the int 3.  Back it off, so we're looking at the instruction that
	 * triggered the fault.
	 */
	if (cpusave->krs_gregs->kregs[KREG_TRAPNO] == T_BPTFLT)
		cpusave->krs_gregs->kregs[KREG_PC]--;

	return (kaif_main_loop(cpusave));
}
