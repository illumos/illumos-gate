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

#include "assym.h"

#include <sys/asm_linkage.h>
#include <sys/machthread.h>
#include <sys/param.h>
#include <sys/vm_machparam.h>
#include <sys/privregs.h>
#include <sys/intreg.h>
#include <sys/vis.h>
#include <sys/clock.h>
#include <vm/hat_sfmmu.h>

	.weak	cpu_feature_init
	.type	cpu_feature_init, #function

	.weak	cpu_early_feature_init
	.type	cpu_early_feature_init, #function

/*
 * Processor initialization
 *
 * This is the kernel entry point for other cpus except the first one.
 * When the prom jumps to this location we are still executing with the
 * prom's trap table.  It expects the cpuid as its first parameter.
 */

	! allocate a temporary stack to run on while we figure who and
	! what we are.
	.seg	".data"
	.align	8
etmpstk:
	.skip	2048
tmpstk:
	.word	0

	ENTRY_NP(cpu_startup)
	!
	! Initialize CPU state registers
	!
	! The boot cpu and other cpus are different.  The boot cpu has gone
	! through boot, and its state might be affected as a result.  The
	! other cpus' states come directly from the prom.
	!
	wrpr	%g0, PSTATE_KERN, %pstate
	wr	%g0, %g0, %fprs		! clear fprs
	CLEARTICKNPT			! allow user rdtick

	!
	! Set up temporary stack
	!
	set	tmpstk, %g1
	sub	%g1, SA(KFPUSIZE+GSR_SIZE), %g2
	and	%g2, 0x3F, %g3
	sub	%g2, %g3, %o2
	sub	%o2, SA(MINFRAME) + STACK_BIAS, %sp

	mov	%o0, %l1		! save cpuid

	call	sfmmu_mp_startup
	sub	%g0, 1, THREAD_REG	! catch any curthread acceses

	! On OPL platforms, context page size TLB programming must be enabled in
	! ASI_MEMCNTL.  To avoid Olympus-C and Jupiter sTLB errata (strands with
	! different TLB page size settings), this must be done here before any
	! reference to non-nucleus memory.  An early hook is added to perform
	! cpu specific initialization.
	!
	sethi	%hi(cpu_early_feature_init), %o0
	or	%o0, %lo(cpu_early_feature_init), %o0
	brz	%o0, 0f
	nop
	call	%o0
	nop

0:
	! SET_KCONTEXTREG(reg0, reg1, reg2, reg3, reg4, label1, label2, label3)
	SET_KCONTEXTREG(%o0, %g1, %g2, %g3, %l3, l1, l2, l3)

	! We are now running on the kernel's trap table.
	!
	! It is very important to have a thread pointer and a cpu struct
	! *before* calling into C routines .
	! Otherwise, overflow/underflow handlers, etc. can get very upset!
	!
	!
	! We don't want to simply increment
	! ncpus right now because it is in the cache, and
	! we don't have the cache on yet for this CPU.
	!
	set	cpu, %l3
	sll	%l1, CPTRSHIFT, %l2	! offset into CPU vector.
	ldn	[%l3 + %l2], %l3	! pointer to CPU struct
	ldn	[%l3 + CPU_THREAD], THREAD_REG	! set thread pointer (%g7)

	!
	! Set up any required cpu feature
	!
	sethi	%hi(cpu_feature_init), %o0
	or	%o0, %lo(cpu_feature_init), %o0
	brz	%o0, 1f
	nop
	call	%o0
	nop

1:
	!
	! Resume the thread allocated for the CPU.
	!
 	ldn	[THREAD_REG + T_PC], %i7
	ldn	[THREAD_REG + T_SP], %fp
	ret				! "return" into the thread
	restore				! WILL cause underflow
	SET_SIZE(cpu_startup)

