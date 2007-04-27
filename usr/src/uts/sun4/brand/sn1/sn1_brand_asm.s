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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if defined(lint)

#include <sys/systm.h>

#else	/* lint */

#include <sys/asm_linkage.h>
#include <sys/machthread.h>
#include <sys/privregs.h>
#include "assym.h"

#endif	/* lint */

#ifdef	lint

void
sn1_brand_syscall_callback(void)
{
}

#else	/* lint */

#ifdef sun4v

#define GLOBALS_SWAP(reg)				\
	rdpr	%gl, reg				;\
	wrpr	reg, 1, %gl

#define GLOBALS_RESTORE(reg)				\
	wrpr	reg, 0, %gl

#else /* !sun4v */

#define GLOBALS_SWAP(reg)				\
	rdpr	%pstate, reg				;\
	wrpr	reg, PSTATE_AG, %pstate

#define GLOBALS_RESTORE(reg)				\
	wrpr	reg, %g0, %pstate

#endif /* !sun4v */

	/*
	 * Input parameters:
	 * %g1: return point
	 * %g2: pointer to our cpu structure
	 */
	ENTRY(sn1_brand_syscall_callback)

	/*
	 * save some locals in the CPU tmp area to give us a little
	 * room to work.
	 */
	stn	%l0, [%g2 + CPU_TMP1]
	stn	%l1, [%g2 + CPU_TMP2]

#ifdef sun4v
	/*
	 * On sun4v save our input parameters (which are stored in the
	 * alternate globals) since we'll need to switch between alternate
	 * globals and normal globals, and on sun4v the alternate globals
	 * are not preserved across these types of switches.
	 */
	stn	%l2, [%g2 + CPU_TMP3]
	stn	%l3, [%g2 + CPU_TMP4]
	mov	%g1, %l2
	mov	%g2, %l3
#endif /* sun4v */

	/*
	 * Switch from the alternate to user globals to grab the syscall
	 * number, then switch back to the alternate globals.
	 *
	 * If the system call number is >= 1024, then it is coming from the
	 * emulation support library and should not be emulated.
	 */
	GLOBALS_SWAP(%l0)		! switch to normal globals
	cmp	%g1, 1024		! is this call from the library?
	bl,a	1f
	mov	%g1, %l1		! delay slot - grab syscall number
	sub	%g1, 1024, %g1		! convert magic num to real syscall
	ba	2f			! jump back into syscall path
1:
	GLOBALS_RESTORE(%l0)		! delay slot -
					! switch back to alternate globals

	/*
	 * Check to see if we want to interpose on this system call.  If
	 * not, we jump back into the normal syscall path and pretend
	 * nothing happened.
	 */
	set	sn1_emulation_table, %g3
	ldn	[%g3], %g3
	add	%g3, %l1, %g3
	ldub	[%g3], %g3
	brz	%g3, 2f
	nop

	/*
	 * Find the address of the userspace handler.
	 * cpu->cpu_thread->t_procp->p_brandhdlr.
	 */
#ifdef sun4v
	! restore the alternate global registers after incrementing %gl
	mov	%l3, %g2
#endif /* sun4v */
	ldn	[%g2 + CPU_THREAD], %g3		! load thread pointer
	ldn	[%g3 + T_PROCP], %g3		! get proc pointer
	ldn	[%g3 + P_BRAND_DATA], %g3	! get brand handler
	brz	%g3, 2f				! has it been set?
	nop

	/*
	 * Now the magic happens.  Grab the trap return address and then
	 * reset it to point to the user space handler.  When we execute
	 * the 'done' instruction, we will jump into our handler instead of
	 * the user's code.  We also stick the old return address in %g6,
	 * so we can return to the proper instruction in the user's code.
	 * Note: we also pass back the base address of the syscall
	 * emulation table.  This is a performance hack to avoid having to
	 * look it up on every call.
	 */
	rdpr	%tnpc, %l1		! save old tnpc
	wrpr	%g0, %g3, %tnpc		! setup tnpc
	GLOBALS_SWAP(%l0)		! switch to normal globals
	mov	%l1, %g6		! pass tnpc to user code in %g6
	GLOBALS_RESTORE(%l0)		! switch back to alternate globals

	/* Update the address we're going to return to */
#ifdef sun4v
	set	fast_trap_done_chk_intr, %l2
#else /* !sun4v */
	set	fast_trap_done_chk_intr, %g1
#endif /* !sun4v */

2:
	/*
	 * Restore registers before returning.
	 *
	 * Note that %g2 should be loaded with the CPU struct addr and
	 * %g1 should be loaded the address we're going to return to.
	 */
#ifdef sun4v
	! restore the alternate global registers after incrementing %gl
	mov	%l3, %g2
	mov	%l2, %g1

	ldn	[%g2 + CPU_TMP4], %l3	! restore locals
	ldn	[%g2 + CPU_TMP3], %l2
#endif /* sun4v */

	ldn	[%g2 + CPU_TMP2], %l1	! restore locals
	ldn	[%g2 + CPU_TMP1], %l0

	jmp	%g1
	nop
	SET_SIZE(sn1_brand_syscall_callback)
#endif	/* lint */
