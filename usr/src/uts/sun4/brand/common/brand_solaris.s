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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This is an assembly file that gets #include-ed into the brand-specific
 * assembly files (e.g. sn1_brand_asm.s) for Solaris-derived brands.
 * We can't make these into functions since in the trap context there's
 * no easy place to save the extra parameters that would be required, so
 * each brand module needs its own copy of this code.  We #include this and
 * use brand-specific #defines to replace the XXX_brand_... definitions.
 */ 

#ifdef lint

#include <sys/systm.h>

void
XXX_brand_syscall32_callback(void)
{
}

void
XXX_brand_syscall_callback(void)
{
}

#else   /* !lint */

#include <sys/asm_linkage.h>
#include <sys/machthread.h>
#include <sys/privregs.h>
#include "assym.h"

#ifdef _ASM	/* The remainder of this file is only for assembly files */

#if defined(sun4v)

#define	GLOBALS_SWAP(reg)				\
	rdpr	%gl, reg;				\
	wrpr	reg, 1, %gl

/*
 * The GLOBALS_RESTORE macro can only be one instruction since it's
 * used in a delay slot.
 */
#define	GLOBALS_RESTORE(reg)				\
	wrpr	reg, 0, %gl

#else /* !sun4v */

#define	GLOBALS_SWAP(reg)				\
	rdpr	%pstate, reg;				\
	wrpr	reg, PSTATE_AG, %pstate

/*
 * The GLOBALS_RESTORE macro can only be one instruction since it's
 * used in a delay slot.
 */
#define	GLOBALS_RESTORE(reg)				\
	wrpr	reg, %g0, %pstate

#endif /* !sun4v */

/*
 * Input parameters:
 * %g1: return point
 * %g2: pointer to our cpu structure
 */
ENTRY(XXX_brand_syscall32_callback)
	/*
	 * If the trapping thread has the address mask bit clear, then it's
	 * a 64-bit process, and has no business calling 32-bit syscalls.
	 */
	rdpr	%tstate, %g3;		/* %tstate.am is the trapping */
	andcc	%g3, TSTATE_AM, %g3;	/*   threads address mask bit */
	bne,pt	%xcc, _entry;
	nop;
	jmp	%g1;			/* 64 bit process, bail out */
	nop;
SET_SIZE(XXX_brand_syscall32_callback)

/*
 * Input parameters:
 * %g1: return point
 * %g2: pointer to our cpu structure
 */
ENTRY(XXX_brand_syscall_callback)
	/*
	 * If the trapping thread has the address mask bit set, then it's
	 * a 32-bit process, and has no business calling 64-bit syscalls.
	 */
	rdpr	%tstate, %g3;		/* %tstate.am is the trapping */
	andcc	%g3, TSTATE_AM, %g3;	/*   threads address mask bit */
	be,pt	%xcc, _entry;
	nop;
	jmp	%g1;			/* 32 bit process, bail out */
	nop;
SET_SIZE(XXX_brand_syscall_callback)

ENTRY(XXX_brand_syscall_callback_common)
_entry:
	/*
	 * Input parameters:
	 * %g1: return point
	 * %g2: pointer to our cpu structure
	 *
	 * Note that we're free to use any %g? registers as long as
	 * we are are executing with alternate globals.  If we're
	 * executing with user globals we need to backup any registers
	 * that we want to use so that we can restore them when we're
	 * done.
	 *
	 * Save some locals in the CPU tmp area to give us a little
	 * room to work.
	 */
	stn	%l0, [%g2 + CPU_TMP1];
	stn	%l1, [%g2 + CPU_TMP2];

#if defined(sun4v)
	/*
	 * On sun4v save our input parameters (which are stored in the
	 * alternate globals) since we'll need to switch between alternate
	 * globals and normal globals, and on sun4v the alternate globals
	 * are not preserved across these types of switches.
	 */
	stn	%l2, [%g2 + CPU_TMP3];
	stn	%l3, [%g2 + CPU_TMP4];

	mov	%g1, %l2;		/* save %g1 in %l2 */
	mov	%g2, %l3;		/* save %g2 in %l3 */
#endif /* sun4v */

	/*
	 * Switch from the alternate to user globals to grab the syscall
	 * number.
	 */
	GLOBALS_SWAP(%l0);		/* switch to normal globals */

	/*
	 * If the system call number is >= 1024, then it is a native
	 * syscall that doesn't need emulation.
	 */
	cmp	%g1, 1024;		/* is this a native syscall? */
	bl,a	_indirect_check;	/* probably not, continue checking */
	mov	%g1, %l1;		/* delay slot - grab syscall number */

	/*
	 * This is a native syscall, probably from the emulation library.
	 * Subtract 1024 from the syscall number and let it go through.
	 */
	sub	%g1, 1024, %g1;		/* convert magic num to real syscall */
	ba	_exit;			/* jump back into syscall path */
	GLOBALS_RESTORE(%l0);		/* delay slot - */
					/* switch back to alternate globals */

_indirect_check:
	/*
	 * If the system call number is 0 (SYS_syscall), then this might be
	 * an indirect syscall, in which case the actual syscall number
	 * would be stored in %o0, in which case we need to redo the
	 * the whole >= 1024 check.
	 */
	brnz,pt %g1, _emulation_check;	/* is this an indirect syscall? */
	nop;				/* if not, goto the emulation check */

	/*
	 * Indirect syscalls are only supported for 32 bit processes so
	 * consult the tstate address mask again.
	 */
	rdpr	%tstate, %l1;		/* %tstate.am is the trapping */
	andcc	%l1, TSTATE_AM, %l1;	/*   threads address mask bit */
	be,a,pn	%xcc, _exit;
	GLOBALS_RESTORE(%l0);		/* delay slot -	*/
					/* switch back to alternate globals */

	/*
	 * The caller is 32 bit and this an indirect system call.
	 */
	cmp	%o0, 1024;		/* is this a native syscall? */
	bl,a	_emulation_check;	/* no, goto the emulation check */
	mov	%o0, %l1;		/* delay slot - grab syscall number */

	/*
	 * This is native indirect syscall, probably from the emulation
	 * library.  Subtract 1024 from the syscall number and let it go
	 * through.
	 */
	sub	%o0, 1024, %o0;		/* convert magic num to real syscall */
	ba	_exit;			/* jump back into syscall path */
	GLOBALS_RESTORE(%l0);		/* delay slot - */
					/* switch back to alternate globals */

_emulation_check:
	GLOBALS_RESTORE(%l0);		/* switch back to alternate globals */

	/*
	 * Check to see if we want to interpose on this system call.  If
	 * not, we jump back into the normal syscall path and pretend
	 * nothing happened.  %l1 contains the syscall we're invoking.
	 */
	set	XXX_emulation_table, %g3;
	ldn	[%g3], %g3;
	add	%g3, %l1, %g3;
	ldub	[%g3], %g3;
	brz	%g3, _exit;
	nop;

	/*
	 * Find the address of the userspace handler.
	 * cpu->cpu_thread->t_procp->p_brand_data->spd_handler.
	 */
#if defined(sun4v)
	/* restore the alternate global registers after incrementing %gl */
	mov	%l3, %g2;
#endif /* sun4v */
	ldn	[%g2 + CPU_THREAD], %g3;	/* get thread ptr */
	ldn	[%g3 + T_PROCP], %g4;		/* get proc ptr */
	ldn	[%g4 + P_BRAND_DATA], %g5;	/* get brand data ptr */
	ldn	[%g5 + SPD_HANDLER], %g5;	/* get userland brnd hdlr ptr */
	brz	%g5, _exit;			/* has it been set? */
	nop;

	/*
	 * Make sure this isn't an agent lwp.  We can't do syscall
	 * interposition for system calls made by a agent lwp.  See
	 * the block comments in the top of the brand emulation library
	 * for more information.
	 */
	ldn	[%g4 + P_AGENTTP], %g4;		/* get agent thread ptr */
	cmp	%g3, %g4;			/* is this an agent thread? */
	be,pn	%xcc, _exit;			/* if so don't emulate */
	nop;

	/*
	 * Now the magic happens.  Grab the trap return address and then
	 * reset it to point to the user space handler.  When we execute
	 * the 'done' instruction, we will jump into our handler instead of
	 * the user's code.  We also stick the old return address in %g5,
	 * so we can return to the proper instruction in the user's code.
	 * Note: we also pass back the base address of the syscall
	 * emulation table.  This is a performance hack to avoid having to
	 * look it up on every call.
	 */
	rdpr	%tnpc, %l1;		/* save old tnpc */
	wrpr	%g0, %g5, %tnpc;	/* setup tnpc */
	GLOBALS_SWAP(%l0);		/* switch to normal globals */
	mov	%l1, %g5;		/* pass tnpc to user code in %g5 */
	GLOBALS_RESTORE(%l0);		/* switch back to alternate globals */

	/* Update the address we're going to return to */
#if defined(sun4v)
	set	fast_trap_done_chk_intr, %l2;
#else /* !sun4v */
	set	fast_trap_done_chk_intr, %g1;
#endif /* !sun4v */

_exit:
	/*
	 * Restore registers before returning.
	 *
	 * Note that %g2 should be loaded with the CPU struct addr and
	 * %g1 should be loaded the address we're going to return to.
	 */
#if defined(sun4v)
	/* restore the alternate global registers after incrementing %gl */
	mov	%l2, %g1;		/* restore %g1 from %l2 */
	mov	%l3, %g2;		/* restore %g2 from %l3 */

	ldn	[%g2 + CPU_TMP4], %l3;	/* restore locals */
	ldn	[%g2 + CPU_TMP3], %l2;
#endif /* sun4v */

	ldn	[%g2 + CPU_TMP2], %l1;	/* restore locals */
	ldn	[%g2 + CPU_TMP1], %l0;

	jmp	%g1;
	nop;
SET_SIZE(XXX_brand_syscall_callback_common)

#endif	/* _ASM */
#endif	/* !lint */
