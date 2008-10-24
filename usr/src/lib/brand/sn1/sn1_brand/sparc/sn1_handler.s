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

#include <sn1_misc.h>

#if defined(lint)

void
sn1_handler(void)
{
}

#else	/* !lint */

#define	PIC_SETUP(r)						\
	mov	%o7, %g1;					\
9:	call	8f;						\
	sethi	%hi(_GLOBAL_OFFSET_TABLE_ - (9b - .)), r;	\
8:	or	r, %lo(_GLOBAL_OFFSET_TABLE_ - (9b - .)), r;	\
	add	r, %o7, r;					\
	mov	%g1, %o7

/*
 * Translate a global symbol into an address.  The resulting address
 * is returned in the first register parameter.  The second register
 * is just for scratch space.
 */
#if defined(__sparcv9)
#define	GET_SYM_ADDR(r1, r2, name)		\
	PIC_SETUP(r1)				;\
	sethi	%hi(name), r2			;\
	or	r2, %lo(name), r2		;\
	ldn	[r2 + r1], r1
#else /* !__sparcv9 */
#define	GET_SYM_ADDR(r1, r2, name)		\
	PIC_SETUP(r1);			\
	ld	[r1 + name], r1
#endif /* !__sparcv9 */

	.section	".text"

	/*
	 * When we get here, %g1 should contain the system call and
	 * %g5 should contain the address immediately after the trap
	 * instruction.
	 */
	ENTRY_NP(sn1_handler)

	/*
	 * 64-bit sparc may need to save 3 parameters on the stack.
	 * 32-bit sparc may need to save 4 parameters on the stack.
	 *
	 * Our stack frame format is documented in sn1_misc.h.
	 */
	save	%sp, -SA(MINFRAME + EH_LOCALS_SIZE), %sp

	/*
	 * Save the current caller state into gregs and gwins.
	 * Note that this state isn't exact, %g1 and %g5 have been
	 * already been lost.  Also, we've pushed a stack frame so
	 * the callers output registers are our input registers.
	 */
	stn	%g0, [%sp + EH_LOCALS_GREG(REG_G1)]	/* %g1 is lost */
	stn	%g2, [%sp + EH_LOCALS_GREG(REG_G2)]
	stn	%g3, [%sp + EH_LOCALS_GREG(REG_G3)]
	stn	%g4, [%sp + EH_LOCALS_GREG(REG_G4)]
	stn	%g0, [%sp + EH_LOCALS_GREG(REG_G5)]	/* %g5 is lost */
	stn	%g6, [%sp + EH_LOCALS_GREG(REG_G6)]
	stn	%g7, [%sp + EH_LOCALS_GREG(REG_G7)]
	stn	%i0, [%sp + EH_LOCALS_GREG(REG_O0)]
	stn	%i1, [%sp + EH_LOCALS_GREG(REG_O1)]
	stn	%i2, [%sp + EH_LOCALS_GREG(REG_O2)]
	stn	%i3, [%sp + EH_LOCALS_GREG(REG_O3)]
	stn	%i4, [%sp + EH_LOCALS_GREG(REG_O4)]
	stn	%i5, [%sp + EH_LOCALS_GREG(REG_O5)]
	stn	%i6, [%sp + EH_LOCALS_GREG(REG_O6)]
	stn	%i7, [%sp + EH_LOCALS_GREG(REG_O7)]
	sub	%g5, 4, %o0
	stn	%o0, [%sp + EH_LOCALS_GREG(REG_PC)]
	stn	%g5, [%sp + EH_LOCALS_GREG(REG_nPC)]
	rd	%y, %o0
	stn	%o0, [%sp + EH_LOCALS_GREG(REG_Y)]
#if defined(__sparcv9)
	stn	%g0, [%sp + EH_LOCALS_GREG(REG_ASI)]
	rd	%fprs, %o0
	stn	%o0, [%sp + EH_LOCALS_GREG(REG_FPRS)]
#endif /* __sparcv9 */

	/*
	 * Look up the system call's entry in the sysent table
	 * and obtain the address of the proper emulation routine (%l2).
	 */
	mov	%g1, %l5			/* save syscall number */
	GET_SYM_ADDR(%l1, %l2, sn1_sysent_table)
	mov	%l5, %g1			/* restore syscall number */
	sll	%g1, (1 + CLONGSHIFT), %l2	/* Each entry has 2 longs */
	add	%l2, %l1, %l2			/* index to proper entry */
	ldn	[%l2], %l2			/* emulation func address */

	/*
	 * Look up the system call's entry in the sysent table,
	 * taking into account the posibility of indirect system calls, and
	 * obtain the number of arguments (%l4) and return value flag (%l3).
	 */
#if defined(__sparcv9)
	mov	%g1, %l3			/* %g1 == syscall number */
#else /* !__sparcv9 */
	/*
	 * Check for indirect system calls, in which case the real syscall
	 * number is the first parameter to the indirect system call.
	 */
	cmp	%g1, %g0			/* saved syscall number */
	bne,a,pt %icc, no_indir			/* indirect syscall? */
	mov	%g1, %l3			/* %g1 == syscall number */
	mov	%i0, %l3			/* %i0 == syscall number */
no_indir:
#endif /* !__sparcv9 */
	sll	%l3, (1 + CLONGSHIFT), %l3	/* Each entry has 2 longs */
	add	%l3, %l1, %l3			/* index to proper entry */
	ldn	[%l3 + CPTRSIZE], %l4		/* number of args + rv flag */
	sethi	%hi(RV_MASK), %l5
	or	%l5, %lo(RV_MASK), %l5
	andcc	%l4, %l5, %l3			/* strip out number of args*/
	andcc	%l4, NARGS_MASK, %l4		/* strip out rv flag */

	/*
	 * Setup arguments for our emulation call.  Our input arguments,
	 * 0 to N, will become emulation call arguments 1 to N+1.
	 * %l4 == number of arguments.
	 */
	mov	%i0, %o1
	mov	%i1, %o2
	mov	%i2, %o3
	mov	%i3, %o4
	mov	%i4, %o5

	/* 7th argument and above get passed on the stack */
	cmp	%l4, 0x6
	bl,pt	%ncc, args_copied
	nop
	stn	%i5, [%sp + EH_ARGS_OFFSET(0)]	/* copy 6th syscall arg */
	cmp	%l4, 0x7
	bl,pt	%ncc, args_copied
	nop
	ldn	[%fp + EH_ARGS_OFFSET(0)], %l5	/* copy 7th syscall arg */
	stn	%l5, [%sp + EH_ARGS_OFFSET(1)]
	cmp	%l4, 0x8
	bl,pt	%ncc, args_copied
	nop
	ldn	[%fp + EH_ARGS_OFFSET(1)], %l5
	stn	%l5, [%sp + EH_ARGS_OFFSET(2)]	/* copy 8th syscall arg */
#if !defined(__sparcv9)
	cmp	%l4, 0x9
	bl,pt	%ncc, args_copied
	nop
	ldn	[%fp + EH_ARGS_OFFSET(2)], %l5
	stn	%l5, [%sp + EH_ARGS_OFFSET(3)]	/* copy 9th syscall arg */
#endif /* !__sparcv9 */

args_copied:
	/*
	 * The first parameter to the emulation callback function is a
	 * pointer to a sysret_t structure.
	 *
	 * invoke the emulation routine.
	 */
	ALTENTRY(sn1_handler_savepc)
	call	%l2
	add	%sp, EH_LOCALS_SYSRET, %o0	/* arg0 == sysret_t ptr */

	/* Check for syscall emulation success or failure */
	cmp	%g0, %o0
	be	success
	nop
	subcc   %g0, 1, %g0			/* failure, set carry flag */
	ba	return
	mov	%o0, %i0			/* return, %o0 == errno */

success:
	/* There is always at least one return value. */
	ldn	[%sp + EH_LOCALS_SYSRET1], %i0	/* %i0 == sys_rval1 */
	cmp	%l3, RV_DEFAULT			/* check rv flag */
	be,a	clear_carry
	mov	%g0, %i1			/* clear second rval */
	ldn	[%sp + EH_LOCALS_SYSRET2], %i1	/* %i1 == sys_rval2 */
clear_carry:
	addcc	%g0, %g0, %g0			/* success, clear carry flag */

return:
	/*
	 * Our syscall emulation is complete.  Return to the caller that
	 * originally invoked a system which needed emulation.  Note that
	 * we have to load the return address that we saved earlier because
	 * it's possible that %g5 was overwritten by a nested call into
	 * this emulation library.
	 */
	ldn	[%sp + EH_LOCALS_GREG(REG_nPC)], %g5
	jmp	%g5
	restore					/* delay slot */
	SET_SIZE(sn1_handler)


#endif	/* !lint */
