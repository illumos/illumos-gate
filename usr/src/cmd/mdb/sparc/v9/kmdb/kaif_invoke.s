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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>

#include <mdb/mdb_kreg.h>

/*
 * Kernel function call invocation
 */

#if !defined(__lint)

	.section	RODATA
	.align		8

	/*
	 * A jump table containing the addresses for register argument copy 
	 * code.
	 */
copyargs:
	.xword	cp0arg
	.xword	cp1arg
	.xword	cp2arg
	.xword	cp3arg
	.xword	cp4arg
	.xword	cp5arg
copyargsend:
	.xword	cp6arg

#endif	/* __lint */

#if defined(__lint)
/*ARGSUSED*/
uintptr_t
kaif_invoke(uintptr_t funcva, uint_t argc, const uintptr_t *argv, 
    kreg_t g6, kreg_t g7)
{
	return (0);
}
#else

	ENTRY_NP(kaif_invoke)

	save	%sp, -SA(MINFRAME), %sp

	/*
	 * Will registers suffice, or do we need to put excess args (>6) on the
	 * stack?
	 */
	sub	%i1, 6, %i1	! %i1 is now num regs over 6 (if any)
	brgz,pn	%i1, savestackargs
	sllx	%i1, 3, %i1	! (argc - 6) * 8

	/*
	 * We have fewer than six arguments.  Below, starting at the cp6arg 
	 * label, we've got code that'll copy these arguments to the out
	 * registers in descending order (%o5 is copied, then %o4, and so on).
	 * We only want to move valid arguments, so we'll jump into this copy
	 * code just before it copies our highest arg.  If we have four args,
	 * for example, we'll jump to cp4arg.
	 *
	 * %i6 is now a negative word-scaled offset, which we can use to
	 * retrieve the appropriate address from the jump table.  We start at
	 * bottom of the table, and let the negative offset jump back to the
	 * correct location.  If we have four arguments, %i1 will be -16.  
	 * Starting from copyargs+48 (the address of the last slot), we get
	 * copyargs+32, which contains the address (cp4arg) to be used to copy 
	 * four arguments.
	 */
	setx	copyargsend, %l1, %l0
	ldx	[%l0 + %i1], %l0
	jmp	%l0
	nop

savestackargs:	
	/*
	 * We have more than six arguments, and will thus need to allocate space
	 * for the seventh and beyond on the stack.  %i1 is the number of bytes
	 * needed to hold the seventh and higher arguments.
	 */

	/* Allocate swap space - %i1 rounded up to STACK_ALIGN */
	add	%i1, STACK_ALIGN/2, %g1
	and	%g1, -STACK_ALIGN, %g1
	sub	%sp, %g1, %sp

	add	%i2, 6*8, %l0			! %l0 is &argv[6]
	add	%sp, STACK_BIAS+MINFRAME, %l1	! %l1 is base of stack reg save

	/* 
	 * Copy arguments to the stack.  %i1 is the offset from the seventh arg
	 * in argv and the offset from the base of the stack save area.
	 */
	sub	%i1, 8, %i1
1:
	ldx	[%l0 + %i1], %l2
	stx	%l2, [%l1 + %i1]
	brnz,pt	%i1, 1b
	sub	%i1, 8, %i1

	/*
	 * Copy the register arguments.  The argc <= 6 case will be jumping to
	 * one of these labels.
	 */
cp6arg:	ldx	[%i2 + 5*8], %o5
cp5arg:	ldx	[%i2 + 4*8], %o4
cp4arg:	ldx	[%i2 + 3*8], %o3
cp3arg:	ldx	[%i2 + 2*8], %o2
cp2arg:	ldx	[%i2 + 1*8], %o1
cp1arg:	ldx	[%i2 + 0*8], %o0
cp0arg:

	mov	%g6, %l0
	mov	%i3, %g6	! Restore PROC_REG for kernel call

	mov	%g7, %l1
	mov	%i4, %g7	! Restore THREAD_REG for kernel call

	jmpl	%i0, %o7	! Make call
	nop

	mov	%l0, %g6
	mov	%l1, %g7

	ret
	restore	%g0, %o0, %o0

	SET_SIZE(kaif_invoke)
	
#endif
