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
 *	Copyright (c) 1991,1992 by Sun Microsystems, Inc.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"machdep.h"
#if	defined(lint)
#include	<sys/types.h>
#include	"sgs.h"
#include	"_a.out.h"
#else

	.file	"boot_a.out.s"
	.seg	".text"
#endif

/*
 * We got here because the initial call to a function resolved to a procedure
 * linkage table entry.  That entry did a branch to the first PLT entry, which
 * in turn did a call to aout_rtbndr (refer aout_plt_init()).
 *
 * the code sequence that got us here was:
 *
 * PLT entry for foo():
 *	save	%sp, -0x60, %sp			! patched first
 *	call	.PLT0				! patched second
 *	sethi	%hi(XXXXXXX), %g0		! unchanged
 *
 * Therefore on entry, %i7 has the address of the call, which will be added
 * to the offset to the plt entry in %g1 to calculate the plt entry address
 * we must also subtract 4 for because the address of PLT0 points to the
 * save instruction before the call
 *
 * the plt entry is rewritten:
 *
 * PLT entry for foo():
 *	sethi	%hi(entry_pt), %g1
 *	jmpl	%g1 + %lo(entry_pt), %g0
 */

#if	defined(lint)

void
aout_rtbndr(caddr_t pc)
{
	(void) aout_bndr(pc);
}

#else
	.global	aout_rtbndr
	.type   aout_rtbndr, #function
	.align	4

aout_rtbndr:
	save	%sp, -80, %sp
	call	aout_bndr		! returns function address in %o0
	add	%i7, -0x4, %o0		! %o0 now has address of PLT0
	mov	%o0, %g1		! save address of routine binded
	restore				! how many restores needed ? 2
	jmp	%g1			! jump to it
	restore
	nop
	.size	aout_rtbndr, . - aout_rtbndr

#endif


/*
 * After the first call to a plt, aout_bndr() will have determined the true
 * address of the function being bound.  The plt is now rewritten so that
 * any subsequent calls go directly to the bound function.
 *
 * the new plt entry is:
 *
 *	sethi	%hi(function address), %g1	! patched first
 *	jmpl	%g1 + %lo(function address, %g0	! patched second
 */

#if	defined(lint)

void
aout_plt_write(caddr_t pc, unsigned long symval)
{
	/* LINTED */
	*(unsigned long *)(pc) = (M_SETHIG1 | (symval >> (32 - 22)));
	/* LINTED */
	*(unsigned long *)(pc + 4) = (M_JMPL | (symval & S_MASK(10)));

}

#else
	.global	aout_plt_write
	.type	aout_plt_write, #function
	.align	4

aout_plt_write:
	srl	%o1, 10, %o2		! Get high part of function address
	sethi	%hi(M_SETHIG1), %o3	! Get sethi instruction
	or	%o3, %o2, %o3		! Add sethi and function address
	st	%o3, [%o0]		! Store instruction in plt[0]
	iflush  %o0
	stbar
	sethi	%hi(M_JMPL), %o3	! Get jmpl instruction
	and	%o1, 0x3ff, %o2		! Lower part of function address
	or	%o3, %o2, %o3		!	is or'ed into instruction
	st	%o3, [%o0 + 4]		! Store instruction in plt[1]
	retl
	iflush	%o0 + 4
	.size	aout_plt_write, . - aout_plt_write

#endif
