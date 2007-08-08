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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<link.h>
#include	"machdep.h"
#include	"_audit.h"

#if	defined(lint)
#include	<sys/types.h>
#include	"_rtld.h"
#else
#include	<sys/stack.h>
#include	<sys/asm_linkage.h>

	.file	"boot_elf.s"
	.seg	".text"
#endif

/*
 * We got here because the initial call to a function resolved to a procedure
 * linkage table entry.  That entry did a branch to the first PLT entry, which
 * in turn did a call to elf_rtbndr (refer elf_plt_init()).
 *
 * the code sequence that got us here was:
 *
 * PLT entry for foo():
 *	sethi	(.-PLT0), %g1			! not changed by rtld
 *	ba,a	.PLT0				! patched atomically 2nd
 *	nop					! patched first
 *
 * Therefore on entry, %i7 has the address of the call, which will be added
 * to the offset to the plt entry in %g1 to calculate the plt entry address
 * we must also subtract 4 because the address of PLT0 points to the
 * save instruction before the call.
 *
 * the plt entry is rewritten:
 *
 * PLT entry for foo():
 *	sethi	(.-PLT0), %g1
 *	sethi	%hi(entry_pt), %g1
 *	jmpl	%g1 + %lo(entry_pt), %g0
 */

#if	defined(lint)

extern unsigned long	elf_bndr(Rt_map *, unsigned long, caddr_t);

static void
elf_rtbndr(Rt_map *lmp, unsigned long pltoff, caddr_t from)
{
	(void) elf_bndr(lmp, pltoff, from);
}


#else
	.weak	_elf_rtbndr		! keep dbx happy as it likes to
	_elf_rtbndr = elf_rtbndr	! rummage around for our symbols

	.global	elf_rtbndr
	.type   elf_rtbndr, #function
	.align	4

elf_rtbndr:
	mov	%i7, %o0		! Save callers address(profiling)
	save	%sp, -SA(MINFRAME), %sp	! Make a frame
	srl	%g1, 10, %o1		! shift offset set by sethi
					! %o1 has offset from jump slot
					! to PLT0 which will be used to
					! calculate plt relocation entry
					! by elf_bndr
	ld	[%i7 + 8], %o0		! %o0 has ptr to lm
	call	elf_bndr		! returns function address in %o0
	mov	%i0, %o2		! Callers address is arg 3
	mov	%o0, %g1		! save address of routine binded
	restore				! how many restores needed ? 2
	jmp	%g1			! jump to it
	restore
	.size 	elf_rtbndr, . - elf_rtbndr

#endif


#if defined(lint)
void
iflush_range(caddr_t addr, size_t len)
{
	/* LINTED */
	uintptr_t base;

	base = (uintptr_t)addr & ~7;	/* round down to 8 byte alignment */
	len = (len + 7) & ~7;		/* round up to multiple of 8 bytes */
	for (len -= 8; (long)len >= 0; len -= 8)
		/* iflush(base + len) */;
}
#else
	ENTRY(iflush_range)
	add	%o1, 7, %o1
	andn	%o0, 7, %o0
	andn	%o1, 7, %o1
1:	subcc	%o1, 8, %o1
	bge,a	1b
	iflush	%o0 + %o1
	retl
	nop
	SET_SIZE(iflush_range)
#endif

/*
 * Initialize the first plt entry so that function calls go to elf_rtbndr
 *
 * The first plt entry (PLT0) is:
 *
 *	save	%sp, -64, %sp
 *	call	elf_rtbndr
 *	nop
 *	address of lm
 */

#if	defined(lint)

void
elf_plt_init(void *plt, caddr_t lmp)
{
	*((uint_t *)plt + 0) = (unsigned long) M_SAVESP64;
	*((uint_t *)plt + 4) = M_CALL | (((unsigned long)elf_rtbndr -
			((unsigned long)plt)) >> 2);
	*((uint_t *)plt + 8) = M_NOP;
	*((uint_t *)plt + 12) = (unsigned long) lmp;
}

#else
	.global	elf_plt_init
	.type	elf_plt_init, #function
	.align	4

elf_plt_init:
	save	%sp, -SA(MINFRAME), %sp	! Make a frame
1:
	call	2f
	sethi	%hi((_GLOBAL_OFFSET_TABLE_ - (1b - .))), %l7
2:
	sethi	%hi(M_SAVESP64), %o0	! Get save instruction
	or	%o0, %lo(M_SAVESP64), %o0
	or	%l7, %lo((_GLOBAL_OFFSET_TABLE_ - (1b - .))), %l7
	st	%o0, [%i0]		! Store in plt[0]
	iflush	%i0
	add	%l7, %o7, %l7
	ld	[%l7 + elf_rtbndr], %l7
	inc	4, %i0			! Bump plt to point to plt[1]
	sub	%l7, %i0, %o0		! Determine -pc so as to produce
					! offset from plt[1]
	srl	%o0, 2, %o0		! Express offset as number of words
	sethi	%hi(M_CALL), %o4	! Get sethi instruction
	or	%o4, %o0, %o4		! Add elf_rtbndr address
	st	%o4, [%i0]		! Store instruction in plt
	iflush	%i0
	sethi	%hi(M_NOP), %o0		! Generate nop instruction
	st	%o0, [%i0 + 4]		! Store instruction in plt[2]
	iflush	%i0 + 4
	st	%i1, [%i0 + 8]		! Store instruction in plt[3]
	iflush	%i0 + 8
	ret
	restore
	.size	elf_plt_init, . - elf_plt_init
#endif

#if	defined(lint)

ulong_t
elf_plt_trace()
{
	return (0);
}
#else
	.global	elf_plt_trace
	.type   elf_plt_trace, #function
	.align	4

/*
 * The dyn_plt that called us has already created a stack-frame for
 * us and placed the following entries in it:
 *
 *	[%fp - 0x4]	* dyndata
 *	[%fp - 0x8]	* prev stack size
 *
 * dyndata currently contains:
 *
 *	dyndata:
 *	0x0	uintptr_t	*reflmp
 *	0x4	uintptr_t	*deflmp
 *	0x8	ulong_t		symndx
 *	0xc	ulong_t		sb_flags
 *	0x10	Sym		symdef.st_name
 *	0x14			symdef.st_value
 *	0x18			symdef.st_size
 *	0x1c			symdef.st_info
 *	0x1d			symdef.st_other
 *	0x1e			symdef.st_shndx
 */
#define	REFLMP_OFF		0x0
#define	DEFLMP_OFF		0x4
#define	SYMNDX_OFF		0x8
#define	SBFLAGS_OFF		0xc
#define	SYMDEF_OFF		0x10
#define	SYMDEF_VALUE_OFF	0x14

elf_plt_trace:
1:	call	2f
	sethi	%hi(_GLOBAL_OFFSET_TABLE_+(.-1b)), %l7
2:	or	%l7, %lo(_GLOBAL_OFFSET_TABLE_+(.-1b)), %l7
	add	%l7, %o7, %l7

	ld	[%l7+audit_flags], %l3
	ld	[%l3], %l3		! %l3 = audit_flags
	andcc	%l3, AF_PLTENTER, %g0
	beq	.end_pltenter
	ld	[%fp + -0x4], %l1	! l1 = * dyndata
	ld	[%l1 + SBFLAGS_OFF], %l2 ! l2 = sb_flags
	andcc	%l2, LA_SYMB_NOPLTENTER, %g0
	beq	.start_pltenter
	ld	[%l1 + SYMDEF_VALUE_OFF], %l0	! l0 =
						!  sym.st_value(calling address)
	ba	.end_pltenter
	nop

	/*
	 * save all registers into La_sparcv8_regs
	 */
.start_pltenter:
	sub	%sp, 0x20, %sp		! create space for La_sparcv8_regs
					! storage on the stack.

	sub	%fp, 0x28, %o4		

	st	%i0, [%o4]
	st	%i1, [%o4 + 0x4]
	st	%i2, [%o4 + 0x8]
	st	%i3, [%o4 + 0xc]	! because a regwindow shift has
	st	%i4, [%o4 + 0x10]	! already occured our current %i*
	st	%i5, [%o4 + 0x14]	! register's are the equivalent of
	st	%i6, [%o4 + 0x18]	! the %o* registers that the final
	st	%i7, [%o4 + 0x1c]	! procedure shall see.

	ld	[%fp + -0x4], %l1	! %l1 == * dyndata
	ld	[%l1 + REFLMP_OFF], %o0	! %o0 = reflmp
	ld	[%l1 + DEFLMP_OFF], %o1	! %o1 = deflmp
	add	%l1, SYMDEF_OFF, %o2	! %o2 = symp
	ld	[%l1 + SYMNDX_OFF], %o3	! %o3 = symndx
	call	audit_pltenter
	add	%l1, SBFLAGS_OFF, %o5	! %o3 = * sb_flags

	mov	%o0, %l0		! %l0 == calling address

	add	%sp, 0x20, %sp		! cleanup La_sparcv8_regs off
					! of the stack.

.end_pltenter:
	/*
	 * If *no* la_pltexit() routines exist we do not need to keep the
	 * stack frame before we call the actual routine.  Instead we jump to
	 * it and remove our self from the stack at the same time.
	 */
	ld	[%l7+audit_flags], %l3
	ld	[%l3], %l3		! %l3 = audit_flags
	andcc	%l3, AF_PLTEXIT, %g0
	beq	.bypass_pltexit
	ld	[%fp + -0x4], %l1	! %l1 = * dyndata
	ld	[%l1 + SBFLAGS_OFF], %l2 ! %l2 = sb_flags
	andcc	%l2, LA_SYMB_NOPLTEXIT, %g0
	bne	.bypass_pltexit
	nop

	ba	.start_pltexit
	nop
.bypass_pltexit:
	jmpl	%l0, %g0
	restore

.start_pltexit:
	/*
	 * In order to call la_pltexit() we must duplicate the
	 * arguments from the 'callers' stack on our stack frame.
	 *
	 * First we check the size of the callers stack and grow
	 * our stack to hold any of the arguments.  That need
	 * duplicating (these are arguments 6->N), because the
	 * first 6 (0->5) are passed via register windows on sparc.
	 */

	/*
	 * The first calculation is to determine how large the
	 * argument passing area might be.  Since there is no
	 * way to distinquish between 'argument passing' and
	 * 'local storage' from the previous stack this amount must
	 * cover both.
	 */
	ld	[%fp + -0x8], %l1	! %l1 = callers stack size
	sub	%l1, 0x58, %l1		! %l1 = argument space on caller's
					!	stack
	/*
	 * Next we compare the prev. stack size against the audit_argcnt.
	 * We copy at most 'audit_argcnt' arguments.
	 *
	 * NOTE: on sparc we always copy at least six args since these
	 *	 are in reg-windows and not on the stack.
	 *
	 * NOTE: Also note that we multiply (shift really) the arg count
	 *	 by 4 which is the 'word size' to calculate the amount
	 *	 of stack space needed.
	 */
	ld	[%l7 + audit_argcnt], %l2
	ld	[%l2], %l2		! %l2 = audit_arg_count
	cmp	%l2, 6
	ble	.grow_stack
	sub	%l2, 6, %l2
	sll	%l2, 2, %l2
	cmp	%l1, %l2
	ble	.grow_stack
	nop
	mov	%l2, %l1
.grow_stack:
	/*
	 * When duplicating the stack we skip the first '0x5c' bytes.
	 * This is the space on the stack reserved for preserving
	 * the register windows and such and do not need to be duplicated
	 * on this new stack frame.  We start duplicating at the
	 * portion of the stack reserved for argument's above 6.
	 */
	sub	%sp, %l1, %sp		! grow our stack by amount required.
	sra	%l1, 0x2, %l1		! %l1 = %l1 / 4 (words to copy)
	mov	0x5c, %l2		! %l2 = index into stack & frame

1:
	cmp	%l1, 0
	ble	2f
	nop
	ld	[%fp + %l2], %l3	! duplicate args from previous
	st	%l3, [%sp + %l2]	! stack onto current stack
	add	%l2, 0x4, %l2
	ba	1b
	sub	%l1, 0x1, %l1
2:
	mov	%i0, %o0		! copy ins to outs
	mov	%i1, %o1
	mov	%i2, %o2
	mov	%i3, %o3
	mov	%i4, %o4
	call	%l0			! call routine
	mov	%i5, %o5
	mov	%o1, %l2		! l2 = second 1/2 of return value
					! for those those 64 bit operations
					! link div64 - yuck...

					! %o0 = retval
	ld	[%fp + -0x4], %l1
	ld	[%l1 + REFLMP_OFF], %o1	! %o1 = reflmp
	ld	[%l1 + DEFLMP_OFF], %o2	! %o2 = deflmp
	add	%l1, SYMDEF_OFF, %o3	! %o3 = symp
	call	audit_pltexit
	ld	[%l1 + SYMNDX_OFF], %o4	! %o4 = symndx

	mov	%o0, %i0		! pass on return code
	mov	%l2, %i1
	ret
	restore
	.size	elf_plt_trace, . - elf_plt_trace

#endif

/*
 * After the first call to a plt, elf_bndr() will have determined the true
 * address of the function being bound.  The plt is now rewritten so that
 * any subsequent calls go directly to the bound function.  If the library
 * to which the function belongs is being profiled refer to _plt_cg_write.
 *
 * the new plt entry is:
 *
 *	sethi	(.-PLT0), %g1			! constant
 *	sethi	%hi(function address), %g1	! patched second
 *	jmpl	%g1 + %lo(function address, %g0	! patched first
 */

#if	defined(lint)

void
plt_full_range(uintptr_t pc, uintptr_t symval)
{
	uint_t *	plttab = (uint_t *)pc;
	plttab[2] = (M_JMPL | ((unsigned long)symval & S_MASK(10)));
	plttab[1] = (M_SETHIG1 | ((unsigned long)symval >> (32 - 22)));
}

#else
	ENTRY(plt_full_range)

	sethi	%hi(M_JMPL), %o3	! Get jmpl instruction
	and	%o1, 0x3ff, %o2		! Lower part of function address
	or	%o3, %o2, %o3		!	is or'ed into instruction
	st	%o3, [%o0 + 8]		! Store instruction in plt[2]
	iflush	%o0 + 8
	stbar

	srl	%o1, 10, %o1		! Get high part of function address
	sethi	%hi(M_SETHIG1), %o3	! Get sethi instruction
	or	%o3, %o1, %o3		! Add sethi and function address
	st	%o3, [%o0 + 4]		! Store instruction in plt[1]
	retl
	iflush	%o0 + 4

	SET_SIZE(plt_full_range)

#endif	/* defined(lint) */

