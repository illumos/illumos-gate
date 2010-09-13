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
 *	sethi	(.-PLT0), %g1
 *	ba,a	.PLT0				! patched atomically 2nd
 *	nop					! patched 1st
 *	nop
 *	nop
 *	nop
 *	nop
 *	nop
 *
 * Therefore on entry, %i7 has the address of the call, which will be added
 * to the offset to the plt entry in %g1 to calculate the plt entry address
 * we must also subtract 4 because the address of PLT0 points to the
 * save instruction before the call.
 *
 * The PLT entry is rewritten in one of several ways.  For the full 64-bit
 * span, the following sequence is generated:
 *
 *	nop
 *	sethi	%hh(entry_pt), %g1
 *	sethi	%lm(entry_pt), %g5
 *	or	%g1, %hm(entry_pt), %g1
 *	sllx	%g1, 32, %g1
 *	or	%g1, %g5, %g5
 *	jmpl	%g5 + %lo(entry_pt), %g0
 *	nop
 *
 * Shorter code sequences are possible, depending on reachability
 * constraints.  Note that 'call' is not as useful as it might seem in
 * this context, because it is only capable of plus or minus 2Gbyte
 * PC-relative jumps, and the rdpc instruction is very slow.
 *
 * At the time of writing, the present and future SPARC CPUs that will use
 * this code are only capable of addressing the bottom 43-bits and top 43-bits
 * of the address space.  And since shared libraries are placed at the top
 * of the address space, the "top 44-bits" sequence will effectively always be
 * used.  See elf_plt_write() below.  The "top 32-bits" are used when they
 * can reach.
 */

#if	defined(lint)

extern unsigned long	elf_bndr(Rt_map *, unsigned long, caddr_t);

/*
 * We're called here from .PLTn in a new frame, with %o0 containing
 * the result of a sethi (. - .PLT0), and %o1 containing the pc of
 * the jmpl instruction we're got here with inside .PLT1
 */
void
elf_rtbndr(Rt_map *lmp, unsigned long pltoff, caddr_t from)
{
	(void) elf_bndr(lmp, pltoff, from);
}

#else
	.weak	_elf_rtbndr		! keep dbx happy as it likes to
	_elf_rtbndr = elf_rtbndr	! rummage around for our symbols

	ENTRY(elf_rtbndr)
	mov	%i7, %o3		! Save callers address(profiling)
	save	%sp, -SA(MINFRAME), %sp
	mov	%g4, %l5		! Save g4 (safe across function calls)
	sub	%i1, 0x38, %o1		! compute addr of .PLT0 from addr of .PLT1 jmpl
	ldx	[%o1 + 0x40], %o0	! ld PLT2[X] into third arg
	srl	%i0, 10, %o1		! shift offset set by sethi
	call	elf_bndr		! returns function address in %o0
	mov	%i3, %o2		! Callers address is arg 3	
	mov	%o0, %g1		! save address of routine binded
	mov	%l5, %g4		! restore g4
	restore				! how many restores needed ? 2
	jmp	%g1			! jump to it
	restore
	SET_SIZE(elf_rtbndr)

#endif


#if	defined(lint)
void
elf_rtbndr_far(Rt_map *lmp, unsigned long pltoff, caddr_t from)
{
	(void) elf_bndr(lmp, pltoff, from);
}
#else
ENTRY(elf_rtbndr_far)
	mov	%i7, %o3		! Save callers address
	save	%sp, -SA(MINFRAME), %sp
	mov	%g4, %l5		! preserve %g4
	sub	%i1, 0x18, %o2		! compute address of .PLT0 from
					!   .PLT0 jmpl instr.
	sub	%i0, %o2, %o1		! pltoff = pc - 0x10 - .PLT0
	sub	%o1, 0x10, %o1
	ldx	[%o2 + 0x40], %o0	! ld PLT2[X] into third arg
	call	elf_bndr		! returns function address in %o0
	mov	%i3, %o2		! Callers address is arg3
	mov	%o0, %g1		! save address of routine binded
	mov	%l5, %g4		! restore g4
	restore				! how many restores needed ? 2
	jmp	%g1			! jump to it
	restore
SET_SIZE(elf_rtbndr_far)
#endif


/*
 * Initialize a plt entry so that function calls go to 'bindfunc'
 * (We parameterize the binding function here because we call this
 * routine twice - once for PLT0 and once for PLT1 with different
 * binding functions.)
 *
 * The plt entries (PLT0 and PLT1) look like:
 *
 *	save	%sp, -176, %sp
 *	sethi	%hh(bindfunc), %l0
 *	sethi	%lm(bindfunc), %l1
 *	or	%l0, %hm(bindfunc), %l0
 *	sllx	%l0, 32, %l0
 *	or	%l0, %l1, %l0
 *	jmpl	%l0 + %lo(bindfunc), %o1
 *	mov	%g1, %o0
 */

#define	M_SAVE_SP176SP	0x9de3bf50	/*	save	%sp, -176, %sp */
#define	M_SETHI_L0	0x21000000	/*	sethi	0x0, %l0 */
#define	M_SETHI_L1	0x23000000	/*	sethi	0x0, %l1 */
#define	M_OR_L0L0	0xa0142000	/*	or	%l0, 0x0, %l0 */
#define	M_SLLX_L032L0	0xa12c3020	/*	sllx	%l0, 32, %l0 */
#define	M_OR_L0L1L0	0xa0140011	/*	or	%l0, %l1, %l0 */
#define	M_JMPL_L0O1	0x93c42000	/*	jmpl	%l0 + 0, %o1 */
#define	M_MOV_G1O0	0x90100001	/*	or	%g0, %g1, %o0 */

#if	defined(lint)

#define	HH22(x)	0		/* for lint's benefit */
#define	LM22(x)	0
#define	HM10(x)	0
#define	LO10(x)	0

/* ARGSUSED */
void
elf_plt_init(void *plt, caddr_t bindfunc)
{
	uint_t	*_plt;

	_plt = (uint_t *)plt;
	_plt[0] = M_SAVE_SP176SP;
	_plt[1] = M_SETHI_L0 | HH22(bindfunc);
	_plt[2] = M_SETHI_L1 | LM22(bindfunc);
	_plt[3] = M_OR_L0L0 | HM10(bindfunc);
	_plt[4] = M_SLLX_L032L0;
	_plt[5] = M_OR_L0L1L0;
	_plt[6] = M_JMPL_L0O1 | LO10(bindfunc);
	_plt[7] = M_MOV_G1O0;
}

#else
	ENTRY(elf_plt_init)
	save	%sp, -SA(MINFRAME), %sp	! Make a frame

	sethi	%hi(M_SAVE_SP176SP), %o0	! Get save instruction
	or	%o0, %lo(M_SAVE_SP176SP), %o0
	st	%o0, [%i0]		! Store in plt[0]

	sethi	%hi(M_SETHI_L0), %o4	! Get "sethi 0x0, %l0" insn
	srlx	%i1, 42, %o2		! get %hh(function address)
	or	%o4, %o2, %o4		!	or value into instruction
	st	%o4, [%i0 + 0x4]	! Store instruction in plt[1]
	iflush	%i0			! .. and flush

	sethi	%hi(M_SETHI_L1), %o4	! Get "sethi 0x0, %l1" insn
	srl	%i1, 10, %o2		! get %lm(function address)
	or	%o4, %o2, %o4		!	or value into instruction
	st	%o4, [%i0 + 0x8]	! Store instruction in plt[2]

	sethi	%hi(M_OR_L0L0), %o4	! Get "or %l0, 0x0, %l0" insn
	or	%o4, %lo(M_OR_L0L0), %o4
	srlx	%i1, 32, %o2		! get %hm(function address)
	and	%o2, 0x3ff, %o2		! pick out bits 42-33
	or	%o4, %o2, %o4		!	or value into instruction
	st	%o4, [%i0 + 0xc]	! Store instruction in plt[3]
	iflush	%i0 + 8			! .. and flush

	sethi	%hi(M_SLLX_L032L0), %o4	! get "sllx %l0, 32, %l0" insn
	or	%o4, %lo(M_SLLX_L032L0), %o4
	st	%o4, [%i0 + 0x10]	! Store instruction in plt[4]

	sethi	%hi(M_OR_L0L1L0), %o4	! get "or %l0, %l1, %l0" insn
	or	%o4, %lo(M_OR_L0L1L0), %o4
	st	%o4, [%i0 + 0x14]	! Store instruction in plt[5]
	iflush	%i0 + 0x10		! .. and flush

	sethi	%hi(M_JMPL_L0O1), %o4	! get "jmpl %l0 + 0, %o1" insn
	or	%o4, %lo(M_JMPL_L0O1), %o4
	and	%i1, 0x3ff, %o2		! get %lo(function address)
	or	%o4, %o2, %o4		!	or value into instruction
	st	%o4, [%i0 + 0x18]	! Store instruction in plt[6]

	sethi	%hi(M_MOV_G1O0), %o4	! get "mov %g1, %o0" insn
	or	%o4, %lo(M_MOV_G1O0), %o4
	st	%o4, [%i0 + 0x1c]	! Store instruction in plt[7]
	iflush	%i0 + 0x18		! .. and flush
	
	ret
	restore
	SET_SIZE(elf_plt_init)
#endif


	

#if	defined(lint)
/*
 *  The V9 ABI assigns the link map identifier, the
 *  Rt_map pointer, to the start of .PLT2.
 */
void
elf_plt2_init(unsigned int *plt2, Rt_map * lmp)
{
	/* LINTED */
	*(unsigned long *)plt2 = (unsigned long)lmp;
}
#else
	ENTRY(elf_plt2_init)
	stx	%o1, [%o0]
	retl
	iflush	%o0
	SET_SIZE(elf_plt2_init)
#endif

	

/*
 * After the first call to a plt, elf_bndr() will have determined the true
 * address of the function being bound.  The plt is now rewritten so that
 * any subsequent calls go directly to the bound function.  If the library
 * to which the function belongs is being profiled refer to _plt_cg_write.
 *
 * For complete 64-bit spanning, the new plt entry is:
 *
 *	nop
 *	sethi	%hh(function address), %g1
 *	sethi	%lm(function address), %g5
 *	or	%g1, %hm(function address), %g1
 *	sllx	%g1, 32, %g1
 *	or	%g1, %g5, %g5
 *	jmpl	%g5, %lo(function address), %g0
 *	nop
 *
 * However, shorter instruction sequences are possible and useful.
 * This version gets us anywhere in the top 44 bits of the
 * address space - since this is where shared objects live most
 * of the time, this case is worth optimizing.
 *
 *	nop
 *	sethi	%h44(~function_address), %g5
 *	xnor	%g5, %m44(~function address), %g1
 *	sllx	%g1, 12, %g1
 *	jmpl	%g1 + %l44(function address), %g0
 *	nop
 *	nop
 *	nop
 *
 * This version gets anywhere in the top 32 bits:
 *
 *	nop
 *	sethi	%hi(~function_address), %g5
 *	xnor	%g5, %lo(~function_address), %g1
 *	jmpl	%g1, %g0
 *	nop
 *	nop
 *	nop
 *	nop
 *
 * This version get's us to a destination within
 * +- 8megs of the PLT's address:
 *
 *	nop
 *	ba,a	<dest>
 *	nop
 *	nop
 *	nop
 *	nop
 *	nop
 *	nop
 *
 * This version get's us to a destination within
 * +- 2megs of the PLT's address:
 *
 *	nop
 *	ba,a,pt	%icc, <dest>
 *	nop
 *	nop
 *	nop
 *	nop
 *	nop
 *	nop
 *
 *
 * The PLT is written in reverse order to ensure re-entrant behaviour.
 * Note that the first two instructions must be overwritten with a
 * single stx.
 *
 * Note that even in the 44-bit case, we deliberately use both %g5 and
 * %g1 to prevent anyone accidentally relying on either of them being
 * non-volatile across a function call.
 */

#define	M_JMPL_G5G0	0x81c16000	/* jmpl %g5 + 0, %g0 */
#define	M_OR_G1G5G5	0x8a104005	/* or %g1, %g5, %g5 */
#define	M_SLLX_G132G1	0x83287020	/* sllx %g1, 32, %g1 */
#define	M_OR_G1G1	0x82106000	/* or %g1, 0x0, %g1 */
#define	M_SETHI_G5	0x0b000000	/* sethi 0x0, %g5 */
#define	M_SETHI_G1	0x03000000	/* sethi 0x0, %g1 */
#define	M_NOP		0x01000000	/* sethi 0x0, %g0 */

#define	M_JMPL_G1G0	0x81c06000	/* jmpl %g1 + 0, %g0 */
#define	M_SLLX_G112G1	0x8328700c	/* sllx %g1, 12, %g1 */
#define	M_XNOR_G5G1	0x82396000	/* xnor	%g5, 0, %g1 */

#if	defined(lint)

/* ARGSUSED */
#define	MASK(m)		((1ul << (m)) - 1ul)
#define	BITS(v, u, l)	(((v) >> (l)) & MASK((u) - (l) + 1))
#define	H44(v)		BITS(v, 43, 22)
#define	M44(v)		BITS(v, 21, 12)
#define	L44(v)		BITS(v, 11, 0)

#endif

#if	defined(lint)

void
/* ARGSUSED1 */
plt_upper_32(uintptr_t pc, uintptr_t symval)
{
	ulong_t		sym = (ulong_t)symval;
	/* LINTED */
	ulong_t		nsym = ~sym;
	uint_t *	plttab = (uint_t *)pc;

	plttab[3] = M_JMPL_G1G0;
	plttab[2] = (uint_t)(M_XNOR_G5G1 | LO10(nsym));
	*(ulong_t *)pc =
	    ((ulong_t)M_NOP << 32) | (M_SETHI_G5 | LM22(nsym));
}

#else


	ENTRY(plt_upper_32)
	!
	! Address lies in top 32-bits of address space, so use
	! compact PLT sequence
	!
	sethi	%hi(M_JMPL_G1G0), %o3	! Get "jmpl %g1, %g0" insn
	st	%o3, [%o0 + 0xc]	! store instruction in plt[3]
	iflush	%o0 + 0xc		! .. and flush

	not	%o1, %o4
	sethi	%hi(M_XNOR_G5G1), %o3	! Get "xnor %g5, %g1, %g1" insn
	and	%o4, 0x3ff, %o2		! pick out bits 0-9
	or	%o3, %o2, %o3		!	or value into instruction
	st	%o3, [%o0 + 0x8]	! store instruction in plt[2]
	iflush	%o0 + 0x8		! .. and flush

	sethi	%hi(M_SETHI_G5), %o3	! Get "sethi 0x0, %g5" insn
	srl	%o4, 10, %o2		! get %lm(~function address)
	or	%o3, %o2, %o3		!	or value into instruction

	sethi	%hi(M_NOP), %o4		! Get "nop" instruction
	sllx	%o4, 32, %o4		! shift to top of instruction pair
	or	%o3, %o4, %o3		!	or value into instruction pair
	stx	%o3, [%o0]		! store instructions into plt[0] plt[1]
	retl
	iflush	%o0			! .. and flush
	SET_SIZE(plt_upper_32)
#endif	/* defined lint */
	

#if	defined(lint)

void
/* ARGSUSED1 */
plt_upper_44(uintptr_t pc, uintptr_t symval)
{
	ulong_t		sym = (ulong_t)symval;
	ulong_t		nsym = ~sym;
	uint_t *	plttab = (uint_t *)pc;

	/* LINTED */
	plttab[4] = (uint_t)(M_JMPL_G1G0 | L44(sym));
	plttab[3] = M_SLLX_G112G1;
	/* LINTED */
	plttab[2] = (uint_t)(M_XNOR_G5G1 | M44(nsym));
	*(ulong_t *)pc = ((ulong_t)M_NOP << 32) | (M_SETHI_G5 | H44(nsym));
}

#else


	ENTRY(plt_upper_44)
	!
	! Address lies in top 44-bits of address space, so use
	! compact PLT sequence
	!
	setuw	M_JMPL_G1G0, %o3	! Get "jmpl %g1, %g0" insn
	and	%o1, 0xfff, %o2		! lower 12 bits of function address
	or	%o3, %o2, %o3		!	is or'ed into instruction
	st	%o3, [%o0 + 0x10]	! store instruction in plt[4]
	iflush	%o0 + 0x10		! .. and flush

	setuw	M_SLLX_G112G1, %o3	! Get "sllx %g1, 12, %g1" insn
	st	%o3, [%o0 + 0xc]	! store instruction in plt[3]

	not	%o1, %o4
	setuw	M_XNOR_G5G1, %o3	! Get "xnor %g5, 0, %g1" insn
	srlx	%o4, 12, %o2		! get %m44(0 - function address)
	and	%o2, 0x3ff, %o2		! pick out bits 21-12
	or	%o3, %o2, %o3		!	or value into instruction
	st	%o3, [%o0 + 8]		! store instruction in plt[2]
	iflush	%o0 + 8			! .. and flush

	setuw	M_SETHI_G5, %o3		! Get "sethi 0x0, %g5" insn
	srlx	%o4, 22, %o2		! get %h44(0 - function address)
	or	%o3, %o2, %o3		!	or value into instruction

	setuw	M_NOP, %o4		! Get "nop" instruction
	sllx	%o4, 32, %o4		! shift to top of instruction pair
	or	%o3, %o4, %o3		!	or value into instruction pair
	stx	%o3, [%o0]		! store instructions into plt[0] plt[1]
	retl
	iflush	%o0			! .. and flush
	SET_SIZE(plt_upper_44)

#endif	/* defined(lint) */


#if	defined(lint)

void
/* ARGSUSED1 */
plt_full_range(uintptr_t pc, uintptr_t symval)
{
	uint_t *	plttab = (uint_t *)pc;

	plttab[6] = M_JMPL_G5G0 | LO10(symval);
	plttab[5] = M_OR_G1G5G5;
	plttab[4] = M_SLLX_G132G1;
	plttab[3] = M_OR_G1G1 | HM10(symval);
	plttab[2] = M_SETHI_G5 | LM22(symval);
	*(ulong_t *)pc =
		((ulong_t)M_NOP << 32) | (M_SETHI_G1 | HH22(symval));
}

#else
	ENTRY(plt_full_range)
	!
	! Address lies anywhere in 64-bit address space, so use
	! full PLT sequence
	!
	sethi	%hi(M_JMPL_G5G0), %o3	! Get "jmpl %g5, %g0" insn
	and	%o1, 0x3ff, %o2		! lower 10 bits of function address
	or	%o3, %o2, %o3		!	is or'ed into instruction
	st	%o3, [%o0 + 0x18]	! store instruction in plt[6]
	iflush	%o0 + 0x18		! .. and flush

	sethi	%hi(M_OR_G1G5G5), %o3	! Get "or %g1, %g5, %g1" insn
	or	%o3, %lo(M_OR_G1G5G5), %o3
	st	%o3, [%o0 + 0x14]	! store instruction in plt[5]

	sethi	%hi(M_SLLX_G132G1), %o3	!  Get "sllx %g1, 32, %g1" insn
	or	%o3, %lo(M_SLLX_G132G1), %o3
	st	%o3, [%o0 + 0x10]	! store instruction in plt[4]
	iflush	%o0 + 0x10		! .. and flush

	sethi	%hi(M_OR_G1G1), %o3	! Get "or %g1, 0x0, %g1" insn
	or	%o3, %lo(M_OR_G1G1), %o3
	srlx	%o1, 32, %o2		! get %hm(function address)
	and	%o2, 0x3ff, %o2		! pick out bits 42-33
	or	%o3, %o2, %o3		!	or value into instruction
	st	%o3, [%o0 + 0xc]	! store instruction in plt[3]

	sethi	%hi(M_SETHI_G5), %o3	! Get "sethi 0x0, %g5" insn
	srl	%o1, 10, %o2		! get %lm(function address)
	or	%o3, %o2, %o3		!	or value into instruction
	st	%o3, [%o0 + 0x8]	! store instruction in plt[2]
	iflush	%o0 + 8			! .. and flush

	sethi	%hi(M_SETHI_G1), %o3	! Get "sethi 0x0, %g1" insn
	srlx	%o1, 42, %o2		! get %hh(function address)
	or	%o3, %o2, %o3		!	or value into instruction

	sethi	%hi(M_NOP), %o4		! Get "nop" instruction
	sllx	%o4, 32, %o4		! shift to top of instruction pair
	or	%o3, %o4, %o3		!	or value into instruction pair
	stx	%o3, [%o0]		! store instructions into plt[0] plt[1]
	retl
	iflush	%o0			! .. and flush

	SET_SIZE(plt_full_range)

#endif	/* defined(lint) */

/*
 * performs the 'iflush' instruction on a range of memory.
 */
#if	defined(lint)
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
	bge,a,pt %xcc, 1b
	iflush	%o0 + %o1
	retl
	nop
	SET_SIZE(iflush_range)
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

/*
 * The dyn_plt that called us has already created a stack-frame for
 * us and placed the following entries in it:
 *
 *	[%fp + STACK_BIAS + -0x8]	* dyndata
 *	[%fp + STACK_BIAS + -0x10]	* prev stack size
 *
 * dyndata currently contains:
 *
 *	dyndata:
 *	0x0	Addr		*reflmp
 *	0x8	Addr		*deflmp
 *	0x10	Word		symndx
 *	0x14	Word		sb_flags
 *	0x18	Sym		symdef.st_name
 *	0x1c			symdef.st_info
 *	0x1d			symdef.st_other
 *	0x1e			symdef.st_shndx
 *	0x20			symdef.st_value
 *	0x28			symdef.st_size
 */
#define	REFLMP_OFF		0x0	
#define	DEFLMP_OFF		0x8	
#define	SYMNDX_OFF		0x10
#define	SBFLAGS_OFF		0x14
#define	SYMDEF_OFF		0x18
#define	SYMDEF_VALUE_OFF	0x20

#define	LAREGSSZ	0x40	/* sizeof (La_sparcv9_regs) */

	
elf_plt_trace:
1:	call	2f
	sethi	%hi(_GLOBAL_OFFSET_TABLE_ - (1b - .)), %l7
2:	or	%l7, %lo(_GLOBAL_OFFSET_TABLE_ - (1b - .)), %l7
	add	%l7, %o7, %l7

	ldx	[%fp + STACK_BIAS + -CLONGSIZE], %l1	! l1 = * dyndata
	lduw	[%l1 + SBFLAGS_OFF], %l2		! l2 = sb_flags
	andcc	%l2, LA_SYMB_NOPLTENTER, %g0
	be,pt	%icc, .start_pltenter
	ldx	[%l1 + SYMDEF_VALUE_OFF], %l0	! l0 = 
						!  sym.st_value(calling address)
	ba,a,pt	%icc, .end_pltenter
	nop

	/*
	 * save all registers into La_sparcv9_regs
	 */
.start_pltenter:
	sub	%sp, LAREGSSZ, %sp	! create space for La_sparcv9_regs
					! storage on the stack.

	add	%fp, STACK_BIAS - (LAREGSSZ + (2 * CLONGSIZE)), %o4	! addr of new space.

	stx	%i0, [%o4 + 0x0]
	stx	%i1, [%o4 + 0x8]
	stx	%i2, [%o4 + 0x10]
	stx	%i3, [%o4 + 0x18]	! because a regwindow shift has
	stx	%i4, [%o4 + 0x20]	! already occured our current %i*
	stx	%i5, [%o4 + 0x28]	! register's are the equivalent of
	stx	%i6, [%o4 + 0x30]	! the %o* registers that the final
	stx	%i7, [%o4 + 0x38]	! procedure shall see.
	mov	%g4, %l5		! save g4 (safe across function calls)


	ldx	[%fp + STACK_BIAS + -CLONGSIZE], %l1	! %l1 == * dyndata
	ldx	[%l1 + REFLMP_OFF], %o0		! %o0 = reflmp
	ldx	[%l1 + DEFLMP_OFF], %o1		! %o1 = deflmp
	add	%l1, SYMDEF_OFF, %o2		! %o2 = symp
	lduw	[%l1 + SYMNDX_OFF], %o3		! %o3 = symndx
	call	audit_pltenter
	add	%l1, SBFLAGS_OFF, %o5		! %o3 = * sb_flags

	mov	%o0, %l0		! %l0 == calling address
	add	%sp, LAREGSSZ, %sp	! cleanup La_sparcv9_regs off
					! of the stack.

.end_pltenter:
	/*
	 * If *no* la_pltexit() routines exist we do not need
	 * to keep the stack frame before we call the actual
	 * routine.  Instead we jump to it and remove ourself
	 * from the stack at the same time.
	 */
	ldx	[%l7+audit_flags], %l3
	lduw	[%l3], %l3				! %l3 = audit_flags
	andcc	%l3, AF_PLTEXIT, %g0			! AF_PLTEXIT = 2
	be,pt	%icc, .bypass_pltexit
	ldx	[%fp + STACK_BIAS + -CLONGSIZE], %l1	! %l1 = * dyndata
	lduw	[%l1 + SBFLAGS_OFF], %l2		! %l2 = sb_flags
	andcc	%l2, LA_SYMB_NOPLTEXIT, %g0		! LA_SYMB_NOPLTEXIT = 2
	bne,a,pt	%icc, .bypass_pltexit
	nop

	ba,a,pt	%icc, .start_pltexit
	nop
.bypass_pltexit:
	mov	%l5, %g4		! restore g4
	jmpl	%l0, %g0
	restore

.start_pltexit:
	/*
	 * In order to call la_pltexit() we must duplicate the
	 * arguments from the 'callers' stack on our stack frame.
	 *
	 * First we check the size of the callers stack and grow
	 * our stack to hold any of the arguments that need
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
	ldx	[%fp + STACK_BIAS + -(2 * CLONGSIZE)], %l1	! %l1 = callers
						!	stack size
	sub	%l1, MINFRAME, %l1		! %l1 = argument space on
						!	caller's stack
	/*
	 * Next we compare the prev. stack size against the audit_argcnt.  We
	 * copy at most 'audit_argcnt' arguments.  The default arg count is 64.
	 *
	 * NOTE: on sparc we always copy at least six args since these
	 *	 are in reg-windows and not on the stack.
	 *
	 * NOTE: Also note that we multiply (shift really) the arg count
	 *	 by 8 which is the 'word size' to calculate the amount
	 *	 of stack space needed.
	 */
	ldx	[%l7 + audit_argcnt], %l2
	lduw	[%l2], %l2			! %l2 = audit_argcnt
	cmp	%l2, 6
	ble,pn	%icc, .grow_stack
	sub	%l2, 6, %l2
	sllx	%l2, CLONGSHIFT, %l2		! arg count * 8
	cmp	%l1, %l2			! 
	ble,a,pn	%icc, .grow_stack
	nop
	mov	%l2, %l1
.grow_stack:
	/*
	 * When duplicating the stack we skip the first SA(MINFRAME)
	 * bytes. This is the space on the stack reserved for preserving
	 * the register windows and such and do not need to be duplicated
	 * on this new stack frame.  We start duplicating at the portion
	 * of the stack reserved for argument's above 6.
	 */
	sub	%sp, %l1, %sp		! grow our stack by amount required.
	srax	%l1, CLONGSHIFT, %l1	! %l1 = %l1 / 8 (words to copy)
	mov	SA(MINFRAME), %l2	! %l2 = index into stack & frame

1:
	cmp	%l1, 0
	ble,a,pn	%icc, 2f
	nop

	add	%fp, %l2, %l4
	ldx	[%l4 + STACK_BIAS], %l3		! duplicate args from previous
	add	%sp, %l2, %l4
	stx	%l3, [%l4 + STACK_BIAS]		! stack onto current stack

	add	%l2, CLONGSIZE, %l2
	ba,pt	%icc, 1b
	sub	%l1, 0x1, %l1
2:
	mov	%i0, %o0		! copy ins to outs
	mov	%i1, %o1
	mov	%i2, %o2
	mov	%i3, %o3
	mov	%i4, %o4
	mov	%i5, %o5
	call	%l0			! call original routine
	mov	%l5, %g4		! restore g4
	mov	%o1, %l2		! l2 = second 1/2 of return value
					! for those those 64 bit operations
					! link div64 - yuck...

					! %o0 = retval
	ldx	[%fp + STACK_BIAS + -CLONGSIZE], %l1
	ldx	[%l1 + REFLMP_OFF], %o1		! %o1 = reflmp
	ldx	[%l1 + DEFLMP_OFF], %o2		! %o2 = deflmp
	add	%l1, SYMDEF_OFF, %o3		! %o3 = symp
	call	audit_pltexit
	lduw	[%l1 + SYMNDX_OFF], %o4		! %o4 = symndx

	mov	%o0, %i0			! pass on return code
	mov	%l2, %i1
	ret
	restore
	.size	elf_plt_trace, . - elf_plt_trace

#endif

