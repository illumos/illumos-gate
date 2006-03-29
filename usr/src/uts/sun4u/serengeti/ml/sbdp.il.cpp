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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file is through cpp before being used as
 * an inline.  It contains support routines used
 * only by DR for the copy-rename sequence.
 */

#if defined(lint)
#include <sys/types.h>
#endif /* lint */

#ifndef	INLINE

#include <sys/asm_linkage.h>

#else /* INLINE */

#define	ENTRY_NP(x)	.inline	x,0
#define	retl		/* nop */
#define	SET_SIZE(x)	.end

#endif /* INLINE */

#include <sys/privregs.h>
#include <sys/sun4asi.h>
#include <sys/machparam.h>
#include <sys/machthread.h>
#include <sys/cheetahregs.h>
#include <sys/cheetahasm.h>

/*
 * Bcopy routine used by DR to copy
 * between physical addresses. 
 * Borrowed from Starfire DR 2.6.
 */
#if defined(lint)

/*ARGSUSED*/
void
bcopy32_il(uint64_t paddr1, uint64_t paddr2)
{}

#else /* lint */

	ENTRY_NP(bcopy32_il)
	.register %g2, #scratch
	.register %g3, #scratch
        rdpr    %pstate, %o4
        andn    %o4, PSTATE_IE | PSTATE_AM, %g3		! clear IE, AM bits
        wrpr    %g0, %g3, %pstate

        ldxa    [%o0]ASI_MEM, %o2
	add	%o0, 8, %o0
        ldxa    [%o0]ASI_MEM, %o3
	add	%o0, 8, %o0
        ldxa    [%o0]ASI_MEM, %g1
	add	%o0, 8, %o0
        ldxa    [%o0]ASI_MEM, %g2

	stxa    %o2, [%o1]ASI_MEM
	add	%o1, 8, %o1
	stxa    %o3, [%o1]ASI_MEM
	add	%o1, 8, %o1
	stxa    %g1, [%o1]ASI_MEM
	add	%o1, 8, %o1
	stxa    %g2, [%o1]ASI_MEM

	stxa	%g0, [%o1]ASI_DC_INVAL	/* flush line from dcache */
	membar	#Sync

	retl
        wrpr    %g0, %o4, %pstate       ! restore earlier pstate register value
	SET_SIZE(bcopy32_il)

#endif /* lint */

#if defined(lint)

/*ARGSUSED*/
void
flush_ecache_il(uint64_t physaddr, uint_t size, uint_t linesize)
{}

#else /* lint */

	ENTRY_NP(flush_ecache_il)
	rdpr	%pstate, %o3
	andn	%o3, PSTATE_IE | PSTATE_AM, %o4
	wrpr	%g0, %o4, %pstate	! clear AM to access 64 bit physaddr
	GET_CPU_IMPL(%o4)
	cmp	%o4, PANTHER_IMPL
	bne	%xcc, 3f
	  nop
	! Panther needs to flush L2 before L3.
	!
	! We need to free up a temp reg for the L2 flush macro (register usage
	! convention for inlines allows %o0-%o5, %f0-%f31 as temporaries.)
	! Since physaddr is only used for Cheetah, Panther can use %o0 for
	! the L2 flush.
	PN_L2_FLUSHALL(%o0, %o4, %o5)
3:
	ECACHE_FLUSHALL(%o1, %o2, %o0, %o4)
	wrpr	%g0, %o3, %pstate	! restore earlier pstate
	SET_SIZE(flush_ecache_il)

#endif /* lint */

#if defined(lint)

/*ARGUSED*/
void
stphysio_il(uint64_t physaddr, u_int value)
{}
 
/*ARGSUSED*/
u_int
ldphysio_il(uint64_t physaddr)
{ return(0); }

uint64_t
lddphys_il(uint64_t physaddr)
{ return (0x0ull); }

uint64_t
ldxasi_il(uint64_t physaddr, uint_t asi)
{ return (0x0ull); }

#else /* lint */

	ENTRY_NP(stphysio_il)
	rdpr	%pstate, %o2		/* read PSTATE reg */
	andn	%o2, PSTATE_IE | PSTATE_AM, %o3
	wrpr	%g0, %o3, %pstate
	stwa	%o1, [%o0]ASI_IO        /* store value via bypass ASI */
	retl
	wrpr	%g0, %o2, %pstate		/* restore the PSTATE */
	SET_SIZE(stphysio_il)

	!
	! load value at physical address in I/O space
	!
	! u_int   ldphysio_il(uint64_t physaddr)
	!
	ENTRY_NP(ldphysio_il)
	rdpr	%pstate, %o2		/* read PSTATE reg */
	andn	%o2, PSTATE_IE | PSTATE_AM, %o3
	wrpr	%g0, %o3, %pstate
	lduwa	[%o0]ASI_IO, %o0	/* load value via bypass ASI */
	retl
	wrpr	%g0, %o2, %pstate	/* restore pstate */
	SET_SIZE(ldphysio_il)

        !
        ! Load long word value at physical address
        !
        ! uint64_t lddphys_il(uint64_t physaddr)
        !
        ENTRY_NP(lddphys_il)
        rdpr    %pstate, %o4
        andn    %o4, PSTATE_IE | PSTATE_AM, %o5
        wrpr    %o5, 0, %pstate
        ldxa    [%o0]ASI_MEM, %o0
        retl
        wrpr    %g0, %o4, %pstate       /* restore earlier pstate register value */
        SET_SIZE(lddphys_il)

        !
        ! Load long word value from designated asi.
        !
        ! uint64_t ldxasi_il(uint64_t physaddr, uint_t asi)
        !
        ENTRY_NP(ldxasi_il)
        rdpr    %pstate, %o4
        andn    %o4, PSTATE_IE | PSTATE_AM, %o5
        wrpr    %o5, 0, %pstate
	wr	%o1, 0, %asi
        ldxa    [%o0]%asi, %o0
        retl
        wrpr    %g0, %o4, %pstate       /* restore earlier pstate register value */
        SET_SIZE(ldxasi_il)

#endif /* lint */

#if defined(lint)

/*
 * Argument to sbdp_exec_script_il is a pointer to:
 *
 * typedef struct {
 *	uint64_t	masr_addr;
 *	uint64_t	masr;
 *	uint_t	asi;
 *	uint_t		_filler;
 * } sbdp_rename_script_t;
 */

/*ARGUSED*/
void
sbdp_exec_script_il(void *sp)
{}
 
#else /* lint */

	ENTRY_NP(sbdp_exec_script_il)
	mov	%o0, %o2

	rdpr	%pstate, %o4		/* read PSTATE reg */
	andn	%o4, PSTATE_IE | PSTATE_AM, %o1
	wrpr	%g0, %o1, %pstate

	membar #Sync

0:					/* cache script */
	ldx	[%o2], %o1
	ldx	[%o2 + 16], %o1
	cmp	%g0, %o1
	bnz,pt	%xcc, 0b
	add	%o2, 24, %o2

	b	2f			/* cache it */
	nop
1:
	ldx	[%o0], %o1
	brz,pn	%o1, 5f
	ld	[%o0 + 16], %o2
	wr	%o2, 0, %asi
	b	3f
	nop
2:
	b	4f			/* cache it */
	nop
3:
	ldx	[%o0 + 8], %o2
	stxa	%o2, [%o1]%asi
	membar	#Sync
	add	%o0, 24, %o0
	b	1b
	ldxa	[%o1]%asi, %g0	/* read back to insure written */
4:
	b	1b			/* caching done */
	nop
5:	
	retl
	wrpr	%g0, %o4, %pstate	/* restore the PSTATE */
	SET_SIZE(sbdp_exec_script_il)

#endif /* lint */
