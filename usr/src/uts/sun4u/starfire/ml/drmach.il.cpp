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
 * Copyright 2001,2003 Sun Microsystems, Inc.  All rights reserved.
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
	srl	%o1, 0, %o1		! clear upper 32 bits
	srl	%o2, 0, %o2		! clear upper 32 bits
	rdpr	%pstate, %o3
	andn	%o3, PSTATE_IE | PSTATE_AM, %o4
	wrpr	%g0, %o4, %pstate	! clear AM to access 64 bit physaddr
	b	2f
	  nop
1:
	ldxa	[%o0 + %o1]ASI_MEM, %g0	! start reading from physaddr + size
2:
	subcc	%o1, %o2, %o1
	bgeu,a	1b
	  nop

	! retl
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

#endif /* lint */

#if defined(lint)

/*
 * Argument to drmach_exec_script_il is a pointer to:
 *
 * typedef struct {
 *	uint64_t	masr_addr;
 *	uint_t		masr;
 *	uint_t		_filler;
 * } drmach_rename_script_t;
 */

/*ARGUSED*/
void
drmach_exec_script_il(void *sp)
{}
 
#else /* lint */

	ENTRY_NP(drmach_exec_script_il)
	mov	%o0, %o2
0:					/* cache script */
	ldx	[%o2], %o1
	cmp	%g0, %o1
	bnz,pt	%xcc, 0b
	add	%o2, 16, %o2

	rdpr	%pstate, %o4		/* read PSTATE reg */
	andn	%o4, PSTATE_IE | PSTATE_AM, %o1
	wrpr	%g0, %o1, %pstate

	b	2f			/* cache it */
	nop
1:
	ldx	[%o0], %o1
	cmp	%g0, %o1
	bz,pn	%xcc, 5f
	ld	[%o0 + 8], %o2
	b	3f
	stwa	%o2, [%o1]ASI_IO
2:
	b	4f			/* cache it */
	nop
3:
	add	%o0, 16, %o0
	b	1b
	lduwa	[%o1]ASI_IO, %g0	/* read back to insure written */
4:
	b	1b			/* caching done */
	nop
5:	
	retl
	wrpr	%g0, %o4, %pstate	/* restore the PSTATE */
	SET_SIZE(drmach_exec_script_il)

#endif /* lint */
