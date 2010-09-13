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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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
#else
#include "assym.h"
#endif /* lint */

#include <sys/asm_linkage.h>
#include <sys/param.h>
#include <sys/privregs.h>
#include <sys/machasi.h>
#include <sys/spitregs.h>
#include <sys/mmu.h>
#include <sys/machthread.h>
#include <sys/pte.h>
#include <sys/stack.h>
#include <sys/vis.h>

#ifndef	lint

/*
 * arg1 = icache_size
 * arg2 = icache_linesize
 */
#define	ICACHE_FLUSHALL(lbl, arg1, arg2, tmp1)			\
	ldxa	[%g0]ASI_LSU, tmp1				;\
	btst	LSU_IC, tmp1					;\
	bz,pn	%icc, lbl/**/1					;\
	sub	arg1, arg2, tmp1				;\
lbl/**/0:							;\
	stxa	%g0, [tmp1]ASI_IC_TAG				;\
	membar	#Sync						;\
	cmp	%g0, tmp1					;\
	bne,pt	%icc, lbl/**/0					;\
	sub	tmp1, arg2, tmp1				;\
lbl/**/1:

/*
 * arg1 = dcache_size
 * arg2 = dcache_linesize
 */
#define	DCACHE_FLUSHALL(lbl, arg1, arg2, tmp1)			\
	ldxa	[%g0]ASI_LSU, tmp1				;\
	btst	LSU_DC, tmp1					;\
	bz,pn	%icc, lbl/**/1					;\
	sub	arg1, arg2, tmp1				;\
lbl/**/0:							;\
	stxa	%g0, [tmp1]ASI_DC_TAG				;\
	membar	#Sync						;\
	cmp	%g0, tmp1					;\
	bne,pt	%icc, lbl/**/0					;\
	sub	tmp1, arg2, tmp1				;\
lbl/**/1:

/*
 * arg1 = ecache flush physaddr
 * arg2 = size
 * arg3 = ecache_linesize
 */
#define	ECACHE_FLUSHALL(lbl, arg1, arg2, arg3, tmp1, tmp2)	\
	rdpr	%pstate, tmp1					;\
	andn	tmp1, PSTATE_IE | PSTATE_AM, tmp2		;\
	wrpr	%g0, tmp2, %pstate				;\
	b	lbl/**/1					;\
lbl/**/0:							;\
	sub	arg2, arg3, arg2				;\
lbl/**/1:							;\
	brgez,a	arg2, lbl/**/0					;\
	ldxa	[arg1 + arg2]ASI_MEM, %g0			;\
	wrpr	%g0, tmp1, %pstate

#ifdef SF_ERRATA_32
#define	SF_WORKAROUND(tmp1, tmp2)				\
	sethi	%hi(FLUSH_ADDR), tmp2				;\
	set	MMU_PCONTEXT, tmp1				;\
	stxa	%g0, [tmp1]ASI_DMMU				;\
	flush	tmp2						;
#else
#define	SF_WORKAROUND(tmp1, tmp2)
#endif /* SF_ERRATA_32 */

/*
 * arg1 = vaddr
 * arg2 = ctxnum
 *	- disable interrupts and clear address mask
 *	  to access 64 bit physaddr
 *	- Blow out the TLB.
 *	  . If it's kernel context, then use primary context.
 *	  . Otherwise, use secondary.
 */
#define VTAG_FLUSHPAGE(lbl, arg1, arg2, tmp1, tmp2, tmp3, tmp4)	\
	rdpr	%pstate, tmp1					;\
	andn	tmp1, PSTATE_IE | PSTATE_AM, tmp2		;\
	wrpr	tmp2, 0, %pstate				;\
	brnz,pt	arg2, lbl/**/1					;\
	sethi	%hi(FLUSH_ADDR), tmp2				;\
	stxa	%g0, [arg1]ASI_DTLB_DEMAP			;\
	stxa	%g0, [arg1]ASI_ITLB_DEMAP			;\
	b	lbl/**/5					;\
	  flush	tmp2						;\
lbl/**/1:							;\
	set	MMU_SCONTEXT, tmp3				;\
	ldxa	[tmp3]ASI_DMMU, tmp4				;\
	or	DEMAP_SECOND | DEMAP_PAGE_TYPE, arg1, arg1	;\
	cmp	tmp4, arg2					;\
	be,a,pt	%icc, lbl/**/4					;\
	  nop							;\
	stxa	arg2, [tmp3]ASI_DMMU				;\
lbl/**/4:							;\
	stxa	%g0, [arg1]ASI_DTLB_DEMAP			;\
	stxa	%g0, [arg1]ASI_ITLB_DEMAP			;\
	flush	tmp2						;\
	be,a,pt	%icc, lbl/**/5					;\
	  nop							;\
	stxa	tmp4, [tmp3]ASI_DMMU				;\
	flush	tmp2						;\
lbl/**/5:							;\
	wrpr	%g0, tmp1, %pstate

/*
 * arg1 = dtlb entry
 *	- Before first compare:
 *		tmp4 = tte
 *		tmp5 = vaddr
 *		tmp6 = cntxnum
 */
#define	DTLB_FLUSH_UNLOCKED(lbl, arg1, tmp1, tmp2, tmp3, \
				tmp4, tmp5, tmp6) \
lbl/**/0:							;\
	sllx	arg1, 3, tmp3					;\
	SF_WORKAROUND(tmp1, tmp2)				;\
	ldxa	[tmp3]ASI_DTLB_ACCESS, tmp4			;\
	srlx	tmp4, 6, tmp4					;\
	andcc	tmp4, 1, %g0					;\
	bnz,pn	%xcc, lbl/**/1					;\
	srlx	tmp4, 57, tmp4					;\
	andcc	tmp4, 1, %g0					;\
	beq,pn	%xcc, lbl/**/1					;\
	  nop							;\
	set	TAGREAD_CTX_MASK, tmp1				;\
	ldxa	[tmp3]ASI_DTLB_TAGREAD, tmp2			;\
	and	tmp2, tmp1, tmp6				;\
	andn	tmp2, tmp1, tmp5				;\
	VTAG_FLUSHPAGE(VD, tmp5, tmp6, tmp1, tmp2, tmp3, tmp4)	;\
lbl/**/1:							;\
	brgz,pt	arg1, lbl/**/0					;\
	sub	arg1, 1, arg1

/*
 * arg1 = itlb entry
 *	- Before first compare:
 *		tmp4 = tte
 *		tmp5 = vaddr
 *		tmp6 = cntxnum
 */
#define	ITLB_FLUSH_UNLOCKED(lbl, arg1, tmp1, tmp2, tmp3, \
				tmp4, tmp5, tmp6) \
lbl/**/0:							;\
	sllx	arg1, 3, tmp3					;\
	SF_WORKAROUND(tmp1, tmp2)				;\
	ldxa	[tmp3]ASI_ITLB_ACCESS, tmp4			;\
	srlx	tmp4, 6, tmp4					;\
	andcc	tmp4, 1, %g0					;\
	bnz,pn	%xcc, lbl/**/1					;\
	srlx	tmp4, 57, tmp4					;\
	andcc	tmp4, 1, %g0					;\
	beq,pn	%xcc, lbl/**/1					;\
	  nop							;\
	set	TAGREAD_CTX_MASK, tmp1				;\
	ldxa	[tmp3]ASI_ITLB_TAGREAD, tmp2			;\
	and	tmp2, tmp1, tmp6				;\
	andn	tmp2, tmp1, tmp5				;\
	VTAG_FLUSHPAGE(VI, tmp5, tmp6, tmp1, tmp2, tmp3, tmp4)	;\
lbl/**/1:							;\
	brgz,pt	arg1, lbl/**/0					;\
	sub	arg1, 1, arg1

#define	CLEARTL(lvl)			\
	wrpr	%g0, lvl, %tl		;\
	wrpr	%g0, %g0, %tpc		;\
	wrpr	%g0, %g0, %tnpc		;\
	wrpr	%g0, %g0, %tt

#define	SWITCH_STACK(estk)					\
	flushw							;\
	sub	estk, SA(KFPUSIZE+GSR_SIZE), estk		;\
	andn	estk, 0x3f, estk				;\
	sub	estk, SA(MINFRAME) + STACK_BIAS, %sp		;\
	mov	estk, %fp

#endif	/* !lint */

#if defined(lint)

/*ARGSUSED*/
void
drmach_shutdown_asm(uint64_t mbox_addr)
{}

#else /* lint */

	ENTRY_NP(drmach_shutdown_asm)
	mov	%o0, %o5

	ldxa	[%o5]ASI_MEM, %o0	! get 8-byte estack in o0
	add	%o5, 8, %o5
	ldxa	[%o5]ASI_MEM, %o1	! get 8-byte flushaddr in o1
	add	%o5, 8, %o5
	lda	[%o5]ASI_MEM, %o2	! get 4-byte size in o2
	srl	%o2, 0, %o2
	add	%o5, 4, %o5
	lda	[%o5]ASI_MEM, %o3	! get 4-byte linesize in o3
	srl	%o3, 0, %o3
	add	%o5, 4, %o5
	ldxa	[%o5]ASI_MEM, %o4	! get 8-byte physaddr in o4


	! %o0 = base (va mapping this code in bbsram)
	! %o1 = flushaddr for ecache
	! %o2 = size to use for ecache flush
	! %o3 = ecache linesize
	! %o4 = phys addr of byte to clear when finished
	!
	! output: Stores a zero at [%o4]ASI_MEM

	membar	#LoadStore

	!
	! Switch stack pointer to bbsram
	!
	SWITCH_STACK(%o0)

	!
	! Get some globals
	!
	mov	%o3, %g1		! ecache_linesize
	mov	%o4, %o0		! physaddr byte to clear

	sethi	%hi(dcache_linesize), %g2
	ld	[%g2 + %lo(dcache_linesize)], %g2

	sethi	%hi(dcache_size), %g3
	ld	[%g3 + %lo(dcache_size)], %g3

	sethi	%hi(icache_linesize), %g4
	ld	[%g4 + %lo(icache_linesize)], %g4

	sethi	%hi(icache_size), %g5
	ld	[%g5 + %lo(icache_size)], %g5

	sethi	%hi(dtlb_entries), %o5
	ld	[%o5 + %lo(dtlb_entries)], %o5
	sllx	%o5, 32, %o5
	srlx	%o5, 32, %o5

	sethi	%hi(itlb_entries), %o3
	ld	[%o3 + %lo(itlb_entries)], %o3
	!
	! cram Xtlb_entries into a single register (%o5)
	! %o5 upper 32 = itlb_entries
	!     lower 32 = dtlb_entries
	!
	sllx	%o3, 32, %o3
	or	%o5, %o3, %o5

	!
	! Flush E$
	!
	ECACHE_FLUSHALL(EC, %o1, %o2, %g1, %o3, %o4)
	!
	! %o1 & %o2 now available
	!

	membar	#Sync

	!
	! Flush D$
	!
	DCACHE_FLUSHALL(DC, %g3, %g2, %o3)

	!
	! Flush I$
	!
	ICACHE_FLUSHALL(IC, %g5, %g4, %o3)

	membar	#Sync

	!
	! Flush dtlb's
	!
	srlx	%o5, 32, %g5		! %g5 = itlb_entries
	sllx	%o5, 32, %o5
	srlx	%o5, 32, %g1
	sub	%g1, 1, %g1		! %g1 = dtlb_entries - 1

	DTLB_FLUSH_UNLOCKED(D, %g1, %g3, %g4, %o2, %o3, %o4, %o5)

	!
	! Flush itlb's
	!
	sub	%g5, 1, %g1		! %g1 = itlb_entries - 1

	ITLB_FLUSH_UNLOCKED(I, %g1, %g3, %g4, %o2, %o3, %o4, %o5)

	membar	#Sync

	!
	! Clear byte to signal finished.
	!
	stba	%g0, [%o0]ASI_MEM
	membar	#Sync

	!
	! read ensures that last write completed (has left queue in the PC chip)
	!
	lduba	[%o0]ASI_MEM, %g0
5:
	ba	5b
	nop
	SET_SIZE(drmach_shutdown_asm)

	.global	drmach_shutdown_asm_end

	.skip	2048

drmach_shutdown_asm_end:

#endif /* lint */
