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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file is through cpp before being used as
 * an inline.  It contains support routines used
 * only by DR for the copy-rename sequence.
 */

#include "assym.h"

#include <sys/asm_linkage.h>
#include <sys/param.h>
#include <sys/privregs.h>
#include <sys/machasi.h>
#include <sys/mmu.h>
#include <sys/machthread.h>
#include <sys/pte.h>
#include <sys/stack.h>
#include <sys/vis.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/vtrace.h>
#include <sys/clock.h>
#include <sys/asi.h>
#include <sys/fsr.h>
#include <sys/cheetahregs.h>
#include <sys/cheetahasm.h>

/*
 * Invalidating the E$ tags is only needed on Cheetah following
 * the manual displacement flush.  The internal flush ASI used by
 * Cheetahplus, Jaguar, and Panther will invalidate the cache lines.
 *
 * arg1 = ecache_size
 * arg2 = ecache_linesize
 */
#define ECACHE_FLUSHTAGS(arg1, arg2, tmp1)			\
	GET_CPU_IMPL(tmp1)					;\
	srlx	arg1, 1, arg1					;\
	cmp	tmp1, CHEETAH_IMPL				;\
        bne	1f						;\
	nop							;\
	sub	arg1, arg2, tmp1				;\
0:								;\
        stxa    %g0, [tmp1]ASI_EC_DIAG				;\
        membar  #Sync						;\
        cmp     %g0, tmp1					;\
        bne,pt  %icc, 0b					;\
        sub     tmp1, arg2, tmp1				;\
1:


#define SWITCH_STACK(estk)                                      \
        flushw                                                  ;\
        sub     estk, SA(KFPUSIZE+GSR_SIZE), estk              ;\
        andn    estk, 0x3f, estk                                ;\
        sub     estk, SA(MINFRAME) + STACK_BIAS, %sp            ;\
        mov     estk, %fp

/*
 * Returns icache size and linesize in reg1 and reg2, respectively.
 * Panther has a larger icache compared to Cheetahplus and Jaguar.
 */
#define	GET_ICACHE_PARAMS(reg1, reg2)				\
	GET_CPU_IMPL(reg1)					;\
	cmp	reg1, PANTHER_IMPL				;\
	bne	%xcc, 1f					;\
	  nop							;\
	set	PN_ICACHE_SIZE, reg1				;\
	set	PN_ICACHE_LSIZE, reg2				;\
	ba	2f						;\
	  nop							;\
1:								;\
	set	CH_ICACHE_SIZE, reg1				;\
	set	CH_ICACHE_LSIZE, reg2				;\
2:

        ENTRY_NP(sbdp_shutdown_asm)
        ! %o0 = address of sbdp_shutdown_t structure passed in
        !
        ! struct sbdp_shutdown {
        !       uint64_t        estack;    -> %o0
        !       uint64_t        flushaddr; -> %o1
        !       uint32_t        size;      -> %o2
        !       uint32_t        linesize;  -> %g1
        !       uint64_t        physaddr;  -> %o0
        ! } sbdp_shutdown_t;
        !
        membar  #LoadStore
        mov     %o0, %o4
        ldx     [%o4], %o0
        ldx     [%o4 + 8], %o1
        ld      [%o4 + 16], %o2
        ld      [%o4 + 20], %g1

        !
        ! Switch stack pointer to bbsram
        !
        SWITCH_STACK(%o0)

        ldx     [%o4 + 24], %o0 !save physaddr in %o0
        !
        ! Get some globals
        !
	! ecache_linesize already in %g1

        sethi   %hi(dcache_linesize), %g2
        ld      [%g2 + %lo(dcache_linesize)], %g2

        sethi   %hi(dcache_size), %g3
        ld      [%g3 + %lo(dcache_size)], %g3

	!
	! Save the E$ size
	!
	mov	%o2, %o5
        !
        ! Flush E$
        !
        rdpr    %pstate, %o3
        andn    %o3, PSTATE_IE | PSTATE_AM, %o4
        wrpr    %g0, %o4, %pstate

	! Panther needs to flush L2 before L3 cache. 
	PN_L2_FLUSHALL(%o4, %g4, %g5)

        ECACHE_FLUSHALL(%o2, %g1, %o1, %o4)

        wrpr    %g0, %o3, %pstate

	!
	! Invalidate the E$ tags (Cheetah only).
	!
	ECACHE_FLUSHTAGS(%o5, %g1, %o3)

        !
        ! %o2 & %o3 now available
        !

        membar  #Sync

        !
        ! Flush D$
        !
        CH_DCACHE_FLUSHALL(%g3, %g2, %o3)

        !
        ! Flush I$
        !
	GET_ICACHE_PARAMS(%g5, %g4)
        CH_ICACHE_FLUSHALL(%g5, %g4, %o3, %o4)

        membar  #Sync

        !
        ! Flush all unlocked dtlb's & itlb's
        !
	sethi	%hi(FLUSH_ADDR), %g3
	set	DEMAP_ALL_TYPE, %g1
	stxa	%g0, [%g1]ASI_DTLB_DEMAP
	stxa	%g0, [%g1]ASI_ITLB_DEMAP
	flush	%g3

	sir	0
        SET_SIZE(sbdp_shutdown_asm)

        .global sbdp_shutdown_asm_end

        .skip   2048

sbdp_shutdown_asm_end:


#include "assym.h"

#define	TT_HSM	0x99

!
! Move a single cache line of data.  Survive UE and CE on the read
!
! i0 = src va
! i1 = dst va
! i2 = line count
! i3 = line size
! i4 = cache of fpu state
!
	ENTRY(sgdr_mem_blkcopy)

	! TODO: can we safely SAVE here
	save	%sp, -SA(MINFRAME + 2*64), %sp

	! XXX do we need to save the state of the fpu?
	rd	%fprs, %i4
	btst	(FPRS_DU|FPRS_DL|FPRS_FEF), %i4

	! always enable FPU
	wr	%g0, FPRS_FEF, %fprs

	bz,a	1f
	 nop

	! save in-use fpregs on stack
	membar	#Sync
	add	%fp, STACK_BIAS - 81, %o2
	and	%o2, -64, %o2
	stda	%d0, [%o2]ASI_BLK_P
	membar	#Sync

1:
	brz,pn	%i2, 2f				! while (linecount) {
	 nop
	ldda	[%i0]ASI_BLK_P, %d0		! *dst = *src;
	membar	#Sync
	stda	%d0, [%i1]ASI_BLK_COMMIT_P
	membar	#Sync

	add	%i0, %i3, %i0			! dst++, src++;
	add	%i1, %i3, %i1

	ba	1b				! linecount-- }
	 dec	%i2

2:
	membar	#Sync

	! restore fp to the way we got it
	btst	(FPRS_DU|FPRS_DL|FPRS_FEF), %i4
	bz,a	3f
	 nop

	! restore fpregs from stack
	add	%fp, STACK_BIAS - 81, %o2
	and	%o2, -64, %o2
	ldda	[%o2]ASI_BLK_P, %d0
	membar	#Sync

3:
	wr	%g0, %i4, %fprs			! fpu back to the way it was
	ret
	restore
	SET_SIZE(sgdr_mem_blkcopy)

        ! Store long word value at mc regs
        !
        ! void  stdmcdecode(uint64_t physaddr, uint64_t value)
        !
        ENTRY(stdmcdecode)
        /*
         * disable interrupts, clear Address Mask to access 64 bit physaddr
         */
        rdpr    %pstate, %o4
        andn    %o4, PSTATE_IE | PSTATE_AM, %o5
        wrpr    %o5, 0, %pstate         ! clear IE, AM bits
        stxa    %o1, [%o0]ASI_MC_DECODE
	membar	#Sync
        retl
        wrpr    %g0, %o4, %pstate       ! restore earlier pstate register value
        SET_SIZE(stdmcdecode)

