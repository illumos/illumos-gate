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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains the low-level DMV interrupt
 * handler for IDN cross-domain interrupts.
 */

#if defined(lint)
#include <sys/types.h>
#endif /* lint */

#include <sys/asm_linkage.h>
#include <sys/machasi.h>
#include <sys/privregs.h>
#include <sys/intreg.h>
#include <sys/machthread.h>

#include <sys/idn.h>

#if !defined(lint)
#include "idn_offsets.h"
#endif /* !lint */

#define	IDN_MONDO

/*
 * The IDN_DMV_CPU_SHIFT is based on the sizeof (idn_dmv_cpu_t)
 * which must be a power of 2 to optimize calculating our
 * entry into idn_dmv_cpu[].
 */
#define	IDN_DMV_CPU_SHIFT	4

/*
 *--------------------------------------------------------
 */
#if defined(lint)

/*
 * Would be nice to use init_mondo, but unforunately
 * it assumes the first arg is 32-bits.
 */
/*ARGSUSED*/
void
idnxf_init_mondo(uint64_t arg0, uint64_t arg1, uint64_t arg2)
{}

#else /* lint */

	.global _idn_dispatch_status_busy
_idn_dispatch_status_busy:
	.asciz	"ASI_INTR_DISPATCH_STATUS error: busy"
	.align	4

	ENTRY_NP(idnxf_init_mondo)
#ifdef DEBUG
	!
	! IDSR should not be busy at the moment - borrowed from init_mondo
	!
	ldxa	[%g0]ASI_INTR_DISPATCH_STATUS, %g1
	btst	IDSR_BUSY, %g1
	bz,pt	%xcc, 1f
	mov	ASI_INTR_DISPATCH, %asi
	sethi	%hi(_idn_dispatch_status_busy), %o0
	call	panic
	or	%o0, %lo(_idn_dispatch_status_busy), %o0
#endif /* DEBUG */

	mov	ASI_INTR_DISPATCH, %asi
1:
	stxa	%o0, [IDDR_0]%asi	! dmv_word0
	stxa	%o1, [IDDR_1]%asi	! dmv_word1
	stxa	%o2, [IDDR_2]%asi	! dmv_word2

	retl
	membar	#Sync

	SET_SIZE(idnxf_init_mondo)

#endif /* lint */
/*
 *--------------------------------------------------------
 */
#if defined(lint)

/*
 * Unfortunately, send_mondo is rather picky about getting
 * a result from the cpu it sends an interrupt to.  If it
 * doesn't get a result within a specific timeframe it
 * will panic!  For IDN that's not cool since a cpu hungup
 * in one could ultimately result in the demise of a cpu
 * in another domain.  Instead of getting our panties in
 * a bind, we simply bail out.
 */
/*ARGSUSED*/
int
idnxf_send_mondo(int upaid)
{ return (0); }

#else /* lint */

	.seg	".data"

	.global _idn_send_mondo_failure
_idn_send_mondo_failure:
	.word	0

	.seg	".text"
	ENTRY(idnxf_send_mondo)
	!
	! NOTE:
	!	This is stolen from send_mondo.  The changes
	!	are those ifdef'd with IDN_MONDO
	!
	! construct the interrupt dispatch command register in %g1
	! also, get the dispatch out as SOON as possible
	! (initial analysis puts the minimum dispatch time at around
	!  30-60 cycles.  hence, we try to get the dispatch out quickly
	!  and then start the rapid check loop).
	!
	rd	%tick, %o4			! baseline tick
	sll	%o0, IDCR_PID_SHIFT, %g1	! IDCR<18:14> = upa port id
	or	%g1, IDCR_OFFSET, %g1		! IDCR<13:0> = 0x70
	stxa	%g0, [%g1]ASI_INTR_DISPATCH	! interrupt vector dispatch
#if defined(SF_ERRATA_54)
	membar	#Sync				! store must occur before load
	mov	0x20, %g3			! UDBH Control Register Read
	ldxa	[%g3]ASI_SDB_INTR_R, %g0
#endif
	membar	#Sync
	clr	%o2				! clear NACK counter
	clr	%o3				! clear BUSY counter

	!
	! how long, in ticks, are we willing to wait completely
	!
	sethi	%hi(xc_tick_limit), %g2
	ldx	[%g2 + %lo(xc_tick_limit)], %g2
	add	%g2, %o4, %o5			! compute the limit value

	!
	! check the dispatch status
	!
.check_dispatch:
	ldxa	[%g0]ASI_INTR_DISPATCH_STATUS, %o1
	brz,pn	%o1, .dispatch_complete
	  rd	%tick, %g5

	!
	! see if we've gone beyond the limit
	! (can tick ever overflow?)
	!
.timeout_primed:
	sub	%o5, %g5, %g2			! limit - tick < 0 if timeout
	brgez,pt %g2, .check_busy
	  inc	%o3				! bump the BUSY counter

#ifdef IDN_MONDO
	!
	! Within the context of IDN we don't want
	! to panic just because we can't send_mondo.
	! Clear the dispatch register and increment
	! our count of failures.
	!
	stxa	%g0, [%g1]ASI_INTR_DISPATCH
	sethi	%hi(_idn_send_mondo_failure), %o0
	ld	[%o0 + %lo(_idn_send_mondo_failure)], %o1
	inc	%o1
	st	%o1, [%o0 + %lo(_idn_send_mondo_failure)]
	retl
	  mov	-1, %o0				! return (-1)
#else /* IDN_MONDO */
	!
	! time to die, see if we are already panicing
	! 
	mov	%o0, %o1			! save target
	sethi	%hi(_send_mondo_nack), %o0
	or	%o0, %lo(_send_mondo_nack), %o0
	sethi	%hi(panicstr), %g2
	ldn	[%g2 + %lo(panicstr)], %g2
	brnz	%g2, .dispatch_complete		! skip if already in panic
	  nop
	call	panic
	  nop
#endif /* IDN_MONDO */

.check_busy:
	btst	IDSR_BUSY, %o1			! was it BUSY?
	bnz,pt	%xcc, .check_dispatch
	  nop

	!
	! we weren't busy, we must have been NACK'd
	! wait a while and send again
	! (this might need jitter)
	!
	sethi	%hi(sys_clock_mhz), %g2
	lduw	[%g2 + %lo(sys_clock_mhz)], %g2
	rd	%tick, %g4
	add	%g2, %g4, %g2
.delay:
	cmp	%g2, %g4
	bgu,pt	%xcc, .delay
	rd	%tick, %g4

	stxa	%g0, [%g1]ASI_INTR_DISPATCH	! interrupt vector dispatch
#if defined(SF_ERRATA_54)
	membar	#Sync				! store must occur before load
	ldxa	[%g3]ASI_SDB_INTR_R, %g0
#endif
	membar	#Sync
	clr	%o3				! reset BUSY counter
	ba	.check_dispatch
	  inc	%o2				! bump the NACK counter

.dispatch_complete:
#ifndef IDN_MONDO
#ifdef SEND_MONDO_STATS
	!
	! Increment the appropriate entry in a send_mondo timeout array
	! x_entry[CPU][MSB]++;
	sub	%g5, %o4, %g5			! how long did we wait?
	clr	%o1				! o1 is now bit counter
1:	orcc	%g5, %g0, %g0			! any bits left?
	srlx	%g5, 1, %g5			! bits to the right
	bne,a,pt %xcc, 1b
	  add	%o1, 4, %o1			! pointer increment

	!
	! now compute the base of the x_early entry for our cpu
	!
	CPU_INDEX(%o0, %g5)
	sll	%o0, 8, %o0			! 64 * 4
	add	%o0, %o1, %o1			! %o0 = &[CPU][delay]

	!
	! and increment the appropriate value
	!
	sethi	%hi(x_early), %o0
	or	%o0, %lo(x_early), %o0
	ld	[%o0 + %o1], %g5
	inc	%g5
	st	%g5, [%o0 + %o1]
#endif	/* SEND_MONDO_STATS */
#endif /* !IDN_MONDO */
	retl
#ifdef IDN_MONDO
	  mov	%g0, %o0			! return (0)
#else /* IDN_MONDO */
	  nop
#endif /* IDN_MONDO */
	SET_SIZE(idnxf_send_mondo)

#endif /* lint */
/*
 *--------------------------------------------------------
 */
#if defined(lint)

/*ARGSUSED*/
void
idn_dmv_handler(void *arg)
{}

#else /* lint */

	ENTRY_NP(idn_dmv_handler)
	!
	! On entry:
	!	g1 = idn_dmv_data
	!	g2 = word 0
	!
	ldx	[%g1 + IDN_DMV_QBASE], %g4	! g4 = idn_dmv_qbase
	add	%g1, IDN_DMV_CPU, %g3		! g3 = &idn_dmv_cpu[0]

	CPU_INDEX(%g6, %g5)		! g6 = cpuid

	!
	! g5 = cur = idn_dmv_cpu[cpuid]
	!
	sll	%g6, IDN_DMV_CPU_SHIFT, %g6	! g6 = cpuid * 8
	add	%g3, IDN_DMV_CURRENT, %g3
	ld	[%g6 + %g3], %g5
	!
	! g5 = idn_dmv_cpu[cpuid].idn_dmv_current
	!      offset from idn_dmv_qbase
	!
	or	%g5, %g0, %g5		! get to 64-bits
	add	%g5, %g4, %g5		! g5 = idn_dmv_current
					!      actual address
	ldstub	[%g5 + IV_INUSE], %g7	! cur->iv_inuse = 0xff
	brz,pt	%g7, 1f			! did we get it?
	sub	%g3, IDN_DMV_CURRENT, %g4

	!
	! Queue is FULL.  Drop interrupt.
	!
	add	%g4, IDN_DMV_LOSTINTR, %g3
	ld	[%g6 + %g3], %g2
	!
	! g2 = idn_dmv_cpu[cpuid].idn_iv_lostintr++
	!
	inc	%g2
	set	dmv_finish_intr, %g4
	st	%g2, [%g3 + %g6]
	jmp	%g4
	mov	-1, %g1
	!
	! not reached
	!

1:
	add	%g4, IDN_DMV_ACTIVE, %g7
	!
	! Move current pointer to next one.
	! idn_dmv_current[cpuid] = cur->iv_next
	!
	ld	[%g5 + IV_NEXT], %g4
	st	%g4, [%g3 + %g6]

	!
	! Start filling in structure with data.
	!
	stx	%g2, [%g5 + IV_HEAD]

	mov	IRDR_1, %g2
	mov	IRDR_2, %g4
	ldxa	[%g2]ASI_INTR_RECEIVE, %g2	! g2 = xargs[0,1]
	ldxa	[%g4]ASI_INTR_RECEIVE, %g4	! g4 = xargs[2,3]

	stx	%g2, [%g5 + IV_XARGS0]
	stx	%g4, [%g5 + IV_XARGS2]

	membar	#StoreLoad|#StoreStore

	clrb	[%g5 + IV_READY]	! cur->iv_ready = 0 (unlocked)

	!
	! See if we're already active, i.e. have things
	! queued.  If so, don't bother generating a soft
	! interrupt.  IDN interrupts could exhaust the
	! intr_vec structs for the given cpu and that code
	! doesn't know how to survive with intr_vec structs!
	!
	ldstub	[%g6 + %g7], %g7	! idn_dmv_active = 0xff
	brz,a,pt %g7, 2f
	ldx	[%g1 + IDN_SOFT_INUM], %g7	! g7 = idn_soft_inum
	mov	-1, %g7
2:

	!
	! Setup to cause an IDN soft interrupt to occur,
	! (if necessary).
	!
	set	dmv_finish_intr, %g3
	jmp	%g3
	mov	%g7, %g1

	SET_SIZE(idn_dmv_handler)

#endif /* lint */
