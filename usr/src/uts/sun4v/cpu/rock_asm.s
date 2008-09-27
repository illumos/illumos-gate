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

#include <sys/asm_linkage.h>
#include <sys/hypervisor_api.h>		/* For FAST_TRAP */
#include <sys/rock_hypervisor_api.h>
#include <sys/sun4asi.h>	/* ASI_BLK_P */
#include <sys/machthread.h>	/* THREAD_REG */
#include <sys/fsr.h>		/* FPRS_FEF, FPRS_DU */
#include <vm/hat_sfmmu.h>	/* TSBTAG_INVALID */

#define	TRANS_RETRY_COUNT	3

/*
 * XXX Delete this comment and these #undef's when the corresponding
 * Makefile.workarounds lines are deleted.
 * XXX
 *
 * Transactional instructions are used here regardless of what's in
 * Makefile.workarounds.
 */
#undef	chkpt
#undef	commit


#if defined(lint)

#include <sys/mutex.h>

void
cpu_smt_pause(void)
{}

void
fp_zero(void)
{}

/*ARGSUSED*/
uint64_t
hv_rk_perf_count_init(uint64_t counter)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_rk_perf_count_release(uint64_t counter)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_rk_perf_count_set(uint64_t counter, uint64_t value)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_rk_perf_count_get(uint64_t counter, uint64_t *value)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_rk_perf_count_start(uint64_t counter, uint64_t value)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_rk_perf_count_overflow(uint64_t counter, uint64_t *ovf_cnt)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_rk_perf_count_stop(uint64_t counter)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_rk_perf_sample_init(uint64_t sampler, uint64_t ringbuf_pa)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_rk_perf_sample_release(uint64_t sampler)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_rk_perf_sample_start(uint64_t sampler, uint64_t freq,
	 		uint64_t list_size, uint64_t valist_pa)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_rk_perf_sample_config(uint64_t sampler, uint64_t reg_va, uint64_t reg_value)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_rk_perf_sample_pending(uint64_t sampler, uint64_t *pend_cnt)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_rk_perf_sample_stop(uint64_t sampler)
{ return (0); }

/*ARGSUSED*/
void
cpu_inv_tsb(caddr_t tsb_base, uint_t tsb_bytes)
{}

#else	/* lint */

/* XXX TODO XXX
 * When we get real hardware, we need to do performance tuning on this.
 * Does it help?  Does it ever hurt?  How many membar's should we have here?
 */
	/*
	 * Called from various spin loops to prevent this strand from
	 * stealing too many cycles from its sibling, who is presumably
	 * doing useful work.
	 */
	ENTRY_NP(cpu_smt_pause)
	membar	#Halt
	retl
	nop
	SET_SIZE(cpu_smt_pause)


/*
 * fp_zero() - clear all fp data registers and the fsr
 */

.global	fp_zero_zero
.align 8
fp_zero_zero:
	.xword	0

	ENTRY_NP(fp_zero)
	sethi	%hi(fp_zero_zero), %o0
	ldx	[%o0 + %lo(fp_zero_zero)], %fsr
	movxtod %g0, %d0
	fzero   %d2
	movxtod %g0, %d4
	fzero   %d6
	movxtod %g0, %d8
	fzero   %d10
	movxtod %g0, %d12
	fzero   %d14
	movxtod %g0, %d16
	fzero   %d18
	movxtod %g0, %d20
	fzero   %d22
	movxtod %g0, %d24
	fzero   %d26
	movxtod %g0, %d28
	fzero   %d30
	movxtod %g0, %d32
	fzero   %d34
	movxtod %g0, %d36
	fzero   %d38
	movxtod %g0, %d40
	fzero   %d42
	movxtod %g0, %d44
	fzero   %d46
	movxtod %g0, %d48
	fzero   %d50
	movxtod %g0, %d52
	fzero   %d54
	movxtod %g0, %d56
	fzero   %d58
	movxtod %g0, %d60
	retl
	fzero   %d62
	SET_SIZE(fp_zero)

	/* hcalls for performance counters */

	/*
	 * uint64_t hv_rk_perf_count_init(uint64_t counter);
	 */
	ENTRY(hv_rk_perf_count_init)
	mov	HV_RK_PERF_COUNT_INIT, %o5
	ta	FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_rk_perf_count_init)

	/*
	 * uint64_t hv_rk_perf_count_release(uint64_t counter);
	 */
	ENTRY(hv_rk_perf_count_release)
	mov	HV_RK_PERF_COUNT_RELEASE, %o5
	ta	FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_rk_perf_count_release)

	/*
	 * uint64_t hv_rk_perf_count_set(uint64_t counter, uint64_t value)
	 */
	ENTRY(hv_rk_perf_count_set)
	mov	HV_RK_PERF_COUNT_SET, %o5
	ta	FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_rk_perf_count_set)

	/*
	 * uint64_t hv_rk_perf_count_get(uint64_t counter, uint64_t *value)
	 */
	ENTRY(hv_rk_perf_count_get)
	mov	HV_RK_PERF_COUNT_GET, %o5
	mov	%o1, %o2	! Save the address
	ta	FAST_TRAP
	retl
	  stx	%o1, [%o2]	! Value is returned in %o1 by the HV
	SET_SIZE(hv_rk_perf_count_get)

	/*
	 * uint64_t hv_rk_perf_count_start(uint64_t counter, uint64_t value)
	 */
	ENTRY(hv_rk_perf_count_start)
	mov	HV_RK_PERF_COUNT_START, %o5
	ta	FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_rk_perf_count_start)

	/*
	 * uint64_t hv_rk_perf_count_overflow(uint64_t counter,
	 * 						uint64_t *ovf_cnt)
	 */
	ENTRY(hv_rk_perf_count_overflow)
	mov	%o1, %o2
	mov	HV_RK_PERF_COUNT_OVERFLOW, %o5
	ta	FAST_TRAP
	retl
	  stx	%o1, [%o2]
	SET_SIZE(hv_rk_perf_count_overflow)

	/*
	 * uint64_t hv_rk_perf_count_stop(uint64_t counter)
	 */
	ENTRY(hv_rk_perf_count_stop)
	mov	HV_RK_PERF_COUNT_STOP, %o5
	ta	FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_rk_perf_count_stop)

	/*
	 * uint64_t hv_rk_perf_sample_init(uint64_t counter,
						uint64_t ringbuf_pa)
	 */
	ENTRY(hv_rk_perf_sample_init)
	mov	HV_RK_PERF_SAMPLE_INIT, %o5
	ta	FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_rk_perf_sample_init)

	/*
	 * uint64_t hv_rk_perf_sample_release(uint64_t counter)
	 */
	ENTRY(hv_rk_perf_sample_release)
	mov	HV_RK_PERF_SAMPLE_RELEASE, %o5
	ta	FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_rk_perf_sample_release)

	/*
	 * uint64_t hv_rk_perf_sample_config(uint64_t sampler, uint64_t reg_va,
	 *					uint64_t reg_value)
	 */
	ENTRY(hv_rk_perf_sample_config)
	mov	HV_RK_PERF_SAMPLE_CONFIG, %o5
	ta	FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_rk_perf_sample_config)

	/*
	 * uint64_t hv_rk_perf_sample_start(uint64_t sampler, uint64_t freq,
	 *			uint64_t list_size, uint64_t valist_pa)
	 */
	ENTRY(hv_rk_perf_sample_start)
	mov	HV_RK_PERF_SAMPLE_START, %o5
	ta	FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_rk_perf_sample_start)

	/*
	 * uint64_t hv_rk_perf_sample_pending(uint64_t sampler, 
	 *					uint64_t *pend_cnt)
	 */
	ENTRY(hv_rk_perf_sample_pending)
	mov	%o1, %o2
	mov	HV_RK_PERF_SAMPLE_PENDING, %o5
	ta	FAST_TRAP
	retl
	  stx	%o1, [%o2]
	SET_SIZE(hv_rk_perf_sample_pending)

	/*
	 * uint64_t hv_rk_perf_sample_stop(uint64_t sampler)
	 */
	ENTRY(hv_rk_perf_sample_stop)
	mov	HV_RK_PERF_SAMPLE_STOP, %o5
	ta	FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_rk_perf_sample_stop)

/*
 * Invalidate all of the entries within the TSB, by setting the inv bit
 * in the tte_tag field of each tsbe.
 *
 * We take advantage of the fact that the TSBs are page aligned and a
 * multiple of PAGESIZE to use ASI_BLK_INIT_xxx ASI.
 *
 * See TSB_LOCK_ENTRY and the miss handlers for how this works in practice
 * (in short, we set all bits in the upper word of the tag, and we give the
 * invalid bit precedence over other tag bits in both places).
 */

#define	VIS_BLOCKSIZE	64
#include "assym.h"	/* T_PREEMPT */

	ENTRY(cpu_inv_tsb)

	! Get space for aligned block of saved fp regs.
	save	%sp, -SA(MINFRAME + 2*VIS_BLOCKSIZE), %sp

	! kpreempt_disable();
	ldsb	[THREAD_REG + T_PREEMPT], %l3
	inc	%l3
	stb	%l3, [THREAD_REG + T_PREEMPT]

	! See if fpu was in use.  If it was, we need to save off the
	! floating point registers to the stack.
	rd	%fprs, %l0			! %l0 = cached copy of fprs
	mov	%g0, %l2

	btst	FPRS_FEF, %l0
	bz,pt	%icc, 4f
	nop

	! If upper half fp registers are in use, save them as they will be
	! used below.
	btst	FPRS_DU, %l0
	bz,pt	%icc, 4f
	nop

	! save in-use fpregs on stack

	add	%fp, STACK_BIAS - 65, %l1	! get stack frame for fp regs
	and	%l1, -VIS_BLOCKSIZE, %l1	! block align frame
	stda	%d32, [%l1]ASI_BLK_P		! %l1 = addr of saved fp regs

	! Set a flag saying fp regs are saved.
	mov	1, %l2

	! enable fp

4:	membar	#StoreStore|#StoreLoad|#LoadStore
	wr	%g0, FPRS_FEF|FPRS_DU, %fprs
	wr	%g0, ASI_BLK_P, %asi

	! load up FP registers with invalid TSB tag.
	set	TSBTAG_INVALID, %l3
	movxtod	%l3, %d32
	movxtod	%l3, %d36
	movxtod	%l3, %d40	! Invalidate context
	movxtod	%l3, %d44
	movxtod	%g0, %d34
	movxtod	%g0, %d38
	movxtod	%g0, %d42	! Zero in TTE
	movxtod	%g0, %d46

	ba,pt	%xcc, .cpu_inv_doblock
	mov	(4*VIS_BLOCKSIZE), %i4	! we do 4 stda's each loop below

.cpu_inv_blkstart:
	stda	%d32, [%i0+128]%asi
	stda	%d32, [%i0+64]%asi
	stda	%d32, [%i0]%asi

	add	%i0, %i4, %i0
	sub	%i1, %i4, %i1

.cpu_inv_doblock:
	cmp	%i1, (4*VIS_BLOCKSIZE)	! check for completion
	bgeu,a	%icc, .cpu_inv_blkstart
	  stda	%d32, [%i0+192]%asi

.cpu_inv_finish:
	membar	#Sync
	brz,a	%l2, .cpu_inv_finished
	  wr	%l0, 0, %fprs		! restore fprs

	! restore fpregs from stack
	ldda    [%l1]ASI_BLK_P, %d32

	membar	#Sync
	wr	%l0, 0, %fprs		! restore fprs

.cpu_inv_finished:
	! kpreempt_enable();
	ldsb	[THREAD_REG + T_PREEMPT], %l3
	dec	%l3
	stb	%l3, [THREAD_REG + T_PREEMPT]
	ret
	restore
	SET_SIZE(cpu_inv_tsb)

#endif /* lint */
