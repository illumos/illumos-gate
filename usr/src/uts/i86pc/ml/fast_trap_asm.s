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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include <sys/regset.h>
#include <sys/psw.h>

#if defined(__lint)

#include <sys/types.h>
#include <sys/thread.h>
#include <sys/systm.h>
#include <sys/lgrp.h>

#else   /* __lint */

#include <sys/pcb.h>
#include <sys/trap.h>
#include <sys/ftrace.h>
#include <sys/traptrace.h>
#include <sys/clock.h>
#include <sys/panic.h>
#include <sys/privregs.h>

#include "assym.h"

#endif	/* __lint */


#if defined(__lint)

hrtime_t
get_hrtime(void)
{ return (0); }

hrtime_t
get_hrestime(void)
{
	hrtime_t ts;

	gethrestime((timespec_t *)&ts);
	return (ts);
}

hrtime_t
gethrvtime(void)
{
	klwp_t *lwp = ttolwp(curthread);
	struct mstate *ms = &lwp->lwp_mstate;

	return (gethrtime() - ms->ms_state_start + ms->ms_acct[LMS_USER]);
}

uint64_t
getlgrp(void)
{
	return (((uint64_t)(curthread->t_lpl->lpl_lgrpid) << 32) |
			curthread->t_cpu->cpu_id);
}

#else	/* __lint */

/*
 * XX64: We are assuming that libc continues to expect the 64-bit value being
 * returned in %edx:%eax.  We further assume that it is safe to leave
 * the top 32-bit intact in %rax as they will be ignored by libc.  In
 * other words, if the 64-bit value is already in %rax, while we manually
 * manufacture a 64-bit value in %edx:%eax by setting %edx to be the high
 * 32 bits of %rax, we don't zero them out in %rax.
 * The following amd64 versions will need to be changed if the above
 * assumptions are not true.
 */

#if defined(__amd64)

	.globl	gethrtimef
	ENTRY_NP(get_hrtime)
	FAST_INTR_PUSH
	movq	gethrtimef(%rip), %rax
	INDIRECT_CALL_REG(rax)
	movq	%rax, %rdx
	shrq	$32, %rdx			/* high 32-bit in %edx */
	FAST_INTR_POP
	FAST_INTR_RETURN
	SET_SIZE(get_hrtime)

#elif defined(__i386)

	.globl	gethrtimef
	ENTRY_NP(get_hrtime)
	FAST_INTR_PUSH
	call	*gethrtimef
	FAST_INTR_POP
	FAST_INTR_RETURN
	SET_SIZE(get_hrtime)

#endif	/* __i386 */

#if defined(__amd64)

	.globl	gethrestimef
	ENTRY_NP(get_hrestime)
	FAST_INTR_PUSH
	subq	$TIMESPEC_SIZE, %rsp
	movq	%rsp, %rdi
	movq	gethrestimef(%rip), %rax
	INDIRECT_CALL_REG(rax)
	movl	(%rsp), %eax
	movl	CLONGSIZE(%rsp), %edx
	addq	$TIMESPEC_SIZE, %rsp
	FAST_INTR_POP
	FAST_INTR_RETURN
	SET_SIZE(get_hrestime)

#elif defined(__i386)

	.globl	gethrestimef
	ENTRY_NP(get_hrestime)
	FAST_INTR_PUSH
	subl	$TIMESPEC_SIZE, %esp
	pushl	%esp
	call	*gethrestimef
	movl	_CONST(4 + 0)(%esp), %eax
	movl	_CONST(4 + CLONGSIZE)(%esp), %edx
	addl	$_CONST(4 + TIMESPEC_SIZE), %esp
	FAST_INTR_POP
	FAST_INTR_RETURN
	SET_SIZE(get_hrestime)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY_NP(gethrvtime)
	FAST_INTR_PUSH
	call	gethrtime_unscaled		/* get time since boot */
	movq	%gs:CPU_LWP, %rcx		/* current lwp */
	subq	LWP_MS_STATE_START(%rcx), %rax	/* - ms->ms_state_start */
	addq	LWP_ACCT_USER(%rcx), %rax	/* add ms->ms_acct[LMS_USER] */
	subq	$16, %rsp
	movq	%rax, (%rsp)
	movq	%rsp, %rdi
	call	scalehrtime
	movq	(%rsp), %rax
	addq	$16, %rsp
	movq	%rax, %rdx
	shrq	$32, %rdx			/* high 32-bit in %rdx */
	FAST_INTR_POP
	FAST_INTR_RETURN
	SET_SIZE(gethrvtime)

#elif defined(__i386)

	ENTRY_NP(gethrvtime)
	FAST_INTR_PUSH
	call	gethrtime_unscaled		/* get time since boot */
	movl	%gs:CPU_LWP, %ecx		/* current lwp */
	subl	LWP_MS_STATE_START(%ecx), %eax	/* - ms->ms_state_start */
	sbbl	LWP_MS_STATE_START+4(%ecx), %edx
	addl	LWP_ACCT_USER(%ecx), %eax	/* add ms->ms_acct[LMS_USER] */
	adcl	LWP_ACCT_USER+4(%ecx), %edx
	subl	$0x8, %esp
	leal	(%esp), %ecx
	movl	%eax, (%ecx)
	movl	%edx, 4(%ecx)
	pushl	%ecx
	call	scalehrtime
	popl	%ecx
	movl	(%ecx), %eax
	movl	4(%ecx), %edx
	addl	$0x8, %esp
	FAST_INTR_POP
	FAST_INTR_RETURN
	SET_SIZE(gethrvtime)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY_NP(getlgrp)
	FAST_INTR_PUSH
	movq	%gs:CPU_THREAD, %rcx
	movq	T_LPL(%rcx), %rcx
	movl	LPL_LGRPID(%rcx), %edx
	movl	%gs:CPU_ID, %eax
	FAST_INTR_POP
	FAST_INTR_RETURN
	SET_SIZE(getlgrp)

#elif defined(__i386)

	ENTRY_NP(getlgrp)
	FAST_INTR_PUSH
	movl	%gs:CPU_THREAD, %ecx
	movl	T_LPL(%ecx), %ecx
	movl	LPL_LGRPID(%ecx), %edx
	movl	%gs:CPU_ID, %eax
	FAST_INTR_POP
	FAST_INTR_RETURN
	SET_SIZE(getlgrp)

#endif	/* __i386 */

#endif	/* __lint */
