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
 */
/*
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/asm_linkage.h>
#include <sys/regset.h>

#include "assym.h"

	ENTRY_NP(dtrace_getfp)
	movq	%rbp, %rax
	ret
	SET_SIZE(dtrace_getfp)


	ENTRY_NP(dtrace_getvmreg)

	movq	%rdi, %rdx
	vmread	%rdx, %rax
	ret

	SET_SIZE(dtrace_getvmreg)


	ENTRY(dtrace_cas32)
	movl	%esi, %eax
	lock
	cmpxchgl %edx, (%rdi)
	ret
	SET_SIZE(dtrace_cas32)

	ENTRY(dtrace_casptr)
	movq	%rsi, %rax
	lock
	cmpxchgq %rdx, (%rdi)
	ret
	SET_SIZE(dtrace_casptr)

	ENTRY(dtrace_caller)
	movq	$-1, %rax
	ret
	SET_SIZE(dtrace_caller)

	ENTRY(dtrace_copy)
	pushq	%rbp
	call	smap_disable
	movq	%rsp, %rbp

	xchgq	%rdi, %rsi		/* make %rsi source, %rdi dest */
	movq	%rdx, %rcx		/* load count */
	repz				/* repeat for count ... */
	smovb				/*   move from %ds:rsi to %ed:rdi */
	call	smap_enable
	leave
	ret
	SET_SIZE(dtrace_copy)

	ENTRY(dtrace_copystr)
	pushq	%rbp
	movq	%rsp, %rbp
	call	smap_disable
0:
	movb	(%rdi), %al		/* load from source */
	movb	%al, (%rsi)		/* store to destination */
	addq	$1, %rdi		/* increment source pointer */
	addq	$1, %rsi		/* increment destination pointer */
	subq	$1, %rdx		/* decrement remaining count */
	cmpb	$0, %al
	je	2f
	testq	$0xfff, %rdx		/* test if count is 4k-aligned */
	jnz	1f			/* if not, continue with copying */
	testq	$CPU_DTRACE_BADADDR, (%rcx) /* load and test dtrace flags */
	jnz	2f
1:
	cmpq	$0, %rdx
	jne	0b
2:
	call	smap_enable
	leave
	ret

	SET_SIZE(dtrace_copystr)

	ENTRY(dtrace_fulword)
	call	smap_disable
	movq	(%rdi), %rax
	call	smap_enable
	ret
	SET_SIZE(dtrace_fulword)

	ENTRY(dtrace_fuword8_nocheck)
	call	smap_disable
	xorq	%rax, %rax
	movb	(%rdi), %al
	call	smap_enable
	ret
	SET_SIZE(dtrace_fuword8_nocheck)

	ENTRY(dtrace_fuword16_nocheck)
	call	smap_disable
	xorq	%rax, %rax
	movw	(%rdi), %ax
	call	smap_enable
	ret
	SET_SIZE(dtrace_fuword16_nocheck)

	ENTRY(dtrace_fuword32_nocheck)
	call	smap_disable
	xorq	%rax, %rax
	movl	(%rdi), %eax
	call	smap_enable
	ret
	SET_SIZE(dtrace_fuword32_nocheck)

	ENTRY(dtrace_fuword64_nocheck)
	call	smap_disable
	movq	(%rdi), %rax
	call	smap_enable
	ret
	SET_SIZE(dtrace_fuword64_nocheck)

	ENTRY(dtrace_probe_error)
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$0x8, %rsp
	movq	%r9, (%rsp)
	movq	%r8, %r9
	movq	%rcx, %r8
	movq	%rdx, %rcx
	movq	%rsi, %rdx
	movq	%rdi, %rsi
	movl	dtrace_probeid_error(%rip), %edi
	call	dtrace_probe
	addq	$0x8, %rsp
	leave
	ret
	SET_SIZE(dtrace_probe_error)

