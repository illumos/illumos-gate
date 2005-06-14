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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if defined(__lint)
#include <kmdb/kmdb_asmutil.h>
#endif

#include <sys/asm_linkage.h>

#if defined(__lint)
/*ARGSUSED*/
uintptr_t
cas(uintptr_t *rs1, uintptr_t rs2, uintptr_t rd)
{
	return (0);
}
#else

	ENTRY_NP(cas)
	movq	%rsi, %rax
	lock
	  cmpxchgq %rdx, (%rdi)
	ret
	SET_SIZE(cas)
#endif

#if defined(__lint)
void
membar_producer(void)
{
}
#else

	ENTRY(membar_producer)
	sfence
	ret
	SET_SIZE(membar_producer)

#endif

#if defined(__lint)
/*ARGSUSED*/
void
rdmsr(uint32_t addr, uint64_t *retp)
{
}
#else

	ENTRY(rdmsr)
	movl	%edi, %ecx
	rdmsr
	movl	%eax, (%rsi)
	movl	%edx, 4(%rsi)
	ret
	SET_SIZE(rdmsr)

#endif

#if defined(__lint)
/*ARGSUSED*/
void
wrmsr(uint32_t addr, uint64_t *valp)
{
}
#else

	ENTRY(wrmsr)
	movl	(%rsi), %eax
	movl	4(%rsi), %edx
	movl	%edi, %ecx
	wrmsr
	ret
	SET_SIZE(wrmsr)

#endif

#if defined(__lint)
uintptr_t
get_fp(void)
{
	return (0);
}
#else

	ENTRY(get_fp)
	movq	%rbp, %rax
	ret
	SET_SIZE(get_fp)

#endif

#if defined(__lint)
/*ARGSUSED*/
void
kmt_in(void *buf, size_t nbytes, uintptr_t addr)
{
}

/*ARGSUSED*/
void
kmt_out(void *buf, size_t nbytes, uintptr_t addr)
{
}
#else

	ENTRY_NP(kmt_in)
	cmpq	$4, %rsi
	je	4f	
	cmpq	$2, %rsi
	je	2f

1:	inb	(%dx)
	movb	%al, 0(%rdi)
	ret

2:	inw	(%dx)
	movw	%ax, 0(%rdi)
	ret

4:	inl	(%dx)
	movl	%eax, 0(%rdi)
	ret
	SET_SIZE(kmt_in)

	ENTRY_NP(kmt_out)
	cmpq	$4, %rsi
	je	4f
	cmpq	$2, %rsi
	je	2f

1:	movb	0(%rdi), %al
	outb	(%dx)
	ret

2:	movw	0(%rdi), %ax
	outw	(%dx)
	ret

4:	movl	0(%rdi), %eax
	outl	(%dx)
	ret
	SET_SIZE(kmt_out)

#endif
