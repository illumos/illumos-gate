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

#if defined(lint) || defined(__lint)
#include <sys/types.h>
#else
#include <sys/asm_linkage.h>
#endif

#if defined(lint) || defined(__lint)

/*ARGSUSED*/
void
set_bit(int nr, volatile void * addr)
{}

/*ARGSUSED*/
void
clear_bit(int nr, volatile void * addr)
{}

/*ARGSUSED*/
int
test_and_set_bit(int nr, volatile void * addr)
{
	return (0);
}

/*ARGSUSED*/
int
test_and_clear_bit(int nr, volatile void * addr)
{
	return (0);
}

/*ARGSUSED*/
int
find_first_zero_bit(void * addr, unsigned size)
{
	return (0);
}

/*ARGSUSED*/
int
atomic_cmpset_int(volatile unsigned int *dst,
		  unsigned int exp, unsigned int src)
{
	return (0);
}

void mb()
{}

#else	/* lint */

#if defined(__amd64)

	ENTRY(set_bit)
	lock
	btsl	%edi, (%rsi)
	ret
	SET_SIZE(set_bit)

#elif defined(__i386)

	ENTRY(set_bit)
	movl	0x4(%esp), %edx
	movl	0x8(%esp), %eax
	lock
	btsl	%edx, (%eax)
	ret
	SET_SIZE(set_bit)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(clear_bit)
	lock
	btrl	%edi, (%rsi)
	ret
	SET_SIZE(clear_bit)

#elif defined(__i386)

	ENTRY(clear_bit)
	movl	0x4(%esp), %edx
	movl	0x8(%esp), %eax
	lock
	btrl	%edx, (%eax)
	ret
	SET_SIZE(clear_bit)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(test_and_set_bit)
	lock
	btsl	%edi, (%rsi)
	sbbl	%eax, %eax
	ret
	SET_SIZE(test_and_set_bit)

#elif defined(__i386)

	ENTRY(test_and_set_bit)
	movl	0x4(%esp), %eax
	movl	0x8(%esp), %edx
	lock
	btsl	%eax, (%edx)
	sbbl	%eax, %eax
	ret
	SET_SIZE(test_and_set_bit)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(test_and_clear_bit)
	lock
	btrl	%edi, (%rsi)
	sbbl	%eax, %eax
	ret
	SET_SIZE(test_and_clear_bit)

#elif defined(__i386)

	ENTRY(test_and_clear_bit)
	movl	0x4(%esp), %eax
	movl	0x8(%esp), %edx
	lock
	btrl	%eax, (%edx)
	sbbl	%eax, %eax
	ret
	SET_SIZE(test_and_clear_bit)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(find_first_zero_bit)
	xorl	%edx, %edx
	testl	%esi, %esi
	pushq	%rbx
	je	first_one
	leal	0x1f(%rsi), %ecx
	movq	%rdi, %rbx
	shrl	$0x5, %ecx
	movq	$-0x1, %rax
	xorq	%rdx, %rdx
	repz
	scasl
	je	second_one
	xorq	-4(%rdi), %rax
	subq	$0x4, %rdi
	bsfq	%rax, %rdx
second_one:
	subq	%rbx, %rdi
	shlq	$0x3, %rdi
	addq	%rdi, %rdx
first_one:
	popq	%rbx
	movl	%edx, %eax
	ret
	SET_SIZE(find_first_zero_bit)

#elif defined(__i386)

	ENTRY(find_first_zero_bit)
	pushl	%edi
	pushl	%ebx
	movl	0x10(%esp), %eax
	xorl	%edx, %edx
	testl	%eax, %eax
	movl	0xc(%esp), %edi
	je	first_one
	leal	0x1f(%eax), %ecx
	shrl	$0x5, %ecx
	movl	%edi, %ebx
	movl	$-0x1, %eax
	xorl	%edx, %edx
	repz
	scasl
	je	second_one
	xorl	-0x4(%edi), %eax
	subl	$0x4, %edi
	bsfl	%eax, %edx
second_one:
	subl	%ebx, %edi
	shll	$0x3, %edi
	addl	%edi, %edx
first_one:
	popl	%ebx
	movl	%edx, %eax
	popl	%edi
	ret
	SET_SIZE(find_first_zero_bit)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(atomic_cmpset_int)
	movl	%esi, %eax
	lock
	cmpxchgl	%edx, (%rdi)
	sete	%al
	movzbl	%al, %eax
	ret
	SET_SIZE(atomic_cmpset_int)

#elif defined(__i386)

	ENTRY(atomic_cmpset_int)
	movl	0x4(%esp), %edx
	movl	0x8(%esp), %eax
	movl	0xc(%esp), %ecx
	lock
	cmpxchgl	%ecx, (%edx)
	sete	%al
	movzbl	%al, %eax
	ret
	SET_SIZE(atomic_cmpset_int)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(mb)
	lock
	addl	$0x0, 0x0(%rsp)
	ret
	SET_SIZE(mb)

#elif defined(__i386)

	ENTRY(mb)
	lock
	addl	$0x0, 0x0(%esp)
	ret
	SET_SIZE(mb)

#endif	/* __i386 */

#endif /* lint */
