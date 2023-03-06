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

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>

#if defined(__amd64)

	/*
	 * do a cpuid instruction, returning the eax/edx values
	 *
	 * uint32_t get_cpuid_edx(uint32_t *eax)
	 */
	ENTRY_NP(get_cpuid_edx)
	pushq	%rbx
	movl	(%rdi), %eax
	cpuid
	movl	%eax, (%rdi)
	movl	%edx, %eax
	popq	%rbx
	ret
	SET_SIZE(get_cpuid_edx)

	/*
	 * void outb(int port, uint8_t value)
	 */
	ENTRY(outb)
	movw	%di, %dx
	movb	%sil, %al
	outb	(%dx)
	ret
	SET_SIZE(outb)

	/*
	 * uint8_t inb(int port)
	 */
	ENTRY(inb)
	xorl	%eax, %eax
	movw	%di, %dx
	inb	(%dx)
	ret
	SET_SIZE(inb)

	ENTRY(htonl)
	movl    %edi, %eax
	bswap   %eax
	ret
	SET_SIZE(htonl)

#elif defined(__i386)

	.code32

	/*
	 * do a cpuid instruction, returning the eax/edx values
	 *
	 * uint32_t get_cpuid_edx(uint32_t *eax)
	 */
	ENTRY_NP(get_cpuid_edx)
	movl	4(%esp), %ecx
	movl	(%ecx), %eax
	pushl	%ebx
	cpuid
	popl	%ebx
	movl	4(%esp), %ecx
	movl	%eax, (%ecx)
	movl	%edx, %eax
	ret
	SET_SIZE(get_cpuid_edx)

	/*
	 * void outb(int port, uint8_t value)
	 */
	ENTRY_NP(outb)
	movl	4(%esp), %edx
	movl	8(%esp), %eax
	outb	(%dx)
	ret
	SET_SIZE(outb)

	/*
	 * uint8_t inb(int port)
	 */
	ENTRY_NP(inb)
	movl	4(%esp), %edx
	inb	(%dx)
	andl	$0xff, %eax
	ret
	SET_SIZE(inb)

	ENTRY(htonl)
	movl    4(%esp), %eax
	bswap   %eax
	ret
	SET_SIZE(htonl)

#endif	/* __i386 */

