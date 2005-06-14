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
	movl	4(%esp), %edx	/* rs1 */
	movl	8(%esp), %eax	/* rs2 */
	movl	12(%esp), %ecx	/* rd */
	lock
	cmpxchgl %ecx, (%edx)
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
	lock
	xorl	$0, (%esp)		/ flush the write buffer
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
	movl	4(%esp), %ecx
	rdmsr
	movl	8(%esp), %ecx
	movl	%eax, (%ecx)
	movl	%edx, 4(%ecx)
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
	movl	8(%esp), %ecx
	movl	(%ecx), %eax
	movl	4(%ecx), %edx
	movl	4(%esp), %ecx
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
	movl	%ebp, %eax
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
	movl	4(%esp), %ecx	/* buf */
	movl	8(%esp), %eax	/* nbytes */
	movl	12(%esp), %edx	/* addr */

	cmp	$4, %eax
	je	4f
	cmp	$2, %eax
	je	2f

1:	inb	(%dx)
	movb	%al, 0(%ecx)
	ret

2:	inw	(%dx)
	movw	%ax, 0(%ecx)
	ret

4:	inl	(%dx)
	movl	%eax, 0(%ecx)
	ret
	SET_SIZE(kmt_in)

	ENTRY_NP(kmt_out)
	movl	4(%esp), %ecx	/* buf */
	movl	8(%esp), %eax	/* nbytes */
	movl	12(%esp), %edx	/* addr */

	cmp	$4, %eax
	je	4f
	cmp	$2, %eax
	je	2f

1:	movb	0(%ecx), %al
	outb	(%dx)
	ret

2:	movw	0(%ecx), %ax
	outw	(%dx)
	ret

4:	movl	0(%ecx), %eax
	outl	(%dx)
	ret
	SET_SIZE(kmt_out)

#endif
