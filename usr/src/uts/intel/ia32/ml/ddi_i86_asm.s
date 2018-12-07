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
 * Copyright 2019 Joyent, Inc.
 */

#if defined(lint) || defined(__lint)
#include <sys/types.h>
#include <sys/sunddi.h>
#else
#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include "assym.h"
#endif

#if defined(lint) || defined(__lint)

/*ARGSUSED*/
uint8_t
ddi_get8(ddi_acc_handle_t handle, uint8_t *addr)
{
	return (0);
}

/*ARGSUSED*/
uint8_t
ddi_mem_get8(ddi_acc_handle_t handle, uint8_t *addr)
{
	return (0);
}

/*ARGSUSED*/
uint8_t
ddi_io_get8(ddi_acc_handle_t handle, uint8_t *dev_addr)
{
	return (0);
}

/*ARGSUSED*/
uint16_t
ddi_get16(ddi_acc_handle_t handle, uint16_t *addr)
{
	return (0);
}

/*ARGSUSED*/
uint16_t
ddi_mem_get16(ddi_acc_handle_t handle, uint16_t *addr)
{
	return (0);
}

/*ARGSUSED*/
uint16_t
ddi_io_get16(ddi_acc_handle_t handle, uint16_t *dev_addr)
{
	return (0);
}

/*ARGSUSED*/
uint32_t
ddi_get32(ddi_acc_handle_t handle, uint32_t *addr)
{
	return (0);
}

/*ARGSUSED*/
uint32_t
ddi_mem_get32(ddi_acc_handle_t handle, uint32_t *addr)
{
	return (0);
}

/*ARGSUSED*/
uint32_t
ddi_io_get32(ddi_acc_handle_t handle, uint32_t *dev_addr)
{
	return (0);
}

/*ARGSUSED*/
uint64_t
ddi_get64(ddi_acc_handle_t handle, uint64_t *addr)
{
	return (0);
}

/*ARGSUSED*/
uint64_t
ddi_mem_get64(ddi_acc_handle_t handle, uint64_t *addr)
{
	return (0);
}

/*ARGSUSED*/
void
ddi_put8(ddi_acc_handle_t handle, uint8_t *addr, uint8_t value)
{}

/*ARGSUSED*/
void
ddi_mem_put8(ddi_acc_handle_t handle, uint8_t *dev_addr, uint8_t value)
{}

/*ARGSUSED*/
void
ddi_io_put8(ddi_acc_handle_t handle, uint8_t *dev_addr, uint8_t value)
{}

/*ARGSUSED*/
void
ddi_put16(ddi_acc_handle_t handle, uint16_t *addr, uint16_t value)
{}

/*ARGSUSED*/
void
ddi_mem_put16(ddi_acc_handle_t handle, uint16_t *dev_addr, uint16_t value)
{}

/*ARGSUSED*/
void
ddi_io_put16(ddi_acc_handle_t handle, uint16_t *dev_addr, uint16_t value)
{}

/*ARGSUSED*/
void
ddi_put32(ddi_acc_handle_t handle, uint32_t *addr, uint32_t value)
{}

/*ARGSUSED*/
void
ddi_mem_put32(ddi_acc_handle_t handle, uint32_t *dev_addr, uint32_t value)
{}

/*ARGSUSED*/
void
ddi_io_put32(ddi_acc_handle_t handle, uint32_t *dev_addr, uint32_t value)
{}

/*ARGSUSED*/
void
ddi_put64(ddi_acc_handle_t handle, uint64_t *addr, uint64_t value)
{}

/*ARGSUSED*/
void
ddi_mem_put64(ddi_acc_handle_t handle, uint64_t *dev_addr, uint64_t value)
{}

/*ARGSUSED*/
void
ddi_rep_get8(ddi_acc_handle_t handle, uint8_t *host_addr, uint8_t *dev_addr,
    size_t repcount, uint_t flags)
{}

/*ARGSUSED*/
void
ddi_rep_get16(ddi_acc_handle_t handle, uint16_t *host_addr, uint16_t *dev_addr,
    size_t repcount, uint_t flags)
{}

/*ARGSUSED*/
void
ddi_rep_get32(ddi_acc_handle_t handle, uint32_t *host_addr, uint32_t *dev_addr,
    size_t repcount, uint_t flags)
{}

/*ARGSUSED*/
void
ddi_rep_get64(ddi_acc_handle_t handle, uint64_t *host_addr, uint64_t *dev_addr,
    size_t repcount, uint_t flags)
{}

/*ARGSUSED*/
void
ddi_rep_put8(ddi_acc_handle_t handle, uint8_t *host_addr, uint8_t *dev_addr,
    size_t repcount, uint_t flags)
{}

/*ARGSUSED*/
void
ddi_rep_put16(ddi_acc_handle_t handle, uint16_t *host_addr, uint16_t *dev_addr,
    size_t repcount, uint_t flags)
{}

/*ARGSUSED*/
void
ddi_rep_put32(ddi_acc_handle_t handle, uint32_t *host_addr, uint32_t *dev_addr,
    size_t repcount, uint_t flags)
{}

/*ARGSUSED*/
void
ddi_rep_put64(ddi_acc_handle_t handle, uint64_t *host_addr, uint64_t *dev_addr,
    size_t repcount, uint_t flags)
{}

/*ARGSUSED*/
void
ddi_mem_rep_get8(ddi_acc_handle_t handle, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags)
{}

/*ARGSUSED*/
void
ddi_mem_rep_get16(ddi_acc_handle_t handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{}

/*ARGSUSED*/
void
ddi_mem_rep_get32(ddi_acc_handle_t handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{}

/*ARGSUSED*/
void
ddi_mem_rep_get64(ddi_acc_handle_t handle, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{}

/*ARGSUSED*/
void
ddi_mem_rep_put8(ddi_acc_handle_t handle, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags)
{}

/*ARGSUSED*/
void
ddi_mem_rep_put16(ddi_acc_handle_t handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{}

/*ARGSUSED*/
void
ddi_mem_rep_put32(ddi_acc_handle_t handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{}

/*ARGSUSED*/
void
ddi_mem_rep_put64(ddi_acc_handle_t handle, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{}

#else	/* lint */


#if defined(__amd64)

	ENTRY(ddi_get8)
	ALTENTRY(ddi_getb)
	ALTENTRY(ddi_mem_getb)
	ALTENTRY(ddi_mem_get8)
	ALTENTRY(ddi_io_getb)
	ALTENTRY(ddi_io_get8)
	movl	ACC_ATTR(%rdi), %edx
	cmpl	$_CONST(DDI_ACCATTR_IO_SPACE|DDI_ACCATTR_DIRECT), %edx
	jne	1f
	movq	%rsi, %rdx
	xorq	%rax, %rax
	inb	(%dx)
	ret
1:
	cmpl	$_CONST(DDI_ACCATTR_CPU_VADDR|DDI_ACCATTR_DIRECT), %edx
	jne	2f
	movzbq	(%rsi), %rax
	ret
2:
	movq	ACC_GETB(%rdi), %rax
	INDIRECT_JMP_REG(rax)
	SET_SIZE(ddi_get8)
	SET_SIZE(ddi_getb)
	SET_SIZE(ddi_mem_getb)
	SET_SIZE(ddi_mem_get8)
	SET_SIZE(ddi_io_getb)
	SET_SIZE(ddi_io_get8)

#elif defined(__i386)

	ENTRY(ddi_get8)
	ALTENTRY(ddi_getb)
	ALTENTRY(ddi_mem_getb)
	ALTENTRY(ddi_mem_get8)
	ALTENTRY(ddi_io_getb)
	ALTENTRY(ddi_io_get8)
	movl	4(%esp), %eax
	movl	ACC_ATTR(%eax), %ecx
	cmpl	$_CONST(DDI_ACCATTR_IO_SPACE|DDI_ACCATTR_DIRECT), %ecx
	jne	1f
	movl	8(%esp), %edx
	xorl	%eax, %eax
	inb	(%dx)
	ret
1:
	cmpl	$_CONST(DDI_ACCATTR_CPU_VADDR|DDI_ACCATTR_DIRECT), %ecx
	jne	2f
	movl	8(%esp), %eax
	movzbl	(%eax), %eax
	ret
2:
	jmp	*ACC_GETB(%eax)
	SET_SIZE(ddi_get8)
	SET_SIZE(ddi_getb)
	SET_SIZE(ddi_mem_getb)
	SET_SIZE(ddi_mem_get8)
	SET_SIZE(ddi_io_getb)
	SET_SIZE(ddi_io_get8)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(ddi_get16)
	ALTENTRY(ddi_getw)
	ALTENTRY(ddi_mem_getw)
	ALTENTRY(ddi_mem_get16)
	ALTENTRY(ddi_io_getw)
	ALTENTRY(ddi_io_get16)
	movl	ACC_ATTR(%rdi), %edx
	cmpl	$_CONST(DDI_ACCATTR_IO_SPACE|DDI_ACCATTR_DIRECT), %edx
	jne	3f
	movq	%rsi, %rdx
	xorq	%rax, %rax
	inw	(%dx)
	ret
3:
	cmpl	$_CONST(DDI_ACCATTR_CPU_VADDR|DDI_ACCATTR_DIRECT), %edx
	jne	4f
	movzwq	(%rsi), %rax
	ret
4:
	movq	ACC_GETW(%rdi), %rax
	INDIRECT_JMP_REG(rax)
	SET_SIZE(ddi_get16)
	SET_SIZE(ddi_getw)
	SET_SIZE(ddi_mem_getw)
	SET_SIZE(ddi_mem_get16)
	SET_SIZE(ddi_io_getw)
	SET_SIZE(ddi_io_get16)

#elif defined(__i386)

	ENTRY(ddi_get16)
	ALTENTRY(ddi_getw)
	ALTENTRY(ddi_mem_getw)
	ALTENTRY(ddi_mem_get16)
	ALTENTRY(ddi_io_getw)
	ALTENTRY(ddi_io_get16)
	movl	4(%esp), %eax
	movl	ACC_ATTR(%eax), %ecx
	cmpl	$_CONST(DDI_ACCATTR_IO_SPACE|DDI_ACCATTR_DIRECT), %ecx
	jne	3f
	movl	8(%esp), %edx
	xorl	%eax, %eax
	inw	(%dx)
	ret
3:
	cmpl	$_CONST(DDI_ACCATTR_CPU_VADDR|DDI_ACCATTR_DIRECT), %ecx
	jne	4f
	movl	8(%esp), %eax
	movzwl	(%eax), %eax
	ret
4:
	jmp	*ACC_GETW(%eax)
	SET_SIZE(ddi_get16)
	SET_SIZE(ddi_getw)
	SET_SIZE(ddi_mem_getw)
	SET_SIZE(ddi_mem_get16)
	SET_SIZE(ddi_io_getw)
	SET_SIZE(ddi_io_get16)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(ddi_get32)
	ALTENTRY(ddi_getl)
	ALTENTRY(ddi_mem_getl)
	ALTENTRY(ddi_mem_get32)
	ALTENTRY(ddi_io_getl)
	ALTENTRY(ddi_io_get32)
	movl	ACC_ATTR(%rdi), %edx
	cmpl	$_CONST(DDI_ACCATTR_IO_SPACE|DDI_ACCATTR_DIRECT), %edx
	jne	5f
	movq	%rsi, %rdx
	inl	(%dx)
	ret
5:
	cmpl	$_CONST(DDI_ACCATTR_CPU_VADDR|DDI_ACCATTR_DIRECT), %edx
	jne	6f
	movl	(%rsi), %eax
	ret
6:
	movq	ACC_GETL(%rdi), %rax
	INDIRECT_JMP_REG(rax)
	SET_SIZE(ddi_get32)
	SET_SIZE(ddi_getl)
	SET_SIZE(ddi_mem_getl)
	SET_SIZE(ddi_mem_get32)
	SET_SIZE(ddi_io_getl)
	SET_SIZE(ddi_io_get32)

#elif defined(__i386)

	ENTRY(ddi_get32)
	ALTENTRY(ddi_getl)
	ALTENTRY(ddi_mem_getl)
	ALTENTRY(ddi_mem_get32)
	ALTENTRY(ddi_io_getl)
	ALTENTRY(ddi_io_get32)
	movl	4(%esp), %eax
	movl	ACC_ATTR(%eax), %ecx
	cmpl	$_CONST(DDI_ACCATTR_IO_SPACE|DDI_ACCATTR_DIRECT), %ecx
	jne	5f
	movl	8(%esp), %edx
	inl	(%dx)
	ret
5:
	cmpl	$_CONST(DDI_ACCATTR_CPU_VADDR|DDI_ACCATTR_DIRECT), %ecx
	jne	6f
	movl	8(%esp), %eax
	movl	(%eax), %eax
	ret
6:
	jmp	*ACC_GETL(%eax)
	SET_SIZE(ddi_get32)
	SET_SIZE(ddi_getl)
	SET_SIZE(ddi_mem_getl)
	SET_SIZE(ddi_mem_get32)
	SET_SIZE(ddi_io_getl)
	SET_SIZE(ddi_io_get32)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(ddi_get64)
	ALTENTRY(ddi_getll)
	ALTENTRY(ddi_mem_getll)
	ALTENTRY(ddi_mem_get64)
	movq	ACC_GETLL(%rdi), %rax
	INDIRECT_JMP_REG(rax)
	SET_SIZE(ddi_get64)
	SET_SIZE(ddi_getll)
	SET_SIZE(ddi_mem_getll)
	SET_SIZE(ddi_mem_get64)

#elif defined(__i386)

	ENTRY(ddi_get64)
	ALTENTRY(ddi_getll)
	ALTENTRY(ddi_mem_getll)
	ALTENTRY(ddi_mem_get64)
	movl	4(%esp), %eax
	jmp	*ACC_GETLL(%eax)
	SET_SIZE(ddi_get64)
	SET_SIZE(ddi_getll)
	SET_SIZE(ddi_mem_getll)
	SET_SIZE(ddi_mem_get64)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(ddi_put8)
	ALTENTRY(ddi_putb)
	ALTENTRY(ddi_mem_putb)
	ALTENTRY(ddi_mem_put8)
	ALTENTRY(ddi_io_putb)
	ALTENTRY(ddi_io_put8)
	movl	ACC_ATTR(%rdi), %ecx
	cmpl	$_CONST(DDI_ACCATTR_IO_SPACE|DDI_ACCATTR_DIRECT), %ecx
	jne	7f
	movq	%rdx, %rax
	movq	%rsi, %rdx
	outb	(%dx)
	ret
7:
	cmpl	$_CONST(DDI_ACCATTR_CPU_VADDR|DDI_ACCATTR_DIRECT), %ecx
	jne	8f
	movb	%dl, (%rsi)
	ret
8:
	movq	ACC_PUTB(%rdi), %rax
	INDIRECT_JMP_REG(rax)
	SET_SIZE(ddi_put8)
	SET_SIZE(ddi_putb)
	SET_SIZE(ddi_mem_putb)
	SET_SIZE(ddi_mem_put8)
	SET_SIZE(ddi_io_putb)
	SET_SIZE(ddi_io_put8)

#elif defined(__i386)

	ENTRY(ddi_put8)
	ALTENTRY(ddi_putb)
	ALTENTRY(ddi_mem_putb)
	ALTENTRY(ddi_mem_put8)
	ALTENTRY(ddi_io_putb)
	ALTENTRY(ddi_io_put8)
	movl	4(%esp), %eax
	movl	ACC_ATTR(%eax), %ecx
	cmpl	$_CONST(DDI_ACCATTR_IO_SPACE|DDI_ACCATTR_DIRECT), %ecx
	jne	7f
	movl	12(%esp), %eax
	movl	8(%esp), %edx
	outb	(%dx)
	ret
7:
	cmpl	$_CONST(DDI_ACCATTR_CPU_VADDR|DDI_ACCATTR_DIRECT), %ecx
	jne	8f
	movl	8(%esp), %eax
	movl	12(%esp), %ecx
	movb	%cl, (%eax)
	ret
8:
	jmp	*ACC_PUTB(%eax)
	SET_SIZE(ddi_put8)
	SET_SIZE(ddi_putb)
	SET_SIZE(ddi_mem_putb)
	SET_SIZE(ddi_mem_put8)
	SET_SIZE(ddi_io_putb)
	SET_SIZE(ddi_io_put8)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(ddi_put16)
	ALTENTRY(ddi_putw)
	ALTENTRY(ddi_mem_putw)
	ALTENTRY(ddi_mem_put16)
	ALTENTRY(ddi_io_putw)
	ALTENTRY(ddi_io_put16)
	movl	ACC_ATTR(%rdi), %ecx
	cmpl	$_CONST(DDI_ACCATTR_IO_SPACE|DDI_ACCATTR_DIRECT), %ecx
	jne	8f
	movq	%rdx, %rax
	movq	%rsi, %rdx
	outw	(%dx)
	ret
8:
	cmpl	$_CONST(DDI_ACCATTR_CPU_VADDR|DDI_ACCATTR_DIRECT), %ecx
	jne	9f
	movw	%dx, (%rsi)
	ret
9:
	movq	ACC_PUTW(%rdi), %rax
	INDIRECT_JMP_REG(rax)
	SET_SIZE(ddi_put16)
	SET_SIZE(ddi_putw)
	SET_SIZE(ddi_mem_putw)
	SET_SIZE(ddi_mem_put16)
	SET_SIZE(ddi_io_putw)
	SET_SIZE(ddi_io_put16)

#elif defined(__i386)

	ENTRY(ddi_put16)
	ALTENTRY(ddi_putw)
	ALTENTRY(ddi_mem_putw)
	ALTENTRY(ddi_mem_put16)
	ALTENTRY(ddi_io_putw)
	ALTENTRY(ddi_io_put16)
	movl	4(%esp), %eax
	movl	ACC_ATTR(%eax), %ecx
	cmpl	$_CONST(DDI_ACCATTR_IO_SPACE|DDI_ACCATTR_DIRECT), %ecx
	jne	8f
	movl	12(%esp), %eax
	movl	8(%esp), %edx
	outw	(%dx)
	ret
8:
	cmpl	$_CONST(DDI_ACCATTR_CPU_VADDR|DDI_ACCATTR_DIRECT), %ecx
	jne	9f
	movl	8(%esp), %eax
	movl	12(%esp), %ecx
	movw	%cx, (%eax)
	ret
9:
	jmp	*ACC_PUTW(%eax)
	SET_SIZE(ddi_put16)
	SET_SIZE(ddi_putw)
	SET_SIZE(ddi_mem_putw)
	SET_SIZE(ddi_mem_put16)
	SET_SIZE(ddi_io_putw)
	SET_SIZE(ddi_io_put16)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(ddi_put32)
	ALTENTRY(ddi_putl)
	ALTENTRY(ddi_mem_putl)
	ALTENTRY(ddi_mem_put32)
	ALTENTRY(ddi_io_putl)
	ALTENTRY(ddi_io_put32)
	movl	ACC_ATTR(%rdi), %ecx
	cmpl	$_CONST(DDI_ACCATTR_IO_SPACE|DDI_ACCATTR_DIRECT), %ecx
	jne	8f
	movq	%rdx, %rax
	movq	%rsi, %rdx
	outl	(%dx)
	ret
8:
	cmpl	$_CONST(DDI_ACCATTR_CPU_VADDR|DDI_ACCATTR_DIRECT), %ecx
	jne	9f
	movl	%edx, (%rsi)
	ret
9:
	movq	ACC_PUTL(%rdi), %rax
	INDIRECT_JMP_REG(rax)
	SET_SIZE(ddi_put32)
	SET_SIZE(ddi_putl)
	SET_SIZE(ddi_mem_putl)
	SET_SIZE(ddi_mem_put32)
	SET_SIZE(ddi_io_putl)
	SET_SIZE(ddi_io_put32)

#elif defined(__i386)

	ENTRY(ddi_put32)
	ALTENTRY(ddi_putl)
	ALTENTRY(ddi_mem_putl)
	ALTENTRY(ddi_mem_put32)
	ALTENTRY(ddi_io_putl)
	ALTENTRY(ddi_io_put32)
	movl	4(%esp), %eax
	movl	ACC_ATTR(%eax), %ecx
	cmpl	$_CONST(DDI_ACCATTR_IO_SPACE|DDI_ACCATTR_DIRECT), %ecx
	jne	8f
	movl	12(%esp), %eax
	movl	8(%esp), %edx
	outl	(%dx)
	ret
8:
	cmpl	$_CONST(DDI_ACCATTR_CPU_VADDR|DDI_ACCATTR_DIRECT), %ecx
	jne	9f
	movl	8(%esp), %eax
	movl	12(%esp), %ecx
	movl	%ecx, (%eax)
	ret
9:
	jmp	*ACC_PUTL(%eax)
	SET_SIZE(ddi_put32)
	SET_SIZE(ddi_putl)
	SET_SIZE(ddi_mem_putl)
	SET_SIZE(ddi_mem_put32)
	SET_SIZE(ddi_io_putl)
	SET_SIZE(ddi_io_put32)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(ddi_put64)
	ALTENTRY(ddi_putll)
	ALTENTRY(ddi_mem_putll)
	ALTENTRY(ddi_mem_put64)
	movq	ACC_PUTLL(%rdi), %rax
	INDIRECT_JMP_REG(rax)
	SET_SIZE(ddi_put64)
	SET_SIZE(ddi_putll)
	SET_SIZE(ddi_mem_putll)
	SET_SIZE(ddi_mem_put64)

#elif defined(__i386)

	ENTRY(ddi_put64)
	ALTENTRY(ddi_putll)
	ALTENTRY(ddi_mem_putll)
	ALTENTRY(ddi_mem_put64)
	movl	4(%esp), %eax
	jmp	*ACC_PUTLL(%eax)
	SET_SIZE(ddi_put64)
	SET_SIZE(ddi_putll)
	SET_SIZE(ddi_mem_putll)
	SET_SIZE(ddi_mem_put64)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(ddi_rep_get8)
	ALTENTRY(ddi_rep_getb)
	ALTENTRY(ddi_mem_rep_getb)
	ALTENTRY(ddi_mem_rep_get8)
	movq	ACC_REP_GETB(%rdi), %rax
	INDIRECT_JMP_REG(rax)
	SET_SIZE(ddi_rep_get8)
	SET_SIZE(ddi_rep_getb)
	SET_SIZE(ddi_mem_rep_getb)
	SET_SIZE(ddi_mem_rep_get8)

#elif defined(__i386)

	ENTRY(ddi_rep_get8)
	ALTENTRY(ddi_rep_getb)
	ALTENTRY(ddi_mem_rep_getb)
	ALTENTRY(ddi_mem_rep_get8)
	movl	4(%esp), %eax
	jmp	*ACC_REP_GETB(%eax)
	SET_SIZE(ddi_rep_get8)
	SET_SIZE(ddi_rep_getb)
	SET_SIZE(ddi_mem_rep_getb)
	SET_SIZE(ddi_mem_rep_get8)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(ddi_rep_get16)
	ALTENTRY(ddi_rep_getw)
	ALTENTRY(ddi_mem_rep_getw)
	ALTENTRY(ddi_mem_rep_get16)
	movq	ACC_REP_GETW(%rdi), %rax
	INDIRECT_JMP_REG(rax)
	SET_SIZE(ddi_rep_get16)
	SET_SIZE(ddi_rep_getw)
	SET_SIZE(ddi_mem_rep_getw)
	SET_SIZE(ddi_mem_rep_get16)

#elif defined(__i386)

	ENTRY(ddi_rep_get16)
	ALTENTRY(ddi_rep_getw)
	ALTENTRY(ddi_mem_rep_getw)
	ALTENTRY(ddi_mem_rep_get16)
	movl	4(%esp), %eax
	jmp	*ACC_REP_GETW(%eax)
	SET_SIZE(ddi_rep_get16)
	SET_SIZE(ddi_rep_getw)
	SET_SIZE(ddi_mem_rep_getw)
	SET_SIZE(ddi_mem_rep_get16)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(ddi_rep_get32)
	ALTENTRY(ddi_rep_getl)
	ALTENTRY(ddi_mem_rep_getl)
	ALTENTRY(ddi_mem_rep_get32)
	movq	ACC_REP_GETL(%rdi), %rax
	INDIRECT_JMP_REG(rax)
	SET_SIZE(ddi_rep_get32)
	SET_SIZE(ddi_rep_getl)
	SET_SIZE(ddi_mem_rep_getl)
	SET_SIZE(ddi_mem_rep_get32)

#elif defined(__i386)

	ENTRY(ddi_rep_get32)
	ALTENTRY(ddi_rep_getl)
	ALTENTRY(ddi_mem_rep_getl)
	ALTENTRY(ddi_mem_rep_get32)
	movl	4(%esp), %eax
	jmp	*ACC_REP_GETL(%eax)
	SET_SIZE(ddi_rep_get32)
	SET_SIZE(ddi_rep_getl)
	SET_SIZE(ddi_mem_rep_getl)
	SET_SIZE(ddi_mem_rep_get32)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(ddi_rep_get64)
	ALTENTRY(ddi_rep_getll)
	ALTENTRY(ddi_mem_rep_getll)
	ALTENTRY(ddi_mem_rep_get64)
	movq	ACC_REP_GETLL(%rdi), %rax
	INDIRECT_JMP_REG(rax)
	SET_SIZE(ddi_rep_get64)
	SET_SIZE(ddi_rep_getll)
	SET_SIZE(ddi_mem_rep_getll)
	SET_SIZE(ddi_mem_rep_get64)

#elif defined(__i386)

	ENTRY(ddi_rep_get64)
	ALTENTRY(ddi_rep_getll)
	ALTENTRY(ddi_mem_rep_getll)
	ALTENTRY(ddi_mem_rep_get64)
	movl	4(%esp), %eax
	jmp	*ACC_REP_GETLL(%eax)
	SET_SIZE(ddi_rep_get64)
	SET_SIZE(ddi_rep_getll)
	SET_SIZE(ddi_mem_rep_getll)
	SET_SIZE(ddi_mem_rep_get64)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(ddi_rep_put8)
	ALTENTRY(ddi_rep_putb)
	ALTENTRY(ddi_mem_rep_putb)
	ALTENTRY(ddi_mem_rep_put8)
	movq	ACC_REP_PUTB(%rdi), %rax
	INDIRECT_JMP_REG(rax)
	SET_SIZE(ddi_rep_put8)
	SET_SIZE(ddi_rep_putb)
	SET_SIZE(ddi_mem_rep_putb)
	SET_SIZE(ddi_mem_rep_put8)

#elif defined(__i386)

	ENTRY(ddi_rep_put8)
	ALTENTRY(ddi_rep_putb)
	ALTENTRY(ddi_mem_rep_putb)
	ALTENTRY(ddi_mem_rep_put8)
	movl	4(%esp), %eax
	jmp	*ACC_REP_PUTB(%eax)
	SET_SIZE(ddi_rep_put8)
	SET_SIZE(ddi_rep_putb)
	SET_SIZE(ddi_mem_rep_putb)
	SET_SIZE(ddi_mem_rep_put8)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(ddi_rep_put16)
	ALTENTRY(ddi_rep_putw)
	ALTENTRY(ddi_mem_rep_putw)
	ALTENTRY(ddi_mem_rep_put16)
	movq	ACC_REP_PUTW(%rdi), %rax
	INDIRECT_JMP_REG(rax)
	SET_SIZE(ddi_rep_put16)
	SET_SIZE(ddi_rep_putw)
	SET_SIZE(ddi_mem_rep_putw)
	SET_SIZE(ddi_mem_rep_put16)

#elif defined(__i386)

	ENTRY(ddi_rep_put16)
	ALTENTRY(ddi_rep_putw)
	ALTENTRY(ddi_mem_rep_putw)
	ALTENTRY(ddi_mem_rep_put16)
	movl	4(%esp), %eax
	jmp	*ACC_REP_PUTW(%eax)
	SET_SIZE(ddi_rep_put16)
	SET_SIZE(ddi_rep_putw)
	SET_SIZE(ddi_mem_rep_putw)
	SET_SIZE(ddi_mem_rep_put16)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(ddi_rep_put32)
	ALTENTRY(ddi_rep_putl)
	ALTENTRY(ddi_mem_rep_putl)
	ALTENTRY(ddi_mem_rep_put32)
	movq	ACC_REP_PUTL(%rdi), %rax
	INDIRECT_JMP_REG(rax)
	SET_SIZE(ddi_rep_put32)
	SET_SIZE(ddi_rep_putl)
	SET_SIZE(ddi_mem_rep_putl)
	SET_SIZE(ddi_mem_rep_put32)

#elif defined(__i386)

	ENTRY(ddi_rep_put32)
	ALTENTRY(ddi_rep_putl)
	ALTENTRY(ddi_mem_rep_putl)
	ALTENTRY(ddi_mem_rep_put32)
	movl	4(%esp), %eax
	jmp	*ACC_REP_PUTL(%eax)
	SET_SIZE(ddi_rep_put32)
	SET_SIZE(ddi_rep_putl)
	SET_SIZE(ddi_mem_rep_putl)
	SET_SIZE(ddi_mem_rep_put32)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(ddi_rep_put64)
	ALTENTRY(ddi_rep_putll)
	ALTENTRY(ddi_mem_rep_putll)
	ALTENTRY(ddi_mem_rep_put64)
	movq	ACC_REP_PUTLL(%rdi), %rax
	INDIRECT_JMP_REG(rax)
	SET_SIZE(ddi_rep_put64)
	SET_SIZE(ddi_rep_putll)
	SET_SIZE(ddi_mem_rep_putll)
	SET_SIZE(ddi_mem_rep_put64)

#elif defined(__i386)

	ENTRY(ddi_rep_put64)
	ALTENTRY(ddi_rep_putll)
	ALTENTRY(ddi_mem_rep_putll)
	ALTENTRY(ddi_mem_rep_put64)
	movl	4(%esp), %eax
	jmp	*ACC_REP_PUTLL(%eax)
	SET_SIZE(ddi_rep_put64)
	SET_SIZE(ddi_rep_putll)
	SET_SIZE(ddi_mem_rep_putll)
	SET_SIZE(ddi_mem_rep_put64)

#endif	/* __i386 */

#endif /* lint */

#if defined(lint) || defined(__lint)

/*ARGSUSED*/
uint8_t
i_ddi_vaddr_get8(ddi_acc_impl_t *hdlp, uint8_t *addr)
{
	return (*addr);
}

/*ARGSUSED*/
uint16_t
i_ddi_vaddr_get16(ddi_acc_impl_t *hdlp, uint16_t *addr)
{
	return (*addr);
}

/*ARGSUSED*/
uint32_t
i_ddi_vaddr_get32(ddi_acc_impl_t *hdlp, uint32_t *addr)
{
	return (*addr);
}

/*ARGSUSED*/
uint64_t
i_ddi_vaddr_get64(ddi_acc_impl_t *hdlp, uint64_t *addr)
{
	return (*addr);
}

#else	/* lint */

#if defined(__amd64)

	ENTRY(i_ddi_vaddr_get8)
	movzbq	(%rsi), %rax
	ret
	SET_SIZE(i_ddi_vaddr_get8)

#elif defined(__i386)

	ENTRY(i_ddi_vaddr_get8)
	movl	8(%esp), %eax
	movzbl	(%eax), %eax
	ret
	SET_SIZE(i_ddi_vaddr_get8)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(i_ddi_vaddr_get16)
	movzwq	(%rsi), %rax
	ret
	SET_SIZE(i_ddi_vaddr_get16)

#elif defined(__i386)

	ENTRY(i_ddi_vaddr_get16)
	movl	8(%esp), %eax
	movzwl	(%eax), %eax
	ret
	SET_SIZE(i_ddi_vaddr_get16)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(i_ddi_vaddr_get32)
	movl	(%rsi), %eax
	ret
	SET_SIZE(i_ddi_vaddr_get32)

#elif defined(__i386)

	ENTRY(i_ddi_vaddr_get32)
	movl	8(%esp), %eax
	movl	(%eax), %eax
	ret
	SET_SIZE(i_ddi_vaddr_get32)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(i_ddi_vaddr_get64)
	movq	(%rsi), %rax
	ret
	SET_SIZE(i_ddi_vaddr_get64)

#elif defined(__i386)

	ENTRY(i_ddi_vaddr_get64)
	movl	8(%esp), %ecx
	movl	(%ecx), %eax
	movl	4(%ecx), %edx
	ret
	SET_SIZE(i_ddi_vaddr_get64)

#endif	/* __i386 */

#endif /* lint */


#if defined(lint) || defined(__lint)

/*ARGSUSED*/
uint8_t
i_ddi_io_get8(ddi_acc_impl_t *hdlp, uint8_t *addr)
{
	return (0);
}

/*ARGSUSED*/
uint16_t
i_ddi_io_get16(ddi_acc_impl_t *hdlp, uint16_t *addr)
{
	return (0);
}

/*ARGSUSED*/
uint32_t
i_ddi_io_get32(ddi_acc_impl_t *hdlp, uint32_t *addr)
{
	return (0);
}

#else	/* lint */

#if defined(__amd64)

	ENTRY(i_ddi_io_get8)
	movq	%rsi, %rdx
	inb	(%dx)
	movzbq	%al, %rax
	ret
	SET_SIZE(i_ddi_io_get8)

#elif defined(__i386)

	ENTRY(i_ddi_io_get8)
	movl	8(%esp), %edx
	inb	(%dx)
	movzbl	%al, %eax
	ret
	SET_SIZE(i_ddi_io_get8)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(i_ddi_io_get16)
	movq	%rsi, %rdx
	inw	(%dx)
	movzwq	%ax, %rax
	ret
	SET_SIZE(i_ddi_io_get16)

#elif defined(__i386)

	ENTRY(i_ddi_io_get16)
	movl	8(%esp), %edx
	inw	(%dx)
	movzwl	%ax, %eax
	ret
	SET_SIZE(i_ddi_io_get16)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(i_ddi_io_get32)
	movq	%rsi, %rdx
	inl	(%dx)
	ret
	SET_SIZE(i_ddi_io_get32)

#elif defined(__i386)

	ENTRY(i_ddi_io_get32)
	movl	8(%esp), %edx
	inl	(%dx)
	ret
	SET_SIZE(i_ddi_io_get32)

#endif	/* __i386 */

#endif /* lint */

#if defined(lint) || defined(__lint)

/*ARGSUSED*/
void
i_ddi_vaddr_put8(ddi_acc_impl_t *hdlp, uint8_t *addr, uint8_t value)
{
	*addr = value;
}

/*ARGSUSED*/
void
i_ddi_vaddr_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value)
{
	*addr = value;
}

/*ARGSUSED*/
void
i_ddi_vaddr_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value)
{
	*(uint32_t *)addr = value;
}

/*ARGSUSED*/
void
i_ddi_vaddr_put64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value)
{
	*addr = value;
}

#else	/* lint */

#if defined(__amd64)

	ENTRY(i_ddi_vaddr_put8)
	movb	%dl, (%rsi)
	ret
	SET_SIZE(i_ddi_vaddr_put8)

#elif defined(__i386)

	ENTRY(i_ddi_vaddr_put8)
	movl	8(%esp), %eax
	movb	12(%esp), %cl
	movb	%cl, (%eax)
	ret
	SET_SIZE(i_ddi_vaddr_put8)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(i_ddi_vaddr_put16)
	movw	%dx, (%rsi)
	ret
	SET_SIZE(i_ddi_vaddr_put16)

#elif defined(__i386)

	ENTRY(i_ddi_vaddr_put16)
	movl	8(%esp), %eax
	movl	12(%esp), %ecx
	movw	%cx, (%eax)
	ret
	SET_SIZE(i_ddi_vaddr_put16)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(i_ddi_vaddr_put32)
	movl	%edx, (%rsi)
	ret
	SET_SIZE(i_ddi_vaddr_put32)

#elif defined(__i386)

	ENTRY(i_ddi_vaddr_put32)
	movl	8(%esp), %eax
	movl	12(%esp), %ecx
	movl	%ecx, (%eax)
	ret
	SET_SIZE(i_ddi_vaddr_put32)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(i_ddi_vaddr_put64)
	movq	%rdx, (%rsi)
	ret
	SET_SIZE(i_ddi_vaddr_put64)

#elif defined(__i386)

	ENTRY(i_ddi_vaddr_put64)
	movl	8(%esp), %ecx
	movl	12(%esp), %edx
	movl	16(%esp), %eax
	movl	%edx, (%ecx)
	movl	%eax, 4(%ecx)
	ret
	SET_SIZE(i_ddi_vaddr_put64)

#endif	/* __i386 */

#endif /* lint */

#if defined(lint) || defined(__lint)

/*ARGSUSED*/
void
i_ddi_io_put8(ddi_acc_impl_t *hdlp, uint8_t *addr, uint8_t value)
{}

/*ARGSUSED*/
void
i_ddi_io_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value)
{}

/*ARGSUSED*/
void
i_ddi_io_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value)
{}

#else	/* lint */

#if defined(__amd64)

	ENTRY(i_ddi_io_put8)
	movq	%rdx, %rax
	movq	%rsi, %rdx
	outb	(%dx)
	ret
	SET_SIZE(i_ddi_io_put8)

#elif defined(__i386)

	ENTRY(i_ddi_io_put8)
	movl	12(%esp), %eax
	movl	8(%esp), %edx
	outb	(%dx)
	ret
	SET_SIZE(i_ddi_io_put8)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(i_ddi_io_put16)
	movq	%rdx, %rax
	movq	%rsi, %rdx
	outw	(%dx)
	ret
	SET_SIZE(i_ddi_io_put16)

#elif defined(__i386)

	ENTRY(i_ddi_io_put16)
	movl	12(%esp), %eax
	movl	8(%esp), %edx
	outw	(%dx)
	ret
	SET_SIZE(i_ddi_io_put16)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(i_ddi_io_put32)
	movq	%rdx, %rax
	movq	%rsi, %rdx
	outl	(%dx)
	ret
	SET_SIZE(i_ddi_io_put32)

#elif defined(__i386)

	ENTRY(i_ddi_io_put32)
	movl	12(%esp), %eax
	movl	8(%esp), %edx
	outl	(%dx)
	ret
	SET_SIZE(i_ddi_io_put32)

#endif	/* __i386 */

#endif /* lint */

#if defined(lint) || defined(__lint)

/*ARGSUSED*/
void
i_ddi_io_rep_get8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{}

/*ARGSUSED*/
void
i_ddi_io_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{}

/*ARGSUSED*/
void
i_ddi_io_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{}

#else	/* lint */

#if defined(__amd64)

	/*
	 * Incoming arguments
	 *
	 * %rdi	: hdlp
	 * %rsi	: host_addr
	 * %rdx	: dev_addr
	 * %rcx	: repcount
	 * %r8	: flags
	 *
	 * This routine will destroy values in %rdx, %rsi, %rcx.
	 */
	ENTRY(i_ddi_io_rep_get8)

	cmpq	$DDI_DEV_AUTOINCR, %r8
	je	gb_ioadv
	movq	%rsi, %rdi
	rep
	insb
	ret

gb_ioadv:
	andq	%rcx, %rcx
	jz	gb_ioadv_done
gb_ioadv2:
	inb	(%dx)
	movb	%al, (%rsi)
	incq	%rdx
	incq	%rsi
	decq	%rcx
	jg	gb_ioadv2

gb_ioadv_done:
	rep;	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */

	SET_SIZE(i_ddi_io_rep_get8)

#elif defined(__i386)

	ENTRY(i_ddi_io_rep_get8)
	pushl	%edi

	movl	12(%esp),%edi			/ get host_addr
	movl	16(%esp),%edx			/ get port
	movl	20(%esp),%ecx			/ get repcount
	cmpl	$DDI_DEV_AUTOINCR, 24(%esp)
	je	gb_ioadv

	rep
	insb
	popl	%edi
	ret

gb_ioadv:
	andl	%ecx, %ecx
	jz	gb_ioadv_done
gb_ioadv2:
	inb	(%dx)
	movb	%al,(%edi)
	incl	%edi
	incl	%edx
	decl	%ecx
	jg	gb_ioadv2

gb_ioadv_done:
	popl	%edi
	ret

	SET_SIZE(i_ddi_io_rep_get8)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(i_ddi_io_rep_get16)

	cmpq	$DDI_DEV_AUTOINCR, %r8
	je	gw_ioadv

	movq	%rsi, %rdi
	rep
	insw
	ret

gw_ioadv:
	andq	%rcx, %rcx
	jz	gw_ioadv_done
gw_ioadv2:
	inw	(%dx)
	movw	%ax,(%rsi)
	addq	$2, %rsi
	addq	$2, %rdx
	decq	%rcx
	jg	gw_ioadv2

gw_ioadv_done:
	rep;	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */
	SET_SIZE(i_ddi_io_rep_get16)

#elif defined(__i386)

	ENTRY(i_ddi_io_rep_get16)
	pushl	%edi

	movl	12(%esp),%edi			/ get host_addr
	movl	16(%esp),%edx			/ get port
	movl	20(%esp),%ecx			/ get repcount
	cmpl	$DDI_DEV_AUTOINCR, 24(%esp)
	je	gw_ioadv

	rep
	insw
	popl	%edi
	ret

gw_ioadv:
	andl	%ecx, %ecx
	jz	gw_ioadv_done
gw_ioadv2:
	inw	(%dx)
	movw	%ax,(%edi)
	addl	$2, %edi
	addl	$2, %edx
	decl	%ecx
	jg	gw_ioadv2

gw_ioadv_done:
	popl	%edi
	ret
	SET_SIZE(i_ddi_io_rep_get16)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(i_ddi_io_rep_get32)

	cmpq	$DDI_DEV_AUTOINCR, %r8
	je	gl_ioadv

	movq	%rsi, %rdi
	rep
	insl
	ret

gl_ioadv:
	andq	%rcx, %rcx
	jz	gl_ioadv_done
gl_ioadv2:
	inl	(%dx)
	movl	%eax,(%rsi)
	addq	$4, %rsi
	addq	$4, %rdx
	decq	%rcx
	jg	gl_ioadv2

gl_ioadv_done:
	rep;	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */

	SET_SIZE(i_ddi_io_rep_get32)


#elif defined(__i386)

	ENTRY(i_ddi_io_rep_get32)
	pushl	%edi

	movl	12(%esp),%edi			/ get host_addr
	movl	16(%esp),%edx			/ get port
	movl	20(%esp),%ecx			/ get repcount
	cmpl	$DDI_DEV_AUTOINCR, 24(%esp)
	je	gl_ioadv

	rep
	insl
	popl	%edi
	ret

gl_ioadv:
	andl	%ecx, %ecx
	jz	gl_ioadv_done
gl_ioadv2:
	inl	(%dx)
	movl	%eax,(%edi)
	addl	$4, %edi
	addl	$4, %edx
	decl	%ecx
	jg	gl_ioadv2

gl_ioadv_done:
	popl	%edi
	ret

	SET_SIZE(i_ddi_io_rep_get32)

#endif	/* __i386 */

#endif /* lint */

#if defined(lint) || defined(__lint)

/*ARGSUSED*/
void
i_ddi_io_rep_put8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{}

/*ARGSUSED*/
void
i_ddi_io_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{}

/*ARGSUSED*/
void
i_ddi_io_rep_put32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{}

#else	/* lint */

#if defined(__amd64)

	/*
	 * Incoming arguments
	 *
	 * %rdi	: hdlp
	 * %rsi	: host_addr
	 * %rdx	: dev_addr
	 * %rcx	: repcount
	 * %r8	: flags
	 *
	 * This routine will destroy values in %rdx, %rsi, %rcx.
	 */
	ENTRY(i_ddi_io_rep_put8)

	cmpq	$DDI_DEV_AUTOINCR, %r8
	je	pb_ioadv

	movq	%rsi, %rdi
	rep
	outsb
	ret

pb_ioadv:
	andq	%rcx, %rcx
	jz	pb_ioadv_done
pb_ioadv2:
	movb	(%rsi), %al
	outb	(%dx)
	incq	%rsi
	incq	%rdx
	decq	%rcx
	jg	pb_ioadv2

pb_ioadv_done:
	rep;	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */
	SET_SIZE(i_ddi_io_rep_put8)

#elif defined(__i386)

	ENTRY(i_ddi_io_rep_put8)
	pushl	%esi

	movl	12(%esp),%esi			/ get host_addr
	movl	16(%esp),%edx			/ get port
	movl	20(%esp),%ecx			/ get repcount
	cmpl	$DDI_DEV_AUTOINCR, 24(%esp)
	je	pb_ioadv

	rep
	outsb
	popl	%esi
	ret

pb_ioadv:
	andl	%ecx, %ecx
	jz	pb_ioadv_done
pb_ioadv2:
	movb	(%esi), %al
	outb	(%dx)
	incl	%esi
	incl	%edx
	decl	%ecx
	jg	pb_ioadv2

pb_ioadv_done:
	popl	%esi
	ret
	SET_SIZE(i_ddi_io_rep_put8)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(i_ddi_io_rep_put16)

	cmpq	$DDI_DEV_AUTOINCR, %r8
	je	pw_ioadv

	movq	%rsi, %rdi
	rep
	outsw
	ret

pw_ioadv:
	andq	%rcx, %rcx
	jz	pw_ioadv_done
pw_ioadv2:
	movw	(%rsi), %ax
	outw	(%dx)
	addq	$2, %rsi
	addq	$2, %rdx
	decq	%rcx
	jg	pw_ioadv2

pw_ioadv_done:
	rep;	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */
	SET_SIZE(i_ddi_io_rep_put16)

#elif defined(__i386)

	ENTRY(i_ddi_io_rep_put16)
	pushl	%esi

	movl	12(%esp),%esi			/ get host_addr
	movl	16(%esp),%edx			/ get port
	movl	20(%esp),%ecx			/ get repcount
	cmpl	$DDI_DEV_AUTOINCR, 24(%esp)
	je	pw_ioadv

	rep
	outsw
	popl	%esi
	ret

pw_ioadv:
	andl	%ecx, %ecx
	jz	pw_ioadv_done
pw_ioadv2:
	movw	(%esi), %ax
	outw	(%dx)
	addl	$2, %esi
	addl	$2, %edx
	decl	%ecx
	jg	pw_ioadv2

pw_ioadv_done:
	popl	%esi
	ret
	SET_SIZE(i_ddi_io_rep_put16)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(i_ddi_io_rep_put32)

	cmpq	$DDI_DEV_AUTOINCR, %r8
	je	pl_ioadv

	movq	%rsi, %rdi
	rep
	outsl
	ret

pl_ioadv:
	andq	%rcx, %rcx
	jz	pl_ioadv_done
pl_ioadv2:
	movl	(%rsi), %eax
	outl	(%dx)
	addq	$4, %rsi
	addq	$4, %rdx
	decq	%rcx
	jg	pl_ioadv2

pl_ioadv_done:
	rep;	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */
	SET_SIZE(i_ddi_io_rep_put32)

#elif defined(__i386)

	ENTRY(i_ddi_io_rep_put32)
	pushl	%esi

	movl	12(%esp),%esi			/ get host_addr
	movl	16(%esp),%edx			/ get port
	movl	20(%esp),%ecx			/ get repcount
	cmpl	$DDI_DEV_AUTOINCR, 24(%esp)
	je	pl_ioadv

	rep
	outsl
	popl	%esi
	ret

pl_ioadv:
	andl	%ecx, %ecx
	jz	pl_ioadv_done
pl_ioadv2:
	movl	(%esi), %eax
	outl	(%dx)
	addl	$4, %esi
	addl	$4, %edx
	decl	%ecx
	jg	pl_ioadv2

pl_ioadv_done:
	popl	%esi
	ret
	SET_SIZE(i_ddi_io_rep_put32)

#endif	/* __i386 */

#endif /* lint */
