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
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/asm_linkage.h>
#include <sys/regset.h>

#if defined(lint)
#include <sys/dtrace_impl.h>
#else
#include "assym.h"
#endif

#if defined(lint) || defined(__lint)

greg_t
dtrace_getfp(void)
{ return (0); }

#else	/* lint */

#if defined(__amd64)

	ENTRY_NP(dtrace_getfp)
	movq	%rbp, %rax
	ret
	SET_SIZE(dtrace_getfp)

#elif defined(__i386)

	ENTRY_NP(dtrace_getfp)
	movl	%ebp, %eax
	ret
	SET_SIZE(dtrace_getfp)

#endif	/* __i386 */
#endif	/* lint */


#if defined(lint) || defined(__lint)

/*ARGSUSED*/
uint64_t
dtrace_getvmreg(uint32_t reg, volatile uint16_t *flags)
{ return (0); }

#else	/* lint */

#if defined(__amd64)

	ENTRY_NP(dtrace_getvmreg)

	movq	%rdi, %rdx
	vmread	%rdx, %rax
	ret

	SET_SIZE(dtrace_getvmreg)

#elif defined(__i386)

	ENTRY_NP(dtrace_getvmreg)
	pushl	%ebp			/ Setup stack frame
	movl	%esp, %ebp

	movl	12(%ebp), %eax		/ Load flag pointer
	movw	(%eax), %cx		/ Load flags
	orw	$CPU_DTRACE_ILLOP, %cx	/ Set ILLOP
	movw	%cx, (%eax)		/ Store flags

	leave
	ret
	SET_SIZE(dtrace_getvmreg)

#endif	/* __i386 */
#endif	/* lint */


#if defined(lint) || defined(__lint)

uint32_t
dtrace_cas32(uint32_t *target, uint32_t cmp, uint32_t new)
{
	uint32_t old;

	if ((old = *target) == cmp)
		*target = new;
	return (old);
}

void *
dtrace_casptr(void *target, void *cmp, void *new)
{
	void *old;

	if ((old = *(void **)target) == cmp)
		*(void **)target = new;
	return (old);
}

#else	/* lint */

#if defined(__amd64)

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

#elif defined(__i386)

	ENTRY(dtrace_cas32)
	ALTENTRY(dtrace_casptr)
	movl	4(%esp), %edx
	movl	8(%esp), %eax
	movl	12(%esp), %ecx
	lock
	cmpxchgl %ecx, (%edx)
	ret
	SET_SIZE(dtrace_casptr)
	SET_SIZE(dtrace_cas32)

#endif	/* __i386 */
#endif	/* lint */

#if defined(lint)

/*ARGSUSED*/
uintptr_t
dtrace_caller(int aframes)
{
	return (0);
}

#else	/* lint */

#if defined(__amd64)
	ENTRY(dtrace_caller)
	movq	$-1, %rax
	ret
	SET_SIZE(dtrace_caller)

#elif defined(__i386)

	ENTRY(dtrace_caller)
	movl	$-1, %eax
	ret
	SET_SIZE(dtrace_caller)

#endif	/* __i386 */
#endif	/* lint */

#if defined(lint)

/*ARGSUSED*/
void
dtrace_copy(uintptr_t src, uintptr_t dest, size_t size)
{}

#else

#if defined(__amd64)

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

#elif defined(__i386)

	ENTRY(dtrace_copy)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%esi
	pushl	%edi

	movl	8(%ebp), %esi		/ Load source address
	movl	12(%ebp), %edi		/ Load destination address
	movl	16(%ebp), %ecx		/ Load count
	repz				/ Repeat for count...
	smovb				/   move from %ds:si to %es:di

	popl	%edi
	popl	%esi
	movl	%ebp, %esp
	popl	%ebp
	ret
	SET_SIZE(dtrace_copy)

#endif	/* __i386 */
#endif

#if defined(lint)

/*ARGSUSED*/
void
dtrace_copystr(uintptr_t uaddr, uintptr_t kaddr, size_t size,
    volatile uint16_t *flags)
{}

#else

#if defined(__amd64)

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

#elif defined(__i386)

	ENTRY(dtrace_copystr)

	pushl	%ebp			/ Setup stack frame
	movl	%esp, %ebp
	pushl	%ebx			/ Save registers
	
	movl	8(%ebp), %ebx		/ Load source address
	movl	12(%ebp), %edx		/ Load destination address
	movl	16(%ebp), %ecx		/ Load count

0:
	movb	(%ebx), %al		/ Load from source
	movb	%al, (%edx)		/ Store to destination
	incl	%ebx			/ Increment source pointer
	incl	%edx			/ Increment destination pointer
	decl	%ecx			/ Decrement remaining count
	cmpb	$0, %al
	je	2f
	testl	$0xfff, %ecx		/ Check if count is 4k-aligned
	jnz	1f
	movl	20(%ebp), %eax		/ load flags pointer
	testl	$CPU_DTRACE_BADADDR, (%eax) / load and test dtrace flags
	jnz	2f
1:
	cmpl	$0, %ecx
	jne	0b

2:
	popl	%ebx
	movl	%ebp, %esp
	popl	%ebp
	ret

	SET_SIZE(dtrace_copystr)

#endif	/* __i386 */
#endif

#if defined(lint)

/*ARGSUSED*/
uintptr_t
dtrace_fulword(void *addr)
{ return (0); }

#else
#if defined(__amd64)

	ENTRY(dtrace_fulword)
	call	smap_disable
	movq	(%rdi), %rax
	call	smap_enable
	ret
	SET_SIZE(dtrace_fulword)

#elif defined(__i386)

	ENTRY(dtrace_fulword)
	movl	4(%esp), %ecx
	xorl	%eax, %eax
	movl	(%ecx), %eax
	ret
	SET_SIZE(dtrace_fulword)

#endif	/* __i386 */
#endif

#if defined(lint)

/*ARGSUSED*/
uint8_t
dtrace_fuword8_nocheck(void *addr)
{ return (0); }

#else
#if defined(__amd64)

	ENTRY(dtrace_fuword8_nocheck)
	call	smap_disable
	xorq	%rax, %rax
	movb	(%rdi), %al
	call	smap_enable
	ret
	SET_SIZE(dtrace_fuword8_nocheck)

#elif defined(__i386)

	ENTRY(dtrace_fuword8_nocheck)
	movl	4(%esp), %ecx
	xorl	%eax, %eax
	movzbl	(%ecx), %eax
	ret
	SET_SIZE(dtrace_fuword8_nocheck)

#endif	/* __i386 */
#endif

#if defined(lint)

/*ARGSUSED*/
uint16_t
dtrace_fuword16_nocheck(void *addr)
{ return (0); }

#else
#if defined(__amd64)

	ENTRY(dtrace_fuword16_nocheck)
	call	smap_disable
	xorq	%rax, %rax
	movw	(%rdi), %ax
	call	smap_enable
	ret
	SET_SIZE(dtrace_fuword16_nocheck)

#elif defined(__i386)

	ENTRY(dtrace_fuword16_nocheck)
	movl	4(%esp), %ecx
	xorl	%eax, %eax
	movzwl	(%ecx), %eax
	ret
	SET_SIZE(dtrace_fuword16_nocheck)

#endif	/* __i386 */
#endif

#if defined(lint)

/*ARGSUSED*/
uint32_t
dtrace_fuword32_nocheck(void *addr)
{ return (0); }

#else
#if defined(__amd64)

	ENTRY(dtrace_fuword32_nocheck)
	call	smap_disable
	xorq	%rax, %rax
	movl	(%rdi), %eax
	call	smap_enable
	ret
	SET_SIZE(dtrace_fuword32_nocheck)

#elif defined(__i386)

	ENTRY(dtrace_fuword32_nocheck)
	movl	4(%esp), %ecx
	xorl	%eax, %eax
	movl	(%ecx), %eax
	ret
	SET_SIZE(dtrace_fuword32_nocheck)

#endif	/* __i386 */
#endif

#if defined(lint)

/*ARGSUSED*/
uint64_t
dtrace_fuword64_nocheck(void *addr)
{ return (0); }

#else
#if defined(__amd64)

	ENTRY(dtrace_fuword64_nocheck)
	call	smap_disable
	movq	(%rdi), %rax
	call	smap_enable
	ret
	SET_SIZE(dtrace_fuword64_nocheck)

#elif defined(__i386)

	ENTRY(dtrace_fuword64_nocheck)
	movl	4(%esp), %ecx
	xorl	%eax, %eax
	xorl	%edx, %edx
	movl	(%ecx), %eax
	movl	4(%ecx), %edx
	ret
	SET_SIZE(dtrace_fuword64_nocheck)

#endif	/* __i386 */
#endif

#if defined(lint) || defined(__lint)

/*ARGSUSED*/
void
dtrace_probe_error(dtrace_state_t *state, dtrace_epid_t epid, int which,
    int fault, int fltoffs, uintptr_t illval)
{}

#else	/* lint */
#if defined(__amd64)

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
	
#elif defined(__i386)

	ENTRY(dtrace_probe_error)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	0x1c(%ebp)
	pushl	0x18(%ebp)
	pushl	0x14(%ebp)
	pushl	0x10(%ebp)
	pushl	0xc(%ebp)
	pushl	0x8(%ebp)
	pushl	dtrace_probeid_error
	call	dtrace_probe
	movl	%ebp, %esp
	popl	%ebp
	ret
	SET_SIZE(dtrace_probe_error)

#endif	/* __i386 */
#endif
