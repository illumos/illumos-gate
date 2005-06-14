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

#include <sys/asm_linkage.h>

#if defined(__lint)
#include <amd64/amd64.h>
#include <amd64/cpu.h>
#else
#include <assym.h>
#endif

#if defined(__lint)

void
amd64_system_reset(void)
{}

void
amd64_flush_tlb(void)
{}

/*ARGSUSED*/
void
amd64_flush_tlbentry(char *addr)
{}

#else

	ENTRY_NP(amd64_system_reset)
	movw	$0x64, %dx
	movb	$0xfe, %al
	outb	(%dx)
	hlt
	SET_SIZE(amd64_system_reset);

	/*
	 * Note: does NOT flush global entries if PGE enabled...
	 */
	ENTRY_NP(amd64_flush_tlb)
	movl	%cr3, %eax
	movl	%eax, %cr3
	ret
	SET_SIZE(amd64_flush_tlb)

	ENTRY_NP(amd64_flush_tlbentry)
	movl	4(%esp), %eax
	invlpg	(%eax)
	ret
	SET_SIZE(amd64_flush_tlbentry)
#endif

#if defined(__lint)

ulong_t
amd64_get_cr0(void)
{ return (0ul); }

ulong_t
amd64_get_cr2(void)
{ return (0ul); }

ulong_t
amd64_get_cr3(void)
{ return (0ul); }

ulong_t
amd64_get_cr4(void)
{ return (0ul); }

#else

	ENTRY(amd64_get_cr0)
	movl	%cr0, %eax
	ret
	SET_SIZE(amd64_get_cr0)

	ENTRY(amd64_get_cr2)
	movl	%cr2, %eax
	ret
	SET_SIZE(amd64_get_cr2)

	ENTRY(amd64_get_cr3)
	movl	%cr3, %eax
	ret
	SET_SIZE(amd64_get_cr3)

	ENTRY(amd64_get_cr4)
	movl	%cr4, %eax
	ret
	SET_SIZE(amd64_get_cr4)

#endif

#if defined(__lint)

/*ARGSUSED*/
void
amd64_rdmsr(uint32_t msr, uint64_t *data)
{}

/*ARGSUSED*/
void
amd64_wrmsr(uint32_t msr, const uint64_t *data)
{}

#else

	ENTRY(amd64_rdmsr)
	movl	4(%esp), %ecx
	rdmsr
	movl	8(%esp), %ecx
	movl	%eax, (%ecx)
	movl	%edx, 4(%ecx)
	ret
	SET_SIZE(amd64_rdmsr)

	ENTRY(amd64_wrmsr)
	movl	8(%esp), %ecx
	movl	(%ecx), %eax
	movl	4(%ecx), %edx
	movl	4(%esp), %ecx
	wrmsr
	ret
	SET_SIZE(amd64_wrmsr)

#endif	/* __lint */

#if defined(__lint)

ulong_t
amd64_get_eflags(void)
{ return (0); }

#else	/* __lint */

	ENTRY(amd64_get_eflags)
	pushfl
	pop	%eax
	ret
	SET_SIZE(amd64_get_eflags)

#endif	/* __lint */

#if defined(__lint)

/*ARGSUSED*/
void
amd64_cpuid_insn(uint32_t eax, struct amd64_cpuid_regs *vcr)
{}

#else	/* __lint */

        ENTRY(amd64_cpuid_insn)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	pushl	%esi
	movl	0x8(%ebp), %eax
	movl	0xc(%ebp), %esi
	cpuid
	movl	%eax, AMD64_CPUID_REG_EAX(%esi)
	movl	%ebx, AMD64_CPUID_REG_EBX(%esi)
	movl	%ecx, AMD64_CPUID_REG_ECX(%esi)
	movl	%edx, AMD64_CPUID_REG_EDX(%esi)
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
	SET_SIZE(amd64_cpuid_insn)

#endif	/* __lint */

#if defined(__lint)

unsigned
amd64_cpuid_supported(void) { return (1); }

#else
	/*
	 * Based on code from AMD64 Volume 3
	 */
	ENTRY(amd64_cpuid_supported)
	pushf
	popl	%eax
	mov	%eax, %edx		/* save %eax for later */
	xorl	%eax, 0x200000		/* toggle bit 21 */
	pushl	%eax
	popf				/* save new %eax to EFLAGS */
	pushf				/* save new EFLAGS */
	popl	%ecx			/* copy EFLAGS to %eax */
	xorl	%eax, %eax
	cmpl	%ecx, %edx		/* see if bit 21 has changes */
	jne	1f
	incl	%eax
1:
	ret
	SET_SIZE(amd64_cpuid_supported)
#endif	/* __lint */
