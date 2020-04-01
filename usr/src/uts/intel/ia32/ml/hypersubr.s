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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/asm_linkage.h>
#ifndef __xpv
#include <sys/xpv_support.h>
#endif
#include <sys/hypervisor.h>

/*
 * Hypervisor "system calls"
 *
 * amd64
 *	%rax == call number
 *	args in registers (%rdi, %rsi, %rdx, %r10, %r8, %r9)
 *
 * Note that we use %r10 instead of %rcx for passing 4th argument as in
 * C calling convention since the "syscall" instruction clobbers %rcx.
 *
 * (These calls can be done more efficiently as gcc-style inlines, but
 * for simplicity and help with initial debugging, we use these primitives
 * to build the hypervisor calls up from C wrappers.)
 */

/*
 * XXPV grr - assembler can't deal with an instruction in a quoted string
 */
#undef	TRAP_INSTR	/* cause it's currently "int $0x82" */

/*
 * The method for issuing a hypercall (i.e. a system call to the
 * hypervisor) varies from platform to platform.  In 32-bit PV domains, an
 * 'int 82' triggers the call.  In 64-bit PV domains, a 'syscall' does the
 * trick.
 *
 * HVM domains are more complicated.  In all cases, we want to issue a
 * VMEXIT instruction, but AMD and Intel use different opcodes to represent
 * that instruction.  Rather than build CPU-specific modules with the
 * different opcodes, we use the 'hypercall page' provided by Xen.  This
 * page contains a collection of code stubs that do nothing except issue
 * hypercalls using the proper instructions for this machine.  To keep the
 * wrapper code as simple and efficient as possible, we preallocate that
 * page below.  When the module is loaded, we ask Xen to remap the
 * underlying PFN to that of the hypercall page.
 *
 * Note: this same mechanism could be used in PV domains, but using
 * hypercall page requires a call and several more instructions than simply
 * issuing the proper trap.
 */
#if !defined(__xpv)

#define	HYPERCALL_PAGESIZE		0x1000
#define	HYPERCALL_SHINFO_PAGESIZE	0x1000

	.data
	.align	HYPERCALL_SHINFO_PAGESIZE
	.globl	hypercall_shared_info_page
	.type	hypercall_shared_info_page, @object
	.size	hypercall_shared_info_page, HYPERCALL_SHINFO_PAGESIZE
hypercall_shared_info_page:
	.skip	HYPERCALL_SHINFO_PAGESIZE

	.text
	.align	HYPERCALL_PAGESIZE
	.globl	hypercall_page
	.type	hypercall_page, @function
hypercall_page:
	.skip	HYPERCALL_PAGESIZE
	.size	hypercall_page, HYPERCALL_PAGESIZE
#define	TRAP_INSTR			\
	shll	$5, %eax;		\
	addq	$hypercall_page, %rax;	\
	INDIRECT_JMP_REG(rax);

#else /* !_xpv */

#define	TRAP_INSTR	syscall
#endif /* !__xpv */


	ENTRY_NP(__hypercall0)
	ALTENTRY(__hypercall0_int)
	movl	%edi, %eax
	TRAP_INSTR
	ret
	SET_SIZE(__hypercall0)

	ENTRY_NP(__hypercall1)
	ALTENTRY(__hypercall1_int)
	movl	%edi, %eax
	movq	%rsi, %rdi		/* arg 1 */
	TRAP_INSTR
	ret
	SET_SIZE(__hypercall1)

	ENTRY_NP(__hypercall2)
	ALTENTRY(__hypercall2_int)
	movl	%edi, %eax
	movq	%rsi, %rdi		/* arg 1 */
	movq	%rdx, %rsi		/* arg 2 */
	TRAP_INSTR
	ret
	SET_SIZE(__hypercall2)

	ENTRY_NP(__hypercall3)
	ALTENTRY(__hypercall3_int)
	movl	%edi, %eax
	movq	%rsi, %rdi		/* arg 1 */
	movq	%rdx, %rsi		/* arg 2 */
	movq	%rcx, %rdx		/* arg 3 */
	TRAP_INSTR
	ret
	SET_SIZE(__hypercall3)

	ENTRY_NP(__hypercall4)
	ALTENTRY(__hypercall4_int)
	movl	%edi, %eax
	movq	%rsi, %rdi		/* arg 1 */
	movq	%rdx, %rsi		/* arg 2 */
	movq	%rcx, %rdx		/* arg 3 */
	movq	%r8, %r10		/* r10 = 4th arg */
	TRAP_INSTR
	ret
	SET_SIZE(__hypercall4)

	ENTRY_NP(__hypercall5)
	ALTENTRY(__hypercall5_int)
	movl	%edi, %eax
	movq	%rsi, %rdi		/* arg 1 */
	movq	%rdx, %rsi		/* arg 2 */
	movq	%rcx, %rdx		/* arg 3 */
	movq	%r8, %r10		/* r10 = 4th arg */
	movq	%r9, %r8		/* arg 5 */
	TRAP_INSTR
	ret
	SET_SIZE(__hypercall5)

