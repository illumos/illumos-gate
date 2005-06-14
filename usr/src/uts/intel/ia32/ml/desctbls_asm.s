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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include <sys/regset.h>
#include <sys/panic.h>
#include <sys/ontrap.h>
#include <sys/privregs.h>
#include <sys/segments.h>

#if defined(__lint)
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/archsystm.h>
#include <sys/byteorder.h>
#include <sys/dtrace.h>
#include <sys/x86_archext.h>
#else   /* __lint */
#include "assym.h"
#endif  /* __lint */

#if defined(__lint)

/*ARGSUSED*/
void rd_idtr(desctbr_t *idtr)
{}

/*ARGSUSED*/
void wr_idtr(desctbr_t *idtr)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(rd_idtr)
	sidt	(%rdi)
	ret
	SET_SIZE(rd_idtr)

	ENTRY_NP(wr_idtr)
	lidt	(%rdi)
	ret
	SET_SIZE(wr_idtr)

#elif defined(__i386)

	ENTRY_NP(rd_idtr)
	pushl	%ebp
	movl	%esp, %ebp
	movl	8(%ebp), %edx
	sidt	(%edx)
	leave
	ret
	SET_SIZE(rd_idtr)

	ENTRY_NP(wr_idtr)
	pushl	%ebp
	movl	%esp, %ebp
	movl	8(%ebp), %edx
	lidt	(%edx)
	leave
	ret
	SET_SIZE(wr_idtr)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

/*ARGSUSED*/
void rd_gdtr(desctbr_t *gdtr)
{}

/*ARGSUSED*/
void wr_gdtr(desctbr_t *gdtr)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(rd_gdtr)
	sgdt	(%rdi)
	ret
	SET_SIZE(rd_gdtr)

	ENTRY_NP(wr_gdtr)
	lgdt	(%rdi)
	jmp	1f
	nop
1:
	movl	$KDS_SEL, %eax
	movw	%ax, %ss
	/*
	 * zero %ds and %es - they're ignored anyway
	 */
	xorl	%eax, %eax
	movw	%ax, %ds
	movw	%ax, %es
	/*
	 * set %fs and %gs (probably to zero also)
	 */
	movl	$KFS_SEL, %eax
	movw	%ax, %fs
	movl	$KGS_SEL, %eax
	movw	%ax, %gs
	popq	%rax
	pushq	$KCS_SEL
	pushq	%rax
	lretq
	SET_SIZE(wr_gdtr)

#elif defined(__i386)

	ENTRY_NP(rd_gdtr)
	pushl	%ebp
	movl	%esp, %ebp
	movl	8(%ebp), %edx
	sgdt	(%edx)
	leave
	ret
	SET_SIZE(rd_gdtr)

	ENTRY_NP(wr_gdtr)
	pushl	%ebp
	movl	%esp, %ebp
	movl	8(%ebp), %edx
	lgdt	(%edx)
	nop
	ljmp	$KCS_SEL, $.next
.next:
	movl	$KDS_SEL, %eax
	movw	%ax, %ds	
	movw	%ax, %es	
	movw	%ax, %ss	
	movl	$KFS_SEL, %eax
	movw	%ax, %fs	
	movl	$KGS_SEL, %eax
	movw	%ax, %gs	
	leave
	ret
	SET_SIZE(wr_gdtr)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

/*ARGSUSED*/
void wr_ldtr(selector_t ldtsel)
{}

selector_t rd_ldtr(void)
{ return (0); }

#if defined(__amd64)
void clr_ldt_sregs(void)
{}
#endif

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(wr_ldtr)
	movq	%rdi, %rax
	lldt	%ax
	ret
	SET_SIZE(wr_ldtr)

	ENTRY_NP(rd_ldtr)
	xorl	%eax, %eax
	sldt	%ax
	ret
	SET_SIZE(rd_ldtr)

	/*
	 * Make sure any stale ldt selectors are cleared by loading
	 * KDS_SEL (kernel %ds gdt selector). This is necessary
	 * since the kernel does not use %es, %fs and %ds. %cs and
	 * %ss are necessary and setup by the kernel along with %gs
	 * to point to current cpu struct. If we take a kmdb breakpoint
	 * in the kernel and resume with a stale ldt selector kmdb
	 * would #gp fault if it points to a ldt in the context of
	 * another process.
	 *
	 * WARNING: Nocona and AMD have different behaviour about storing
	 * the null selector into %fs and %gs while in long mode. On AMD
	 * chips fsbase and gsbase is not cleared. But on nocona storing
	 * null selector into %fs or %gs has the side effect of clearing
	 * fsbase or gsbase. For that reason we use KDS_SEL which has
	 * consistent behavoir between AMD and Nocona.
	 */
	ENTRY_NP(clr_ldt_sregs)

	/*
	 * Save GSBASE before resetting %gs to KDS_SEL
	 * then restore GSBASE.
	 */
	cli
	movq	%rbx, %rdi
	movw	$KDS_SEL, %bx
        movl    $MSR_AMD_GSBASE, %ecx
        rdmsr
        movw    %bx, %gs
	wrmsr
	sti
	movw	%bx, %ds
	movw	%bx, %es
	movw	%bx, %fs
	movq	%rdi, %rbx
	ret
	SET_SIZE(clr_ldt_sregs)

#elif defined(__i386)

	ENTRY_NP(wr_ldtr)
	movw	4(%esp), %ax
	lldt	%ax
	ret
	SET_SIZE(wr_ldtr)

	ENTRY_NP(rd_ldtr)
	xorl	%eax, %eax
	sldt	%ax
	ret
	SET_SIZE(rd_ldtr)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

/*ARGSUSED*/
void wr_tsr(selector_t tsssel)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(wr_tsr)
	movq	%rdi, %rax
	ltr	%ax
	ret
	SET_SIZE(wr_tsr)

#elif defined(__i386)

	ENTRY_NP(wr_tsr)
	movw	4(%esp), %ax
	ltr	%ax
	ret
	SET_SIZE(wr_tsr)

#endif	/* __i386 */
#endif	/* __lint */
