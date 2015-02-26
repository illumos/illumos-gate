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
#include <sys/regset.h>
#include <sys/panic.h>
#include <sys/ontrap.h>
#include <sys/privregs.h>
#include <sys/segments.h>
#include <sys/trap.h>

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
void
rd_idtr(desctbr_t *idtr)
{}

/*ARGSUSED*/
void
wr_idtr(desctbr_t *idtr)
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
void
rd_gdtr(desctbr_t *gdtr)
{}

/*ARGSUSED*/
void
wr_gdtr(desctbr_t *gdtr)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(rd_gdtr)
	pushq	%rbp
	movq	%rsp, %rbp
	sgdt	(%rdi)
	leave
	ret
	SET_SIZE(rd_gdtr)

	ENTRY_NP(wr_gdtr)
	pushq	%rbp
	movq	%rsp, %rbp
	lgdt	(%rdi)
	jmp	1f
	nop
1:
	leave
	ret
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
	jmp	1f
	nop
1:
	leave
	ret
	SET_SIZE(wr_gdtr)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__amd64)
#if defined(__lint)

/*ARGSUSED*/
void
load_segment_registers(selector_t cs, selector_t fs, selector_t gs,
    selector_t ss)
{}

selector_t
get_cs_register()
{ return (0); }

#else	/* __lint */

	/*
	 * loads zero selector for ds and es.
	 */
	ENTRY_NP(load_segment_registers)
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%rdi
	pushq	$.newcs
	lretq
.newcs:
	/*
	 * zero %ds and %es - they're ignored anyway
	 */
	xorl	%eax, %eax
	movw	%ax, %ds
	movw	%ax, %es
	movl	%esi, %eax
	movw	%ax, %fs
	movl	%edx, %eax
	movw	%ax, %gs
	movl	%ecx, %eax
	movw	%ax, %ss
	leave
	ret
	SET_SIZE(load_segment_registers)

	ENTRY_NP(get_cs_register)
	movq	%cs, %rax
	ret
	SET_SIZE(get_cs_register)

#endif	/* __lint */
#elif defined(__i386)

#if defined(__lint)

/*ARGSUSED*/
void
load_segment_registers(
    selector_t cs, selector_t ds, selector_t es,
    selector_t fs, selector_t gs, selector_t ss)
{}

selector_t
get_cs_register()
{ return ((selector_t) 0); }

#else	/* __lint */

	ENTRY_NP(load_segment_registers)
	pushl	%ebp
	movl	%esp, %ebp

	pushl	0x8(%ebp)
	pushl	$.newcs
	lret
.newcs:
	movw	0xc(%ebp), %ax
	movw	%ax, %ds
	movw	0x10(%ebp), %ax
	movw	%ax, %es
	movw	0x14(%ebp), %ax
	movw	%ax, %fs
	movw	0x18(%ebp), %ax
	movw	%ax, %gs
	movw	0x1c(%ebp), %ax
	movw	%ax, %ss
	leave
	ret
	SET_SIZE(load_segment_registers)

	ENTRY_NP(get_cs_register)
	movl	$0, %eax
	movw	%cs, %ax
	ret
	SET_SIZE(get_cs_register)

#endif	/* __lint */
#endif	/* __i386 */

#if defined(__lint)

/*ARGSUSED*/
void
wr_ldtr(selector_t ldtsel)
{}

selector_t
rd_ldtr(void)
{ return (0); }

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
void
wr_tsr(selector_t tsssel)
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
