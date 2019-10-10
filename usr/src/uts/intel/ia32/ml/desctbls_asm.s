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
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include <sys/regset.h>
#include <sys/panic.h>
#include <sys/ontrap.h>
#include <sys/privregs.h>
#include <sys/segments.h>
#include <sys/trap.h>

#include "assym.h"

	ENTRY_NP(rd_idtr)
	sidt	(%rdi)
	ret
	SET_SIZE(rd_idtr)

	ENTRY_NP(wr_idtr)
	lidt	(%rdi)
	ret
	SET_SIZE(wr_idtr)

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

	ENTRY_NP(wr_tsr)
	movq	%rdi, %rax
	ltr	%ax
	ret
	SET_SIZE(wr_tsr)

