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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"fpcw.s"

#include <SYS.h>

	ENTRY(_getcw)
	fstcw	(%rdi)
	ret
	SET_SIZE(_getcw)

	ENTRY(_putcw)
	subq	$8,%rsp
	movq	%rdi,(%rsp)
	fldcw	(%rsp)
	addq	$8,%rsp
	ret
	SET_SIZE(_putcw)

	ENTRY(_getsw)
	fstsw	(%rdi)
	ret
	SET_SIZE(_getsw)

	ENTRY(_putsw)
	andq	$0x3f,%rdi
	jnz	1f
	fnclex
	ret
1:
	subq	$32,%rsp
	fnstsw	%ax
	fnstenv	(%rsp)
	andw	$0xffc0,%ax
	orw	%ax,%di
	movw	%di,4(%rsp)
	fldenv	(%rsp)
	addq	$32,%rsp
	ret
	SET_SIZE(_putsw)

	ENTRY(_getmxcsr)
	stmxcsr	(%rdi)
	ret
	SET_SIZE(_getmxcsr)

	ENTRY(_putmxcsr)
	subq	$8,%rsp
	movq	%rdi,(%rsp)
	ldmxcsr	(%rsp)
	addq	$8,%rsp
	ret
	SET_SIZE(_putmxcsr)
