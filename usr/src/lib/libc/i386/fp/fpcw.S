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
	movl	4(%esp),%eax
	fstcw	(%eax)
	ret
	SET_SIZE(_getcw)

	ENTRY(_putcw)
	fldcw	4(%esp)
	ret
	SET_SIZE(_putcw)

	ENTRY(_getsw)
	movl	4(%esp),%eax
	fstsw	(%eax)
	ret
	SET_SIZE(_getsw)

	ENTRY(_putsw)
	movl	4(%esp),%ecx
	andl	$0x3f,%ecx
	jnz	1f
	fnclex
	ret
1:
	fnstsw	%ax
	subl	$28,%esp
	fnstenv	(%esp)
	andw	$0xffc0,%ax
	orw	%ax,%cx
	movw	%cx,4(%esp)
	fldenv	(%esp)
	addl	$28,%esp
	ret
	SET_SIZE(_putsw)

	ENTRY(_getmxcsr)
	movl	4(%esp),%eax
	stmxcsr	(%eax)
	ret
	SET_SIZE(_getmxcsr)

	ENTRY(_putmxcsr)
	ldmxcsr	4(%esp)
	ret
	SET_SIZE(_putmxcsr)
