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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file "remquo.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(remquo,function)
#include "libm_protos.h"

	ENTRY(remquo)
	fldl	12(%esp)		/ load arg y
	fldl	4(%esp)			/ load arg x
.Lrem_loop:
	fprem1				/ partial remainder
	fstsw	%ax			/ store status word
	andw	$0x400,%ax		/ check whether reduction complete
	jne	.Lrem_loop		/ while reduction incomplete, do fprem1
	fstsw	%ax
	fwait
	fstp	%st(1)
	movw	%ax,%dx
	andw	$0x4000,%dx		/ get C3
	sarw	$13,%dx
	movw	%ax,%cx
	andw	$0x100,%cx		/ get C0
	sarw	$6,%cx
	addw	%cx,%dx
	andw	$0x200,%ax		/ get C1
	sarw	$9,%ax
	addw	%dx,%ax
	cwtl
	movl	8(%esp),%edx		/ sign and bexp of x
	movl	16(%esp),%ecx		/ sign and bexp of y
	andl	$0x80000000,%edx	/ edx <- sign(x)
	andl	$0x80000000,%ecx	/ ecx <- sign(y)
	cmpl	%edx,%ecx
	je	.pos
	negl	%eax			/ negative n
.pos:
	movl	20(%esp),%ecx
	movl	%eax,0(%ecx)		/ last 3 significant bits of quotient
	ret
	.align	4
	SET_SIZE(remquo)
