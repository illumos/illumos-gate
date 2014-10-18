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

	.file	"floorl.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(ceill,function)
LIBM_ANSI_PRAGMA_WEAK(floorl,function)
#include "libm_synonyms.h"

	ENTRY(ceill)
	subl	$8,%esp
	fstcw	(%esp)
	fldt	12(%esp)
	movw	(%esp),%cx
	orw	$0x0c00,%cx
	xorw	$0x0400,%cx
	movw	%cx,4(%esp)
	fldcw	4(%esp)			/ set RD = up
	frndint
	fstcw	4(%esp)			/ restore RD
	movw	4(%esp),%dx
	andw	$0xf3ff,%dx
	movw	(%esp),%cx
	andw	$0x0c00,%cx
	orw	%dx,%cx
	movw	%cx,(%esp)
	fldcw	(%esp)			/ restore RD
	addl	$8,%esp
	ret
	.align	4
	SET_SIZE(ceill)


	ENTRY(floorl)
	subl	$8,%esp
	fstcw	(%esp)
	fldt	12(%esp)
	movw	(%esp),%cx
	orw	$0x0c00,%cx
	xorw	$0x0800,%cx
	movw	%cx,4(%esp)
	fldcw	4(%esp)			/ set RD = down
	frndint
	fstcw	4(%esp)			/ restore RD
	movw	4(%esp),%dx
	andw	$0xf3ff,%dx
	movw	(%esp),%cx
	andw	$0x0c00,%cx
	orw	%dx,%cx
	movw	%cx,(%esp)
	fldcw	(%esp)			/ restore RD
	addl	$8,%esp
	ret
	.align	4
	SET_SIZE(floorl)
