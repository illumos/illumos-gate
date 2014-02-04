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

	.file	"truncl.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(truncl,function)
#include "libm_synonyms.h"

	ENTRY(truncl)
	movl	%esp,%eax
	subl	$8,%esp
	fstcw	-8(%eax)
	fldt	4(%eax)
	movw	-8(%eax),%cx
	orw	$0x0c00,%cx
	movw	%cx,-4(%eax)
	fldcw	-4(%eax)		/ set RD = to_zero
	frndint
	fstcw	-4(%eax)
	movw	-4(%eax),%dx
	andw	$0xf3ff,%dx
	movw	-8(%eax),%cx
	andw	$0x0c00,%cx
	orw	%dx,%cx
	movw	%cx,-8(%eax)
	fldcw	-8(%eax)		/ restore RD
	addl	$8,%esp
	ret
	.align	4
	SET_SIZE(truncl)
