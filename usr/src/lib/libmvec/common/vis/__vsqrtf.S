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

	.file	"__vsqrtf.S"

#include "libm.h"

	.section	".text"
	.file	"__vsqrtf.S"

	ENTRY(__vsqrtf)

	lda	[%o1]0x82,%f0
	subcc	%o0,1,%o0
	bneg,pn	%icc,.exit
	sll	%o2,2,%o2
	ba	.loop
	sll	%o4,2,%o4

	.align	16
.loop:
	fsqrts	%f0,%f2
	lda	[%o1+%o2]0x82,%f0
	add	%o1,%o2,%o1
	subcc	%o0,1,%o0
	st	%f2,[%o3]
	bpos,pt	%icc,.loop
	add	%o3,%o4,%o3
.exit:
	retl
	nop

	SET_SIZE(__vsqrtf)

