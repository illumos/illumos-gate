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

	.file	"_mul64.s"

/
/   function __mul64(A,B:Longint):Longint;
/	{Overflow is not checked}
/
/ We essentially do multiply by longhand, using base 2**32 digits.
/               a       b	parameter A
/	     x 	c       d	parameter B
/		---------
/               ad      bd
/       ac	bc
/       -----------------
/       ac	ad+bc	bd
/
/       We can ignore ac and top 32 bits of ad+bc: if <> 0, overflow happened.
/

#include "SYS.h"

	ENTRY(__mul64)
	push	%ebp
	mov    	%esp,%ebp
	pushl	%esi
	mov	12(%ebp),%eax	/ A.hi (a)
	mull	16(%ebp)	/ Multiply A.hi by B.lo (produces ad)
	xchg	%ecx,%eax	/ ecx = bottom half of ad.
	movl    8(%ebp),%eax	/ A.Lo (b)
	movl	%eax,%esi	/ Save A.lo for later
	mull	16(%ebp)	/ Multiply A.Lo by B.LO (dx:ax = bd.)
	addl	%edx,%ecx	/ cx is ad
	xchg	%eax,%esi       / esi is bd, eax = A.lo (d)
	mull	20(%ebp)	/ Multiply A.lo * B.hi (producing bc)
	addl	%ecx,%eax	/ Produce ad+bc
	movl	%esi,%edx
	xchg	%eax,%edx
	popl	%esi
	movl	%ebp,%esp
	popl	%ebp
	ret     $16
	SET_SIZE(__mul64)
