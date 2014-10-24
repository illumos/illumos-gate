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

	.file	"nextafter.S"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(nextafter,function)
	.weak _nextafter
	.type _nextafter,#function
_nextafter	= __nextafter
#include "libm_protos.h"

	RO_DATA
	.align	8
.Lconstant:
two54 	= 0x00
	.word	0x43500000,0x0		!  2**54
twom54 	= 0x08
	.word	0x3c900000,0x0		!  2**-54
tiny	= 0x10
	.word	0x00100000,0x0		!  tiny

! variable using fp
x 	= -0x8
y 	= -0x10

	ENTRY(nextafter)
	save	%sp,-128,%sp
	PIC_SETUP(l7)
	std	%i0,[%fp+x]
	or	%g0,%i0,%o0		! save original arguments
	or	%g0,%i1,%o1
	std	%i2,[%fp+y]
	or	%g0,%i2,%o2
	or	%g0,%i3,%o3
	ldd	[%fp+x],%f2		! x
	ldd	[%fp+y],%f0		! y
	fcmpd	%f2,%f0			! x:y
	PIC_SET(l7,.Lconstant,l0)
	sethi	%hi(0x80000000),%l1
	andn	%i0,%l1,%l4
	fbe	9f			! next_return
	nop
	fbu,a	9f			! next_return
	fmuld	%f2,%f0,%f0		! + -> * for Cheetah
	orcc	%i1,%l4,%g0		! see if x is zero
	bne	1f
	tst	%i0
    ! x is zero, return sign(y)*min
	and	%i2,%l1,%i0
	ba	4f			! next_final
	mov	1,%i1
1:	bge	2f
	nop
    ! x is negative
	fbl	1f			! next_subulp
	nop
	fbg	3f			! next_addulp
	nop
2:
	fbl	3f			! next_addulp
	nop
1:					! next_subulp
	subcc	%i1,1,%i1
	ba	4f			! next_final
	subx	%i0,0,%i0
3:					! next_addulp
	addcc	%i1,1,%i1
	addx	%i0,0,%i0
4:					! next_final
	sethi	%hi(0x7ff00000),%l3
	std	%i0,[%fp+x]
	andcc	%i0,%l3,%i2
	be,a	1f			! xflow
	ldd	[%l0+tiny],%f2
	cmp	%i2,%l3
	bne,a	9f			! next_return
	ldd	[%fp+x],%f0
	call	NAME(_SVID_libm_err)	! overflow
	or	%g0,46,%o4
	ba	9f
	nop
1:					! xflow
	fmuld	%f2,%f2,%f2
	ldd	[%fp+x],%f0
9:					! next_return
	ret
	restore

	SET_SIZE(nextafter)
