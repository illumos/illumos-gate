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

        .file "nextafter.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(nextafter,function)
	.weak _nextafter
	.type _nextafter,@function
_nextafter	= __nextafter
#include "libm_protos.h"

	.data
	.align	8
Fmin:	.long	0x1,0x0
ftmp:	.long	0,0		/// WILL WRITE INTO


	ENTRY(nextafter)
	pushl	%ebp
	movl	%esp,%ebp
	fldl	16(%ebp)	/ y
	subl	$8,%esp
	fldl	8(%ebp)		/ load x
	fucom			/ x : y
	fstsw	%ax
	sahf
	jp	.NaN
	je	.equal
	fstp	%st(1)		/ x
	ja	.bigger
	/ x < y
	ftst
	movl	$1,%ecx		/// Fmin
	movl	%ecx,-8(%ebp)
	movl	$0,%ecx		/// Fmin+4
	movl	%ecx,-4(%ebp)
	fnstsw	%ax
	sahf
	je	.final
	ja	.addulp
	jb	.subulp
.bigger:
	/ x > y
	ftst
	movl	$1,%ecx		/// Fmin
	movl	%ecx,-8(%ebp)
	movl	$0,%ecx		/// Fmin+4
	xorl	$0x80000000,%ecx
	movl	%ecx,-4(%ebp)
	fnstsw	%ax
	sahf
	je	.final
	jb	.addulp
.subulp:
	movl	8(%ebp),%eax	/ low x
	movl	12(%ebp),%ecx	/ high x
	subl	$1,%eax		/ low x - ulp
	movl	%eax,-8(%ebp)
	sbbl	$0x0,%ecx
	movl	%ecx,-4(%ebp)
	jmp	.final
.addulp:
	movl	8(%ebp),%eax	/ low x
	movl	12(%ebp),%ecx	/ high x
	addl	$1,%eax		/ low x + ulp
	movl	%eax,-8(%ebp)
	adcl	$0x0,%ecx
	movl	%ecx,-4(%ebp)

.final:
	fstp	%st(0)
	fldl	-8(%ebp)
	andl	$0x7ff00000,%ecx
	jz	.underflow
	cmpl	$0x7ff00000,%ecx
	je	.overflow
	jmp	.return
.overflow:
	PIC_SETUP(1)
	pushl	$46
	fstp	%st(0)		/ stack empty
	pushl	-4(%ebp)
	pushl	-8(%ebp)
	pushl	-4(%ebp)
	pushl	-8(%ebp)
	call	PIC_F(_SVID_libm_err)
	addl	$20,%esp
	PIC_WRAPUP
	jmp	.return
.underflow:
	PIC_SETUP(2)
	fldl	PIC_L(Fmin)
	fmul	%st(0),%st
	fstpl	PIC_L(ftmp)	/ create underflow signal
	PIC_WRAPUP
	jmp	.return
.equal:
	fstp	%st(0)		/ C99 says to return y when x == y
	jmp	.return
.NaN:
	faddp	%st,%st(1)	/ x+y,x
.return:
	fwait
	leave
	ret
	.align	4
	SET_SIZE(nextafter)
