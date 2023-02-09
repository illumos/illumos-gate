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

        .file "acos.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(acos,function)
#include "libm_protos.h"

	ENTRY(acos)
	fldl	4(%esp)			/ push x
	fld1				/ push 1
	fld	%st(1)			/ x , 1 , x
	fabs				/ |x| , 1 , x
	fucomp
	fstsw   %ax
	sahf
	ja	.ERR
	fadd	%st(1),%st		/ 1+x,x
	fldz
	fucomp	
	fstsw	%ax
	sahf
	jp	.L1
	jne	.L1
	/ x is -1 
	fstp	%st(0)			/ -1
	fstp	%st(0)			/ empty NPX stack
	fldpi
	ret
.L1:
	fxch	%st(1)			/ x,1+x
	fld1				/ 1,x,1+x
	fsubp	%st,%st(1)		/ 1-x,1+x
	fdivp	%st,%st(1)		/ (1-x)/(1+x)
	fsqrt
	fld1				/ 1,sqrt((1-x)/(1+x))
	fpatan
	fadd	%st(0),%st
	ret

.ERR:
	/ |x| > 1
	pushl   %ebp
	movl    %esp,%ebp
	PIC_SETUP(1)
	fstp	%st(0)			/ x
	fstp	%st(0)			/ empty NPX stack
	pushl   $1
	pushl   12(%ebp)                / high x
	pushl   8(%ebp)                 / low x
	pushl   12(%ebp)                / high x
	pushl   8(%ebp)                 / low x
	call    PIC_F(_SVID_libm_err)	/ report SVID result/error
	addl    $20,%esp
	PIC_WRAPUP
	leave
	ret
	.align	4
	SET_SIZE(acos)
