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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

        .file "asinf.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(asinf,function)
#include "libm_protos.h"

	ENTRY(asinf)
	flds	4(%esp)			/ push x
	fld1				/ push 1
	fld	%st(1)			/ x , 1 , x
	fabs				/ |x| , 1 , x
	fucomp
	fstsw  %ax
	sahf     
	ja	.ERR
	fadd	%st(1),%st		/ 1+x,x
	fld1				/ 1,1+x,x
	fsub	%st(2),%st		/ 1-x,1+x,x
	fmulp	%st,%st(1)		/ (1-x)*(1+x),x
	fsqrt				/ sqrt((1-x)*(1+x)),x
	fpatan				/ atan(x/sqrt((1-x)*(1+x)))
	ret

.ERR:
	/ |x| > 1
	fstp	%st(0)			/ x
	fstp	%st(0)			/ empty NPX stack
	fldz
	fdiv	%st(0),%st		/ 0/0
	ret
	.align	4
	SET_SIZE(asinf)
