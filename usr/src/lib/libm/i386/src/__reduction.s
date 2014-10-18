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

	.file	"__reduction.s"

/
/    After argument reduction which returns n:
/       n mod 4     sin(x)      cos(x)        tan(x)
/     ----------------------------------------------------------
/          0          S           C             S/C
/          1          C          -S            -C/S
/          2         -S          -C             S/C
/          3         -C           S            -C/S
/     ----------------------------------------------------------

#include "libm.h"
#include "libm_synonyms.h"
#include "libm_protos.h"
#undef fabs

	ENTRY(__reduction)
#ifndef PIC
	movl	12(%esp),%eax		/ load the high part of arg
#else
	movl	16(%esp),%eax		/ load the high part of arg
#endif
	andl	$0x7fffffff,%eax	/ clear sign
	cmpl	$0x3fe921fb,%eax	/ Is |x| < pi/4 (= 0x3fe921fb54...) ?
	jbe	.L0
	cmpl	$0x7ff00000,%eax	/ Is arg a NaN or an Inf ?
	jb	.L1
.L0:
#ifndef PIC
	fldl	8(%esp)			/ push arg
#else
	fldl	12(%esp)		/ push arg
#endif
	fwait
	movl	$0,%eax			/ set n = 0
	ret
.L1:
	pushl	%ebp
	movl	%esp,%ebp
	subl	$16,%esp
	PIC_SETUP(1)
	leal	-16(%ebp),%eax		/ address of y[0]
	pushl	%eax
#ifndef PIC
	pushl	16(%ebp)
	pushl	12(%ebp)
#else
	pushl	20(%ebp)
	pushl	16(%ebp)
#endif
	call	PIC_F(__rem_pio2)	/ call __rem_pio2(x,&y)
	fldl	-8(%ebp)		/ y[1]
	fldl	-16(%ebp)		/ y[0], y[1]
	faddp	%st,%st(1)		/ y[0]+y[1] round-to-extended
	addl	$28,%esp		/ 16+4*3
	andl	$3,%eax
	PIC_WRAPUP
	leave
	ret
	.align	4
	SET_SIZE(__reduction)
