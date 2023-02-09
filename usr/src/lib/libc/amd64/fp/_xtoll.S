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

	.file	"_xtoll.s"

#include <SYS.h>

	.set	cw,0
	.set	cw_old,2
	.set	two_words,4

/* This function truncates the top of the 387 stack into a signed long. */

	ENTRY(__xtol)	/* 387-stack to signed long */
	subq	$8,%rsp
	fstcw	cw_old(%rsp)
	movw	cw_old(%rsp),%ax
	movw	%ax,%cx
	andw	$0x0c00,%cx		/* save RC */
	orw	$0x0c00,%ax
	movw	%ax,cw(%rsp)
	fldcw	cw(%rsp)
	fistpl	two_words(%rsp)
					/* fwait implied here */
	fstcw	cw(%rsp)		/* fetch CW in case masks changed */
	movw	cw(%rsp),%ax
	andw	$0xf3ff,%ax
	orw	%cx,%ax			/* restore RC */
	movw	%ax,cw(%rsp)
	fldcw	cw(%rsp)
	movl	two_words(%rsp),%eax
	addq	$8,%rsp
	ret
	SET_SIZE(__xtol)

/* This function truncates the top of the 387 stack into a signed long long. */

	ENTRY(__xtoll)	/* 387-stack to signed long long */
	subq	$16,%rsp
	fstcw	cw_old(%rsp)
	movw	cw_old(%rsp),%ax
	movw	%ax,%cx
	andw	$0x0c00,%cx		/* save RC */
	orw	$0x0c00,%ax
	movw	%ax,cw(%rsp)
	fldcw	cw(%rsp)
	fistpll	8(%rsp)
					/* fwait implied here */
	fstcw	cw(%rsp)		/* fetch CW in case masks changed */
	movw	cw(%rsp),%ax
	andw	$0xf3ff,%ax
	orw	%cx,%ax			/* restore RC */
	movw	%ax,cw(%rsp)
	fldcw	cw(%rsp)
	movq	8(%rsp),%rax
	addq	$16,%rsp
	ret
	SET_SIZE(__xtoll)

/* This function truncates the top of the 387 stack into a unsigned long. */

	.align	16
two_to_31: .4byte	0x4f000000

	ENTRY(__xtoul)	/* 387-stack to unsigned */
	subq	$8,%rsp
	fstcw	cw_old(%rsp)
	movw	cw_old(%rsp),%ax
	movw	%ax,%cx
	andw	$0x0c00,%cx		/* save RC */
	orw	$0x0c00,%ax
	movw	%ax,cw(%rsp)
	fldcw	cw(%rsp)
	flds	two_to_31(%rip)
	fcomip	%st(1),%st		/* compare 2**31 to x */
	jp	.donotsub		/* jump if x is NaN */
	ja	.donotsub		/* jump if 2**31 > x */
	fsubs	two_to_31(%rip)	/* subtract 2**31 */
.donotsub:
	fistpl	two_words(%rsp)
	fwait				/* in case fistpl causes exception */
	movl	two_words(%rsp),%eax
	jp	.donotadd		/* flags did not change */
	ja	.donotadd		/* flags did not change */
	addl	$-2147483648,%eax	/* add back 2**31 */
.donotadd:
	fstcw	cw(%rsp)		/* fetch CW in case masks changed */
	movw	cw(%rsp),%dx
	andw	$0xf3ff,%dx
	orw	%cx,%dx			/* restore RC */
	movw	%dx,cw(%rsp)
	fldcw	cw(%rsp)
	addq	$8,%rsp
	ret
	SET_SIZE(__xtoul)
