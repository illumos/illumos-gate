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

	.file	"_xtoull.s"

#include <SYS.h>

	.set	cw,0
	.set	cw_old,2
	.text
	.align	16
two_to_63: .4byte	0x5f000000

	ENTRY(__xtoull)	/* 387-stack to unsigned long long */
	subq	$16,%rsp
	fstcw	cw_old(%rsp)
	movw	cw_old(%rsp),%ax
	movw	%ax,%cx
	andw	$0x0c00,%cx		/* save RC */
	orw	$0x0c00,%ax
	movw	%ax,cw(%rsp)
	fldcw	cw(%rsp)
	flds	two_to_63(%rip)
	fcomip	%st(1),%st		/* compare 2**63 to x */
	jp	.donotsub		/* jump if x is NaN */
	ja	.donotsub		/* jump if 2**63 > x */
	fsubs	two_to_63(%rip)		/* subtract 2**63 */
.donotsub:
	fistpll	8(%rsp)
	fwait				/* in case fistpll causes exception */
	movq	8(%rsp),%rax
	jp	.donotadd
	ja	.donotadd		/* flags did not change */
	movq	$0x8000000000000000,%rcx
	addq	%rcx,%rax		/* add back 2**63 */
.donotadd:
	fstcw	cw(%rsp)		/* fetch CW in case masks changed */
	movw	cw(%rsp),%dx
	andw	$0xf3ff,%dx
	orw	%cx,%dx			/* restore RC */
	movw	%dx,cw(%rsp)
	fldcw	cw(%rsp)
	addq	$16,%rsp
	ret
	SET_SIZE(__xtoull)
