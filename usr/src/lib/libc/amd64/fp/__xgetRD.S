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

	.file	"__xgetRD.s"

#include <SYS.h>

/ 00 - Round to nearest or even
/ 01 - Round down
/ 10 - Round up
/ 11 - Chop

	ENTRY(__xgetRD)
	subq	$8,%rsp
	fstcw	(%rsp)
	movw	(%rsp),%ax
	shrw	$10,%ax
	andq	$0x3,%rax
	addq	$8,%rsp
	ret
	SET_SIZE(__xgetRD)
