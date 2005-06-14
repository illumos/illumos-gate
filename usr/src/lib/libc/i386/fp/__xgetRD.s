	.ident	"%W%	%E% SMI"

/ Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
/ Use is subject to license terms.
/
/ CDDL HEADER START
/
/ The contents of this file are subject to the terms of the
/ Common Development and Distribution License, Version 1.0 only
/ (the "License").  You may not use this file except in compliance
/ with the License.
/
/ You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
/ or http://www.opensolaris.org/os/licensing.
/ See the License for the specific language governing permissions
/ and limitations under the License.
/
/ When distributing Covered Code, include this CDDL HEADER in each
/ file and include the License file at usr/src/OPENSOLARIS.LICENSE.
/ If applicable, add the following below this CDDL HEADER, with the
/ fields enclosed by brackets "[]" replaced with your own identifying
/ information: Portions Copyright [yyyy] [name of copyright owner]
/
/ CDDL HEADER END
/
/ 00 - Round to nearest or even
/ 01 - Round down
/ 10 - Round up
/ 11 - Chop
	.type	__xgetRD,@function
	.text
	.globl	__xgetRD
	.align	4
__xgetRD:
	pushl	%ebp
	movl	%esp,%ebp
	subl	$4,%esp
	fstcw	-4(%ebp)
	movw	-4(%ebp),%ax
	shrw	$10,%ax
	andl	$0x3,%eax
	leave
	ret
	.align	4
	.size	__xgetRD,.-__xgetRD
