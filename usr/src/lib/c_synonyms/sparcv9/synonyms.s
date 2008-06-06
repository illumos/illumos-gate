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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

	.file	"%M%"

#define	SYN(name)				\
	.align	4;				\
	.global	name;				\
	.global	_/**/name;			\
	.type	_/**/name, #function;		\
_/**/name:					\
	mov	%o7, %g1;			\
	call	name;				\
	mov	%g1, %o7;			\
	.size	_/**/name, (. - _/**/name)

#define	SYN2(name)				\
	.align	4;				\
	.global	name;				\
	.global	__/**/name;			\
	.type	__/**/name, #function;		\
__/**/name:					\
	mov	%o7, %g1;			\
	call	name;				\
	mov	%g1, %o7;			\
	.size	__/**/name, (. - __/**/name)

#include "synonym_list"
