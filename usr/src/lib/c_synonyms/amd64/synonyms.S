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

	.file	"synonyms.s"

#define	SYN(name)				\
	.align	16;				\
	.globl	name;				\
	.globl	_##name;			\
	.type	_##name, @function;		\
_##name:					\
	movq	name@GOTPCREL(%rip), %rax;	\
	jmp	*%rax;				\
	.size	_##name, [. - _##name]

#define	SYN2(name)				\
	.align	16;				\
	.globl	name;				\
	.globl	__##name;			\
	.type	__##name, @function;		\
__##name:					\
	movq	name@GOTPCREL(%rip), %rax;	\
	jmp	*%rax;				\
	.size	__##name, [. - __##name]

#include "synonym_list"
