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

/*
 * Copyright 2023 Oxide Computer Company
 */

	.file	"__getcontext.s"

/*
 * __getcontext() must be implemented in assembler, as opposed
 * to the other members of the SYS_context family (see ucontext.c)
 * because we must be careful to get the precise context of the caller.
 */

#include "SYS.h"

	ENTRY(__getcontext)
	popl	%edx
	pushl	$0
	pushl	%edx
	SYSTRAP_RVAL1(context)
	popl	%edx
	movl	%edx, 0(%esp)
	SYSCERROR
	RET
	SET_SIZE(__getcontext)

	ENTRY(__getcontext_extd)
	popl	%edx
	pushl	$4
	pushl	%edx
	SYSTRAP_RVAL1(context)
	popl	%edx
	movl	%edx, 0(%esp)
	SYSCERROR
	RET
	SET_SIZE(__getcontext_extd)
