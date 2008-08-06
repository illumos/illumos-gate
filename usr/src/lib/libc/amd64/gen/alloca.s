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

	.file	"alloca.s"

#include "SYS.h"

	ENTRY(__builtin_alloca)
	popq	%rcx			/* grab our return address */
	addq	$15, %rdi		/* round size up to multiple of 16 */
	andq	$0xfffffffffffffff0, %rdi
	subq	%rdi, %rsp		/* allocate requested space on stack */
	movq	%rsp, %rax		/* pointer to new memory block */
	jmp	*%rcx			/* return */
	SET_SIZE(__builtin_alloca)
