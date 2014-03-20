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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>

#if defined(lint)

void
_start(void)
{
}

#else	/* lint */

	/*
	 * C language startup routine for the lx brand shared library.
	 */
	ENTRY_NP(_start)
	pushl	$0			/ Build a stack frame. retpc = NULL
	pushl	$0			/ fp = NULL
	movl	%esp, %ebp		/ first stack frame

	/*
	 * Calculate the location of the envp array by adding the size of
	 * the argv array to the start of the argv array.
	 */
	movl	8(%ebp), %eax		/ argc in %eax
	leal	16(%ebp,%eax,4), %edx	/ envp in %edx
	andl	$-16, %esp
	pushl	%edx			/ push envp
	leal	12(%ebp),%edx		/ compute &argv[0]
	pushl	%edx			/ push argv
	pushl	%eax			/ push argc
	call	lx_init
	/*
	 * lx_init will never return.
	 */
	SET_SIZE(_start)

#endif	/* lint */
