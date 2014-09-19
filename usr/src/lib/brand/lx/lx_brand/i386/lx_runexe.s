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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <sys/asm_linkage.h>

#if defined(lint)

/*ARGSUSED*/
void
lx_runexe(void *argv, void *entry)
{
}

#else	/* lint */

	/*
	 * Set our stack pointer, clear the general registers,
	 * and jump to the brand linker's entry point.
	 */
	ENTRY_NP(lx_runexe)
	movl	4(%esp), %eax		/ %eax = &argv[0]
	movl	8(%esp), %ebx		/ Brand linker's entry point in %ebx
	subl	$4, %eax		/ Top of stack - must point at argc
	movl	%eax, %esp		/ Set %esp to what linkers expect

	movl	$0, %eax
	movl	$0, %ecx
	movl	$0, %edx
	movl	$0, %esi
	movl	$0, %edi		
	movl	$0, %ebp

	jmp	*%ebx			/ And away we go...
	SET_SIZE(lx_runexe)

#endif	/* lint */
