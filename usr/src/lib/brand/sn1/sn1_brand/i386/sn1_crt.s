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

#include <sys/asm_linkage.h>

#if defined(lint)

void
_start(void)
{
}

#else	/* lint */
	/*
	 * Initial entry point for the brand emulation library.
	 *
	 * This platform specific assembly entry point exists just to invoke
	 * the common brand library startup routine.  That routine expects to
	 * be called with the following arguments:
	 *	sn1_init(int argc, char *argv[], char *envp[])
	 *
	 * There are no arguments explicitly passed to this entry point,
	 * routine, but we do know how our initial stack has been setup by
	 * the kernel.  The stack format is documented in:
	 *	usr/src/cmd/sgs/rtld/i386/boot.s
	 *
	 * So this routine will troll through the stack to setup the argument
	 * values for the common brand library startup routine and then invoke
	 * it.  This routine is modeled after the default crt1.s`_start()
	 * routines.
	 */
	ENTRY_NP(_start)

	/* Make stack traces look pretty, build a fake stack frame. */
	pushl	$0			/ retpc = NULL
	pushl	$0			/ fp = NULL
	movl	%esp, %ebp		/ first stack frame

	/*
	 * Calculate the location of the envp array by adding the size of
	 * the argv array to the start of the argv array.
	 */
	movl	8(%ebp), %eax		/ argc in %eax
	leal	12(%ebp), %ebx		/ &argv[0] in %ebx
	leal	16(%ebp,%eax,4), %ecx	/ envp in %ecx

	pushl	%ecx			/ push envp (3rd param)
	pushl	%ebx			/ push argv (2nd param)
	pushl	%eax			/ push argc (1st param)
	call	sn1_init

	/*NOTREACHED*/
	SET_SIZE(_start)
#endif	/* lint */
