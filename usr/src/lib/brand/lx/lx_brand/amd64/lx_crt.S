/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <sys/asm_linkage.h>

#if defined(lint)

void
_start(void)
{
}

#else	/* lint */

	/*
	 * C language startup routine for the lx brand shared library.
	 *
	 * That routine expects to be called with the following arguments:
	 *	brand_init(int argc, char *argv[], char *envp[])
	 *
	 * There are no arguments explicitly passed to this entry point,
	 * routine, but we do know how our initial stack has been setup by
	 * the kernel.  The stack format is documented in:
	 * 	usr/src/cmd/sgs/rtld/amd64/boot.s
	 *
	 * So this routine will troll through the stack to setup the argument
	 * values for the common brand library startup routine and then invoke
	 * it.  This routine is modeled after the default crt1.s`_start()
	 * routines.
	 */
	ENTRY_NP(_start)
	pushq	$0			/ Build a stack frame. retpc = NULL
	pushq	$0			/ fp = NULL
	movq	%rsp, %rbp		/ first stack frame

	/*
	 * Calculate the location of the envp array by adding the size of
	 * the argv array to the start of the argv array.
	 */
	movq	16(%rbp), %rdi		/ argc in %rdi (1st param)
	leaq	24(%rbp), %rsi		/ &argv[0] in %rsi (2nd param)
	leaq	32(%rbp,%rdi,8), %rdx	/ envp in %rdx (3rd param)
	call	lx_init

	/* lx_init will never return. */
	/*NOTREACHED*/
	SET_SIZE(_start)
#endif	/* lint */
