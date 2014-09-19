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
	movq	%rdi, %rax		/ %rax = &argv[0]
	movq	%rsi, %rbx		/ Brand linker's entry point in %rbx
	subq	$8, %rax		/ Top of stack - must point at argc
	movq	%rax, %rsp		/ Set %rsp to what linkers expect

	movq	$0, %rdx

	jmp	*%rbx			/ And away we go...

	/* target will never return. */
	SET_SIZE(lx_runexe)
#endif	/* lint */
