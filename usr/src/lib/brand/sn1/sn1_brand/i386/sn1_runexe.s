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
#include <sn1_misc.h>

#if defined(lint)

/*ARGSUSED*/
void
sn1_runexe(void *argv, ulong_t entry)
{
}

#else	/* lint */
	/*
	 * Prepare to jump to the target program we actually want to run.
	 * If this program is dynamically linked then we'll be jumping to
	 * another copy of the linker.  If it's a statically linked program
	 * we'll be jumping directy to it's main entry point.  In any case,
	 * we need to reset our current state stack and register state to
	 * something similar to the initial process state setup by the kernel
	 * and documented at:
	 *	usr/src/cmd/sgs/rtld/i386/boot.s
	 *	usr/src/cmd/sgs/rtld/sparcv9/boot.s
	 *
	 * Of course this is the same stack format as when this executable
	 * was first started, so here we'll just roll back the stack and
	 * frame pointers to their values when this processes first started
	 * execution.
	 */
	ENTRY_NP(sn1_runexe)

	movl	4(%esp), %eax		/ %eax = &argv[0]
	movl	8(%esp), %ebx		/ Brand app entry point in %ebx
	subl	$4, %eax		/ Top of stack - must point at argc
	movl	%eax, %esp		/ Set %esp to what linkers expect

	/*
	 * We also have to make sure to clear %edx since nornally ld.so.1 will
	 * set that to non-zero if there is an exit function that should be
	 * invoked when the process is terminating.  This isn't actually
	 * necessary if the target program we're jumping to is a dynamically
	 * linked program since in that case we're actually jumping to another
	 * copy of ld.so.1 and it will just reset %edx, but if the target
	 * program we're jumping to is a statically linked binary that uses
	 * the standard sun compiler supplied crt1.o`_start(), it will check
	 * to see if %g1 is set.
	 */
	movl	$0, %edx

	jmp	*%ebx			/ And away we go...
	/*
	 * target will never return.
	 */
	SET_SIZE(sn1_runexe)
#endif	/* lint */
