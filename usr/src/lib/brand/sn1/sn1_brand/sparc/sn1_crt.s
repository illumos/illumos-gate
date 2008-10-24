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
#include <sys/link.h>

#if defined(lint)

void
_start(void)
{
}

#else	/* lint */
	.section	".text"
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
	 *	usr/src/cmd/sgs/rtld/sparc/boot.s
	 *	usr/src/cmd/sgs/rtld/sparcv9/boot.s
	 *
	 * So this routine will troll through the stack to setup the argument
	 * values for the common brand library startup routine and then invoke
	 * it.
	 */
	ENTRY_NP(_start)
#if defined (__sparcv9)
	save	%sp, -SA(MINFRAME + EB_MAX_SIZE64), %sp
#else /* !__sparcv9 */
	save	%sp, -SA(MINFRAME + EB_MAX_SIZE32), %sp
#endif /* !__sparcv9 */

	/* get argc */
	ldn	[%fp + WINDOWSIZE + STACK_BIAS], %o0

	/* get argv */
	add	%fp, + WINDOWSIZE + CPTRSIZE + STACK_BIAS, %o1

	/* get envp */
	add	%o0, 1, %l0		! add 1 to argc for last element of 0
	sll	%l0, CPTRSHIFT, %l0	! multiply argc by pointer size
	add	%o1, %l0, %o2		!  and add to argv to get first env ptr

	call	sn1_init
	nop

	/*NOTREACHED*/
	SET_SIZE(_start)
#endif	/* lint */
