/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>

/*
 * Kernel function call invocation
 */

#if defined(__lint)
/*ARGSUSED*/
uintptr_t
kaif_invoke(uintptr_t funcva, uint_t argc, const uintptr_t argv[])
{
	return (0);
}
#else

	ENTRY_NP(kaif_invoke)

	pushl	%ebp
	movl	%esp, %ebp
	pushl	%edi

	movl	0xc(%ebp), %ecx		/* argc */
	movl	0x10(%ebp), %edi	/* argv */

	/* push the contents of argv onto the stack */
1:	cmpl	$0, %ecx
	je	2f
	dec	%ecx
	pushl	(%edi, %ecx, 4)
	jmp	1b

	/* call the function */
2:	movl	0x8(%ebp), %eax
	call	*%eax

	/* pop the arguments */
	movl	0xc(%ebp), %ecx
	sall	$2, %ecx
	addl	%ecx, %esp

	popl	%edi
	leave
	ret

	SET_SIZE(kaif_invoke)

#endif
