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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * exit routine from linker/loader to kernel
 */

#include <sys/asm_linkage.h>
#include <sys/reboot.h>
#include <sys/trap.h>

/*
 *  exitto is called from main() and does 1 things
 *	It then jumps directly to the just-loaded standalone.
 *	There is NO RETURN from exitto(). ????
 */

#if defined(lint)

/* ARGSUSED */
void
exitto(caddr_t entrypoint)
{}

#else	/* lint */

	.data
save_esp2:
        .long   0

	ENTRY(exitto)
	push	%ebp			/ save stack
	mov	%esp,%ebp
	pushal				/ protect secondary boot

	movl	%esp, %eax
	movl	%eax, save_esp2

	/holds address of array of pointers to functions
	movl	$romp, %eax
	movl    (%eax), %ecx

	/holds address of bootops structure
	movl	$ops, %eax
	movl    (%eax), %ebx

	movl	8(%ebp), %eax		
	call   *%eax

	movl	save_esp2, %eax
	movl	%eax, %esp

	popal
	pop	%ebp			/ restore frame pointer

	ret
	SET_SIZE(exitto)
#endif
