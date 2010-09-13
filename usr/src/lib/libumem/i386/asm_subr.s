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

#if defined(lint)

void *
getfp(void)
{
	return (NULL);
}

#ifndef UMEM_STANDALONE
void
_breakpoint(void)
{
	return;
}
#endif

#else	/* lint */

#if defined(__amd64)

	ENTRY(getfp)
	movq	%rbp, %rax
	ret
	SET_SIZE(getfp)

#else	/* __i386 */

	ENTRY(getfp)
	movl	%ebp, %eax
	ret
	SET_SIZE(getfp)

#endif

#ifndef UMEM_STANDALONE
	ENTRY(_breakpoint)
	int	$3
	ret
	SET_SIZE(_breakpoint)
#endif

#endif	/* lint */
