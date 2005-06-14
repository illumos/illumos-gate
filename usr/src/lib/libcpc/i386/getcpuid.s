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

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>

#if defined(lint)

#include <sys/types.h>
#include <sys/inttypes.h>

#include "getcpuid.h"

/*ARGSUSED*/
uint32_t
cpc_getcpuid(uint32_t eax, uint32_t *ebxp, uint32_t *ecxp, uint32_t *edxp)
{ return (0); }

#else	/* lint */

	ENTRY(cpc_getcpuid)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	movl	8(%ebp), %eax
	cpuid
	pushl	%eax
	movl	0xc(%ebp), %eax
	movl	%ebx, (%eax)
	movl	0x10(%ebp), %eax
	movl	%ecx, (%eax)
	movl	0x14(%ebp), %eax
	movl	%edx, (%eax)
	popl	%eax
	popl	%ebx
	popl	%ebp
	ret
	SET_SIZE(cpc_getcpuid)

#endif	/* lint */
