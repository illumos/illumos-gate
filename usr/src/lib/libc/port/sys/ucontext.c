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

#pragma weak getustack = _getustack
#pragma weak setustack = _setustack
#pragma weak _private_setustack = _setustack
#pragma weak __setcontext_syscall = __setcontext

#include "synonyms.h"
#include <ucontext.h>
#include <sys/syscall.h>

/*
 * __getcontext() must be implemented in assembler, as opposed to
 * the other members of the SYS_context family (see __getcontext.s)
 * because we must be careful to get the precise context of the caller.
 */

int
__setcontext(const ucontext_t *ucp)
{
	return (syscall(SYS_context, 1, ucp));
}

int
getustack(stack_t **spp)
{
	return (syscall(SYS_context, 2, spp));
}

int
setustack(stack_t *sp)
{
	return (syscall(SYS_context, 3, sp));
}
