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

	.file	"_lwp_mutex_unlock.s"

#include "SYS.h"
#include <../assym.h>

	ENTRY(_lwp_mutex_unlock)
	movl	4(%esp), %eax
	addl	$MUTEX_LOCK_WORD, %eax
	xorl	%ecx, %ecx
	xchgl	(%eax), %ecx	/ clear lock and get old lock into %ecx
	andl	$WAITER_MASK, %ecx / was anyone waiting on it?
	je	1f
	movl	0(%esp), %ecx	/ prepare to call lwp_mutex_wakeup()
	movl	4(%esp), %edx
	movl	$0, 4(%esp)
	movl	%edx, 0(%esp)
	pushl	%ecx
	SYSTRAP_RVAL1(lwp_mutex_wakeup)	/ lwp_mutex_wakeup(mp, 0)
	popl	%ecx		/ reconstruct the stack frame
	movl	0(%esp), %edx
	movl	%edx, 4(%esp)
	movl	%ecx, 0(%esp)
	SYSLWPERR
	RET
1:
	RETC
	SET_SIZE(_lwp_mutex_unlock)
