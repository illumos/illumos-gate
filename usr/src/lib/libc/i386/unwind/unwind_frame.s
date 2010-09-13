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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"unwind_frame.s"

#include <SYS.h>

/* Cancellation/thr_exit() stuff */

/*
 * _ex_unwind_local(void)
 *
 * Called only from _t_cancel().
 * Unwind two frames and invoke _t_cancel(fp) again.
 *
 * Before this the call stack is: f4 f3 f2 f1 _t_cancel
 * After this the call stack is:  f4 f3 f2 _t_cancel
 *	(as if "call f1" is replaced by "call _t_cancel(fp)" in f2)
 */

	ENTRY(_ex_unwind_local)
	movl	(%ebp), %edx		/ pop first frame [ back to f1() ]
	movl	(%edx), %ebp		/ pop second frame [ back to f2() ]
	movl	4(%edx), %eax		/ save f2's return pc
	movl	%eax, (%edx)		/ mov it up for one arg
	movl	%edx, %esp		/ stack pointer at ret addr
	movl	%ebp, 4(%esp)
	jmp	_t_cancel
	SET_SIZE(_ex_unwind_local)

/*
 * _ex_clnup_handler(void *arg, void  (*clnup)(void *))
 *
 * Called only from _t_cancel().
 * Unwind one frame, call the cleanup handler with argument arg from the
 * restored frame, then jump to _t_cancel(fp) again from the restored frame.
 */

	ENTRY(_ex_clnup_handler)
	pushl	%ebp			/ save current frame pointer
	pushl	8(%esp)			/ first argument [arg]
	movl	(%ebp), %ebp		/ pop out one frame
	call	*16(%esp)		/ call handler [clnup]
	addl	$4, %esp
	popl	%eax			/ old frame pointer
	lea	4(%eax), %esp		/ stk points to old frame
	movl	%ebp, 4(%esp)		/ _t_cancel() gets frame pointer arg
	jmp	_t_cancel
	SET_SIZE(_ex_clnup_handler)

/*
 * _thrp_unwind(void *arg)
 *
 * Ignore the argument; jump to _t_cancel(fp) with caller's fp
 */
	ENTRY(_thrp_unwind)
	movl	%ebp, 4(%esp)
	jmp	_t_cancel
	SET_SIZE(_thrp_unwind)
