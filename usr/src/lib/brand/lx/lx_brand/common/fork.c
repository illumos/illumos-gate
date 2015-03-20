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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Joyent, Inc.  All rights reserved.
 */

#include <errno.h>
#include <unistd.h>
#include <sys/lx_misc.h>
#include <sys/lx_syscall.h>

/*
 * fork() and vfork()
 *
 * These cannot be pass thru system calls because we need libc to do its own
 * initialization or else bad things will happen (i.e. ending up with a bad
 * schedctl page).  On Linux, there is no such thing as forkall(), so we use
 * fork1() here.
 *
 * For vfork(), we have a serious problem because the child is not allowed to
 * return from the current frame because it will corrupt the parent's stack.
 * Since the semantics of vfork() are rather ill-defined (other than "it's
 * faster than fork"), we should theoretically be safe by falling back to
 * fork1().
 */
static long
lx_fork_common(boolean_t is_vfork)
{
	int ret;
	int ptopt = is_vfork ? LX_PTRACE_O_TRACEVFORK : LX_PTRACE_O_TRACEFORK;

	/*
	 * Inform the in-kernel ptrace(2) subsystem that we are about to
	 * emulate fork(2).
	 */
	lx_ptrace_clone_begin(ptopt, B_FALSE);

	/*
	 * Suspend signal delivery, run the stack management prefork handler
	 * and perform the fork operation.
	 */
	_sigoff();
	lx_stack_prefork();
	ret = fork1();
	lx_stack_postfork();

	switch (ret) {
	case -1:
		_sigon();
		return (-errno);

	case 0:
		/*
		 * Returning in the new child.  We must free the stacks and
		 * thread-specific data objects for the threads we did not
		 * duplicate; i.e. every other thread.
		 */
		lx_free_other_stacks();

		lx_ptrace_stop_if_option(ptopt, B_TRUE, 0, NULL);

		/*
		 * Re-enable signal delivery in the child and return to the
		 * new process.
		 */
		_sigon();
		return (0);

	default:
		lx_ptrace_stop_if_option(ptopt, B_FALSE, (ulong_t)ret, NULL);

		/*
		 * Re-enable signal delivery in the parent and return from
		 * the emulated system call.
		 */
		_sigon();
		return (ret);
	}
}

long
lx_fork(void)
{
	return (lx_fork_common(B_FALSE));
}

long
lx_vfork(void)
{
	return (lx_fork_common(B_TRUE));
}
