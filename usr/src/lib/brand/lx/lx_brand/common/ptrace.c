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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Joyent, Inc.  All rights reserved.
 */

#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/lx_misc.h>
#include <sys/lx_debug.h>
#include <sys/lx_syscall.h>
#include <sys/lx_signal.h>
#include <sys/lx_thread.h>
#include <sys/lwp.h>
#include <unistd.h>
#include <fcntl.h>
#include <procfs.h>
#include <sys/frame.h>
#include <strings.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/auxv.h>
#include <thread.h>
#include <pthread.h>
#include <synch.h>
#include <elf.h>
#include <ieeefp.h>
#include <assert.h>
#include <libintl.h>
#include <lx_syscall.h>

/*
 * Much of the Linux ptrace(2) emulation is performed in the kernel, and there
 * is a block comment in "lx_ptrace.c" that describes the facility in some
 * detail.
 */


void
lx_ptrace_stop_if_option(int option, boolean_t child, ulong_t msg,
    ucontext_t *ucp)
{
	/*
	 * We call into the kernel to see if we need to stop for specific
	 * ptrace(2) events.
	 */
	lx_debug("lx_ptrace_stop_if_option(%d, %s, %lu, %p)", option,
	    child ? "TRUE [child]" : "FALSE [parent]", msg, ucp);
	if (ucp == NULL) {
		ucp = (ucontext_t *)lx_find_brand_uc();
		lx_debug("\tucp = %p", ucp);
	}
	if (syscall(SYS_brand, B_PTRACE_STOP_FOR_OPT, option, child, msg,
	    ucp) != 0) {
		if (errno != ESRCH) {
			/*
			 * This should _only_ fail if we are not traced, or do
			 * not have this option set.
			 */
			lx_err_fatal("B_PTRACE_STOP_FOR_OPT failed: %s",
			    strerror(errno));
		}
	}
}

/*
 * Signal to the in-kernel ptrace(2) subsystem that the next native fork() or
 * thr_create() is part of an emulated fork(2) or clone(2).  If PTRACE_CLONE
 * was passed to clone(2), inherit_flag should be B_TRUE.
 */
void
lx_ptrace_clone_begin(int option, boolean_t inherit_flag, int flags)
{
	lx_debug("lx_ptrace_clone_begin(%d, %sPTRACE_CLONE)", option,
	    inherit_flag ? "" : "!");
	if (syscall(SYS_brand, B_PTRACE_CLONE_BEGIN, option,
	    inherit_flag, flags) != 0) {
		lx_err_fatal("B_PTRACE_CLONE_BEGIN failed: %s",
		    strerror(errno));
	}
}
