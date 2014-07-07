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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * wait() family of functions.
 *
 * The first minor difference between the Linux and Solaris family of wait()
 * calls is that the values for WNOHANG and WUNTRACED are different. Thankfully,
 * the exit status values are identical between the two implementations.
 *
 * Things get very different and very complicated when we introduce the Linux
 * threading model.  Under linux, both threads and child processes are
 * represented as processes.  However, the behavior of wait() with respect to
 * each child varies according to the flags given to clone()
 *
 *	SIGCHLD 	The SIGCHLD signal should be sent on termination
 *	CLONE_THREAD	The child shares the same thread group as the parent
 *	CLONE_DETACHED	The parent receives no notification when the child exits
 *
 * The following flags control the Linux behavior w.r.t. the above attributes:
 *
 * 	__WALL		Wait on all children, regardless of type
 * 	__WCLONE	Wait only on non-SIGCHLD children
 * 	__WNOTHREAD	Don't wait on children of other threads in this group
 *
 * The following chart shows whether wait() returns when the child exits:
 *
 *                           default    __WCLONE    __WALL
 *           no SIGCHLD		-	    X	      X
 *              SIGCHLD		X	    -	      X
 *
 * The following chart shows whether wait() returns when the grandchild exits:
 *
 *                           default   __WNOTHREAD
 * 	no CLONE_THREAD		-	    -
 *         CLONE_THREAD		X	    -
 *
 * The CLONE_DETACHED flag is universal - when the child exits, no state is
 * stored and wait() has no effect.
 *
 * XXX Support the above combination of options, or some reasonable subset that
 *     covers at least fork() and pthread_create().
 */

#include <errno.h>
#include <sys/wait.h>
#include <sys/lx_types.h>
#include <sys/lx_signal.h>
#include <sys/lx_misc.h>
#include <sys/lx_syscall.h>
#include <sys/syscall.h>
#include <sys/times.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>
#include <lx_syscall.h>

/*
 * Convert between Linux options and Solaris options, returning -1 if any
 * invalid flags are found.
 */
#define	LX_WNOHANG	0x00000001
#define	LX_WUNTRACED	0x00000002
#define	LX_WEXITED	0x00000004
#define	LX_WCONTINUED	0x00000008
#define	LX_WNOWAIT	0x01000000

#define	LX_WNOTHREAD	0x20000000
#define	LX_WALL		0x40000000
#define	LX_WCLONE	0x80000000

#define	LX_P_ALL	0x0
#define	LX_P_PID	0x1
#define	LX_P_GID	0x2

static int
ltos_options(uintptr_t options)
{
	int newoptions = 0;
	int rval;
	lx_waitid_args_t extra;

	if (((options) & ~(LX_WNOHANG | LX_WUNTRACED | LX_WEXITED |
	    LX_WCONTINUED | LX_WNOWAIT | LX_WNOTHREAD | LX_WALL |
	    LX_WCLONE)) != 0) {
		return (-1);
	}
	/*
	 * We use the B_STORE_ARGS command to store any of LX_WNOTHREAD,
	 * LX_WALL, and LX_WCLONE that have been set as options on this waitid
	 * call. These flags are stored as part of the lwp_brand_data, so that
	 * when there is a later syscall to waitid, the brand code there can
	 * detect that we added extra flags here and use them as appropriate.
	 * We pass them in here rather than the normal channel for flags to
	 * prevent polluting the namespace.
	 */
	extra.waitid_flags = options & (LX_WNOTHREAD | LX_WALL | LX_WCLONE);
	rval = syscall(SYS_brand, B_STORE_ARGS, &extra,
	    sizeof (lx_waitid_args_t), NULL, NULL, NULL, NULL);
	if (rval < 0)
		return (rval);

	if (options & LX_WNOHANG)
		newoptions |= WNOHANG;
	if (options & LX_WUNTRACED)
		newoptions |= WUNTRACED;
	if (options & LX_WEXITED)
		newoptions |= WEXITED;
	if (options & LX_WCONTINUED)
		newoptions |= WCONTINUED;
	if (options & LX_WNOWAIT)
		newoptions |= WNOWAIT;

	/* The trapped option is implicit on Linux */
	newoptions |= WTRAPPED;

	return (newoptions);
}

static int
lx_wstat(int code, int status)
{
	int stat = 0;

	switch (code) {
	case CLD_EXITED:
		stat = status << 8;
		break;
	case CLD_DUMPED:
		stat = stol_signo[status];
		assert(stat != -1);
		stat |= WCOREFLG;
		break;
	case CLD_KILLED:
		stat = stol_signo[status];
		assert(stat != -1);
		break;
	case CLD_TRAPPED:
	case CLD_STOPPED:
		stat = stol_signo[status];
		assert(stat != -1);
		stat <<= 8;
		stat |= WSTOPFLG;
		break;
	case CLD_CONTINUED:
		stat = WCONTFLG;
		break;
	}

	return (stat);
}

/* wrapper to make solaris waitid work properly with ptrace */
static int
lx_waitid_helper(idtype_t idtype, id_t id, siginfo_t *info, int options)
{
	do {
		/*
		 * It's possible that we return EINVAL here if the idtype is
		 * P_PID or P_PGID and id is out of bounds for a valid pid or
		 * pgid, but Linux expects to see ECHILD. No good way occurs to
		 * handle this so we'll punt for now.
		 */
		if (waitid(idtype, id, info, options) < 0)
			return (-errno);

		/*
		 * If the WNOHANG flag was specified and no child was found
		 * return 0.
		 */
		if ((options & WNOHANG) && info->si_pid == 0)
			return (0);

		/*
		 * It's possible that we may have a spurious return for one of
		 * the child processes created by the ptrace subsystem. If
		 * that's the case, we simply try again.
		 */
	} while (lx_ptrace_wait(info) == -1);
	return (0);
}

int
lx_wait4(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4)
{
	siginfo_t info = { 0 };
	struct rusage ru = { 0 };
	idtype_t idtype;
	id_t id;
	int options, status = 0;
	pid_t pid = (pid_t)p1;
	int rval;

	if ((options = ltos_options(p3)) == -1)
		return (-EINVAL);

	/*
	 * While not listed as a valid return code, Linux's wait4(2) does,
	 * in fact, get an EFAULT if either the status pointer or rusage
	 * pointer is invalid. Since a failed waitpid should leave child
	 * process in a state where a future wait4(2) will succeed, we
	 * check them by copying out the values their buffers originally
	 * contained.  (We need to do this as a failed system call should
	 * never affect the contents of a passed buffer.)
	 *
	 * This will fail if the buffers in question are write-only.
	 */
	if ((void *)p2 != NULL &&
	    ((uucopy((void *)p2, &status, sizeof (status)) != 0) ||
	    (uucopy(&status, (void *)p2, sizeof (status)) != 0)))
		return (-EFAULT);

	if ((void *)p4 != NULL) {
		if ((uucopy((void *)p4, &ru, sizeof (ru)) != 0) ||
		    (uucopy(&ru, (void *)p4, sizeof (ru)) != 0))
			return (-EFAULT);
	}

	if (pid < -1) {
		idtype = P_PGID;
		id = -pid;
	} else if (pid == -1) {
		idtype = P_ALL;
		id = 0;
	} else if (pid == 0) {
		idtype = P_PGID;
		id = getpgrp();
	} else {
		idtype = P_PID;
		id = pid;
	}

	options |= WEXITED | WTRAPPED;

	if ((rval = lx_waitid_helper(idtype, id, &info, options)) < 0)
		return (rval);
	/*
	 * If the WNOHANG flag was specified and no child was found return 0.
	 */
	if ((options & WNOHANG) && info.si_pid == 0)
		return (0);

	status = lx_wstat(info.si_code, info.si_status);

	/*
	 * Unfortunately if this attempt to copy out either the status or the
	 * rusage fails, the process will be in an inconsistent state as
	 * subsequent calls to wait for the same child will fail where they
	 * should succeed on a Linux system. This, however, is rather
	 * unlikely since we tested the validity of both above.
	 */
	if (p2 != NULL && uucopy(&status, (void *)p2, sizeof (status)) != 0)
		return (-EFAULT);

	if (p4 != NULL && (rval = lx_getrusage(LX_RUSAGE_CHILDREN, p4)) != 0)
		return (rval);

	return (info.si_pid);
}

int
lx_waitpid(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	return (lx_wait4(p1, p2, p3, NULL));
}

int
lx_waitid(uintptr_t idtype, uintptr_t id, uintptr_t infop, uintptr_t opt)
{
	int rval, options;
	siginfo_t s_info = {0};
	if ((options = ltos_options(opt)) == -1)
		return (-1);
	switch (idtype) {
	case LX_P_ALL:
		idtype = P_ALL;
		break;
	case LX_P_PID:
		idtype = P_PID;
		break;
	case LX_P_GID:
		idtype = P_GID;
		break;
	default:
		return (-EINVAL);
	}
	if ((rval = lx_waitid_helper(idtype, (id_t)id, &s_info, options)) < 0)
		return (rval);

	/* If the WNOHANG flag was specified and no child was found return 0. */
	if ((options & WNOHANG) && s_info.si_pid == 0)
		return (0);

	return (stol_siginfo(&s_info, (lx_siginfo_t *)infop));
}
