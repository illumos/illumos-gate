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
 * Copyright 2019 Joyent, Inc.
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

#include <sys/wait.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>
#include <sys/lx_types.h>
#include <sys/lx_misc.h>
#include <lx_signum.h>
#include <lx_errno.h>
#include <lx_syscall.h>

/*
 * From "uts/common/os/exit.c" and "uts/common/syscall/rusagesys.c":
 */
extern int waitid(idtype_t, id_t, k_siginfo_t *, int);
extern int rusagesys(int, void *, void *, void *, void *);

/*
 * Convert between Linux options and Solaris options, returning -1 if any
 * invalid flags are found.
 */
#define	LX_WNOHANG	0x00000001
#define	LX_WUNTRACED	0x00000002
#define	LX_WSTOPPED	LX_WUNTRACED
#define	LX_WEXITED	0x00000004
#define	LX_WCONTINUED	0x00000008
#define	LX_WNOWAIT	0x01000000

#define	LX_WNOTHREAD	0x20000000
#define	LX_WALL		0x40000000
#define	LX_WCLONE	0x80000000

#define	LX_P_ALL	0x0
#define	LX_P_PID	0x1
#define	LX_P_GID	0x2

/*
 * Split the passed waitpid/waitid options into two separate variables:
 * those for the native illumos waitid(2), and the extra Linux-specific
 * options we will handle in our brand-specific code.
 */
static int
ltos_options(uintptr_t options, int *native_options, int *extra_options)
{
	int newoptions = 0;

	if (((options) & ~(LX_WNOHANG | LX_WUNTRACED | LX_WEXITED |
	    LX_WCONTINUED | LX_WNOWAIT | LX_WNOTHREAD | LX_WALL |
	    LX_WCLONE)) != 0) {
		return (-1);
	}

	*extra_options = options & (LX_WNOTHREAD | LX_WALL | LX_WCLONE);

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

	/*
	 * The trapped option is implicit on Linux.
	 */
	newoptions |= WTRAPPED;

	*native_options = newoptions;
	return (0);
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
		stat = lx_stol_signo(status, SIGKILL) | WCOREFLG;
		break;
	case CLD_KILLED:
		stat = lx_stol_signo(status, SIGKILL);
		break;
	case CLD_TRAPPED:
	case CLD_STOPPED:
		stat = (lx_stol_status(status, SIGKILL) << 8) | WSTOPFLG;
		break;
	case CLD_CONTINUED:
		stat = WCONTFLG;
		break;
	}

	return (stat);
}

static int
lx_call_waitid(idtype_t idtype, id_t id, k_siginfo_t *sip, int native_options,
    int extra_options)
{
	lx_lwp_data_t *lwpd = ttolxlwp(curthread);
	int error;

	/*
	 * Our brand-specific waitid helper only understands a subset of
	 * the possible idtypes.  Ensure we keep to that subset here:
	 */
	if (idtype != P_ALL && idtype != P_PID && idtype != P_PGID) {
		return (EINVAL);
	}

	/*
	 * Enable the return of emulated ptrace(2) stop conditions
	 * through lx_waitid_helper, and stash the Linux-specific
	 * extra waitid() flags.
	 */
	lwpd->br_waitid_emulate = B_TRUE;
	lwpd->br_waitid_flags = extra_options;

	if ((error = waitid(idtype, id, sip, native_options)) == EINTR) {
		/*
		 * According to signal(7), the wait4(2), waitid(2), and
		 * waitpid(2) system calls are restartable.
		 */
		ttolxlwp(curthread)->br_syscall_restart = B_TRUE;
	}

	lwpd->br_waitid_emulate = B_FALSE;
	lwpd->br_waitid_flags = 0;

	return (error);
}

long
lx_wait4(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4)
{
	k_siginfo_t info = { 0 };
	idtype_t idtype;
	id_t id;
	int status = 0;
	pid_t pid = (pid_t)p1;
	int error;
	int native_options, extra_options;
	int *statusp = (int *)p2;
	void *rup = (void *)p4;

	if (ltos_options(p3, &native_options, &extra_options) == -1) {
		return (set_errno(EINVAL));
	}

	if (pid > maxpid) {
		return (set_errno(ECHILD));
	}

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
	if (statusp != NULL) {
		if (copyin(statusp, &status, sizeof (status)) != 0 ||
		    copyout(&status, statusp, sizeof (status)) != 0) {
			return (set_errno(EFAULT));
		}
	}

	/*
	 * Do the same check for the "struct rusage" pointer, which differs
	 * in size for 32- and 64-bit processes.
	 */
	if (rup != NULL) {
		struct rusage ru;
		void *krup = &ru;
		size_t rusz = sizeof (ru);
#if defined(_SYSCALL32_IMPL)
		struct rusage32 ru32;

		if (get_udatamodel() != DATAMODEL_NATIVE) {
			krup = &ru32;
			rusz = sizeof (ru32);
		}
#endif

		if (copyin(rup, krup, rusz) != 0 ||
		    copyout(krup, rup, rusz) != 0) {
			return (set_errno(EFAULT));
		}
	}

	if (pid < -1) {
		idtype = P_PGID;
		id = -pid;
	} else if (pid == -1) {
		idtype = P_ALL;
		id = 0;
	} else if (pid == 0) {
		idtype = P_PGID;
		mutex_enter(&pidlock);
		id = curproc->p_pgrp;
		mutex_exit(&pidlock);
	} else {
		idtype = P_PID;
		id = pid;
	}

	native_options |= (WEXITED | WTRAPPED);

	if ((error = lx_call_waitid(idtype, id, &info, native_options,
	    extra_options)) != 0) {
		return (set_errno(error));
	}

	/*
	 * If the WNOHANG flag was specified and no child was found return 0.
	 */
	if ((native_options & WNOHANG) && info.si_pid == 0) {
		return (0);
	}

	status = lx_wstat(info.si_code, info.si_status);

	/*
	 * Unfortunately if this attempt to copy out either the status or the
	 * rusage fails, the process will be in an inconsistent state as
	 * subsequent calls to wait for the same child will fail where they
	 * should succeed on a Linux system. This, however, is rather
	 * unlikely since we tested the validity of both above.
	 */
	if (statusp != NULL) {
		if (copyout(&status, statusp, sizeof (status)) != 0) {
			return (set_errno(EFAULT));
		}
	}

	if (rup != NULL) {
		if ((error = rusagesys(_RUSAGESYS_GETRUSAGE_CHLD, rup, NULL,
		    NULL, NULL)) != 0) {
			return (set_errno(error));
		}
	}

	return (info.si_pid);
}

long
lx_waitpid(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	return (lx_wait4(p1, p2, p3, (uintptr_t)NULL));
}

long
lx_waitid(uintptr_t idtype, uintptr_t id, uintptr_t infop, uintptr_t opt)
{
	int error;
	int native_options, extra_options;
	k_siginfo_t info = { 0 };

	if (ltos_options(opt, &native_options, &extra_options) == -1) {
		return (set_errno(EINVAL));
	}

	if (((opt) & (LX_WEXITED | LX_WSTOPPED | LX_WCONTINUED)) == 0) {
		return (set_errno(EINVAL));
	}

	switch (idtype) {
	case LX_P_ALL:
		idtype = P_ALL;
		break;
	case LX_P_PID:
		idtype = P_PID;
		break;
	case LX_P_GID:
		idtype = P_PGID;
		break;
	default:
		return (set_errno(EINVAL));
	}

	if ((error = lx_call_waitid(idtype, id, &info, native_options,
	    extra_options)) != 0) {
		return (set_errno(error));
	}

	/*
	 * If the WNOHANG flag was specified and no child was found return 0.
	 */
	if ((native_options & WNOHANG) && info.si_pid == 0) {
		return (0);
	}

#if defined(_SYSCALL32_IMPL)
	if (get_udatamodel() != DATAMODEL_NATIVE) {
		return (stol_ksiginfo32_copyout(&info, (void *)infop));
	} else
#endif
	{
		return (stol_ksiginfo_copyout(&info, (void *)infop));
	}
}
