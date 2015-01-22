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
 * Copyright 2015 Joyent, Inc.  All rights reserved.
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <ucontext.h>
#include <thread.h>
#include <strings.h>
#include <libintl.h>
#include <sys/regset.h>
#include <sys/syscall.h>
#include <sys/inttypes.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/segments.h>
#include <signal.h>
#include <sys/lx_misc.h>
#include <sys/lx_types.h>
#include <sys/lx_signal.h>
#include <sys/lx_syscall.h>
#include <sys/lx_brand.h>
#include <sys/lx_debug.h>
#include <sys/lx_thread.h>
#include <sys/fork.h>

#define	LX_CSIGNAL		0x000000ff
#define	LX_CLONE_VM		0x00000100
#define	LX_CLONE_FS		0x00000200
#define	LX_CLONE_FILES		0x00000400
#define	LX_CLONE_SIGHAND	0x00000800
#define	LX_CLONE_PID		0x00001000
#define	LX_CLONE_PTRACE		0x00002000
#define	LX_CLONE_VFORK		0x00004000
#define	LX_CLONE_PARENT		0x00008000
#define	LX_CLONE_THREAD		0x00010000
#define	LX_CLONE_SYSVSEM	0x00040000
#define	LX_CLONE_SETTLS		0x00080000
#define	LX_CLONE_PARENT_SETTID	0x00100000
#define	LX_CLONE_CHILD_CLEARTID	0x00200000
#define	LX_CLONE_DETACH		0x00400000
#define	LX_CLONE_CHILD_SETTID	0x01000000

#define	SHARED_AS	\
	(LX_CLONE_VM | LX_CLONE_FS | LX_CLONE_FILES | LX_CLONE_SIGHAND	\
	    | LX_CLONE_THREAD)
#define	CLONE_VFORK (LX_CLONE_VM | LX_CLONE_VFORK)
#define	CLONE_TD (LX_CLONE_THREAD|LX_CLONE_DETACH)

#define	IS_FORK(f)	(((f) & SHARED_AS) == 0)
#define	IS_VFORK(f)	(((f) & CLONE_VFORK) == CLONE_VFORK)

#define	LX_EXIT		1
#define	LX_EXIT_GROUP	2

/*
 * This is dicey.  This seems to be an internal glibc structure, and not
 * part of any external interface.  Thus, it is subject to change without
 * notice.  FWIW, clone(2) itself seems to be an internal (or at least
 * unstable) interface, since strace(1) shows it differently than the man
 * page.
 */
struct lx_desc
{
	uint32_t entry_number;
	uint32_t base_addr;
	uint32_t limit;
	uint32_t seg_32bit:1;
	uint32_t contents:2;
	uint32_t read_exec_only:1;
	uint32_t limit_in_pages:1;
	uint32_t seg_not_present:1;
	uint32_t useable:1;
	uint32_t empty:25;
};

struct clone_state {
	void		*c_retaddr;	/* instr after clone()'s int80 */
	int		c_flags;	/* flags to clone(2) */
	int 		c_sig;		/* signal to send on thread exit */
	void 		*c_stk;		/* %esp of new thread */
	void 		*c_ptidp;
	struct lx_desc	*c_ldtinfo;	/* thread-specific segment */
	void		*c_ctidp;
#if defined(_LP64)
	lx_regs_t	c_regs;		/* original register state */
#else
	uintptr_t	c_gs;		/* Linux's %gs */
#endif
	sigset_t	c_sigmask;	/* signal mask */
	lx_affmask_t	c_affmask;	/* CPU affinity mask */
	volatile int	*c_clone_res;	/* pid/error returned to cloner */
};

extern void lx_setup_clone(uintptr_t, void *, void *);

/*
 * Counter incremented when we vfork(2) ourselves, and decremented when the
 * vfork(2)ed child exit(2)s or exec(2)s.
 */
static int is_vforked = 0;

long
lx_exit(uintptr_t p1)
{
	int		ret, status = (int)p1;
	lx_tsd_t	*lx_tsd;

	/*
	 * If we are a vfork(2)ed child, we need to exit as quickly and
	 * cleanly as possible to avoid corrupting our parent.
	 */
	if (is_vforked != 0) {
		is_vforked--;
		_exit(status);
	}

	if ((ret = thr_getspecific(lx_tsd_key, (void **)&lx_tsd)) != 0)
		lx_err_fatal("exit: unable to read thread-specific data: %s",
		    strerror(ret));

	assert(lx_tsd != 0);

	lx_tsd->lxtsd_exit = LX_EXIT;
	lx_tsd->lxtsd_exit_status = status;

	lx_ptrace_stop_if_option(LX_PTRACE_O_TRACEEXIT, B_FALSE,
	    (ulong_t)status);

	/*
	 * Block all signals in the exit context to avoid taking any signals
	 * (to the degree possible) while exiting.
	 */
	(void) sigfillset(&lx_tsd->lxtsd_exit_context.uc_sigmask);

	/*
	 * This thread is exiting.  Restore the state of the thread to
	 * what it was before we started running linux code.
	 * For 64-bit code, since we know we are unwinding the stack back to
	 * lx_init, we need to unwind the syscall mode flag "stack" as well.
	 */
#if defined(_LP64)
	(void) syscall(SYS_brand, B_UNWIND_NTV_SYSC_FLAG);
#endif
	(void) setcontext(&lx_tsd->lxtsd_exit_context);

	/*
	 * If we returned from the setcontext(2), something is very wrong.
	 */
	lx_err_fatal("exit: unable to set exit context: %s", strerror(errno));

	/*NOTREACHED*/
	return (0);
}

long
lx_group_exit(uintptr_t p1)
{
	int		ret, status = (int)p1;
	lx_tsd_t	*lx_tsd;

	/*
	 * If we are a vfork(2)ed child, we need to exit as quickly and
	 * cleanly as possible to avoid corrupting our parent.
	 */
	if (is_vforked != 0) {
		is_vforked--;
		_exit(status);
	}

	if ((ret = thr_getspecific(lx_tsd_key, (void **)&lx_tsd)) != 0)
		lx_err_fatal("group_exit: unable to read thread-specific "
		    "data: %s", strerror(ret));

	assert(lx_tsd != 0);

	lx_tsd->lxtsd_exit = LX_EXIT_GROUP;
	lx_tsd->lxtsd_exit_status = status;

	/*
	 * Block all signals in the exit context to avoid taking any signals
	 * (to the degree possible) while exiting.
	 */
	(void) sigfillset(&lx_tsd->lxtsd_exit_context.uc_sigmask);

	/*
	 * This thread is exiting.  Restore the state of the thread to
	 * what it was before we started running linux code.
	 * For 64-bit code, since we know we are unwinding the stack back to
	 * lx_init, we need to unwind the syscall mode flag "stack" as well.
	 */
#if defined(_LP64)
	(void) syscall(SYS_brand, B_UNWIND_NTV_SYSC_FLAG);
#endif
	(void) setcontext(&lx_tsd->lxtsd_exit_context);

	/*
	 * If we returned from the setcontext(2), something is very wrong.
	 */
	lx_err_fatal("group_exits: unable to set exit context: %s",
	    strerror(errno));

	/*NOTREACHED*/
	return (0);
}

static void *
clone_start(void *arg)
{
	int rval;
	struct clone_state *cs = (struct clone_state *)arg;
	lx_tsd_t lx_tsd;

	/*
	 * Let the kernel finish setting up all the needed state for this
	 * new thread.
	 *
	 * We already created the thread using the thr_create(3C) library
	 * call, so most of the work required to emulate lx_clone(2) has
	 * been done by the time we get to this point.  Instead of creating
	 * a new brandsys(2) subcommand to perform the last few bits of
	 * bookkeeping, we just use the lx_clone() slot in the syscall
	 * table.
	 */
	lx_debug("\tre-vectoring to lx kernel module to complete lx_clone()");
	lx_debug("\tLX_SYS_clone(0x%x, 0x%p, 0x%p, 0x%p, 0x%p)",
	    cs->c_flags, cs->c_stk, cs->c_ptidp, cs->c_ldtinfo, cs->c_ctidp);

	rval = syscall(SYS_brand, B_IKE_SYSCALL + LX_EMUL_clone,
	    cs->c_flags, cs->c_stk, cs->c_ptidp, cs->c_ldtinfo, cs->c_ctidp,
	    NULL);

	/*
	 * At this point the parent is waiting for cs->c_clone_res to go
	 * non-zero to indicate the thread has been cloned.  The value set
	 * in cs->c_clone_res will be used for the return value from
	 * clone().
	 */
	if (rval < 0) {
		*(cs->c_clone_res) = -errno;
		lx_debug("\tkernel clone failed, errno %d\n", errno);
		return (NULL);
	}

	if (lx_sched_setaffinity(0, sizeof (cs->c_affmask),
	    (uintptr_t)&cs->c_affmask) != 0) {
		*(cs->c_clone_res) = -errno;

		lx_err_fatal("Unable to set affinity mask in child thread: %s",
		    strerror(errno));
	}

	/* Initialize the thread specific data for this thread. */
	bzero(&lx_tsd, sizeof (lx_tsd));
#if defined(_ILP32)
	lx_tsd.lxtsd_gs = cs->c_gs;
#else
	lx_tsd.lxtsd_fsbase = (uintptr_t)cs->c_ldtinfo;
#endif

	/*
	 * Use the address of the stack-allocated lx_tsd as the
	 * per-thread storage area to cache various values for later
	 * use.
	 *
	 * This address is only used by this thread, so there is no
	 * danger of other threads using this storage area, nor of it
	 * being accessed once this stack frame has been freed.
	 */
	if (thr_setspecific(lx_tsd_key, &lx_tsd) != 0) {
		*(cs->c_clone_res) = -errno;
		lx_err_fatal("Unable to set thread-specific ptr for clone: %s",
		    strerror(rval));
	}

	/*
	 * Save the current context of this thread.
	 *
	 * We'll restore this context when this thread attempts to exit.
	 */
	if (getcontext(&lx_tsd.lxtsd_exit_context) != 0) {
		*(cs->c_clone_res) = -errno;

		lx_err_fatal("Unable to initialize thread-specific exit "
		    "context: %s", strerror(errno));
	}

	/*
	 * Do the final stack twiddling, reset %gs, and return to the
	 * clone(2) path.
	 */
	if (lx_tsd.lxtsd_exit == 0) {
		if (sigprocmask(SIG_SETMASK, &cs->c_sigmask, NULL) < 0) {
			*(cs->c_clone_res) = -errno;

			lx_err_fatal("Unable to release held signals for child "
			    "thread: %s", strerror(errno));
		}

		/*
		 * Let the parent know that the clone has (effectively) been
		 * completed.
		 */
		*(cs->c_clone_res) = rval;

#if defined(_LP64)
		(void) syscall(SYS_brand, B_CLR_NTV_SYSC_FLAG);
		lx_setup_clone((uintptr_t)&cs->c_regs, cs->c_retaddr,
		    cs->c_stk);
#else
		lx_setup_clone(cs->c_gs, cs->c_retaddr, cs->c_stk);
#endif

		/* lx_setup_clone() should never return. */
		assert(0);
	}

	/*
	 * We are here because the Linux application called the exit() or
	 * exit_group() system call.  In turn the brand library did a
	 * setcontext() to jump to the thread context state saved in
	 * getcontext(), above.
	 */
	if (lx_tsd.lxtsd_exit == LX_EXIT)
		thr_exit((void *)(long)lx_tsd.lxtsd_exit_status);
	else
		exit(lx_tsd.lxtsd_exit_status);

	assert(0);
	/*NOTREACHED*/
}

/*
 * The way Linux handles stopping for FORK vs. CLONE does not map exactly to
 * which syscall was used. Instead, it has to do with which signal is set in
 * the low byte of the clone flag. The only time the CLONE event is emitted is
 * if the clone signal (the low byte of the flags argument) is set to something
 * other than SIGCHLD (see the Linux src in kernel/fork.c do_fork() for the
 * actual code).
 */
static int
ptrace_clone_event(int flags)
{
	if (flags & LX_CLONE_VFORK)
		return (LX_PTRACE_O_TRACEVFORK);

	if ((flags & LX_CSIGNAL) != LX_SIGCHLD)
		return (LX_PTRACE_O_TRACECLONE);

	return (LX_PTRACE_O_TRACEFORK);
}

/*
 * See glibc sysdeps/unix/sysv/linux/x86_64/clone.S code for x64 argument order
 * and the Linux kernel/fork.c code for the various ways arguments can be passed
 * to the clone syscall (CONFIG_CLONE_BACKWARDS, et al).
 */
long
lx_clone(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4,
	uintptr_t p5)
{
	struct clone_state *cs;
	int flags = (int)p1;
	void *cldstk = (void *)p2;
	void *ptidp = (void *)p3;
#if defined(_LP64)
	void *ctidp = (void *)p4;
	struct lx_desc *ldtinfo = (void *)p5;
#else /* is 32bit */
	struct lx_desc *ldtinfo = (void *)p4;
	void *ctidp = (void *)p5;
#endif
	thread_t tid;
	volatile int clone_res;
	int sig;
	int rval;
	int pid;
	lx_regs_t *rp;
	sigset_t sigmask;
	int fork_flags = 0;
	int ptrace_event;

	if (flags & LX_CLONE_SETTLS) {
		lx_debug("lx_clone(flags=0x%x stk=0x%p ptidp=0x%p ldt=0x%p "
		    "ctidp=0x%p", flags, cldstk, ptidp, ldtinfo, ctidp);
	} else {
		lx_debug("lx_clone(flags=0x%x stk=0x%p ptidp=0x%p)",
		    flags, cldstk, ptidp);
	}

	/*
	 * Only supported for pid 0 on Linux
	 */
	if (flags & LX_CLONE_PID)
		return (-EINVAL);

	/*
	 * CLONE_THREAD requires CLONE_SIGHAND.
	 *
	 * CLONE_THREAD and CLONE_DETACHED must both be either set or cleared
	 * in kernel 2.4 and prior.
	 * In kernel 2.6 (and later) CLONE_DETACHED was dropped completely, so
	 * we no longer have this requirement.
	 */

	if (flags & CLONE_TD) {
		if (!(flags & LX_CLONE_SIGHAND))
			return (-EINVAL);
		if (strncmp(lx_release, "2.4", 3) == 0 &&
		    (flags & CLONE_TD) != CLONE_TD)
			return (-EINVAL);
	}

	rp = lx_syscall_regs();

	/* test if pointer passed by user are writable */
	if (flags & LX_CLONE_PARENT_SETTID) {
		if (uucopy(ptidp, &pid, sizeof (int)) != 0)
			return (-EFAULT);
		if (uucopy(&pid, ptidp, sizeof (int)) != 0)
			return (-EFAULT);
	}
	if (flags & LX_CLONE_CHILD_SETTID) {
		if (uucopy(ctidp, &pid, sizeof (int)) != 0)
			return (-EFAULT);
		if (uucopy(&pid, ctidp, sizeof (int)) != 0)
			return (-EFAULT);
	}

	ptrace_event = ptrace_clone_event(flags);

	/* See if this is a fork() operation or a thr_create().  */
	if (IS_FORK(flags) || IS_VFORK(flags)) {
		if (flags & LX_CLONE_PARENT) {
			lx_unsupported("clone(2) only supports CLONE_PARENT "
			    "for threads.\n");
			return (-ENOTSUP);
		}

		if (flags & LX_CLONE_PTRACE)
			lx_ptrace_fork();

		if ((flags & LX_CSIGNAL) == 0)
			fork_flags |= FORK_NOSIGCHLD;

		if (flags & LX_CLONE_VFORK) {
			is_vforked++;
			rval = vforkx(fork_flags);
			if (rval != 0)
				is_vforked--;
		} else {
			rval = forkx(fork_flags);
			if (rval == 0 && lx_is_rpm)
				(void) sleep(lx_rpm_delay);
		}

		/*
		 * Since we've already forked, we can't do much if uucopy
		 * fails, so we just ignore failure. Failure is unlikely since
		 * we've tested the memory before we did the fork.
		 */
		if (rval > 0 && (flags & LX_CLONE_PARENT_SETTID)) {
			(void) uucopy(&rval, ptidp, sizeof (int));
		}

		if (rval == 0 && (flags & LX_CLONE_CHILD_SETTID)) {
			/*
			 * lx_getpid should not fail, and if it does, there's
			 * not much we can do about it since we've already
			 * forked, so on failure, we just don't copy the
			 * memory.
			 */
			pid = lx_getpid();
			if (pid >= 0)
				(void) uucopy(&pid, ctidp, sizeof (int));
		}

		/* Parent just returns */
		if (rval != 0) {
			if (rval > 0)
				lx_ptrace_stop_if_option(ptrace_event, B_FALSE,
				    (ulong_t)rval);
			return ((rval < 0) ? -errno : rval);
		}


		/*
		 * Set up additional data in the lx_proc_data structure as
		 * necessary.
		 */
		rval = syscall(SYS_brand, B_IKE_SYSCALL + LX_EMUL_clone,
		    flags, cldstk, ptidp, ldtinfo, ctidp, NULL);
		if (rval < 0) {
			return (rval);
		}

		/*
		 * lx_setup_clone() doesn't return below, so stop now, if
		 * necessary.
		 */
		lx_ptrace_stop_if_option(ptrace_event, B_TRUE, 0);

		/*
		 * If provided, the child needs its new stack set up.
		 */
		if (cldstk) {
#if defined(_LP64)
			(void) syscall(SYS_brand, B_CLR_NTV_SYSC_FLAG);
			lx_setup_clone((uintptr_t)rp, (void *)rp->lxr_rip,
			    cldstk);
#else
			lx_setup_clone(rp->lxr_gs, (void *)rp->lxr_eip, cldstk);
#endif
			/* lx_setup_clone() should never return. */
			assert(0);
		}

		return (0);
	}

	/*
	 * We have very restricted support.... only exactly these flags are
	 * supported
	 */
	if (((flags & SHARED_AS) != SHARED_AS)) {
		lx_unsupported("clone(2) requires that all or none of "
		    "CLONE_VM/FS/FILES/THREAD/SIGHAND be set. (flags:0x%08X)\n",
		    flags);
		return (-ENOTSUP);
	}

	if (cldstk == NULL) {
		lx_unsupported("clone(2) requires the caller to allocate the "
		    "child's stack.\n");
		return (-ENOTSUP);
	}

	/*
	 * If we want a signal-on-exit, ensure that the signal is valid.
	 */
	if ((sig = ltos_signo[flags & LX_CSIGNAL]) == -1) {
		lx_unsupported("clone(2) passed unsupported signal: %d", sig);
		return (-ENOTSUP);
	}

	/*
	 * To avoid malloc() here, we steal a part of the new thread's
	 * stack to store all the info that thread might need for
	 * initialization.  We also make it 64-bit aligned for good
	 * measure.
	 */
	cs = (struct clone_state *)
	    ((p2 - sizeof (struct clone_state)) & -((uintptr_t)8));
	cs->c_flags = flags;
	cs->c_sig = sig;
	cs->c_stk = cldstk;
	cs->c_ptidp = ptidp;
	cs->c_ldtinfo = ldtinfo;
	cs->c_ctidp = ctidp;
	cs->c_clone_res = &clone_res;
#if defined(_LP64)
	/*
	 * The AMD64 ABI says that the kernel clobbers %rcx and %r11. We
	 * return a value in %rax. The new %rsp and %rip will be setup in
	 * lx_setup_clone. Thus, we don't worry about passing/restoring those
	 * registers.
	 */
	cs->c_regs.lxr_rdi = rp->lxr_rdi;
	cs->c_regs.lxr_rsi = rp->lxr_rsi;
	cs->c_regs.lxr_rbx = rp->lxr_rbx;
	cs->c_regs.lxr_rdx = rp->lxr_rdx;
	cs->c_regs.lxr_rdi = rp->lxr_rdi;
	cs->c_regs.lxr_r8 = rp->lxr_r8;
	cs->c_regs.lxr_r9 = rp->lxr_r9;
	cs->c_regs.lxr_r10 = rp->lxr_r10;
	cs->c_regs.lxr_r12 = rp->lxr_r12;
	cs->c_regs.lxr_r13 = rp->lxr_r13;
	cs->c_regs.lxr_r14 = rp->lxr_r14;
	cs->c_regs.lxr_r15 = rp->lxr_r15;
#else
	cs->c_gs = rp->lxr_gs;
#endif

	if (lx_sched_getaffinity(0, sizeof (cs->c_affmask),
	    (uintptr_t)&cs->c_affmask) == -1)
		lx_err_fatal("Unable to get affinity mask for parent "
		    "thread: %s", strerror(errno));

	/*
	 * We want the new thread to return directly to the return site for
	 * the system call.
	 */
#if defined(_LP64)
	cs->c_retaddr = (void *)rp->lxr_rip;
#else
	cs->c_retaddr = (void *)rp->lxr_eip;
#endif
	clone_res = 0;

	(void) sigfillset(&sigmask);

	/*
	 * Block all signals because the thread we create won't be able to
	 * properly handle them until it's fully set up.
	 */
	if (sigprocmask(SIG_BLOCK, &sigmask, &cs->c_sigmask) < 0) {
		lx_debug("lx_clone sigprocmask() failed: %s", strerror(errno));
		return (-errno);
	}

	rval = thr_create(NULL, NULL, clone_start, cs, THR_DETACHED, &tid);

	/*
	 * Release any pending signals
	 */
	(void) sigprocmask(SIG_SETMASK, &cs->c_sigmask, NULL);

	/*
	 * Wait for the child to be created and have its tid assigned.
	 */
	if (rval == 0) {
		while (clone_res == 0)
			;

		rval = clone_res;
		lx_ptrace_stop_if_option(ptrace_event, B_TRUE, 0);
	}

	return (rval);
}
