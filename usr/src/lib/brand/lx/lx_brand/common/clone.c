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
 * Copyright 2018 Joyent, Inc.
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
#include <sys/mman.h>
#include <sys/debug.h>
#include <lx_syscall.h>

#define	CLONE_VFORK (LX_CLONE_VM | LX_CLONE_VFORK)
#define	CLONE_TD (LX_CLONE_THREAD|LX_CLONE_DETACH)

#define	IS_FORK(f)	(((f) & SHARED_AS) == 0)
#define	IS_VFORK(f)	(((f) & CLONE_VFORK) == CLONE_VFORK)

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
	ucontext_t	c_uc;		/* original register state/sigmask */
	volatile int	*c_clone_res;	/* pid/error returned to cloner */
	int		c_ptrace_event;	/* ptrace(2) event for child stop */
	void		*c_ntv_stk;	/* native stack for this thread */
	size_t		c_ntv_stk_sz;	/* native stack size */
	lx_tsd_t	*c_lx_tsd;	/* tsd area for thread */
};

long
lx_exit(uintptr_t p1)
{
	int		status = (int)p1;
	lx_tsd_t	*lx_tsd = lx_get_tsd();

	/*
	 * If we are a vfork(2)ed child, we need to exit as quickly and
	 * cleanly as possible to avoid corrupting our parent.
	 */
	if (lx_tsd->lxtsd_is_vforked != 0) {
		_exit(status);
	}

	lx_tsd->lxtsd_exit = LX_ET_EXIT;
	lx_tsd->lxtsd_exit_status = status;

	lx_ptrace_stop_if_option(LX_PTRACE_O_TRACEEXIT, B_FALSE,
	    (ulong_t)status, NULL);

	/*
	 * This thread is exiting.  Restore the state of the thread to
	 * what it was before we started running linux code.
	 */
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
	int		status = (int)p1;
	lx_tsd_t	*lx_tsd = lx_get_tsd();

	/*
	 * If we are a vfork(2)ed child, we need to exit as quickly and
	 * cleanly as possible to avoid corrupting our parent.
	 */
	if (lx_tsd->lxtsd_is_vforked != 0) {
		_exit(status);
	}

	lx_tsd->lxtsd_exit = LX_ET_EXIT_GROUP;
	lx_tsd->lxtsd_exit_status = status;

	/*
	 * This thread is exiting.  Restore the state of the thread to
	 * what it was before we started running linux code.
	 */
	(void) setcontext(&lx_tsd->lxtsd_exit_context);

	/*
	 * If we returned from the setcontext(2), something is very wrong.
	 */
	lx_err_fatal("group_exit: unable to set exit context: %s",
	    strerror(errno));

	/*NOTREACHED*/
	return (0);
}

static void *
clone_start(void *arg)
{
	int rval;
	struct clone_state *cs = (struct clone_state *)arg;
	lx_tsd_t *lxtsd;

	/*
	 * Let the kernel finish setting up all the needed state for this
	 * new thread.
	 *
	 * We already created the thread using the thr_create(3C) library
	 * call, so most of the work required to emulate lx_clone(2) has
	 * been done by the time we get to this point.
	 */
	lx_debug("\tre-vectoring to lx kernel module to complete lx_clone()");
	lx_debug("\tB_HELPER_CLONE(0x%x, 0x%p, 0x%p, 0x%p)",
	    cs->c_flags, cs->c_ptidp, cs->c_ldtinfo, cs->c_ctidp);

	rval = syscall(SYS_brand, B_HELPER_CLONE, cs->c_flags, cs->c_ptidp,
	    cs->c_ldtinfo, cs->c_ctidp);

	/*
	 * At this point the parent is waiting for cs->c_clone_res to go
	 * non-zero to indicate the thread has been cloned.  The value set
	 * in cs->c_clone_res will be used for the return value from
	 * clone().
	 */
	if (rval < 0) {
		*(cs->c_clone_res) = -errno;
		lx_debug("\tkernel clone failed, errno %d\n", errno);
		free(cs->c_lx_tsd);
		free(cs);
		return (NULL);
	}

	/*
	 * Initialize the thread specific data for this thread.
	 */
	lxtsd = cs->c_lx_tsd;
	lx_init_tsd(lxtsd);
	lxtsd->lxtsd_clone_state = cs;

	/*
	 * Install the emulation stack for this thread.  Register the
	 * thread-specific data structure with the stack list so that it may be
	 * freed at thread exit or fork(2).
	 */
	lx_install_stack(cs->c_ntv_stk, cs->c_ntv_stk_sz, lxtsd);

	/*
	 * Let the parent know that the clone has (effectively) been
	 * completed.
	 */
	*(cs->c_clone_res) = rval;

	/*
	 * We want to load the general registers from this context, restore the
	 * original signal mask, and switch to the BRAND stack.  The original
	 * signal mask was saved to the context by lx_clone().
	 */
	cs->c_uc.uc_flags = UC_CPU | UC_SIGMASK;
	cs->c_uc.uc_brand_data[0] = (void *)LX_UC_STACK_BRAND;

	/*
	 * New threads will not link into the existing context chain.
	 */
	cs->c_uc.uc_link = NULL;

	/*
	 * Set stack pointer and entry point for new thread:
	 */
	LX_REG(&cs->c_uc, REG_SP) = (uintptr_t)cs->c_stk;
	LX_REG(&cs->c_uc, REG_PC) = (uintptr_t)cs->c_retaddr;

	/*
	 * Return 0 to the child:
	 */
	LX_REG(&cs->c_uc, REG_R0) = (uintptr_t)0;

	/*
	 * Fire the ptrace(2) event stop in the new thread:
	 */
	lx_ptrace_stop_if_option(cs->c_ptrace_event, B_TRUE, 0, &cs->c_uc);

	/*
	 * Jump to the Linux process.  This call cannot return.
	 */
	lx_jump_to_linux(&cs->c_uc);
	/* NOTREACHED */
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
lx_clone(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4, uintptr_t p5)
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
	ucontext_t *ucp;
	sigset_t sigmask, osigmask;
	int fork_flags = 0;
	int ptrace_event;
	lx_tsd_t *lx_tsd = lx_get_tsd();

	if (flags & LX_CLONE_SETTLS) {
		lx_debug("lx_clone(flags=0x%x stk=0x%p ptidp=0x%p ldt=0x%p "
		    "ctidp=0x%p", flags, cldstk, ptidp, ldtinfo, ctidp);
	} else {
		lx_debug("lx_clone(flags=0x%x stk=0x%p ptidp=0x%p)",
		    flags, cldstk, ptidp);
	}

	/*
	 * Only supported for pid 0 on Linux after version 2.3.21, and
	 * apparently not at all since 2.5.16.
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

	if ((flags & LX_CLONE_NS_UNSUP) != 0) {
		lx_unsupported("clone(2) no namespace support "
		    "(flags:0x%08X)\n", flags);
		/*
		 * When the "kernel" does not support namespaces, applications
		 * (e.g. chromium) expect EINVAL, not ENOTSUP.
		 */
		return (-EINVAL);
	}

	ucp = lx_syscall_regs();

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

	/*
	 * Inform the in-kernel ptrace(2) subsystem that we are about to
	 * emulate a fork(2), vfork(2) or clone(2) system call.
	 */
	lx_ptrace_clone_begin(ptrace_event, !!(flags & LX_CLONE_PTRACE), flags);

	/*
	 * Handle a fork(2) operation here. If this is not a fork, a new
	 * thread will be created after this block. We can also create a new
	 * clone-group here (when two or more processes share data represented
	 * by a subset of the SHARED_AS flags, but not a true thread).
	 */
	if (IS_FORK(flags) || IS_VFORK(flags) || LX_IS_CLONE_GRP(flags)) {
		if (flags & LX_CLONE_PARENT) {
			lx_unsupported("clone(2) only supports CLONE_PARENT "
			    "for threads.\n");
			return (-ENOTSUP);
		}

		if ((flags & LX_CSIGNAL) == 0)
			fork_flags |= FORK_NOSIGCHLD;

		/*
		 * Suspend signal delivery, run the stack management prefork
		 * handler and perform the actual fork(2) operation.
		 *
		 * During vfork, Linux will not deliver any signals to any
		 * thread in the parent. Some applications (e.g. Go) depend on
		 * this. For example, we must prevent the following sequence:
		 * 1) Parent with many threads, one thread calls vfork
		 * 2) vforked child resets all signal handlers
		 * 3) a different child of the parent exits and SIGCHLD is sent
		 *    to parent before the vforked child execs/exits
		 * The parent cannot receive the SIGCHLD until afer we repair
		 * the parent's signal handlers in lx_sighandlers_restore, once
		 * the parent resumes after the vfork.
		 */
		if (flags & LX_CLONE_VFORK) {
			lx_block_all_signals();
		} else {
			_sigoff();
		}
		lx_stack_prefork();
		if (flags & LX_CLONE_VFORK) {
			lx_sighandlers_t saved;

			/*
			 * Because we keep our signal disposition at user-land
			 * (and in memory), we must prevent it from being
			 * clobbered should our vforked child change the
			 * disposition (e.g., via sigaction()) before releasing
			 * the address space.  We preserve our disposition by
			 * taking a snapshot of it before the vfork and
			 * restoring it afterwards -- which we can get away
			 * with because we know that we aren't executing
			 * concurrently with our child.
			 */
			lx_sighandlers_save(&saved);
			lx_tsd->lxtsd_is_vforked++;
			rval = vforkx(fork_flags);
			if (rval != 0) {
				lx_tsd->lxtsd_is_vforked--;
				lx_sighandlers_restore(&saved);
			}
		} else {
			rval = forkx(fork_flags);
		}

		/*
		 * The parent process returns through the regular system call
		 * path here.
		 */
		if (rval != 0) {
			/*
			 * Run the stack management postfork handler in the
			 * parent.  In the CLONE_VFORK case, where it only
			 * needs to be performed once due to the shared address
			 * space, it is critical that this step is performed in
			 * the parent and not the child.  The latter can result
			 * in un-woken threads blocked on lx_stack_list_lock.
			 */
			lx_stack_postfork();

			/*
			 * Since we've already forked, we can't do much if
			 * uucopy fails, so we just ignore failure. Failure is
			 * unlikely since we've tested the memory before we did
			 * the fork.
			 */
			if (rval > 0 && (flags & LX_CLONE_PARENT_SETTID)) {
				(void) uucopy(&rval, ptidp, sizeof (int));
			}

			/*
			 * Re-enable signal delivery in the parent process.
			 */
			if (flags & LX_CLONE_VFORK) {
				lx_unblock_all_signals();
			} else {
				_sigon();
			}

			if (rval > 0) {
				lx_ptrace_stop_if_option(ptrace_event, B_FALSE,
				    (ulong_t)rval, NULL);
			}

			return ((rval < 0) ? -errno : rval);
		}

		/*
		 * The rest of this block runs only within the new child
		 * process.
		 */

		if (!IS_VFORK(flags)) {
			/*
			 * For non-vfork children run the stack management
			 * postfork handler.
			 */
			lx_stack_postfork();

			/*
			 * We must free the stacks and thread-specific data
			 * objects for every thread except the one duplicated
			 * from the parent by forkx().
			 */
			lx_free_other_stacks();
		}

		if (rval == 0 && (flags & LX_CLONE_CHILD_SETTID)) {
			/*
			 * lx_getpid should not fail, and if it does, there's
			 * not much we can do about it since we've already
			 * forked, so on failure, we just don't copy the
			 * memory.
			 */
			pid = syscall(SYS_brand, B_GETPID);
			if (pid >= 0)
				(void) uucopy(&pid, ctidp, sizeof (int));
		}

		/*
		 * Set up additional data in the lx_proc_data structure as
		 * necessary.
		 */
		if ((rval = syscall(SYS_brand, B_HELPER_CLONE, flags, ptidp,
		    ldtinfo, ctidp)) < 0) {
			return (rval);
		}

		if (IS_VFORK(flags)) {
			ucontext_t vforkuc;

			/*
			 * The vfork(2) interface is somewhat less than ideal.
			 * The unfortunate notion of borrowing the address
			 * space of the parent process requires us to jump
			 * through several hoops to prevent corrupting parent
			 * emulation state.
			 *
			 * When returning in the child, we make a copy of the
			 * system call return context and discard three pages
			 * of the native stack.  Returning normally would
			 * clobber the native stack frame in which the brand
			 * library in the parent process is presently waiting.
			 *
			 * The calling program is expected to correctly use
			 * this dusty, underspecified relic.  Neglecting to
			 * immediately call execve(2) or exit(2) is not
			 * cricket; this stack space will be permanently lost,
			 * not to mention myriad other undefined behaviour.
			 */
			bcopy(ucp, &vforkuc, sizeof (vforkuc));
			vforkuc.uc_brand_data[1] =
			    (caddr_t)vforkuc.uc_brand_data[1] -
			    LX_NATIVE_STACK_VFORK_GAP;
			vforkuc.uc_link = NULL;

			lx_debug("\tvfork native stack sp %p",
			    vforkuc.uc_brand_data[1]);

			/*
			 * If provided, the child needs its new stack set up.
			 */
			if (cldstk != 0) {
				lx_debug("\tvfork cldstk %p", cldstk);
				LX_REG(&vforkuc, REG_SP) = (uintptr_t)cldstk;
			}

			/*
			 * Re-enable signal delivery in the child process.
			 */
			lx_unblock_all_signals();

			/*
			 * Stop for ptrace if required.
			 */
			lx_ptrace_stop_if_option(ptrace_event, B_TRUE, 0, NULL);

			/*
			 * Return to the child via the specially constructed
			 * vfork(2) context.
			 */
			LX_EMULATE_RETURN(&vforkuc, LX_SYS_clone, 0, 0);
			(void) syscall(SYS_brand, B_EMULATION_DONE, &vforkuc,
			    LX_SYS_clone, 0, 0);

			assert(0);
		}

		/*
		 * If provided, the child needs its new stack set up.
		 */
		if (cldstk != 0) {
			lx_debug("\tcldstk %p", cldstk);
			LX_REG(ucp, REG_SP) = (uintptr_t)cldstk;
		}

		/*
		 * Re-enable signal delivery in the child process.
		 */
		if (flags & LX_CLONE_VFORK) {
			lx_unblock_all_signals();
		} else {
			_sigon();
		}

		/*
		 * Stop for ptrace if required.
		 */
		lx_ptrace_stop_if_option(ptrace_event, B_TRUE, 0, NULL);

		/*
		 * The child process returns via the regular emulated system
		 * call path:
		 */
		return (0);
	}

	/*
	 * A supported clone-group was handled above, so now it must be a
	 * true native thread, which means exactly these flags are supported
	 */
	if (((flags & SHARED_AS) != SHARED_AS)) {
		lx_unsupported("clone(2) a thread requires that all or none of "
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
	 * Initialise the state structure we pass as an argument to the new
	 * thread:
	 */
	if ((cs = malloc(sizeof (*cs))) == NULL) {
		lx_debug("could not allocate clone_state: %d", errno);
		return (-ENOMEM);
	}
	cs->c_flags = flags;
	cs->c_sig = sig;
	cs->c_stk = cldstk;
	cs->c_ptidp = ptidp;
	cs->c_ldtinfo = ldtinfo;
	cs->c_ctidp = ctidp;
	cs->c_clone_res = &clone_res;
	cs->c_ptrace_event = ptrace_event;
	/*
	 * We want the new thread to return directly to the call site for
	 * the system call.
	 */
	cs->c_retaddr = (void *)LX_REG(ucp, REG_PC);
	/*
	 * Copy the saved context for the clone(2) system call so that the
	 * new thread may use it to initialise registers.
	 */
	bcopy(ucp, &cs->c_uc, sizeof (cs->c_uc));
	if ((cs->c_lx_tsd = malloc(sizeof (*cs->c_lx_tsd))) == NULL) {
		free(cs);
		return (-ENOMEM);
	}

	clone_res = 0;

	/*
	 * Block all signals because the thread we create won't be able to
	 * properly handle them until it's fully set up.
	 */
	VERIFY0(sigfillset(&sigmask));
	if (sigprocmask(SIG_BLOCK, &sigmask, &osigmask) < 0) {
		lx_debug("lx_clone sigprocmask() failed: %d", errno);
		free(cs->c_lx_tsd);
		free(cs);
		return (-errno);
	}
	cs->c_uc.uc_sigmask = osigmask;

	/*
	 * Allocate the native stack for this new thread now, so that we
	 * can return failure gracefully as ENOMEM.
	 */
	if (lx_alloc_stack(&cs->c_ntv_stk, &cs->c_ntv_stk_sz) != 0) {
		free(cs->c_lx_tsd);
		free(cs);
		return (-ENOMEM);
	}

	rval = thr_create(NULL, NULL, clone_start, cs, THR_DETACHED, &tid);

	/*
	 * If the thread did not start, free the resources we allocated:
	 */
	if (rval != 0) {
		(void) munmap(cs->c_ntv_stk, cs->c_ntv_stk_sz);
		free(cs->c_lx_tsd);
		free(cs);
	}

	/*
	 * Release any pending signals
	 */
	(void) sigprocmask(SIG_SETMASK, &osigmask, NULL);

	/*
	 * Wait for the child to be created and have its tid assigned.
	 */
	if (rval == 0) {
		while (clone_res == 0)
			;

		rval = clone_res;
		lx_ptrace_stop_if_option(ptrace_event, B_FALSE, (ulong_t)rval,
		    NULL);

		return (rval);
	} else {
		/*
		 * Return the error from thr_create(3C).
		 */
		return (-rval);
	}
}
