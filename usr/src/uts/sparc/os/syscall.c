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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/param.h>
#include <sys/vmparam.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/signal.h>
#include <sys/stack.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/var.h>
#include <sys/inline.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#include <sys/cpuvar.h>
#include <sys/siginfo.h>
#include <sys/trap.h>
#include <sys/machtrap.h>
#include <sys/sysinfo.h>
#include <sys/procfs.h>
#include <sys/prsystm.h>
#include <sys/fpu/fpusystm.h>
#include <sys/modctl.h>
#include <sys/aio_impl.h>
#include <c2/audit.h>
#include <sys/tnf.h>
#include <sys/tnf_probe.h>
#include <sys/machpcb.h>
#include <sys/privregs.h>
#include <sys/copyops.h>
#include <sys/timer.h>
#include <sys/priv.h>
#include <sys/msacct.h>

int syscalltrace = 0;
#ifdef SYSCALLTRACE
static kmutex_t	systrace_lock;		/* syscall tracing lock */
#endif /* SYSCALLTRACE */

static krwlock_t *lock_syscall(struct sysent *, uint_t);

#ifdef _SYSCALL32_IMPL
static struct sysent *
lwp_getsysent(klwp_t *lwp)
{
	if (lwp_getdatamodel(lwp) == DATAMODEL_NATIVE)
		return (sysent);
	return (sysent32);
}
#define	LWP_GETSYSENT(lwp)	(lwp_getsysent(lwp))
#else
#define	LWP_GETSYSENT(lwp)	(sysent)
#endif

/*
 * Called to restore the lwp's register window just before
 * returning to user level (only if the registers have been
 * fetched or modified through /proc).
 */
/*ARGSUSED1*/
void
xregrestore(klwp_t *lwp, int shared)
{
	/*
	 * If locals+ins were modified by /proc copy them out.
	 * Also copy to the shared window, if necessary.
	 */
	if (lwp->lwp_pcb.pcb_xregstat == XREGMODIFIED) {
		struct machpcb *mpcb = lwptompcb(lwp);
		caddr_t sp = (caddr_t)lwptoregs(lwp)->r_sp;

		size_t rwinsize;
		caddr_t rwp;
		int is64;

		if (lwp_getdatamodel(lwp) == DATAMODEL_LP64) {
			rwinsize = sizeof (struct rwindow);
			rwp = sp + STACK_BIAS;
			is64 = 1;
		} else {
			rwinsize = sizeof (struct rwindow32);
			sp = (caddr_t)(uintptr_t)(caddr32_t)(uintptr_t)sp;
			rwp = sp;
			is64 = 0;
		}

		if (is64)
			(void) copyout_nowatch(&lwp->lwp_pcb.pcb_xregs,
			    rwp, rwinsize);
		else {
			struct rwindow32 rwindow32;
			int watched;

			watched = watch_disable_addr(rwp, rwinsize, S_WRITE);
			rwindow_nto32(&lwp->lwp_pcb.pcb_xregs, &rwindow32);
			(void) copyout(&rwindow32, rwp, rwinsize);
			if (watched)
				watch_enable_addr(rwp, rwinsize, S_WRITE);
		}

		/* also copy to the user return window */
		mpcb->mpcb_rsp[0] = sp;
		mpcb->mpcb_rsp[1] = NULL;
		bcopy(&lwp->lwp_pcb.pcb_xregs, &mpcb->mpcb_rwin[0],
		    sizeof (lwp->lwp_pcb.pcb_xregs));
	}
	lwp->lwp_pcb.pcb_xregstat = XREGNONE;
}


/*
 * Get the arguments to the current system call.
 *	lwp->lwp_ap normally points to the out regs in the reg structure.
 *	If the user is going to change the out registers and might want to
 *	get the args (for /proc tracing), it must copy the args elsewhere
 *	via save_syscall_args().
 */
uint_t
get_syscall_args(klwp_t *lwp, long *argp, int *nargsp)
{
	kthread_t	*t = lwptot(lwp);
	uint_t	code = t->t_sysnum;
	long	mask;
	long	*ap;
	int	nargs;

	if (lwptoproc(lwp)->p_model == DATAMODEL_ILP32)
		mask = (uint32_t)0xffffffffU;
	else
		mask = 0xffffffffffffffff;

	if (code != 0 && code < NSYSCALL) {

		nargs = LWP_GETSYSENT(lwp)[code].sy_narg;

		ASSERT(nargs <= MAXSYSARGS);

		*nargsp = nargs;
		ap = lwp->lwp_ap;
		while (nargs-- > 0)
			*argp++ = *ap++ & mask;
	} else {
		*nargsp = 0;
	}
	return (code);
}

#ifdef _SYSCALL32_IMPL
/*
 * Get the arguments to the current 32-bit system call.
 */
uint_t
get_syscall32_args(klwp_t *lwp, int *argp, int *nargsp)
{
	long args[MAXSYSARGS];
	uint_t i, code;

	code = get_syscall_args(lwp, args, nargsp);
	for (i = 0; i != *nargsp; i++)
		*argp++ = (int)args[i];
	return (code);
}
#endif

/*
 *	Save the system call arguments in a safe place.
 *	lwp->lwp_ap normally points to the out regs in the reg structure.
 *	If the user is going to change the out registers, g1, or the stack,
 *	and might want to get the args (for /proc tracing), it must copy
 *	the args elsewhere via save_syscall_args().
 *
 *	This may be called from stop() even when we're not in a system call.
 *	Since there's no easy way to tell, this must be safe (not panic).
 *	If the copyins get data faults, return non-zero.
 */
int
save_syscall_args()
{
	kthread_t	*t = curthread;
	klwp_t		*lwp = ttolwp(t);
	struct regs	*rp = lwptoregs(lwp);
	uint_t		code = t->t_sysnum;
	uint_t		nargs;
	int		i;
	caddr_t		ua;
	model_t		datamodel;

	if (lwp->lwp_argsaved || code == 0)
		return (0);		/* args already saved or not needed */

	if (code >= NSYSCALL) {
		nargs = 0;		/* illegal syscall */
	} else {
		struct sysent *se = LWP_GETSYSENT(lwp);
		struct sysent *callp = se + code;

		nargs = callp->sy_narg;
		if (LOADABLE_SYSCALL(callp) && nargs == 0) {
			krwlock_t	*module_lock;

			/*
			 * Find out how many arguments the system
			 * call uses.
			 *
			 * We have the property that loaded syscalls
			 * never change the number of arguments they
			 * use after they've been loaded once.  This
			 * allows us to stop for /proc tracing without
			 * holding the module lock.
			 * /proc is assured that sy_narg is valid.
			 */
			module_lock = lock_syscall(se, code);
			nargs = callp->sy_narg;
			rw_exit(module_lock);
		}
	}

	/*
	 * Fetch the system call arguments.
	 */
	if (nargs == 0)
		goto out;


	ASSERT(nargs <= MAXSYSARGS);

	if ((datamodel = lwp_getdatamodel(lwp)) == DATAMODEL_ILP32) {

		if (rp->r_g1 == 0) {	/* indirect syscall */

			lwp->lwp_arg[0] = (uint32_t)rp->r_o1;
			lwp->lwp_arg[1] = (uint32_t)rp->r_o2;
			lwp->lwp_arg[2] = (uint32_t)rp->r_o3;
			lwp->lwp_arg[3] = (uint32_t)rp->r_o4;
			lwp->lwp_arg[4] = (uint32_t)rp->r_o5;
			if (nargs > 5) {
				ua = (caddr_t)(uintptr_t)(caddr32_t)(uintptr_t)
				    (rp->r_sp + MINFRAME32);
				for (i = 5; i < nargs; i++) {
					uint32_t a;
					if (fuword32(ua, &a) != 0)
						return (-1);
					lwp->lwp_arg[i] = a;
					ua += sizeof (a);
				}
			}
		} else {
			lwp->lwp_arg[0] = (uint32_t)rp->r_o0;
			lwp->lwp_arg[1] = (uint32_t)rp->r_o1;
			lwp->lwp_arg[2] = (uint32_t)rp->r_o2;
			lwp->lwp_arg[3] = (uint32_t)rp->r_o3;
			lwp->lwp_arg[4] = (uint32_t)rp->r_o4;
			lwp->lwp_arg[5] = (uint32_t)rp->r_o5;
			if (nargs > 6) {
				ua = (caddr_t)(uintptr_t)(caddr32_t)(uintptr_t)
				    (rp->r_sp + MINFRAME32);
				for (i = 6; i < nargs; i++) {
					uint32_t a;
					if (fuword32(ua, &a) != 0)
						return (-1);
					lwp->lwp_arg[i] = a;
					ua += sizeof (a);
				}
			}
		}
	} else {
		ASSERT(datamodel == DATAMODEL_LP64);
		lwp->lwp_arg[0] = rp->r_o0;
		lwp->lwp_arg[1] = rp->r_o1;
		lwp->lwp_arg[2] = rp->r_o2;
		lwp->lwp_arg[3] = rp->r_o3;
		lwp->lwp_arg[4] = rp->r_o4;
		lwp->lwp_arg[5] = rp->r_o5;
		if (nargs > 6) {
			ua = (caddr_t)rp->r_sp + MINFRAME + STACK_BIAS;
			for (i = 6; i < nargs; i++) {
				unsigned long a;
				if (fulword(ua, &a) != 0)
					return (-1);
				lwp->lwp_arg[i] = a;
				ua += sizeof (a);
			}
		}
	}

out:
	lwp->lwp_ap = lwp->lwp_arg;
	lwp->lwp_argsaved = 1;
	t->t_post_sys = 1;	/* so lwp_ap will be reset */
	return (0);
}

void
reset_syscall_args(void)
{
	klwp_t *lwp = ttolwp(curthread);

	lwp->lwp_ap = (long *)&lwptoregs(lwp)->r_o0;
	lwp->lwp_argsaved = 0;
}

/*
 * nonexistent system call-- signal lwp (may want to handle it)
 * flag error if lwp won't see signal immediately
 * This works for old or new calling sequence.
 */
int64_t
nosys()
{
	tsignal(curthread, SIGSYS);
	return ((int64_t)set_errno(ENOSYS));
}

/*
 * Perform pre-system-call processing, including stopping for tracing,
 * auditing, microstate-accounting, etc.
 *
 * This routine is called only if the t_pre_sys flag is set.  Any condition
 * requiring pre-syscall handling must set the t_pre_sys flag.  If the
 * condition is persistent, this routine will repost t_pre_sys.
 */
int
pre_syscall(int arg0)
{
	unsigned int code;
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);
	klwp_t *lwp = ttolwp(t);
	struct regs *rp = lwptoregs(lwp);
	int	repost;

	t->t_pre_sys = repost = 0;	/* clear pre-syscall processing flag */

	ASSERT(t->t_schedflag & TS_DONT_SWAP);

	syscall_mstate(LMS_USER, LMS_SYSTEM);

	/*
	 * The syscall arguments in the out registers should be pointed to
	 * by lwp_ap.  If the args need to be copied so that the outs can
	 * be changed without losing the ability to get the args for /proc,
	 * they can be saved by save_syscall_args(), and lwp_ap will be
	 * restored by post_syscall().
	 */
	ASSERT(lwp->lwp_ap == (long *)&rp->r_o0);

	/*
	 * Make sure the thread is holding the latest credentials for the
	 * process.  The credentials in the process right now apply to this
	 * thread for the entire system call.
	 */
	if (t->t_cred != p->p_cred) {
		cred_t *oldcred = t->t_cred;
		/*
		 * DTrace accesses t_cred in probe context.  t_cred must
		 * always be either NULL, or point to a valid, allocated cred
		 * structure.
		 */
		t->t_cred = crgetcred();
		crfree(oldcred);
	}

	/*
	 * Undo special arrangements to single-step the lwp
	 * so that a debugger will see valid register contents.
	 * Also so that the pc is valid for syncfpu().
	 * Also so that a syscall like exec() can be stepped.
	 */
	if (lwp->lwp_pcb.pcb_step != STEP_NONE) {
		(void) prundostep();
		repost = 1;
	}

	/*
	 * Check for indirect system call in case we stop for tracing.
	 * Don't allow multiple indirection.
	 */
	code = t->t_sysnum;
	if (code == 0 && arg0 != 0) {		/* indirect syscall */
		code = arg0;
		t->t_sysnum = arg0;
	}

	/*
	 * From the proc(4) manual page:
	 * When entry to a system call is being traced, the traced process
	 * stops after having begun the call to the system but before the
	 * system call arguments have been fetched from the process.
	 * If proc changes the args we must refetch them after starting.
	 */
	if (PTOU(p)->u_systrap) {
		if (prismember(&PTOU(p)->u_entrymask, code)) {
			/*
			 * Recheck stop condition, now that lock is held.
			 */
			mutex_enter(&p->p_lock);
			if (PTOU(p)->u_systrap &&
			    prismember(&PTOU(p)->u_entrymask, code)) {
				stop(PR_SYSENTRY, code);
				/*
				 * Must refetch args since they were
				 * possibly modified by /proc.  Indicate
				 * that the valid copy is in the
				 * registers.
				 */
				lwp->lwp_argsaved = 0;
				lwp->lwp_ap = (long *)&rp->r_o0;
			}
			mutex_exit(&p->p_lock);
		}
		repost = 1;
	}

	if (lwp->lwp_sysabort) {
		/*
		 * lwp_sysabort may have been set via /proc while the process
		 * was stopped on PR_SYSENTRY.  If so, abort the system call.
		 * Override any error from the copyin() of the arguments.
		 */
		lwp->lwp_sysabort = 0;
		(void) set_errno(EINTR); /* sets post-sys processing */
		t->t_pre_sys = 1;	/* repost anyway */
		return (1);		/* don't do system call, return EINTR */
	}

	/* begin auditing for this syscall */
	if (audit_active == C2AUDIT_LOADED) {
		uint32_t auditing = au_zone_getstate(NULL);

		if (auditing & AU_AUDIT_MASK) {
			int error;
			if (error = audit_start(T_SYSCALL, code, auditing, \
			    0, lwp)) {
				t->t_pre_sys = 1;	/* repost anyway */
				lwp->lwp_error = 0;	/* for old drivers */
				return (error);
			}
			repost = 1;
		}
	}

#ifndef NPROBE
	/* Kernel probe */
	if (tnf_tracing_active) {
		TNF_PROBE_1(syscall_start, "syscall thread", /* CSTYLED */,
			tnf_sysnum,	sysnum,		t->t_sysnum);
		t->t_post_sys = 1;	/* make sure post_syscall runs */
		repost = 1;
	}
#endif /* NPROBE */

#ifdef SYSCALLTRACE
	if (syscalltrace) {
		int i;
		long *ap;
		char *cp;
		char *sysname;
		struct sysent *callp;

		if (code >= NSYSCALL)
			callp = &nosys_ent;	/* nosys has no args */
		else
			callp = LWP_GETSYSENT(lwp) + code;
		(void) save_syscall_args();
		mutex_enter(&systrace_lock);
		printf("%d: ", p->p_pid);
		if (code >= NSYSCALL)
			printf("0x%x", code);
		else {
			sysname = mod_getsysname(code);
			printf("%s[0x%x]", sysname == NULL ? "NULL" :
			    sysname, code);
		}
		cp = "(";
		for (i = 0, ap = lwp->lwp_ap; i < callp->sy_narg; i++, ap++) {
			printf("%s%lx", cp, *ap);
			cp = ", ";
		}
		if (i)
			printf(")");
		printf(" %s id=0x%p\n", PTOU(p)->u_comm, curthread);
		mutex_exit(&systrace_lock);
	}
#endif /* SYSCALLTRACE */

	/*
	 * If there was a continuing reason for pre-syscall processing,
	 * set the t_pre_sys flag for the next system call.
	 */
	if (repost)
		t->t_pre_sys = 1;
	lwp->lwp_error = 0;	/* for old drivers */
	lwp->lwp_badpriv = PRIV_NONE;	/* for privilege tracing */
	return (0);
}

/*
 * Post-syscall processing.  Perform abnormal system call completion
 * actions such as /proc tracing, profiling, signals, preemption, etc.
 *
 * This routine is called only if t_post_sys, t_sig_check, or t_astflag is set.
 * Any condition requiring pre-syscall handling must set one of these.
 * If the condition is persistent, this routine will repost t_post_sys.
 */
void
post_syscall(long rval1, long rval2)
{
	kthread_t	*t = curthread;
	proc_t	*p = curproc;
	klwp_t	*lwp = ttolwp(t);
	struct regs *rp = lwptoregs(lwp);
	uint_t	error;
	int	code = t->t_sysnum;
	int	repost = 0;
	int	proc_stop = 0;		/* non-zero if stopping for /proc */
	int	sigprof = 0;		/* non-zero if sending SIGPROF */

	t->t_post_sys = 0;

	error = lwp->lwp_errno;

	/*
	 * Code can be zero if this is a new LWP returning after a forkall(),
	 * other than the one which matches the one in the parent which called
	 * forkall().  In these LWPs, skip most of post-syscall activity.
	 */
	if (code == 0)
		goto sig_check;

	/* put out audit record for this syscall */
	if (AU_AUDITING()) {
		rval_t	rval;	/* fix audit_finish() someday */

		/* XX64 -- truncation of 64-bit return values? */
		rval.r_val1 = (int)rval1;
		rval.r_val2 = (int)rval2;
		audit_finish(T_SYSCALL, code, error, &rval);
		repost = 1;
	}

	if (curthread->t_pdmsg != NULL) {
		char *m = curthread->t_pdmsg;

		uprintf("%s", m);
		kmem_free(m, strlen(m) + 1);
		curthread->t_pdmsg = NULL;
	}

	/*
	 * If we're going to stop for /proc tracing, set the flag and
	 * save the arguments so that the return values don't smash them.
	 */
	if (PTOU(p)->u_systrap) {
		if (prismember(&PTOU(p)->u_exitmask, code)) {
			proc_stop = 1;
			(void) save_syscall_args();
		}
		repost = 1;
	}

	/*
	 * Similarly check to see if SIGPROF might be sent.
	 */
	if (curthread->t_rprof != NULL &&
	    curthread->t_rprof->rp_anystate != 0) {
		(void) save_syscall_args();
		sigprof = 1;
	}

	if (lwp->lwp_eosys == NORMALRETURN) {
		if (error == 0) {
#ifdef SYSCALLTRACE
			if (syscalltrace) {
				mutex_enter(&systrace_lock);
				printf(
				    "%d: r_val1=0x%lx, r_val2=0x%lx, id 0x%p\n",
				    p->p_pid, rval1, rval2, curthread);
				mutex_exit(&systrace_lock);
			}
#endif /* SYSCALLTRACE */
			rp->r_tstate &= ~TSTATE_IC;
			rp->r_o0 = rval1;
			rp->r_o1 = rval2;
		} else {
			int sig;

#ifdef SYSCALLTRACE
			if (syscalltrace) {
				mutex_enter(&systrace_lock);
				printf("%d: error=%d, id 0x%p\n",
				    p->p_pid, error, curthread);
				mutex_exit(&systrace_lock);
			}
#endif /* SYSCALLTRACE */
			if (error == EINTR && t->t_activefd.a_stale)
				error = EBADF;
			if (error == EINTR &&
			    (sig = lwp->lwp_cursig) != 0 &&
			    sigismember(&PTOU(p)->u_sigrestart, sig) &&
			    PTOU(p)->u_signal[sig - 1] != SIG_DFL &&
			    PTOU(p)->u_signal[sig - 1] != SIG_IGN)
				error = ERESTART;
			rp->r_o0 = error;
			rp->r_tstate |= TSTATE_IC;
		}
		/*
		 * The default action is to redo the trap instruction.
		 * We increment the pc and npc past it for NORMALRETURN.
		 * JUSTRETURN has set up a new pc and npc already.
		 * If we are a cloned thread of forkall(), don't
		 * adjust here because we have already inherited
		 * the adjusted values from our clone.
		 */
		if (!(t->t_flag & T_FORKALL)) {
			rp->r_pc = rp->r_npc;
			rp->r_npc += 4;
		}
	}

	/*
	 * From the proc(4) manual page:
	 * When exit from a system call is being traced, the traced process
	 * stops on completion of the system call just prior to checking for
	 * signals and returning to user level.  At this point all return
	 * values have been stored into the traced process's saved registers.
	 */
	if (proc_stop) {
		mutex_enter(&p->p_lock);
		if (PTOU(p)->u_systrap &&
		    prismember(&PTOU(p)->u_exitmask, code))
			stop(PR_SYSEXIT, code);
		mutex_exit(&p->p_lock);
	}

	/*
	 * If we are the parent returning from a successful
	 * vfork, wait for the child to exec or exit.
	 * This code must be here and not in the bowels of the system
	 * so that /proc can intercept exit from vfork in a timely way.
	 */
	if (t->t_flag & T_VFPARENT) {
		ASSERT(code == SYS_vfork || code == SYS_forksys);
		ASSERT(rp->r_o1 == 0 && error == 0);
		vfwait((pid_t)rval1);
		t->t_flag &= ~T_VFPARENT;
	}

	/*
	 * If profiling is active, bill the current PC in user-land
	 * and keep reposting until profiling is disabled.
	 */
	if (p->p_prof.pr_scale) {
		if (lwp->lwp_oweupc)
			profil_tick(rp->r_pc);
		repost = 1;
	}

sig_check:
	/*
	 * Reset flag for next time.
	 * We must do this after stopping on PR_SYSEXIT
	 * because /proc uses the information in lwp_eosys.
	 */
	lwp->lwp_eosys = NORMALRETURN;
	clear_stale_fd();
	t->t_flag &= ~T_FORKALL;

	if (t->t_astflag | t->t_sig_check) {
		/*
		 * Turn off the AST flag before checking all the conditions that
		 * may have caused an AST.  This flag is on whenever a signal or
		 * unusual condition should be handled after the next trap or
		 * syscall.
		 */
		astoff(t);
		t->t_sig_check = 0;

		/*
		 * The following check is legal for the following reasons:
		 *	1) The thread we are checking, is ourselves, so there is
		 *	   no way the proc can go away.
		 *	2) The only time we need to be protected by the
		 *	   lock is if the binding is changed.
		 *
		 *	Note we will still take the lock and check the binding
		 *	if the condition was true without the lock held.  This
		 *	prevents lock contention among threads owned by the
		 *	same proc.
		 */

		if (curthread->t_proc_flag & TP_CHANGEBIND) {
			mutex_enter(&p->p_lock);
			if (curthread->t_proc_flag & TP_CHANGEBIND) {
				timer_lwpbind();
				curthread->t_proc_flag &= ~TP_CHANGEBIND;
			}
			mutex_exit(&p->p_lock);
		}

		/*
		 * for kaio requests on the special kaio poll queue,
		 * copyout their results to user memory.
		 */
		if (p->p_aio)
			aio_cleanup(0);

		/*
		 * If this LWP was asked to hold, call holdlwp(), which will
		 * stop.  holdlwps() sets this up and calls pokelwps() which
		 * sets the AST flag.
		 *
		 * Also check TP_EXITLWP, since this is used by fresh new LWPs
		 * through lwp_rtt().  That flag is set if the lwp_create(2)
		 * syscall failed after creating the LWP.
		 */
		if (ISHOLD(p) || (t->t_proc_flag & TP_EXITLWP))
			holdlwp();

		/*
		 * All code that sets signals and makes ISSIG_PENDING
		 * evaluate true must set t_sig_check afterwards.
		 */
		if (ISSIG_PENDING(t, lwp, p)) {
			if (issig(FORREAL))
				psig();
			t->t_sig_check = 1;	/* recheck next time */
		}

		if (sigprof) {
			int nargs = (code > 0 && code < NSYSCALL)?
			    LWP_GETSYSENT(lwp)[code].sy_narg : 0;
			realsigprof(code, nargs, error);
			t->t_sig_check = 1;	/* recheck next time */
		}

		/*
		 * If a performance counter overflow interrupt was
		 * delivered *during* the syscall, then re-enable the
		 * AST so that we take a trip through trap() to cause
		 * the SIGEMT to be delivered.
		 */
		if (lwp->lwp_pcb.pcb_flags & CPC_OVERFLOW)
			aston(t);

		/*
		 * If an asynchronous hardware error is pending, turn AST flag
		 * back on.  AST will be checked again before we return to user
		 * mode and we'll come back through trap() to handle the error.
		 */
		if (lwp->lwp_pcb.pcb_flags & ASYNC_HWERR)
			aston(t);
	}

	/*
	 * Restore register window if a debugger modified it.
	 * Set up to perform a single-step if a debugger requested it.
	 */
	if (lwp->lwp_pcb.pcb_xregstat != XREGNONE)
		xregrestore(lwp, 1);

	lwp->lwp_errno = 0;		/* clear error for next time */

#ifndef NPROBE
	/* Kernel probe */
	if (tnf_tracing_active) {
		TNF_PROBE_3(syscall_end, "syscall thread", /* CSTYLED */,
		    tnf_long,	rval1,		rval1,
		    tnf_long,	rval2,		rval2,
		    tnf_long,	errno,		(long)error);
		repost = 1;
	}
#endif /* NPROBE */

	/*
	 * Set state to LWP_USER here so preempt won't give us a kernel
	 * priority if it occurs after this point.  Call CL_TRAPRET() to
	 * restore the user-level priority.
	 *
	 * It is important that no locks (other than spinlocks) be entered
	 * after this point before returning to user mode (unless lwp_state
	 * is set back to LWP_SYS).
	 *
	 * Sampled times past this point are charged to the user.
	 */
	lwp->lwp_state = LWP_USER;

	if (t->t_trapret) {
		t->t_trapret = 0;
		thread_lock(t);
		CL_TRAPRET(t);
		thread_unlock(t);
	}
	if (CPU->cpu_runrun || t->t_schedflag & TS_ANYWAITQ)
		preempt();
	prunstop();

	/*
	 * t_post_sys will be set if pcb_step is active.
	 */
	if (lwp->lwp_pcb.pcb_step != STEP_NONE) {
		prdostep();
		repost = 1;
	}

	t->t_sysnum = 0;	/* no longer in a system call */

	/*
	 * In case the args were copied to the lwp, reset the
	 * pointer so the next syscall will have the right lwp_ap pointer.
	 */
	lwp->lwp_ap = (long *)&rp->r_o0;
	lwp->lwp_argsaved = 0;

	/*
	 * If there was a continuing reason for post-syscall processing,
	 * set the t_post_sys flag for the next system call.
	 */
	if (repost)
		t->t_post_sys = 1;

	/*
	 * If there is a ustack registered for this lwp, and the stack rlimit
	 * has been altered, read in the ustack. If the saved stack rlimit
	 * matches the bounds of the ustack, update the ustack to reflect
	 * the new rlimit. If the new stack rlimit is RLIM_INFINITY, disable
	 * stack checking by setting the size to 0.
	 */
	if (lwp->lwp_ustack != 0 && lwp->lwp_old_stk_ctl != 0) {
		rlim64_t new_size;
		model_t model;
		caddr_t top;
		struct rlimit64 rl;

		mutex_enter(&p->p_lock);
		new_size = p->p_stk_ctl;
		model = p->p_model;
		top = p->p_usrstack;
		(void) rctl_rlimit_get(rctlproc_legacy[RLIMIT_STACK], p, &rl);
		mutex_exit(&p->p_lock);

		if (rl.rlim_cur == RLIM64_INFINITY)
			new_size = 0;

		if (model == DATAMODEL_NATIVE) {
			stack_t stk;

			if (copyin((stack_t *)lwp->lwp_ustack, &stk,
			    sizeof (stack_t)) == 0 &&
			    (stk.ss_size == lwp->lwp_old_stk_ctl ||
			    stk.ss_size == 0) &&
			    stk.ss_sp == top - stk.ss_size) {
				stk.ss_sp = (void *)((uintptr_t)stk.ss_sp +
				    stk.ss_size - new_size);
				stk.ss_size = new_size;

				(void) copyout(&stk,
				    (stack_t *)lwp->lwp_ustack,
				    sizeof (stack_t));
			}
		} else {
			stack32_t stk32;

			if (copyin((stack32_t *)lwp->lwp_ustack, &stk32,
			    sizeof (stack32_t)) == 0 &&
			    (stk32.ss_size == lwp->lwp_old_stk_ctl ||
			    stk32.ss_size == 0) &&
			    stk32.ss_sp ==
			    (caddr32_t)(uintptr_t)(top - stk32.ss_size)) {
				stk32.ss_sp += stk32.ss_size - new_size;
				stk32.ss_size = new_size;

				(void) copyout(&stk32,
				    (stack32_t *)lwp->lwp_ustack,
				    sizeof (stack32_t));
			}
		}

		lwp->lwp_old_stk_ctl = 0;
	}

	syscall_mstate(LMS_SYSTEM, LMS_USER);
}

/*
 * Call a system call which takes a pointer to the user args struct and
 * a pointer to the return values.  This is a bit slower than the standard
 * C arg-passing method in some cases.
 */
int64_t
syscall_ap()
{
	uint_t	error;
	struct sysent *callp;
	rval_t	rval;
	klwp_t	*lwp = ttolwp(curthread);
	struct regs *rp = lwptoregs(lwp);

	callp = LWP_GETSYSENT(lwp) + curthread->t_sysnum;

	/*
	 * If the arguments don't fit in registers %o0 - o5, make sure they
	 * have been copied to the lwp_arg array.
	 */
	if (callp->sy_narg > 6 && save_syscall_args())
		return ((int64_t)set_errno(EFAULT));

	rval.r_val1 = 0;
	rval.r_val2 = (int)rp->r_o1;
	lwp->lwp_error = 0;	/* for old drivers */
	error = (*(callp->sy_call))(lwp->lwp_ap, &rval);
	if (error)
		return ((int64_t)set_errno(error));
	return (rval.r_vals);
}

/*
 * Load system call module.
 *	Returns with pointer to held read lock for module.
 */
static krwlock_t *
lock_syscall(struct sysent *table, uint_t code)
{
	krwlock_t	*module_lock;
	struct modctl	*modp;
	int		id;
	struct sysent   *callp;

	module_lock = table[code].sy_lock;
	callp = &table[code];

	/*
	 * Optimization to only call modload if we don't have a loaded
	 * syscall.
	 */
	rw_enter(module_lock, RW_READER);
	if (LOADED_SYSCALL(callp))
		return (module_lock);
	rw_exit(module_lock);

	for (;;) {
		if ((id = modload("sys", syscallnames[code])) == -1)
			break;

		/*
		 * If we loaded successfully at least once, the modctl
		 * will still be valid, so we try to grab it by filename.
		 * If this call fails, it's because the mod_filename
		 * was changed after the call to modload() (mod_hold_by_name()
		 * is the likely culprit).  We can safely just take
		 * another lap if this is the case;  the modload() will
		 * change the mod_filename back to one by which we can
		 * find the modctl.
		 */
		modp = mod_find_by_filename("sys", syscallnames[code]);

		if (modp == NULL)
			continue;

		mutex_enter(&mod_lock);

		if (!modp->mod_installed) {
			mutex_exit(&mod_lock);
			continue;
		}
		break;
	}

	rw_enter(module_lock, RW_READER);

	if (id != -1)
		mutex_exit(&mod_lock);

	return (module_lock);
}

/*
 * Loadable syscall support.
 *	If needed, load the module, then reserve it by holding a read
 *	lock for the duration of the call.
 *	Later, if the syscall is not unloadable, it could patch the vector.
 */
/*ARGSUSED*/
int64_t
loadable_syscall(
    long a0, long a1, long a2, long a3,
    long a4, long a5, long a6, long a7)
{
	int64_t		rval;
	struct sysent	*callp;
	struct sysent	*se = LWP_GETSYSENT(ttolwp(curthread));
	krwlock_t	*module_lock;
	int		code;

	code = curthread->t_sysnum;
	callp = se + code;

	/*
	 * Try to autoload the system call if necessary.
	 */
	module_lock = lock_syscall(se, code);

	/*
	 * we've locked either the loaded syscall or nosys
	 */
	if (callp->sy_flags & SE_ARGC) {
		int64_t (*sy_call)();

		sy_call = (int64_t (*)())callp->sy_call;
		rval = (*sy_call)(a0, a1, a2, a3, a4, a5);
	} else {
		rval = syscall_ap();
	}

	rw_exit(module_lock);
	return (rval);
}

/*
 * Handle indirect system calls.
 *	This interface should be deprecated.  The library can handle
 *	this more efficiently, but keep this implementation for old binaries.
 *
 * XX64	Needs some work.
 */
int64_t
indir(int code, long a0, long a1, long a2, long a3, long a4)
{
	klwp_t		*lwp = ttolwp(curthread);
	struct sysent	*callp;

	if (code <= 0 || code >= NSYSCALL)
		return (nosys());

	ASSERT(lwp->lwp_ap != NULL);

	curthread->t_sysnum = code;
	callp = LWP_GETSYSENT(lwp) + code;

	/*
	 * Handle argument setup, unless already done in pre_syscall().
	 */
	if (callp->sy_narg > 5) {
		if (save_syscall_args())	/* move args to LWP array */
			return ((int64_t)set_errno(EFAULT));
	} else if (!lwp->lwp_argsaved) {
		long *ap;

		ap = lwp->lwp_ap;		/* args haven't been saved */
		lwp->lwp_ap = ap + 1;		/* advance arg pointer */
		curthread->t_post_sys = 1;	/* so lwp_ap will be reset */
	}
	return ((*callp->sy_callc)(a0, a1, a2, a3, a4, lwp->lwp_arg[5]));
}

/*
 * set_errno - set an error return from the current system call.
 *	This could be a macro.
 *	This returns the value it is passed, so that the caller can
 *	use tail-recursion-elimination and do return (set_errno(ERRNO));
 */
uint_t
set_errno(uint_t error)
{
	ASSERT(error != 0);		/* must not be used to clear errno */

	curthread->t_post_sys = 1;	/* have post_syscall do error return */
	return (ttolwp(curthread)->lwp_errno = error);
}

/*
 * set_proc_pre_sys - Set pre-syscall processing for entire process.
 */
void
set_proc_pre_sys(proc_t *p)
{
	kthread_t	*t;
	kthread_t	*first;

	ASSERT(MUTEX_HELD(&p->p_lock));

	t = first = p->p_tlist;
	do {
		t->t_pre_sys = 1;
	} while ((t = t->t_forw) != first);
}

/*
 * set_proc_post_sys - Set post-syscall processing for entire process.
 */
void
set_proc_post_sys(proc_t *p)
{
	kthread_t	*t;
	kthread_t	*first;

	ASSERT(MUTEX_HELD(&p->p_lock));

	t = first = p->p_tlist;
	do {
		t->t_post_sys = 1;
	} while ((t = t->t_forw) != first);
}

/*
 * set_proc_sys - Set pre- and post-syscall processing for entire process.
 */
void
set_proc_sys(proc_t *p)
{
	kthread_t	*t;
	kthread_t	*first;

	ASSERT(MUTEX_HELD(&p->p_lock));

	t = first = p->p_tlist;
	do {
		t->t_pre_sys = 1;
		t->t_post_sys = 1;
	} while ((t = t->t_forw) != first);
}

/*
 * set_all_proc_sys - set pre- and post-syscall processing flags for all
 * user processes.
 *
 * This is needed when auditing, tracing, or other facilities which affect
 * all processes are turned on.
 */
void
set_all_proc_sys()
{
	kthread_t	*t;
	kthread_t	*first;

	mutex_enter(&pidlock);
	t = first = curthread;
	do {
		t->t_pre_sys = 1;
		t->t_post_sys = 1;
	} while ((t = t->t_next) != first);
	mutex_exit(&pidlock);
}

/*
 * set_all_zone_usr_proc_sys - set pre- and post-syscall processing flags for
 * all user processes running in the zone of the current process
 *
 * This is needed when auditing is turned on.
 */
void
set_all_zone_usr_proc_sys(zoneid_t zoneid)
{
	proc_t	    *p;
	kthread_t   *t;

	mutex_enter(&pidlock);
	for (p = practive; p != NULL; p = p->p_next) {
		/* skip kernel processes */
		if (p->p_exec == NULLVP || p->p_as == &kas ||
		    p->p_stat == SIDL || p->p_stat == SZOMB ||
		    (p->p_flag & (SSYS | SEXITING | SEXITLWPS)))
			continue;
		/*
		 * Only processes in the given zone (eventually in
		 * all zones) are taken into account
		 */
		if (zoneid == ALL_ZONES || p->p_zone->zone_id == zoneid) {
			mutex_enter(&p->p_lock);
			if ((t = p->p_tlist) == NULL) {
				mutex_exit(&p->p_lock);
				continue;
			}
			/*
			 * Set pre- and post-syscall processing flags
			 * for all threads of the process
			 */
			do {
				t->t_pre_sys = 1;
				t->t_post_sys = 1;
			} while (p->p_tlist != (t = t->t_forw));
			mutex_exit(&p->p_lock);
		}
	}
	mutex_exit(&pidlock);
}

/*
 * set_proc_ast - Set asynchronous service trap (AST) flag for all
 * threads in process.
 */
void
set_proc_ast(proc_t *p)
{
	kthread_t	*t;
	kthread_t	*first;

	ASSERT(MUTEX_HELD(&p->p_lock));

	t = first = p->p_tlist;
	do {
		aston(t);
	} while ((t = t->t_forw) != first);
}
