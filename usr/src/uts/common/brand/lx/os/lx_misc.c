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
 */

/*
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */

#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/privregs.h>
#include <sys/exec.h>
#include <sys/lwp.h>
#include <sys/sem.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>
#include <sys/lx_misc.h>
#include <sys/lx_pid.h>
#include <sys/lx_futex.h>
#include <sys/cmn_err.h>
#include <sys/siginfo.h>
#include <sys/contract/process_impl.h>
#include <sys/x86_archext.h>
#include <sys/sdt.h>
#include <lx_signum.h>
#include <lx_syscall.h>
#include <sys/proc.h>
#include <net/if.h>
#include <sys/sunddi.h>

/* Linux specific functions and definitions */
void lx_setrval(klwp_t *, int, int);
void lx_exec();
int lx_initlwp(klwp_t *);
void lx_forklwp(klwp_t *, klwp_t *);
void lx_exitlwp(klwp_t *);
void lx_freelwp(klwp_t *);
static void lx_save(klwp_t *);
static void lx_restore(klwp_t *);
extern void lx_ptrace_free(proc_t *);

/*
 * Set the return code for the forked child, always zero
 */
/*ARGSUSED*/
void
lx_setrval(klwp_t *lwp, int v1, int v2)
{
	lwptoregs(lwp)->r_r0 = 0;
}

/*
 * Reset process state on exec(2)
 */
void
lx_exec()
{
	klwp_t *lwp = ttolwp(curthread);
	struct lx_lwp_data *lwpd = lwptolxlwp(lwp);
	proc_t *p = ttoproc(curthread);
	lx_proc_data_t *pd = ptolxproc(p);
	int err;

	/*
	 * Any l_handler handlers set as a result of B_REGISTER are now
	 * invalid; clear them.
	 */
	pd->l_handler = NULL;
	pd->l_tracehandler = NULL;

	/*
	 * There are two mutually exclusive special cases we need to
	 * address.  First, if this was a native process prior to this
	 * exec(), then this lwp won't have its brand-specific data
	 * initialized and it won't be assigned a Linux PID yet.  Second,
	 * if this was a multi-threaded Linux process and this lwp wasn't
	 * the main lwp, then we need to make its Solaris and Linux PIDS
	 * match.
	 */
	if (lwpd == NULL) {
		err = lx_initlwp(lwp);
		/*
		 * Only possible failure from this routine should be an
		 * inability to allocate a new PID.  Since single-threaded
		 * processes don't need a new PID, we should never hit this
		 * error.
		 */
		ASSERT(err == 0);
		lwpd = lwptolxlwp(lwp);
	} else if (curthread->t_tid != 1) {
		lx_pid_reassign(curthread);
	}

	/*
	 * Inform ptrace(2) that we are processing an execve(2) call so that if
	 * we are traced we can post either the PTRACE_EVENT_EXEC event or the
	 * legacy SIGTRAP.
	 */
	(void) lx_ptrace_stop_for_option(LX_PTRACE_O_TRACEEXEC, B_FALSE, 0);

	/* clear the fsbase values until the app. can reinitialize them */
	lwpd->br_lx_fsbase = NULL;
	lwpd->br_ntv_fsbase = NULL;

	installctx(lwptot(lwp), lwp, lx_save, lx_restore, NULL, NULL, lx_save,
	    NULL);

	/*
	 * clear out the tls array
	 */
	bzero(lwpd->br_tls, sizeof (lwpd->br_tls));

	/*
	 * reset the tls entries in the gdt
	 */
	kpreempt_disable();
	lx_restore(lwp);
	kpreempt_enable();
}

void
lx_exitlwp(klwp_t *lwp)
{
	struct lx_lwp_data *lwpd = lwptolxlwp(lwp);
	proc_t *p = lwptoproc(lwp);
	kthread_t *t;
	sigqueue_t *sqp = NULL;
	pid_t ppid;
	id_t ptid;

	VERIFY(MUTEX_NOT_HELD(&p->p_lock));

	if (lwpd == NULL)
		return;		/* second time thru' */

	mutex_enter(&p->p_lock);
	lx_ptrace_exit(p, lwp);
	mutex_exit(&p->p_lock);

	if (lwpd->br_clear_ctidp != NULL) {
		(void) suword32(lwpd->br_clear_ctidp, 0);
		(void) lx_futex((uintptr_t)lwpd->br_clear_ctidp, FUTEX_WAKE, 1,
		    NULL, NULL, 0);
	}

	if (lwpd->br_signal != 0) {
		/*
		 * The first thread in a process doesn't cause a signal to
		 * be sent when it exits.  It was created by a fork(), not
		 * a clone(), so the parent should get signalled when the
		 * process exits.
		 */
		if (lwpd->br_ptid == -1)
			goto free;

		sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);
		/*
		 * If br_ppid is 0, it means this is a CLONE_PARENT thread,
		 * so the signal goes to the parent process - not to a
		 * specific thread in this process.
		 */
		p = lwptoproc(lwp);
		if (lwpd->br_ppid == 0) {
			mutex_enter(&p->p_lock);
			ppid = p->p_ppid;
			t = NULL;
		} else {
			/*
			 * If we have been reparented to init or if our
			 * parent thread is gone, then nobody gets
			 * signaled.
			 */
			if ((lx_lwp_ppid(lwp, &ppid, &ptid) == 1) ||
			    (ptid == -1))
				goto free;

			mutex_enter(&pidlock);
			if ((p = prfind(ppid)) == NULL || p->p_stat == SIDL) {
				mutex_exit(&pidlock);
				goto free;
			}
			mutex_enter(&p->p_lock);
			mutex_exit(&pidlock);

			if ((t = idtot(p, ptid)) == NULL) {
				mutex_exit(&p->p_lock);
				goto free;
			}
		}

		sqp->sq_info.si_signo = lwpd->br_signal;
		sqp->sq_info.si_code = lwpd->br_exitwhy;
		sqp->sq_info.si_status = lwpd->br_exitwhat;
		sqp->sq_info.si_pid = lwpd->br_pid;
		sqp->sq_info.si_uid = crgetruid(CRED());
		sigaddqa(p, t, sqp);
		mutex_exit(&p->p_lock);
		sqp = NULL;
	}

free:
	if (lwpd->br_scall_args != NULL) {
		ASSERT(lwpd->br_args_size > 0);
		kmem_free(lwpd->br_scall_args, lwpd->br_args_size);
	}
	if (sqp)
		kmem_free(sqp, sizeof (sigqueue_t));

	lx_freelwp(lwp);
}

void
lx_freelwp(klwp_t *lwp)
{
	struct lx_lwp_data *lwpd = lwptolxlwp(lwp);

	if (lwpd != NULL) {
		(void) removectx(lwptot(lwp), lwp, lx_save, lx_restore,
		    NULL, NULL, lx_save, NULL);
		if (lwpd->br_pid != 0) {
			lx_pid_rele(lwptoproc(lwp)->p_pid,
			    lwptot(lwp)->t_tid);
		}

		/*
		 * Ensure that lx_ptrace_exit() has been called to detach
		 * ptrace(2) tracers and tracees.
		 */
		VERIFY(lwpd->br_ptrace_tracer == NULL);
		VERIFY(lwpd->br_ptrace_accord == NULL);

		lwp->lwp_brand = NULL;
		kmem_free(lwpd, sizeof (struct lx_lwp_data));
	}
}

int
lx_initlwp(klwp_t *lwp)
{
	lx_lwp_data_t *lwpd;
	lx_lwp_data_t *plwpd = ttolxlwp(curthread);
	kthread_t *tp = lwptot(lwp);

	lwpd = kmem_zalloc(sizeof (struct lx_lwp_data), KM_SLEEP);
	lwpd->br_exitwhy = CLD_EXITED;
	lwpd->br_lwp = lwp;
	lwpd->br_clear_ctidp = NULL;
	lwpd->br_set_ctidp = NULL;
	lwpd->br_signal = 0;
	lwpd->br_ntv_syscall = 1;
	lwpd->br_scms = 1;

	/*
	 * lwpd->br_affinitymask was zeroed by kmem_zalloc()
	 * as was lwpd->br_scall_args and lwpd->br_args_size.
	 */

	/*
	 * The first thread in a process has ppid set to the parent
	 * process's pid, and ptid set to -1.  Subsequent threads in the
	 * process have their ppid set to the pid of the thread that
	 * created them, and their ptid to that thread's tid.
	 */
	if (tp->t_next == tp) {
		lwpd->br_ppid = tp->t_procp->p_ppid;
		lwpd->br_ptid = -1;
	} else if (plwpd != NULL) {
		bcopy(plwpd->br_tls, lwpd->br_tls, sizeof (lwpd->br_tls));
		lwpd->br_ppid = plwpd->br_pid;
		lwpd->br_ptid = curthread->t_tid;
		/* The child inherits the 2 fsbase values from the parent */
		lwpd->br_lx_fsbase = plwpd->br_lx_fsbase;
		lwpd->br_ntv_fsbase = plwpd->br_ntv_fsbase;
	} else {
		/*
		 * Oddball case: the parent thread isn't a Linux process.
		 */
		lwpd->br_ppid = 0;
		lwpd->br_ptid = -1;
	}
	lwp->lwp_brand = lwpd;

	if (lx_pid_assign(tp)) {
		kmem_free(lwpd, sizeof (struct lx_lwp_data));
		lwp->lwp_brand = NULL;
		return (-1);
	}
	lwpd->br_tgid = lwpd->br_pid;

	installctx(lwptot(lwp), lwp, lx_save, lx_restore, NULL, NULL,
	    lx_save, NULL);

	/*
	 * If the parent LWP has a ptrace(2) tracer, the new LWP may
	 * need to inherit that same tracer.
	 */
	if (plwpd != NULL) {
		lx_ptrace_inherit_tracer(plwpd, lwpd);
	}

	return (0);
}

/*
 * There is no need to have any locking for either the source or
 * destination struct lx_lwp_data structs.  This is always run in the
 * thread context of the source thread, and the destination thread is
 * always newly created and not referred to from anywhere else.
 */
void
lx_forklwp(klwp_t *srclwp, klwp_t *dstlwp)
{
	struct lx_lwp_data *src = srclwp->lwp_brand;
	struct lx_lwp_data *dst = dstlwp->lwp_brand;

	dst->br_ppid = src->br_pid;
	dst->br_ptid = lwptot(srclwp)->t_tid;
	bcopy(src->br_tls, dst->br_tls, sizeof (dst->br_tls));

	/*
	 * copy only these flags
	 */
	dst->br_lwp_flags = src->br_lwp_flags & BR_CPU_BOUND;
	dst->br_scall_args = NULL;
}

/*
 * When switching a Linux process off the CPU, clear its GDT entries.
 */
/* ARGSUSED */
static void
lx_save(klwp_t *t)
{
	int i;

#if defined(__amd64)
	reset_sregs();
#endif
	for (i = 0; i < LX_TLSNUM; i++)
		gdt_update_usegd(GDT_TLSMIN + i, &null_udesc);
}

/*
 * When switching a Linux process on the CPU, set its GDT entries.
 *
 * For 64-bit code we don't have to worry about explicitly setting the
 * %fsbase via wrmsr(MSR_AMD_FSBASE) here. Instead, that should happen
 * automatically in update_sregs if we are executing in user-land. If this
 * is the case then pcb_rupdate should be set.
 */
static void
lx_restore(klwp_t *t)
{
	struct lx_lwp_data *lwpd = lwptolxlwp(t);
	user_desc_t *tls;
	int i;

	ASSERT(lwpd);

	tls = lwpd->br_tls;
	for (i = 0; i < LX_TLSNUM; i++)
		gdt_update_usegd(GDT_TLSMIN + i, &tls[i]);
}

void
lx_set_gdt(int entry, user_desc_t *descrp)
{

	gdt_update_usegd(entry, descrp);
}

void
lx_clear_gdt(int entry)
{
	gdt_update_usegd(entry, &null_udesc);
}

longlong_t
lx_nosys()
{
	return (set_errno(ENOSYS));
}

/*
 * Brand-specific routine to check if given non-Solaris standard segment
 * register values should be modified to other values.
 */
/*ARGSUSED*/
greg_t
lx_fixsegreg(greg_t sr, model_t datamodel)
{
	uint16_t idx = SELTOIDX(sr);

	ASSERT(sr == (sr & 0xffff));

	/*
	 * If the segment selector is a valid TLS selector, just return it.
	 */
	if (!SELISLDT(sr) && idx >= GDT_TLSMIN && idx <= GDT_TLSMAX)
		return (sr | SEL_UPL);

	/*
	 * Force the SR into the LDT in ring 3 for 32-bit processes.
	 *
	 * 64-bit processes get the null GDT selector since they are not
	 * allowed to have a private LDT.
	 */
#if defined(__amd64)
	return (datamodel == DATAMODEL_ILP32 ? (sr | SEL_TI_LDT | SEL_UPL) : 0);
#elif defined(__i386)
	datamodel = datamodel;  /* datamodel currently unused for 32-bit */
	return (sr | SEL_TI_LDT | SEL_UPL);
#endif	/* __amd64 */
}

/*
 * Brand-specific function to convert the fsbase as pulled from the regsiter
 * into a native fsbase suitable for locating the ulwp_t from the kernel.
 */
uintptr_t
lx_fsbase(klwp_t *lwp, uintptr_t fsbase)
{
	lx_lwp_data_t *lwpd = lwp->lwp_brand;

	if (lwpd->br_ntv_syscall || lwpd->br_ntv_fsbase == NULL)
		return (fsbase);

	return (lwpd->br_ntv_fsbase);
}

/*
 * These two functions simulate winfo and post_sigcld for the lx brand. The
 * difference is delivering a designated signal as opposed to always SIGCLD.
 */
static void
lx_winfo(proc_t *pp, k_siginfo_t *ip, struct lx_proc_data *dat)
{
	ASSERT(MUTEX_HELD(&pidlock));
	bzero(ip, sizeof (k_siginfo_t));
	ip->si_signo = ltos_signo[dat->l_signal];
	ip->si_code = pp->p_wcode;
	ip->si_pid = pp->p_pid;
	ip->si_ctid = PRCTID(pp);
	ip->si_zoneid = pp->p_zone->zone_id;
	ip->si_status = pp->p_wdata;
	ip->si_stime = pp->p_stime;
	ip->si_utime = pp->p_utime;
}

static void
lx_post_exit_sig(proc_t *cp, sigqueue_t *sqp, struct lx_proc_data *dat)
{
	proc_t *pp = cp->p_parent;

	ASSERT(MUTEX_HELD(&pidlock));
	mutex_enter(&pp->p_lock);
	/*
	 * Since Linux doesn't queue SIGCHLD, or any other non RT
	 * signals, we just blindly deliver whatever signal we can.
	 */
	ASSERT(sqp != NULL);
	lx_winfo(cp, &sqp->sq_info, dat);
	sigaddqa(pp, NULL, sqp);
	sqp = NULL;
	mutex_exit(&pp->p_lock);
}


/*
 * Brand specific code for exiting and sending a signal to the parent, as
 * opposed to sigcld().
 */
void
lx_exit_with_sig(proc_t *cp, sigqueue_t *sqp, void *brand_data)
{
	proc_t *pp = cp->p_parent;
	struct lx_proc_data *lx_brand_data = brand_data;
	ASSERT(MUTEX_HELD(&pidlock));

	switch (cp->p_wcode) {
	case CLD_EXITED:
	case CLD_DUMPED:
	case CLD_KILLED:
			ASSERT(cp->p_stat == SZOMB);
			/*
			 * The broadcast on p_srwchan_cv is a kludge to
			 * wakeup a possible thread in uadmin(A_SHUTDOWN).
			 */
			cv_broadcast(&cp->p_srwchan_cv);

			/*
			 * Add to newstate list of the parent
			 */
			add_ns(pp, cp);

			cv_broadcast(&pp->p_cv);
			if ((pp->p_flag & SNOWAIT) ||
			    PTOU(pp)->u_signal[SIGCLD - 1] == SIG_IGN) {
				if (!(cp->p_pidflag & CLDWAITPID))
					freeproc(cp);
			} else if (!(cp->p_pidflag & CLDNOSIGCHLD) &&
			    lx_brand_data->l_signal != 0) {
				lx_post_exit_sig(cp, sqp, lx_brand_data);
				sqp = NULL;
			}
			break;

	case CLD_STOPPED:
	case CLD_CONTINUED:
	case CLD_TRAPPED:
			panic("Should not be called in this case");
	}

	if (sqp)
		siginfofree(sqp);
}

/*
 * Filters based on arguments that have been passed in by a separate syscall
 * using the B_STORE_ARGS mechanism. if the __WALL flag is set, no filter is
 * applied, otherwise we look at the difference between a clone and non-clone
 * process.
 * The definition of a clone process in Linux is a thread that does not deliver
 * SIGCHLD to its parent. The option __WCLONE   indicates to wait only on clone
 * processes. Without that option, a process should only wait on normal
 * children. The following table shows the cases.
 *
 *                   default    __WCLONE
 *   no SIGCHLD      -           X
 *   SIGCHLD         X           -
 *
 * This is an XOR of __WCLONE being set, and SIGCHLD being the signal sent on
 * process exit.
 *
 * More information on wait in lx brands can be found at
 * usr/src/lib/brand/lx/lx_brand/common/wait.c.
 */
boolean_t
lx_wait_filter(proc_t *pp, proc_t *cp)
{
	lx_lwp_data_t *lwpd = ttolxlwp(curthread);
	int flags = lwpd->br_waitid_flags;
	boolean_t ret;

	if (!lwpd->br_waitid_emulate) {
		return (B_TRUE);
	}

	mutex_enter(&cp->p_lock);
	if (flags & LX_WALL) {
		ret = B_TRUE;

	} else {
		int exitsig;
		boolean_t is_clone, _wclone;

		/*
		 * Determine the exit signal for this process:
		 */
		if (cp->p_stat == SZOMB || cp->p_brand == &native_brand) {
			exitsig = cp->p_exit_data;
		} else {
			exitsig = ptolxproc(cp)->l_signal;
		}

		/*
		 * To enable the bitwise XOR to stand in for the absent C
		 * logical XOR, we use the logical NOT operator twice to
		 * ensure the least significant bit is populated with the
		 * __WCLONE flag status.
		 */
		_wclone = !!(flags & LX_WCLONE);
		is_clone = (stol_signo[SIGCHLD] == exitsig);

		ret = (_wclone ^ is_clone) ? B_TRUE : B_FALSE;
	}
	mutex_exit(&cp->p_lock);

	return (ret);
}

void
lx_ifname_convert(char *ifname, int flag)
{
	ASSERT(flag == LX_IFNAME_FROMNATIVE ||
	    flag == LX_IFNAME_TONATIVE);

	if (flag == LX_IFNAME_TONATIVE) {
		if (strncmp(ifname, "lo", IFNAMSIZ) == 0)
			(void) strlcpy(ifname, "lo0", IFNAMSIZ);
	} else if (flag == LX_IFNAME_FROMNATIVE) {
		if (strncmp(ifname, "lo0", IFNAMSIZ) == 0)
			(void) strlcpy(ifname, "lo", IFNAMSIZ);
	}
}
