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
 * Copyright 2016, Joyent, Inc.
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
#include <sys/lx_siginfo.h>
#include <sys/lx_futex.h>
#include <lx_errno.h>
#include <sys/cmn_err.h>
#include <sys/siginfo.h>
#include <sys/contract/process_impl.h>
#include <sys/x86_archext.h>
#include <sys/sdt.h>
#include <lx_signum.h>
#include <lx_syscall.h>
#include <sys/proc.h>
#include <sys/procfs.h>
#include <net/if.h>
#include <inet/ip6.h>
#include <sys/sunddi.h>
#include <sys/dlpi.h>
#include <sys/sysmacros.h>

/* Linux specific functions and definitions */
static void lx_save(klwp_t *);
static void lx_restore(klwp_t *);

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
	struct regs *rp = lwptoregs(lwp);

	/* b_exec is called without p_lock held */
	VERIFY(MUTEX_NOT_HELD(&p->p_lock));

	/*
	 * Any l_handler handlers set as a result of B_REGISTER are now
	 * invalid; clear them.
	 */
	pd->l_handler = NULL;

	/*
	 * If this was a multi-threaded Linux process and this lwp wasn't the
	 * main lwp, then we need to make its Illumos and Linux PIDs match.
	 */
	if (curthread->t_tid != 1) {
		lx_pid_reassign(curthread);
	}

	/*
	 * Inform ptrace(2) that we are processing an execve(2) call so that if
	 * we are traced we can post either the PTRACE_EVENT_EXEC event or the
	 * legacy SIGTRAP.
	 */
	(void) lx_ptrace_stop_for_option(LX_PTRACE_O_TRACEEXEC, B_FALSE, 0, 0);

	/* clear the fs/gsbase values until the app. can reinitialize them */
	lwpd->br_lx_fsbase = NULL;
	lwpd->br_ntv_fsbase = NULL;
	lwpd->br_lx_gsbase = NULL;
	lwpd->br_ntv_gsbase = NULL;

	/*
	 * Clear the native stack flags.  This will be reinitialised by
	 * lx_init() in the new process image.
	 */
	lwpd->br_stack_mode = LX_STACK_MODE_PREINIT;
	lwpd->br_ntv_stack = 0;
	lwpd->br_ntv_stack_current = 0;

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

	/* Grab the updated argv bounds */
	mutex_enter(&p->p_lock);
	lx_read_argv_bounds(p);
	mutex_exit(&p->p_lock);

	/*
	 * The exec syscall doesn't return (so we don't call lx_syscall_return)
	 * but for our ptrace emulation we need to do this so that a tracer
	 * does not get out of sync. We know that by the time this lx_exec
	 * function is called that the exec has succeeded.
	 */
	rp->r_r0 = 0;
	(void) lx_ptrace_stop(LX_PR_SYSEXIT);
}

static void
lx_cleanlwp(klwp_t *lwp, proc_t *p)
{
	struct lx_lwp_data *lwpd = lwptolxlwp(lwp);
	void *rb_list = NULL;

	VERIFY(lwpd != NULL);

	mutex_enter(&p->p_lock);
	if ((lwpd->br_ptrace_flags & LX_PTF_EXITING) == 0) {
		lx_ptrace_exit(p, lwp);
	}

	/*
	 * While we have p_lock, safely grab any robust_list references and
	 * clear the lwp field.
	 */
	sprlock_proc(p);
	rb_list = lwpd->br_robust_list;
	lwpd->br_robust_list = NULL;
	sprunlock(p);

	if (rb_list != NULL) {
		lx_futex_robust_exit((uintptr_t)rb_list, lwpd->br_pid);
	}
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

	if (lwpd == NULL) {
		/* second time thru' */
		return;
	}

	lx_cleanlwp(lwp, p);

	if (lwpd->br_clear_ctidp != NULL) {
		(void) suword32(lwpd->br_clear_ctidp, 0);
		(void) lx_futex((uintptr_t)lwpd->br_clear_ctidp, FUTEX_WAKE, 1,
		    NULL, NULL, 0);
		lwpd->br_clear_ctidp = NULL;
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
}

void
lx_freelwp(klwp_t *lwp)
{
	struct lx_lwp_data *lwpd = lwptolxlwp(lwp);
	proc_t *p = lwptoproc(lwp);
	lx_zone_data_t *lxzdata;
	vfs_t *cgrp;

	VERIFY(MUTEX_NOT_HELD(&p->p_lock));

	if (lwpd == NULL) {
		/*
		 * There is one case where an LX branded process will possess
		 * LWPs which lack their own brand data.  During the course of
		 * executing native binary, the process will be preemptively
		 * branded to allow hooks such as b_native_exec to function.
		 * If that process possesses multiple LWPS, they will _not_ be
		 * branded since they will exit if the exec succeeds.  It's
		 * during this LWP exit that lx_freelwp would be called on an
		 * unbranded LWP.  When that is the case, it is acceptable to
		 * bypass the hook.
		 */
		return;
	}

	/* cgroup integration */
	lxzdata = ztolxzd(p->p_zone);
	mutex_enter(&lxzdata->lxzd_lock);
	cgrp = lxzdata->lxzd_cgroup;
	if (cgrp != NULL) {
		VFS_HOLD(cgrp);
		mutex_exit(&lxzdata->lxzd_lock);
		ASSERT(lx_cgrp_freelwp != NULL);
		(*lx_cgrp_freelwp)(cgrp, lwpd->br_cgroupid, lwptot(lwp)->t_tid,
		    lwpd->br_pid);
		VFS_RELE(cgrp);
	} else {
		mutex_exit(&lxzdata->lxzd_lock);
	}

	/*
	 * It is possible for the lx_freelwp hook to be called without a prior
	 * call to lx_exitlwp being made.  This happens as part of lwp
	 * de-branding when a native binary is executed from a branded process.
	 *
	 * To cover all cases, lx_cleanlwp is called from lx_exitlwp as well
	 * here in lx_freelwp.  When the second call is redundant, the
	 * resources will already be freed and no work will be needed.
	 */
	lx_cleanlwp(lwp, p);

	/*
	 * Remove our system call interposer.
	 */
	lwp->lwp_brand_syscall = NULL;

	(void) removectx(lwptot(lwp), lwp, lx_save, lx_restore, NULL, NULL,
	    lx_save, NULL);
	if (lwpd->br_pid != 0) {
		lx_pid_rele(lwptoproc(lwp)->p_pid, lwptot(lwp)->t_tid);
	}

	/*
	 * Discard the affinity mask.
	 */
	VERIFY(lwpd->br_affinitymask != NULL);
	cpuset_free(lwpd->br_affinitymask);
	lwpd->br_affinitymask = NULL;

	/*
	 * Ensure that lx_ptrace_exit() has been called to detach
	 * ptrace(2) tracers and tracees.
	 */
	VERIFY(lwpd->br_ptrace_tracer == NULL);
	VERIFY(lwpd->br_ptrace_accord == NULL);

	lwp->lwp_brand = NULL;
	kmem_free(lwpd, sizeof (struct lx_lwp_data));
}

void *
lx_lwpdata_alloc(proc_t *p)
{
	lx_lwp_data_t *lwpd;
	struct lx_pid *lpidp;
	cpuset_t *affmask;
	pid_t newpid = 0;
	struct pid *pidp = NULL;

	VERIFY(MUTEX_NOT_HELD(&p->p_lock));

	/*
	 * LWPs beyond the first will require a pid to be allocated to emulate
	 * Linux's goofy thread model.  While this  allocation may be
	 * unnecessary when a single-lwp process undergoes branding, it cannot
	 * be performed during b_initlwp due to p_lock being held.
	 */
	if (p->p_lwpcnt > 0) {
		if ((newpid = pid_allocate(p, 0, 0)) < 0) {
			return (NULL);
		}
		pidp = pid_find(newpid);
	}

	lwpd = kmem_zalloc(sizeof (struct lx_lwp_data), KM_SLEEP);
	lpidp = kmem_zalloc(sizeof (struct lx_pid), KM_SLEEP);
	affmask = cpuset_alloc(KM_SLEEP);

	lpidp->lxp_lpid = newpid;
	lpidp->lxp_pidp = pidp;
	lwpd->br_lpid = lpidp;
	lwpd->br_affinitymask = affmask;

	return (lwpd);
}

/*
 * Free lwp brand data if an error occurred during lwp_create.
 * Otherwise, lx_freelwp will be used to free the resources after they're
 * associated with the lwp via lx_initlwp.
 */
void
lx_lwpdata_free(void *lwpbd)
{
	lx_lwp_data_t *lwpd = (lx_lwp_data_t *)lwpbd;
	VERIFY(lwpd != NULL);
	VERIFY(lwpd->br_lpid != NULL);
	VERIFY(lwpd->br_affinitymask != NULL);

	cpuset_free(lwpd->br_affinitymask);
	if (lwpd->br_lpid->lxp_pidp != NULL) {
		(void) pid_rele(lwpd->br_lpid->lxp_pidp);
	}
	kmem_free(lwpd->br_lpid, sizeof (*lwpd->br_lpid));
	kmem_free(lwpd, sizeof (*lwpd));
}

void
lx_initlwp(klwp_t *lwp, void *lwpbd)
{
	lx_lwp_data_t *lwpd = (lx_lwp_data_t *)lwpbd;
	lx_lwp_data_t *plwpd = ttolxlwp(curthread);
	kthread_t *tp = lwptot(lwp);
	proc_t *p = lwptoproc(lwp);
	lx_zone_data_t *lxzdata;
	vfs_t *cgrp;

	VERIFY(MUTEX_HELD(&p->p_lock));
	VERIFY(lwp->lwp_brand == NULL);

	lwpd->br_exitwhy = CLD_EXITED;
	lwpd->br_lwp = lwp;
	lwpd->br_clear_ctidp = NULL;
	lwpd->br_set_ctidp = NULL;
	lwpd->br_signal = 0;
	lwpd->br_stack_mode = LX_STACK_MODE_PREINIT;
	cpuset_all(lwpd->br_affinitymask);

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
		/* The child inherits the fs/gsbase values from the parent */
		lwpd->br_lx_fsbase = plwpd->br_lx_fsbase;
		lwpd->br_ntv_fsbase = plwpd->br_ntv_fsbase;
		lwpd->br_lx_gsbase = plwpd->br_lx_gsbase;
		lwpd->br_ntv_gsbase = plwpd->br_ntv_gsbase;
	} else {
		/*
		 * Oddball case: the parent thread isn't a Linux process.
		 */
		lwpd->br_ppid = 0;
		lwpd->br_ptid = -1;
	}
	lwp->lwp_brand = lwpd;

	/*
	 * When during lx_lwpdata_alloc, we must decide whether or not to
	 * allocate a new pid to associate with the lwp. Since p_lock is not
	 * held at that point, the only time we can guarantee a new pid isn't
	 * needed is when p_lwpcnt == 0.  This is because other lwps won't be
	 * present to race with us with regards to pid allocation.
	 *
	 * This means that in all other cases (where p_lwpcnt > 0), we expect
	 * that lx_lwpdata_alloc will allocate a pid for us to use here, even
	 * if it is uneeded.  If this process is undergoing an exec, for
	 * example, the single existing lwp will not need a new pid when it is
	 * rebranded.  In that case, lx_pid_assign will free the uneeded pid.
	 */
	VERIFY(lwpd->br_lpid->lxp_pidp != NULL || p->p_lwpcnt == 0);

	lx_pid_assign(tp, lwpd->br_lpid);
	lwpd->br_tgid = lwpd->br_pid;
	/*
	 * Having performed the lx pid assignement, the lpid reference is no
	 * longer needed.  The underlying data will be freed during lx_freelwp.
	 */
	lwpd->br_lpid = NULL;

	installctx(lwptot(lwp), lwp, lx_save, lx_restore, NULL, NULL,
	    lx_save, NULL);

	/*
	 * Install branded system call hooks for this LWP:
	 */
	lwp->lwp_brand_syscall = lx_syscall_enter;

	/*
	 * The new LWP inherits the parent LWP cgroup ID.
	 */
	if (plwpd != NULL) {
		lwpd->br_cgroupid = plwpd->br_cgroupid;
	}
	/*
	 * The new LWP inherits the parent LWP emulated scheduling info.
	 */
	if (plwpd != NULL) {
		lwpd->br_schd_class = plwpd->br_schd_class;
		lwpd->br_schd_pri = plwpd->br_schd_pri;
		lwpd->br_schd_flags = plwpd->br_schd_flags;
		lwpd->br_schd_runtime = plwpd->br_schd_runtime;
		lwpd->br_schd_deadline = plwpd->br_schd_deadline;
		lwpd->br_schd_period = plwpd->br_schd_period;
	}
	lxzdata = ztolxzd(p->p_zone);
	mutex_enter(&lxzdata->lxzd_lock);
	cgrp = lxzdata->lxzd_cgroup;
	if (cgrp != NULL) {
		VFS_HOLD(cgrp);
		mutex_exit(&lxzdata->lxzd_lock);
		ASSERT(lx_cgrp_initlwp != NULL);
		(*lx_cgrp_initlwp)(cgrp, lwpd->br_cgroupid, lwptot(lwp)->t_tid,
		    lwpd->br_pid);
		VFS_RELE(cgrp);
	} else {
		mutex_exit(&lxzdata->lxzd_lock);
	}
}

void
lx_initlwp_post(klwp_t *lwp)
{
	lx_lwp_data_t *plwpd = ttolxlwp(curthread);
	/*
	 * If the parent LWP has a ptrace(2) tracer, the new LWP may
	 * need to inherit that same tracer.
	 */
	if (plwpd != NULL) {
		lx_ptrace_inherit_tracer(plwpd, lwptolxlwp(lwp));
	}
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

	switch (src->br_stack_mode) {
	case LX_STACK_MODE_BRAND:
	case LX_STACK_MODE_NATIVE:
		/*
		 * The parent LWP has an alternate stack installed.
		 * The child LWP should have the same stack base and extent.
		 */
		dst->br_stack_mode = src->br_stack_mode;
		dst->br_ntv_stack = src->br_ntv_stack;
		dst->br_ntv_stack_current = src->br_ntv_stack_current;
		break;

	default:
		/*
		 * Otherwise, clear the stack data for this LWP.
		 */
		dst->br_stack_mode = LX_STACK_MODE_PREINIT;
		dst->br_ntv_stack = 0;
		dst->br_ntv_stack_current = 0;
	}

	/*
	 * copy only these flags
	 */
	dst->br_lwp_flags = src->br_lwp_flags & BR_CPU_BOUND;
	dst->br_scall_args = NULL;
	lx_affinity_forklwp(srclwp, dstlwp);

	/*
	 * Flag so child doesn't ptrace-stop on syscall exit.
	 */
	dst->br_ptrace_flags |= LX_PTF_NOSTOP;
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
 * Brand-specific function to convert the fsbase as pulled from the register
 * into a native fsbase suitable for locating the ulwp_t from the kernel.
 */
uintptr_t
lx_fsbase(klwp_t *lwp, uintptr_t fsbase)
{
	lx_lwp_data_t *lwpd = lwp->lwp_brand;

	if (lwpd->br_stack_mode != LX_STACK_MODE_BRAND ||
	    lwpd->br_ntv_fsbase == NULL) {
		return (fsbase);
	}

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
lx_exit_with_sig(proc_t *cp, sigqueue_t *sqp)
{
	proc_t *pp = cp->p_parent;
	lx_proc_data_t *lx_brand_data = ptolxproc(cp);
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
 * SIGCHLD to its parent. The option __WCLONE indicates to wait only on clone
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
/* ARGSUSED */
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
		lx_proc_data_t *pd = ptolxproc(cp);
		boolean_t is_sigchld = B_TRUE;
		boolean_t match_wclone = B_FALSE;

		/*
		 * When calling clone, an alternate signal can be chosen to
		 * deliver to the parent when the child exits.
		 */
		if (pd != NULL && pd->l_signal != stol_signo[SIGCHLD]) {
			is_sigchld = B_FALSE;
		}
		if ((flags & LX_WCLONE) != 0) {
			match_wclone = B_TRUE;
		}

		ret = (match_wclone ^ is_sigchld) ? B_TRUE : B_FALSE;
	}
	mutex_exit(&cp->p_lock);

	return (ret);
}

void
lx_ifname_convert(char *ifname, lx_if_action_t act)
{
	if (act == LX_IF_TONATIVE) {
		if (strncmp(ifname, "lo", IFNAMSIZ) == 0)
			(void) strlcpy(ifname, "lo0", IFNAMSIZ);
	} else {
		if (strncmp(ifname, "lo0", IFNAMSIZ) == 0)
			(void) strlcpy(ifname, "lo", IFNAMSIZ);
	}
}

void
lx_ifflags_convert(uint64_t *flags, lx_if_action_t act)
{
	uint64_t buf;

	buf = *flags & (IFF_UP | IFF_BROADCAST | IFF_DEBUG |
	    IFF_LOOPBACK | IFF_POINTOPOINT | IFF_NOTRAILERS |
	    IFF_RUNNING | IFF_NOARP | IFF_PROMISC | IFF_ALLMULTI);

	/* Linux has different shift for multicast flag */
	if (act == LX_IF_TONATIVE) {
		if (*flags & 0x1000)
			buf |= IFF_MULTICAST;
	} else {
		if (*flags & IFF_MULTICAST)
			buf |= 0x1000;
	}
	*flags = buf;
}

/*
 * Convert an IPv6 address into the numbers used by /proc/net/if_inet6
 */
unsigned int
lx_ipv6_scope_convert(const in6_addr_t *addr)
{
	if (IN6_IS_ADDR_V4COMPAT(addr)) {
		return (LX_IPV6_ADDR_COMPATv4);
	} else if (IN6_ARE_ADDR_EQUAL(addr, &ipv6_loopback)) {
		return (LX_IPV6_ADDR_LOOPBACK);
	} else if (IN6_IS_ADDR_LINKLOCAL(addr)) {
		return (LX_IPV6_ADDR_LINKLOCAL);
	} else if (IN6_IS_ADDR_SITELOCAL(addr)) {
		return (LX_IPV6_ADDR_SITELOCAL);
	} else {
		return (0x0000U);
	}
}


void
lx_stol_hwaddr(const struct sockaddr_dl *src, struct sockaddr *dst, int *size)
{
	int copy_size = MIN(src->sdl_alen, sizeof (dst->sa_data));

	switch (src->sdl_type) {
	case DL_ETHER:
		dst->sa_family = LX_ARPHRD_ETHER;
		break;
	case DL_LOOP:
		dst->sa_family = LX_ARPHRD_LOOPBACK;
		break;
	default:
		dst->sa_family = LX_ARPHRD_VOID;
	}

	bcopy(LLADDR(src), dst->sa_data, copy_size);
	*size = copy_size;
}

/*
 * Brand hook to convert native kernel siginfo signal number, errno, code, pid
 * and si_status to Linux values. Similar to the stol_ksiginfo function but
 * this one converts in-place, converts the pid, and does not copyout.
 */
void
lx_sigfd_translate(k_siginfo_t *infop)
{
	infop->si_signo = lx_stol_signo(infop->si_signo, LX_SIGKILL);

	infop->si_status = lx_stol_status(infop->si_status, LX_SIGKILL);

	infop->si_code = lx_stol_sigcode(infop->si_code);

	infop->si_errno = lx_errno(infop->si_errno, EINVAL);

	if (infop->si_pid == curproc->p_zone->zone_proc_initpid) {
		infop->si_pid = 1;
	} else if (infop->si_pid == curproc->p_zone->zone_zsched->p_pid) {
		infop->si_pid = 0;
	}
}

int
stol_ksiginfo_copyout(k_siginfo_t *sip, void *ulxsip)
{
	lx_siginfo_t lsi;

	bzero(&lsi, sizeof (lsi));
	lsi.lsi_signo = lx_stol_signo(sip->si_signo, SIGCLD);
	lsi.lsi_code = lx_stol_sigcode(sip->si_code);
	lsi.lsi_errno = lx_errno(sip->si_errno, EINVAL);

	switch (lsi.lsi_signo) {
	case LX_SIGPOLL:
		lsi.lsi_band = sip->si_band;
		lsi.lsi_fd = sip->si_fd;
		break;

	case LX_SIGCHLD:
		lsi.lsi_pid = sip->si_pid;
		if (sip->si_code <= 0 || sip->si_code == CLD_EXITED) {
			lsi.lsi_status = sip->si_status;
		} else {
			lsi.lsi_status = lx_stol_status(sip->si_status,
			    SIGKILL);
		}
		lsi.lsi_utime = sip->si_utime;
		lsi.lsi_stime = sip->si_stime;
		break;

	case LX_SIGILL:
	case LX_SIGBUS:
	case LX_SIGFPE:
	case LX_SIGSEGV:
		lsi.lsi_addr = sip->si_addr;
		break;

	default:
		lsi.lsi_pid = sip->si_pid;
		lsi.lsi_uid = LX_UID32_TO_UID16(sip->si_uid);
	}

	if (copyout(&lsi, ulxsip, sizeof (lsi)) != 0) {
		return (set_errno(EFAULT));
	}

	return (0);
}

#if defined(_SYSCALL32_IMPL)
int
stol_ksiginfo32_copyout(k_siginfo_t *sip, void *ulxsip)
{
	lx_siginfo32_t lsi;

	bzero(&lsi, sizeof (lsi));
	lsi.lsi_signo = lx_stol_signo(sip->si_signo, SIGCLD);
	lsi.lsi_code = lx_stol_sigcode(sip->si_code);
	lsi.lsi_errno = lx_errno(sip->si_errno, EINVAL);

	switch (lsi.lsi_signo) {
	case LX_SIGPOLL:
		lsi.lsi_band = sip->si_band;
		lsi.lsi_fd = sip->si_fd;
		break;

	case LX_SIGCHLD:
		lsi.lsi_pid = sip->si_pid;
		if (sip->si_code <= 0 || sip->si_code == CLD_EXITED) {
			lsi.lsi_status = sip->si_status;
		} else {
			lsi.lsi_status = lx_stol_status(sip->si_status,
			    SIGKILL);
		}
		lsi.lsi_utime = sip->si_utime;
		lsi.lsi_stime = sip->si_stime;
		break;

	case LX_SIGILL:
	case LX_SIGBUS:
	case LX_SIGFPE:
	case LX_SIGSEGV:
		lsi.lsi_addr = (caddr32_t)(uintptr_t)sip->si_addr;
		break;

	default:
		lsi.lsi_pid = sip->si_pid;
		lsi.lsi_uid = LX_UID32_TO_UID16(sip->si_uid);
	}

	if (copyout(&lsi, ulxsip, sizeof (lsi)) != 0) {
		return (set_errno(EFAULT));
	}

	return (0);
}
#endif

/*
 * Linux uses the original bounds of the argv array when determining the
 * contents of /proc/<pid/cmdline.  We mimic those bounds using argv[0] and
 * envp[0] as the beginning and end, respectively.
 */
void
lx_read_argv_bounds(proc_t *p)
{
	user_t *up = PTOU(p);
	lx_proc_data_t *pd = ptolxproc(p);
	uintptr_t addr_arg = up->u_argv;
	uintptr_t addr_env = up->u_envp;
	uintptr_t arg_start = 0, env_start = 0, env_end = 0;
	int i = 0;

	VERIFY(pd != NULL);
	VERIFY(MUTEX_HELD(&p->p_lock));

	/*
	 * Use AT_SUN_PLATFORM in the aux vector to find the end of the envp
	 * strings.
	 */
	for (i = 0; i < __KERN_NAUXV_IMPL; i++) {
		if (up->u_auxv[i].a_type == AT_SUN_PLATFORM) {
			env_end = (uintptr_t)up->u_auxv[i].a_un.a_val;
		}
	}

	mutex_exit(&p->p_lock);
#if defined(_LP64)
	if (p->p_model != DATAMODEL_NATIVE) {
		uint32_t buf32;
		if (copyin((void *)addr_arg, &buf32, sizeof (buf32)) == 0) {
			arg_start = (uintptr_t)buf32;
		}
		if (copyin((void *)addr_env, &buf32, sizeof (buf32)) == 0) {
			env_start = (uintptr_t)buf32;
		}
	} else
#endif /* defined(_LP64) */
	{
		uintptr_t buf;
		if (copyin((void *)addr_arg, &buf, sizeof (buf)) == 0) {
			arg_start = buf;
		}
		if (copyin((void *)addr_env, &buf, sizeof (buf)) == 0) {
			env_start = buf;
		}
	}
	mutex_enter(&p->p_lock);
	pd->l_args_start = arg_start;
	pd->l_envs_start = env_start;
	pd->l_envs_end = env_end;
}

/* Given an LX LWP, determine where user register state is stored. */
lx_regs_location_t
lx_regs_location(lx_lwp_data_t *lwpd, void **ucp, boolean_t for_write)
{
	switch (lwpd->br_stack_mode) {
	case LX_STACK_MODE_BRAND:
		/*
		 * The LWP was stopped with the brand stack and register state
		 * loaded, e.g. during a syscall emulated within the kernel.
		 */
		return (LX_REG_LOC_LWP);

	case LX_STACK_MODE_PREINIT:
		if (for_write) {
			/* setting registers not allowed in this state */
			break;
		}
		if (lwpd->br_ptrace_whatstop == LX_PR_SIGNALLED ||
		    lwpd->br_ptrace_whatstop == LX_PR_SYSEXIT) {
			/* The LWP was stopped by tracing on exec. */
			return (LX_REG_LOC_LWP);
		}
		break;

	case LX_STACK_MODE_NATIVE:
		if (for_write) {
			/* setting registers not allowed in this state */
			break;
		}
		if (lwpd->br_ptrace_whystop == PR_BRAND) {
			/* Called while ptrace-event-stopped by lx_exec. */
			if (lwpd->br_ptrace_whatstop == LX_PR_EVENT) {
				return (LX_REG_LOC_LWP);
			}

			/* Called while ptrace-event-stopped after clone. */
			if (lwpd->br_ptrace_whatstop == LX_PR_SIGNALLED &&
			    lwpd->br_ptrace_stopsig == LX_SIGSTOP &&
			    (lwpd->br_ptrace_flags & LX_PTF_STOPPED)) {
				return (LX_REG_LOC_LWP);
			}

			/*
			 * Called to obtain syscall exit for other cases
			 * (e.g. pseudo return from rt_sigreturn).
			 */
			if (lwpd->br_ptrace_whatstop == LX_PR_SYSEXIT &&
			    (lwpd->br_ptrace_flags & LX_PTF_STOPPED)) {
				return (LX_REG_LOC_LWP);
			}
		}
		break;
	default:
		break;
	}

	if (lwpd->br_ptrace_stopucp != NULL) {
		/*
		 * The LWP was stopped in the usermode emulation library
		 * but a ucontext_t for the preserved brand stack and
		 * register state was provided.  Return the register state
		 * from that ucontext_t.
		 */
		VERIFY(ucp != NULL);
		*ucp = (void *)lwpd->br_ptrace_stopucp;
		return (LX_REG_LOC_UCP);
	}

	return (LX_REG_LOC_UNAVAIL);
}
