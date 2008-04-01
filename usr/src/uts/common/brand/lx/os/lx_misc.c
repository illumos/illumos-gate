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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/privregs.h>
#include <sys/exec.h>
#include <sys/lwp.h>
#include <sys/sem.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>
#include <sys/lx_pid.h>
#include <sys/lx_futex.h>

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
	int err;

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
	proc_t *p;
	kthread_t *t;
	sigqueue_t *sqp = NULL;
	pid_t ppid;
	id_t ptid;

	if (lwpd == NULL)
		return;		/* second time thru' */

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
		if (lwpd->br_pid != 0)
			lx_pid_rele(lwptoproc(lwp)->p_pid,
			    lwptot(lwp)->t_tid);

		lwp->lwp_brand = NULL;
		kmem_free(lwpd, sizeof (struct lx_lwp_data));
	}
}

int
lx_initlwp(klwp_t *lwp)
{
	struct lx_lwp_data *lwpd;
	struct lx_lwp_data *plwpd;
	kthread_t *tp = lwptot(lwp);

	lwpd = kmem_zalloc(sizeof (struct lx_lwp_data), KM_SLEEP);
	lwpd->br_exitwhy = CLD_EXITED;
	lwpd->br_lwp = lwp;
	lwpd->br_clear_ctidp = NULL;
	lwpd->br_set_ctidp = NULL;
	lwpd->br_signal = 0;
	/*
	 * lwpd->br_affinitymask was zeroed by kmem_zalloc().
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
	} else if (ttolxlwp(curthread) != NULL) {
		plwpd = ttolxlwp(curthread);
		bcopy(plwpd->br_tls, lwpd->br_tls, sizeof (lwpd->br_tls));
		lwpd->br_ppid = plwpd->br_pid;
		lwpd->br_ptid = curthread->t_tid;
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
	dst->br_clone_args = NULL;
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

longlong_t
lx_opnotsupp()
{
	return (set_errno(EOPNOTSUPP));
}

/*
 * Brand-specific routine to check if given non-Solaris standard segment
 * register values should be used as-is or if they should be modified to other
 * values.
 */
/*ARGSUSED*/
greg_t
lx_fixsegreg(greg_t sr, model_t datamodel)
{
	struct lx_lwp_data *lxlwp = ttolxlwp(curthread);

	/*
	 * If the segreg is the same as the %gs the brand callback was last
	 * entered with, allow it to be used unmodified.
	 */
	ASSERT(sr == (sr & 0xffff));

	if (sr == (lxlwp->br_ugs & 0xffff))
		return (sr);

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
