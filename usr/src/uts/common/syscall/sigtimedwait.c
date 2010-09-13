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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/bitmap.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/fault.h>
#include <sys/procset.h>
#include <sys/signal.h>
#include <sys/siginfo.h>
#include <sys/time.h>
#include <sys/kmem.h>
#include <sys/schedctl.h>
#include <sys/debug.h>
#include <sys/condvar_impl.h>
#include <sys/model.h>
#include <sys/sdt.h>
#include <sys/zone.h>

static int
copyout_siginfo(model_t datamodel, k_siginfo_t *ksip, void *uaddr)
{
	zoneid_t zoneid = getzoneid();

	if (datamodel == DATAMODEL_NATIVE) {
		if (SI_FROMUSER(ksip) && zoneid != GLOBAL_ZONEID &&
		    zoneid != ksip->si_zoneid) {
			k_siginfo_t sani_sip = *ksip;
			sani_sip.si_pid = curproc->p_zone->zone_zsched->p_pid;
			sani_sip.si_uid = 0;
			sani_sip.si_ctid = -1;
			sani_sip.si_zoneid = zoneid;
			if (copyout(&sani_sip, uaddr, sizeof (sani_sip)))
				return (set_errno(EFAULT));
		} else {
			if (copyout(ksip, uaddr, sizeof (*ksip)))
				return (set_errno(EFAULT));
		}
	}
#ifdef _SYSCALL32_IMPL
	else {
		siginfo32_t si32;

		siginfo_kto32(ksip, &si32);
		if (SI_FROMUSER(ksip) && zoneid != GLOBAL_ZONEID &&
		    zoneid != ksip->si_zoneid) {
			si32.si_pid = curproc->p_zone->zone_zsched->p_pid;
			si32.si_uid = 0;
			si32.si_ctid = -1;
			si32.si_zoneid = zoneid;
		}
		if (copyout(&si32, uaddr, sizeof (si32)))
			return (set_errno(EFAULT));
	}
#endif
	return (ksip->si_signo);
}

/*
 * Wait until a signal within a specified set is posted or until the
 * time interval 'timeout' if specified.  The signal is caught but
 * not delivered. The value of the signal is returned to the caller.
 */
int
sigtimedwait(sigset_t *setp, siginfo_t *siginfop, timespec_t *timeoutp)
{
	sigset_t set;
	k_sigset_t oldmask;
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	proc_t *p = ttoproc(t);
	timespec_t sig_timeout;
	timespec_t *rqtp = NULL;
	int timecheck = 0;
	int ret;
	int error = 0;
	k_siginfo_t info, *infop;
	model_t datamodel = get_udatamodel();

	if (timeoutp) {
		timespec_t now;

		timecheck = timechanged;
		gethrestime(&now);
		if (datamodel == DATAMODEL_NATIVE) {
			if (copyin(timeoutp, &sig_timeout,
			    sizeof (sig_timeout)))
				return (set_errno(EFAULT));
		} else {
			timespec32_t timeout32;

			if (copyin(timeoutp, &timeout32, sizeof (timeout32)))
				return (set_errno(EFAULT));
			TIMESPEC32_TO_TIMESPEC(&sig_timeout, &timeout32)
		}

		if (itimerspecfix(&sig_timeout))
			return (set_errno(EINVAL));
		/*
		 * Convert the timespec value into absolute time.
		 */
		timespecadd(&sig_timeout, &now);
		rqtp = &sig_timeout;
	}
	if (copyin(setp, &set, sizeof (set)))
		return (set_errno(EFAULT));
	sigutok(&set, &t->t_sigwait);
	if (sigisempty(&t->t_sigwait))
		return (set_errno(EINVAL));

	mutex_enter(&p->p_lock);
	/*
	 * set the thread's signal mask to unmask
	 * those signals in the specified set.
	 */
	schedctl_finish_sigblock(t);
	oldmask = t->t_hold;
	sigdiffset(&t->t_hold, &t->t_sigwait);

	/*
	 * Wait until we take a signal or until
	 * the absolute future time is passed.
	 */
	while ((ret = cv_waituntil_sig(&t->t_delay_cv, &p->p_lock,
	    rqtp, timecheck)) > 0)
		continue;
	if (ret == -1)
		error = EAGAIN;

	/*
	 * Restore thread's signal mask to its previous value.
	 */
	t->t_hold = oldmask;
	t->t_sig_check = 1;	/* so post_syscall sees new t_hold mask */

	if (error) {
		mutex_exit(&p->p_lock);
		sigemptyset(&t->t_sigwait);
		return (set_errno(error));	/* timer expired */
	}
	/*
	 * Don't bother with signal if it is not in request set.
	 */
	if (lwp->lwp_cursig == 0 ||
	    !sigismember(&t->t_sigwait, lwp->lwp_cursig)) {
		mutex_exit(&p->p_lock);
		/*
		 * lwp_cursig is zero if pokelwps() awakened cv_wait_sig().
		 * This happens if some other thread in this process called
		 * forkall() or exit().
		 */
		sigemptyset(&t->t_sigwait);
		return (set_errno(EINTR));
	}

	if (lwp->lwp_curinfo)
		infop = &lwp->lwp_curinfo->sq_info;
	else {
		infop = &info;
		bzero(infop, sizeof (info));
		infop->si_signo = lwp->lwp_cursig;
		infop->si_code = SI_NOINFO;
	}

	lwp->lwp_ru.nsignals++;
	ret = lwp->lwp_cursig;
	DTRACE_PROC2(signal__clear, int, ret, ksiginfo_t *, infop);
	lwp->lwp_cursig = 0;
	lwp->lwp_extsig = 0;
	mutex_exit(&p->p_lock);

	if (siginfop)
		ret = copyout_siginfo(datamodel, infop, siginfop);
	if (lwp->lwp_curinfo) {
		siginfofree(lwp->lwp_curinfo);
		lwp->lwp_curinfo = NULL;
	}
	sigemptyset(&t->t_sigwait);
	return (ret);
}
