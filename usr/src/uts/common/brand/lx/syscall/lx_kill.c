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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/zone.h>
#include <sys/thread.h>
#include <sys/signal.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>
#include <lx_signum.h>
#include <sys/contract/process_impl.h>

extern int kill(pid_t, int);

/*
 * Check if it is legal to send this signal to the init process.  Linux
 * kill(2) semantics dictate that no _unhandled_ signal may be sent to pid
 * 1.
 */
static int
lx_init_sig_check(int sig, pid_t pid)
{
	proc_t *p;
	int rv = 0;

	mutex_enter(&pidlock);
	if ((p = prfind(pid)) == NULL || p->p_stat == SIDL) {
		rv = ESRCH;
	} else if (sig != 0) {
		if (sigismember(&cantmask, sig)) {
			rv = EPERM;
		} else {
			mutex_enter(&p->p_lock);
			if (PTOU(p)->u_signal[sig-1] == SIG_DFL ||
			    PTOU(p)->u_signal[sig-1] == SIG_IGN) {
				rv = EPERM;
			}
			mutex_exit(&p->p_lock);
		}
	}
	mutex_exit(&pidlock);

	return (rv);
}

static long
lx_thrkill(pid_t tgid, pid_t pid, int lx_sig, boolean_t tgkill)
{
	kthread_t *t;
	proc_t *pp, *cp = curproc;
	sigqueue_t *sqp;
	int sig, rv;

	/*
	 * Unlike kill(2), Linux tkill(2) doesn't allow signals to
	 * be sent to process IDs <= 0 as it doesn't overlay any special
	 * semantics on the pid.
	 */
	if ((pid <= 0) || ((lx_sig < 0) || (lx_sig > LX_NSIG)) ||
	    ((sig = ltos_signo[lx_sig]) < 0))
		return (set_errno(EINVAL));

	/*
	 * If the Linux pid is 1, translate the pid to the actual init
	 * pid for the zone.  Note that Linux dictates that no unhandled
	 * signals may be sent to init, so check for that, too.
	 *
	 * Otherwise, extract the tid and real pid from the Linux pid.
	 */
	if (pid == 1) {
		pid_t initpid;

		initpid = cp->p_zone->zone_proc_initpid;
		if ((rv = lx_init_sig_check(sig, initpid)) != 0) {
			return (set_errno(rv));
		}
	}
	sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);
	/*
	 * Find the process for the passed pid...
	 */
	if (lx_lpid_lock(pid, curzone, NO_PRLOCK, &pp, &t) != 0) {
		rv = set_errno(ESRCH);
		goto free_and_exit;
	}

	/*
	 * Make sure the thread group matches the thread.
	 */
	if (tgkill) {
		if ((pid == 1 && tgid != 1) ||
		    (pid != 1 && tgid != pp->p_pid)) {
			mutex_exit(&pp->p_lock);
			rv = set_errno(ESRCH);
			goto free_and_exit;
		}
	}

	/*
	 * Deny permission to send the signal if either of the following
	 * is true:
	 *
	 *	+ The signal is SIGCONT and the target pid is not in the same
	 *	  session as the sender
	 *
	 *	+ prochasprocperm() shows the user lacks sufficient permission
	 *	  to send the signal to the target pid
	 */
	if (((sig == SIGCONT) && (pp->p_sessp != cp->p_sessp)) ||
	    (!prochasprocperm(pp, cp, CRED()))) {
		mutex_exit(&pp->p_lock);
		rv = set_errno(EPERM);
		goto free_and_exit;
	}

	/* a signal of 0 means just check for the existence of the thread */
	if (lx_sig == 0) {
		mutex_exit(&pp->p_lock);
		rv = 0;
		goto free_and_exit;
	}

	sqp->sq_info.si_signo = sig;
	sqp->sq_info.si_code = SI_LWP;
	sqp->sq_info.si_pid = cp->p_pid;
	sqp->sq_info.si_zoneid = getzoneid();
	sqp->sq_info.si_uid = crgetruid(CRED());
	sigaddqa(pp, t, sqp);

	mutex_exit(&pp->p_lock);

	return (0);

free_and_exit:
	kmem_free(sqp, sizeof (sigqueue_t));
	return (rv);
}

long
lx_tgkill(pid_t tgid, pid_t pid, int lx_sig)
{
	return (lx_thrkill(tgid, pid, lx_sig, B_TRUE));
}

long
lx_tkill(pid_t pid, int lx_sig)
{
	return (lx_thrkill(0, pid, lx_sig, B_FALSE));
}

long
lx_kill(pid_t lx_pid, int lx_sig)
{
	pid_t s_pid, initpid;
	sigsend_t v;
	zone_t *zone = curzone;
	struct proc *p;
	int err, sig, nfound;

	if ((lx_sig < 0) || (lx_sig > LX_NSIG) ||
	    ((sig = ltos_signo[lx_sig]) < 0))
		return (set_errno(EINVAL));

	initpid = zone->zone_proc_initpid;
	if (lx_pid == 0 || lx_pid == -1) {
		s_pid = 0;
	} else if (lx_pid > 0) {
		/*
		 * Translations for individual processes (including pid 1) is
		 * all handled by lx_lpid_to_spair.
		 */
		if (lx_lpid_to_spair(lx_pid, &s_pid, NULL) != 0) {
			/*
			 * If we didn't find this pid that means it doesn't
			 * exist in this zone.
			 */
			return (set_errno(ESRCH));
		}
	} else {
		ASSERT(lx_pid < 0);
		if (lx_lpid_to_spair(-lx_pid, &s_pid, NULL) != 0) {
			/*
			 * If we didn't find this pid it means that the
			 * process group leader doesn't exist in this zone.
			 * In this case assuming that the Linux pid is
			 * the same as the Solaris pid will get us the
			 * correct behavior.
			 */
			s_pid = -lx_pid;
		}
	}

	/*
	 * Check that it is legal for this signal to be sent to init
	 */
	if (s_pid == initpid && (err = lx_init_sig_check(sig, s_pid)) != 0)
		return (set_errno(err));

	/*
	 * For individual processes, kill() semantics are the same between
	 * Solaris and Linux.
	 */
	if (lx_pid >= 0)
		return (kill(s_pid, sig));

	/*
	 * In Solaris, sending a signal to -pid means "send a signal to
	 * everyone in process group pid."  In Linux it means "send a
	 * signal to everyone in the group other than init."  Sending a
	 * signal to -1 means "send a signal to every process except init
	 * and myself."
	 */

	bzero(&v, sizeof (v));
	v.sig = sig;
	v.checkperm = 1;
	v.sicode = SI_USER;
	err = 0;

	mutex_enter(&pidlock);

	p = (lx_pid == -1) ? practive : pgfind(s_pid);
	nfound = 0;
	while (err == 0 && p != NULL) {
		if ((p->p_zone == zone) && (p->p_stat != SIDL) &&
		    (p->p_pid != initpid) && (lx_pid < -1 || p != curproc)) {
			nfound++;
			err = sigsendproc(p, &v);
		}

		p = (lx_pid == -1) ? p->p_next : p->p_pglink;
	}
	mutex_exit(&pidlock);

	/*
	 * If we found no processes, we'll return ESRCH -- but unlike our
	 * native kill(2), we do not return EPERM if processes are found but
	 * we did not have permission to send any of them a signal.
	 */
	if (nfound == 0)
		err = ESRCH;

	return (err ? set_errno(err) : 0);
}

/*
 * This handles the unusual case where the user sends a non-queueable signal
 * through rt_sigqueueinfo. Signals sent with codes that indicate they are
 * queuable are sent through the sigqueue syscall via the user level function
 * lx_rt_sigqueueinfo().
 */
int
lx_helper_rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *uinfo)
{
	proc_t *target_proc;
	pid_t s_pid;
	zone_t *zone = curproc->p_zone;
	sigsend_t send;
	int err;
	siginfo_t kinfo;

	if (copyin(uinfo, &kinfo, sizeof (siginfo_t)) != 0)
		return (set_errno(EFAULT));
	/* Unlike in lx_kill, this process id must be exact, no negatives. */
	if (tgid == 0)
		return (set_errno(ESRCH));
	if (tgid < 0)
		return (set_errno(EINVAL));
	/*
	 * Translate init directly, otherwise use the convenient utility
	 * function to translate. Since we're sending to the whole group, we
	 * only need the solaris pid, and not the lwp id.
	 */
	if (tgid == 1) {
		s_pid = zone->zone_proc_initpid;
	} else {
		if (lx_lpid_to_spair(tgid, &s_pid, NULL) != 0) {
			/*
			 * If we didn't find this pid that means it doesn't
			 * exist in this zone.
			 */
			return (set_errno(ESRCH));
		}
	}
	/*
	 * We shouldn't have queuable signals here, those are sent elsewhere by
	 * the usermode handler for this emulated call.
	 */
	if (!SI_CANQUEUE(kinfo.si_code)) {
		return (set_errno(EINVAL));
	}
	/* Since our signal shouldn't queue, we just call sigsendproc(). */
	bzero(&send, sizeof (send));
	send.sig = sig;
	send.checkperm = 1;
	send.sicode = kinfo.si_code;
	send.value = kinfo.si_value;

	mutex_enter(&pidlock);
	target_proc = prfind(s_pid);
	err = 0;
	if (target_proc != NULL) {
		err = sigsendproc(target_proc, &send);
		if (err == 0 && send.perm == 0)
			err = EPERM;
	} else {
		err = ESRCH;
	}
	mutex_exit(&pidlock);

	return (err ? set_errno(err) : 0);
}

/*
 * Unlike the above function, this handles all system calls to rt_tgsigqueue
 * regardless of si_code.
 */
int
lx_helper_rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *uinfo)
{
	int err;
	proc_t *p = NULL;
	kthread_t *t;
	sigqueue_t *sqp;
	siginfo_t kinfo;

	if (copyin(uinfo, &kinfo, sizeof (siginfo_t)) != 0) {
		return (set_errno(EFAULT));
	}
	sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);

	if (lx_lpid_lock(tid, curzone, NO_PRLOCK, &p, &t) != 0) {
		err = ESRCH;
		goto errout;
	}

	/*
	 * For group leaders, the SunOS pid == Linux pid, so the SunOS leader
	 * pid should be the same as the tgid.   Because the tgid comes in via
	 * the syscall, we need to check for an invalid value.
	 */
	if (p->p_pid != tgid) {
		err = EINVAL;
		goto errout;
	}

	/*
	 * In order to match the Linux behavior of emitting ESRCH errors before
	 * confirming that the signal is valid, this check _must_ be performed
	 * after the target process/thread is located.
	 */
	if (sig < 0 || sig >= NSIG) {
		err = EINVAL;
		goto errout;
	}

	/*
	 * To merely check for the existence of a thread, the caller will pass
	 * a signal value of 0.
	 */
	if (sig != 0) {
		ASSERT(sqp != NULL);

		sqp->sq_info.si_signo = sig;
		sqp->sq_info.si_code = kinfo.si_code;
		sqp->sq_info.si_pid = p->p_pid;
		sqp->sq_info.si_ctid = PRCTID(p);
		sqp->sq_info.si_zoneid = getzoneid();
		sqp->sq_info.si_uid = crgetruid(CRED());
		sigaddqa(p, t, sqp);
	}
	mutex_exit(&p->p_lock);
	return (0);

errout:
	if (p != NULL) {
		mutex_exit(&p->p_lock);
	}
	kmem_free(sqp, sizeof (sigqueue_t));
	return (set_errno(err));
}
