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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
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
#include <sys/lx_pid.h>
#include <lx_signum.h>
#include <sys/contract/process_impl.h>

extern int kill(pid_t, int);

/*
 * Check if it is legal to send this signal to the init process.  Linux
 * kill(2) semantics dictate that no _unhandled_ signal may be sent to pid
 * 1.
 */
static int
init_sig_check(int sig, pid_t pid)
{
	proc_t *p;
	int rv = 0;

	mutex_enter(&pidlock);

	if (((p = prfind(pid)) == NULL) || (p->p_stat == SIDL))
		rv = ESRCH;
	else if (sig && (sigismember(&cantmask, sig) ||
	    (PTOU(p)->u_signal[sig-1] == SIG_DFL) ||
	    (PTOU(p)->u_signal[sig-1] == SIG_IGN)))
		rv = EPERM;

	mutex_exit(&pidlock);

	return (rv);
}

static long
lx_thrkill(pid_t tgid, pid_t pid, int lx_sig, boolean_t tgkill)
{
	kthread_t *t;
	proc_t *pp;
	pid_t initpid;
	sigqueue_t *sqp;
	struct lx_lwp_data *br = ttolxlwp(curthread);
	int tid = 1;	/* default tid */
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
	initpid = curproc->p_zone->zone_proc_initpid;
	if (pid == 1)
		pid = initpid;
	if ((pid == initpid) && ((rv = init_sig_check(sig, pid)) != 0))
		return (set_errno(rv));
	else if (lx_lpid_to_spair(pid, &pid, &tid) < 0)
		return (set_errno(ESRCH));

	if (tgkill && tgid != pid)
		return (set_errno(ESRCH));

	sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);

	/*
	 * Find the process for the passed pid...
	 */
	mutex_enter(&pidlock);
	if (((pp = prfind(pid)) == NULL) || (pp->p_stat == SIDL)) {
		mutex_exit(&pidlock);
		rv = set_errno(ESRCH);
		goto free_and_exit;
	}
	mutex_enter(&pp->p_lock);
	mutex_exit(&pidlock);

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
	if (((sig == SIGCONT) && (pp->p_sessp != curproc->p_sessp)) ||
	    (!prochasprocperm(pp, curproc, CRED()))) {
		mutex_exit(&pp->p_lock);
		rv = set_errno(EPERM);
		goto free_and_exit;
	}

	/* check for the tid */
	if ((t = idtot(pp, tid)) == NULL) {
		mutex_exit(&pp->p_lock);
		rv = set_errno(ESRCH);
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
	sqp->sq_info.si_pid = br->br_pid;
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
	zone_t *zone = curproc->p_zone;
	struct proc *p;
	int err, sig, nfound;

	if ((lx_sig < 0) || (lx_sig > LX_NSIG) ||
	    ((sig = ltos_signo[lx_sig]) < 0))
		return (set_errno(EINVAL));

	/*
	 * Since some linux apps rely on init(1M) having PID 1, we
	 * transparently translate 1 to the real init(1M)'s pid.  We then
	 * check to be sure that it is legal for this process to send this
	 * signal to init(1M).
	 */
	initpid = zone->zone_proc_initpid;
	if (lx_pid == 1 || lx_pid == -1) {
		s_pid = initpid;
	} else if (lx_pid == 0) {
		s_pid = 0;
	} else if (lx_pid > 0) {
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

	if ((s_pid == initpid) && ((err = init_sig_check(sig, s_pid)) != 0))
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
	if (nfound == 0)
		err = ESRCH;
	else if (err == 0 && v.perm == 0)
		err = EPERM;
	return (err ? set_errno(err) : 0);
}

/*
 * This handles the unusual case where the user sends a non-queueable signal
 * through rt_sigqueueinfo. Signals sent with codes that indicate they are
 * queuable are sent through the sigqueue syscall via the user level function
 * lx_rt_sigqueueinfo().
 */
long
lx_rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *uinfo)
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
	 * the useland handler for this emulated call.
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
long
lx_rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *uinfo)
{
	id_t s_tid;
	pid_t s_pid;
	proc_t *target_proc;
	sigqueue_t *sqp;
	kthread_t *t;
	siginfo_t kinfo;

	if (copyin(uinfo, &kinfo, sizeof (siginfo_t)) != 0)
		return (set_errno(EFAULT));
	if (lx_lpid_to_spair(tid, &s_pid, &s_tid) != 0)
		return (set_errno(ESRCH));
	/*
	 * For group leaders, solaris pid == linux pid, so the solaris leader
	 * pid should be the same as the tgid.
	 */
	ASSERT(s_pid == tgid);

	mutex_enter(&pidlock);
	target_proc = prfind(s_pid);
	if (target_proc != NULL)
		mutex_enter(&target_proc->p_lock);
	mutex_exit(&pidlock);

	if (target_proc == NULL) {
		return (set_errno(ESRCH));
	}
	if (sig < 0 || sig >= NSIG)
		return (set_errno(EINVAL));

	/*
	 * Some code adapted from lwp_kill, duplicated here because we do some
	 * customization to the sq_info field of sqp.
	 */
	if ((t = idtot(target_proc, s_tid)) == NULL) {
		mutex_exit(&target_proc->p_lock);
		return (set_errno(ESRCH));
	}
	/* Just checking for existence of the process, not sending a signal. */
	if (sig == 0) {
		mutex_exit(&target_proc->p_lock);
		return (0);
	}
	sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);
	sqp->sq_info.si_signo = sig;
	sqp->sq_info.si_code = kinfo.si_code;
	sqp->sq_info.si_pid = target_proc->p_pid;
	sqp->sq_info.si_ctid = PRCTID(target_proc);
	sqp->sq_info.si_zoneid = getzoneid();
	sqp->sq_info.si_uid = crgetruid(CRED());
	sigaddqa(target_proc, t, sqp);
	mutex_exit(&target_proc->p_lock);
	return (0);
}
