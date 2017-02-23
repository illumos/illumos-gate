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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/prsystm.h>
#include <sys/cred.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/signal.h>
#include <sys/kmem.h>
#include <sys/unistd.h>
#include <sys/cmn_err.h>
#include <sys/schedctl.h>
#include <sys/debug.h>
#include <sys/contract/process_impl.h>

kthread_t *
idtot(proc_t *p, id_t lwpid)
{
	lwpdir_t *ldp;

	if ((ldp = lwp_hash_lookup(p, lwpid)) != NULL)
		return (ldp->ld_entry->le_thread);
	return (NULL);
}

/*
 * Same as idtot(), but acquire and return
 * the tid hash table entry lock on success.
 * This allows lwp_unpark() to do its job without acquiring
 * p->p_lock (and thereby causing congestion problems when
 * the application calls lwp_unpark() too often).
 */
static kthread_t *
idtot_and_lock(proc_t *p, id_t lwpid, kmutex_t **mpp)
{
	lwpdir_t *ldp;
	kthread_t *t;

	if ((ldp = lwp_hash_lookup_and_lock(p, lwpid, mpp)) != NULL) {
		if ((t = ldp->ld_entry->le_thread) == NULL)
			mutex_exit(*mpp);
		return (t);
	}
	return (NULL);
}

/*
 * Stop an lwp of the current process
 */
int
syslwp_suspend(id_t lwpid)
{
	kthread_t *t;
	int error;
	proc_t *p = ttoproc(curthread);

	mutex_enter(&p->p_lock);
	if ((t = idtot(p, lwpid)) == NULL)
		error = ESRCH;
	else
		error = lwp_suspend(t);
	mutex_exit(&p->p_lock);
	if (error)
		return (set_errno(error));
	return (0);
}

int
syslwp_continue(id_t lwpid)
{
	kthread_t *t;
	proc_t *p = ttoproc(curthread);

	mutex_enter(&p->p_lock);
	if ((t = idtot(p, lwpid)) == NULL) {
		mutex_exit(&p->p_lock);
		return (set_errno(ESRCH));
	}
	lwp_continue(t);
	mutex_exit(&p->p_lock);
	return (0);
}

int
lwp_kill(id_t lwpid, int sig)
{
	sigqueue_t *sqp;
	kthread_t *t;
	proc_t *p = ttoproc(curthread);

	if (sig < 0 || sig >= NSIG)
		return (set_errno(EINVAL));
	if (sig != 0)
		sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);
	mutex_enter(&p->p_lock);
	if ((t = idtot(p, lwpid)) == NULL) {
		mutex_exit(&p->p_lock);
		if (sig != 0)
			kmem_free(sqp, sizeof (sigqueue_t));
		return (set_errno(ESRCH));
	}
	if (sig == 0) {
		mutex_exit(&p->p_lock);
		return (0);
	}
	sqp->sq_info.si_signo = sig;
	sqp->sq_info.si_code = SI_LWP;
	sqp->sq_info.si_pid = p->p_pid;
	sqp->sq_info.si_ctid = PRCTID(p);
	sqp->sq_info.si_zoneid = getzoneid();
	sqp->sq_info.si_uid = crgetruid(CRED());
	sigaddqa(p, t, sqp);
	mutex_exit(&p->p_lock);
	return (0);
}

/*
 * This is the specification of lwp_wait() from the _lwp_wait(2) manual page:
 *
 * The lwp_wait() function blocks the current lwp until the lwp specified
 * by 'lwpid' terminates.  If the specified lwp terminated prior to the call
 * to lwp_wait(), then lwp_wait() returns immediately.  If 'lwpid' is zero,
 * then lwp_wait() waits for any undetached lwp in the current process.
 * If 'lwpid' is not zero, then it must specify an undetached lwp in the
 * current process.  If 'departed' is not NULL, then it points to a location
 * where the id of the exited lwp is stored.
 *
 * When an lwp exits and there are one or more lwps in the process waiting
 * for this specific lwp to exit, then one of the waiting lwps is unblocked
 * and it returns from lwp_wait() successfully.  Any other lwps waiting for
 * this same lwp to exit are also unblocked, however, they return from
 * lwp_wait() with the error ESRCH.  If there are no lwps in the process
 * waiting for this specific lwp to exit but there are one or more lwps
 * waiting for any lwp to exit, then one of the waiting lwps is unblocked
 * and it returns from lwp_wait() successfully.
 *
 * If an lwp is waiting for any lwp to exit, it blocks until an undetached
 * lwp for which no other lwp is waiting terminates, at which time it returns
 * successfully, or until all other lwps in the process are either daemon
 * lwps or lwps waiting in lwp_wait(), in which case it returns EDEADLK.
 */
int
lwp_wait(id_t lwpid, id_t *departed)
{
	proc_t *p = ttoproc(curthread);
	int error = 0;
	int daemon = (curthread->t_proc_flag & TP_DAEMON)? 1 : 0;
	lwpent_t *target_lep;
	lwpdir_t *ldp;
	lwpent_t *lep;

	/*
	 * lwp_wait() is not supported for the /proc agent lwp.
	 */
	if (curthread == p->p_agenttp)
		return (set_errno(ENOTSUP));

	mutex_enter(&p->p_lock);
	prbarrier(p);

	curthread->t_waitfor = lwpid;
	p->p_lwpwait++;
	p->p_lwpdwait += daemon;

	if (lwpid != 0) {
		if ((ldp = lwp_hash_lookup(p, lwpid)) == NULL)
			target_lep = NULL;
		else {
			target_lep = ldp->ld_entry;
			target_lep->le_waiters++;
			target_lep->le_dwaiters += daemon;
		}
	}

	while (error == 0) {
		kthread_t *t;
		id_t tid;
		int i;

		if (lwpid != 0) {
			/*
			 * Look for a specific zombie lwp.
			 */
			if (target_lep == NULL)
				error = ESRCH;
			else if ((t = target_lep->le_thread) != NULL) {
				if (!(t->t_proc_flag & TP_TWAIT))
					error = EINVAL;
			} else {
				/*
				 * We found the zombie we are waiting for.
				 */
				ASSERT(p->p_zombcnt > 0);
				p->p_zombcnt--;
				p->p_lwpwait--;
				p->p_lwpdwait -= daemon;
				curthread->t_waitfor = -1;
				lwp_hash_out(p, lwpid);
				mutex_exit(&p->p_lock);
				if (departed != NULL &&
				    copyout(&lwpid, departed, sizeof (id_t)))
					return (set_errno(EFAULT));
				return (0);
			}
		} else {
			/*
			 * Look for any zombie lwp.
			 */
			int some_non_daemon_will_return = 0;

			/* for each entry in the lwp directory... */
			ldp = p->p_lwpdir;
			for (i = 0; i < p->p_lwpdir_sz; i++, ldp++) {

				if ((lep = ldp->ld_entry) == NULL ||
				    lep->le_thread != NULL)
					continue;

				/*
				 * We found a zombie lwp.  If there is some
				 * other thread waiting specifically for the
				 * zombie we just found, then defer to the other
				 * waiting thread and continue searching for
				 * another zombie.  Also check to see if there
				 * is some non-daemon thread sleeping here in
				 * lwp_wait() that will succeed and return when
				 * we drop p->p_lock.  This is tested below.
				 */
				tid = lep->le_lwpid;
				if (lep->le_waiters != 0) {
					if (lep->le_waiters - lep->le_dwaiters)
						some_non_daemon_will_return = 1;
					continue;
				}

				/*
				 * We found a zombie that no one else
				 * is specifically waiting for.
				 */
				ASSERT(p->p_zombcnt > 0);
				p->p_zombcnt--;
				p->p_lwpwait--;
				p->p_lwpdwait -= daemon;
				curthread->t_waitfor = -1;
				lwp_hash_out(p, tid);
				mutex_exit(&p->p_lock);
				if (departed != NULL &&
				    copyout(&tid, departed, sizeof (id_t)))
					return (set_errno(EFAULT));
				return (0);
			}

			/*
			 * We are waiting for anyone.  If all non-daemon lwps
			 * are waiting here, and if we determined above that
			 * no non-daemon lwp will return, we have deadlock.
			 */
			if (!some_non_daemon_will_return &&
			    p->p_lwpcnt == p->p_lwpdaemon +
			    (p->p_lwpwait - p->p_lwpdwait))
				error = EDEADLK;
		}

		if (error == 0 && lwpid != 0) {
			/*
			 * We are waiting for a specific non-zombie lwp.
			 * Fail if there is a deadlock loop.
			 */
			for (;;) {
				if (t == curthread) {
					error = EDEADLK;
					break;
				}
				/* who are they waiting for? */
				if ((tid = t->t_waitfor) == -1)
					break;
				if (tid == 0) {
					/*
					 * The lwp we are waiting for is
					 * waiting for anyone (transitively).
					 * If there are no zombies right now
					 * and if we would have deadlock due
					 * to all non-daemon lwps waiting here,
					 * wake up the lwp that is waiting for
					 * anyone so it can return EDEADLK.
					 */
					if (p->p_zombcnt == 0 &&
					    p->p_lwpcnt == p->p_lwpdaemon +
					    p->p_lwpwait - p->p_lwpdwait)
						cv_broadcast(&p->p_lwpexit);
					break;
				}
				if ((ldp = lwp_hash_lookup(p, tid)) == NULL ||
				    (t = ldp->ld_entry->le_thread) == NULL)
					break;
			}
		}

		if (error)
			break;

		/*
		 * Wait for some lwp to terminate.
		 */
		if (!cv_wait_sig(&p->p_lwpexit, &p->p_lock))
			error = EINTR;
		prbarrier(p);

		if (lwpid != 0) {
			if ((ldp = lwp_hash_lookup(p, lwpid)) == NULL)
				target_lep = NULL;
			else
				target_lep = ldp->ld_entry;
		}
	}

	if (lwpid != 0 && target_lep != NULL) {
		target_lep->le_waiters--;
		target_lep->le_dwaiters -= daemon;
	}
	p->p_lwpwait--;
	p->p_lwpdwait -= daemon;
	curthread->t_waitfor = -1;
	mutex_exit(&p->p_lock);
	return (set_errno(error));
}

int
lwp_detach(id_t lwpid)
{
	kthread_t *t;
	proc_t *p = ttoproc(curthread);
	lwpdir_t *ldp;
	int error = 0;

	mutex_enter(&p->p_lock);
	prbarrier(p);
	if ((ldp = lwp_hash_lookup(p, lwpid)) == NULL)
		error = ESRCH;
	else if ((t = ldp->ld_entry->le_thread) != NULL) {
		if (!(t->t_proc_flag & TP_TWAIT))
			error = EINVAL;
		else {
			t->t_proc_flag &= ~TP_TWAIT;
			cv_broadcast(&p->p_lwpexit);
		}
	} else {
		ASSERT(p->p_zombcnt > 0);
		p->p_zombcnt--;
		lwp_hash_out(p, lwpid);
	}
	mutex_exit(&p->p_lock);

	if (error)
		return (set_errno(error));
	return (0);
}

/*
 * Unpark the specified lwp.
 */
static int
lwp_unpark(id_t lwpid)
{
	proc_t *p = ttoproc(curthread);
	kthread_t *t;
	kmutex_t *mp;
	int error = 0;

	if ((t = idtot_and_lock(p, lwpid, &mp)) == NULL) {
		error = ESRCH;
	} else {
		mutex_enter(&t->t_delay_lock);
		t->t_unpark = 1;
		cv_signal(&t->t_delay_cv);
		mutex_exit(&t->t_delay_lock);
		mutex_exit(mp);
	}
	return (error);
}

/*
 * Cancel a previous unpark for the specified lwp.
 *
 * This interface exists ONLY to support older versions of libthread, which
 * called lwp_unpark(self) to force calls to lwp_park(self) to return
 * immediately.  These older libthreads required a mechanism to cancel the
 * lwp_unpark(self).
 *
 * libc does not call this interface.  Instead, the sc_park flag in the
 * schedctl page is cleared to force calls to lwp_park() to return
 * immediately.
 */
static int
lwp_unpark_cancel(id_t lwpid)
{
	proc_t *p = ttoproc(curthread);
	kthread_t *t;
	kmutex_t *mp;
	int error = 0;

	if ((t = idtot_and_lock(p, lwpid, &mp)) == NULL) {
		error = ESRCH;
	} else {
		mutex_enter(&t->t_delay_lock);
		t->t_unpark = 0;
		mutex_exit(&t->t_delay_lock);
		mutex_exit(mp);
	}
	return (error);
}

/*
 * Sleep until we are set running by lwp_unpark() or until we are
 * interrupted by a signal or until we exhaust our timeout.
 * timeoutp is an in/out parameter.  On entry, it contains the relative
 * time until timeout.  On exit, we copyout the residual time left to it.
 */
static int
lwp_park(timespec_t *timeoutp, id_t lwpid)
{
	timespec_t rqtime;
	timespec_t rmtime;
	timespec_t now;
	timespec_t *rqtp = NULL;
	kthread_t *t = curthread;
	int timecheck = 0;
	int error = 0;
	model_t datamodel = ttoproc(t)->p_model;

	if (lwpid != 0)		/* unpark the other lwp, if any */
		(void) lwp_unpark(lwpid);

	if (timeoutp) {
		timecheck = timechanged;
		gethrestime(&now);
		if (datamodel == DATAMODEL_NATIVE) {
			if (copyin(timeoutp, &rqtime, sizeof (timespec_t))) {
				error = EFAULT;
				goto out;
			}
		} else {
			timespec32_t timeout32;

			if (copyin(timeoutp, &timeout32, sizeof (timeout32))) {
				error = EFAULT;
				goto out;
			}
			TIMESPEC32_TO_TIMESPEC(&rqtime, &timeout32)
		}

		if (itimerspecfix(&rqtime)) {
			error = EINVAL;
			goto out;
		}
		/*
		 * Convert the timespec value into absolute time.
		 */
		timespecadd(&rqtime, &now);
		rqtp = &rqtime;
	}

	(void) new_mstate(t, LMS_USER_LOCK);

	mutex_enter(&t->t_delay_lock);
	if (!schedctl_is_park())
		error = EINTR;
	while (error == 0 && t->t_unpark == 0) {
		switch (cv_waituntil_sig(&t->t_delay_cv,
		    &t->t_delay_lock, rqtp, timecheck)) {
		case 0:
			error = EINTR;
			break;
		case -1:
			error = ETIME;
			break;
		}
	}
	t->t_unpark = 0;
	mutex_exit(&t->t_delay_lock);

	if (timeoutp != NULL) {
		rmtime.tv_sec = rmtime.tv_nsec = 0;
		if (error != ETIME) {
			gethrestime(&now);
			if ((now.tv_sec < rqtime.tv_sec) ||
			    ((now.tv_sec == rqtime.tv_sec) &&
			    (now.tv_nsec < rqtime.tv_nsec))) {
				rmtime = rqtime;
				timespecsub(&rmtime, &now);
			}
		}
		if (datamodel == DATAMODEL_NATIVE) {
			if (copyout(&rmtime, timeoutp, sizeof (rmtime)))
				error = EFAULT;
		} else {
			timespec32_t rmtime32;

			TIMESPEC_TO_TIMESPEC32(&rmtime32, &rmtime);
			if (copyout(&rmtime32, timeoutp, sizeof (rmtime32)))
				error = EFAULT;
		}
	}
out:
	schedctl_unpark();
	if (t->t_mstate == LMS_USER_LOCK)
		(void) new_mstate(t, LMS_SYSTEM);
	return (error);
}

#define	MAXLWPIDS	1024

/*
 * Unpark all of the specified lwps.
 * Do it in chunks of MAXLWPIDS to avoid allocating too much memory.
 */
static int
lwp_unpark_all(id_t *lwpidp, int nids)
{
	proc_t *p = ttoproc(curthread);
	kthread_t *t;
	kmutex_t *mp;
	int error = 0;
	id_t *lwpid;
	size_t lwpidsz;
	int n;
	int i;

	if (nids <= 0)
		return (EINVAL);

	lwpidsz = MIN(nids, MAXLWPIDS) * sizeof (id_t);
	lwpid = kmem_alloc(lwpidsz, KM_SLEEP);
	while (nids > 0) {
		n = MIN(nids, MAXLWPIDS);
		if (copyin(lwpidp, lwpid, n * sizeof (id_t))) {
			error = EFAULT;
			break;
		}
		for (i = 0; i < n; i++) {
			if ((t = idtot_and_lock(p, lwpid[i], &mp)) == NULL) {
				error = ESRCH;
			} else {
				mutex_enter(&t->t_delay_lock);
				t->t_unpark = 1;
				cv_signal(&t->t_delay_cv);
				mutex_exit(&t->t_delay_lock);
				mutex_exit(mp);
			}
		}
		lwpidp += n;
		nids -= n;
	}
	kmem_free(lwpid, lwpidsz);
	return (error);
}

/*
 * SYS_lwp_park() system call.
 */
int
syslwp_park(int which, uintptr_t arg1, uintptr_t arg2)
{
	int error;

	switch (which) {
	case 0:
		error = lwp_park((timespec_t *)arg1, (id_t)arg2);
		break;
	case 1:
		error = lwp_unpark((id_t)arg1);
		break;
	case 2:
		error = lwp_unpark_all((id_t *)arg1, (int)arg2);
		break;
	case 3:
		/*
		 * This subcode is not used by libc.  It exists ONLY to
		 * support older versions of libthread which do not use
		 * the sc_park flag in the schedctl page.
		 *
		 * These versions of libthread need to be modifed or emulated
		 * to change calls to syslwp_park(1, tid, 0) to
		 * syslwp_park(3, tid).
		 */
		error = lwp_unpark_cancel((id_t)arg1);
		break;
	case 4:
		/*
		 * This subcode is not used by libc.  It exists ONLY to
		 * support older versions of libthread which do not use
		 * the sc_park flag in the schedctl page.
		 *
		 * These versions of libthread need to be modified or emulated
		 * to change calls to syslwp_park(0, ts, tid) to
		 * syslwp_park(4, ts, tid).
		 */
		schedctl_set_park();
		error = lwp_park((timespec_t *)arg1, (id_t)arg2);
		break;
	default:
		error = EINVAL;
		break;
	}

	if (error)
		return (set_errno(error));
	return (0);
}
