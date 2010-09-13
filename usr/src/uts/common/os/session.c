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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/errno.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/policy.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/proc.h>
#include <sys/session.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/strsubr.h>
#include <sys/fs/snode.h>

sess_t session0 = {
	&pid0,		/* s_sidp */
	{0},		/* s_lock */
	1,		/* s_ref */
	B_FALSE,	/* s_sighuped */
	B_FALSE,	/* s_exit */
	0,		/* s_exit_cv */
	0,		/* s_cnt */
	0,		/* s_cnt_cv */
	NODEV,		/* s_dev */
	NULL,		/* s_vp */
	NULL		/* s_cred */
};

void
sess_hold(proc_t *p)
{
	ASSERT(MUTEX_HELD(&pidlock) || MUTEX_HELD(&p->p_splock));
	mutex_enter(&p->p_sessp->s_lock);
	p->p_sessp->s_ref++;
	mutex_exit(&p->p_sessp->s_lock);
}

void
sess_rele(sess_t *sp, boolean_t pidlock_held)
{
	ASSERT(MUTEX_HELD(&pidlock) || !pidlock_held);

	mutex_enter(&sp->s_lock);

	ASSERT(sp->s_ref != 0);
	if (--sp->s_ref > 0) {
		mutex_exit(&sp->s_lock);
		return;
	}
	ASSERT(sp->s_ref == 0);

	/*
	 * It's ok to free this session structure now because we know
	 * that no one else can have a pointer to it.  We know this
	 * to be true because the only time that s_ref can possibly
	 * be incremented is when pidlock or p_splock is held AND there
	 * is a proc_t that points to that session structure.  In that
	 * case we are guaranteed that the s_ref is at least 1 since there
	 * is a proc_t that points to it.  So when s_ref finally drops to
	 * zero then no one else has a reference (and hence pointer) to
	 * this session structure and there is no valid proc_t pointing
	 * to this session structure anymore so, no one can acquire a
	 * reference (and pointer) to this session structure so it's
	 * ok to free it here.
	 */

	if (sp == &session0)
		panic("sp == &session0");

	/* make sure there are no outstanding holds */
	ASSERT(sp->s_cnt == 0);

	/* make sure there is no exit in progress */
	ASSERT(!sp->s_exit);

	/* make sure someone already freed any ctty */
	ASSERT(sp->s_vp == NULL);
	ASSERT(sp->s_dev == NODEV);

	if (!pidlock_held)
		mutex_enter(&pidlock);
	PID_RELE(sp->s_sidp);
	if (!pidlock_held)
		mutex_exit(&pidlock);

	mutex_destroy(&sp->s_lock);
	cv_destroy(&sp->s_cnt_cv);
	kmem_free(sp, sizeof (sess_t));
}

sess_t *
tty_hold(void)
{
	proc_t		*p = curproc;
	sess_t		*sp;
	boolean_t	got_sig = B_FALSE;

	/* make sure the caller isn't holding locks they shouldn't */
	ASSERT(MUTEX_NOT_HELD(&pidlock));

	for (;;) {
		mutex_enter(&p->p_splock);	/* protect p->p_sessp */
		sp = p->p_sessp;
		mutex_enter(&sp->s_lock);	/* protect sp->* */

		/* make sure the caller isn't holding locks they shouldn't */
		ASSERT((sp->s_vp == NULL) ||
		    MUTEX_NOT_HELD(&sp->s_vp->v_stream->sd_lock));

		/*
		 * If the session leader process is not exiting (and hence
		 * not trying to release the session's ctty) then we can
		 * safely grab a hold on the current session structure
		 * and return it.  If on the other hand the session leader
		 * process is exiting and clearing the ctty then we'll
		 * wait till it's done before we loop around and grab a
		 * hold on the session structure.
		 */
		if (!sp->s_exit)
			break;

		/* need to hold the session so it can't be freed */
		sp->s_ref++;
		mutex_exit(&p->p_splock);

		/* Wait till the session leader is done */
		if (!cv_wait_sig(&sp->s_exit_cv, &sp->s_lock))
			got_sig = B_TRUE;

		/*
		 * Now we need to drop our hold on the session structure,
		 * but we can't hold any locks when we do this because
		 * sess_rele() may need to acquire pidlock.
		 */
		mutex_exit(&sp->s_lock);
		sess_rele(sp, B_FALSE);

		if (got_sig)
			return (NULL);
	}

	/* whew, we finally got a hold */
	sp->s_cnt++;
	sp->s_ref++;
	mutex_exit(&sp->s_lock);
	mutex_exit(&p->p_splock);
	return (sp);
}

void
tty_rele(sess_t *sp)
{
	/* make sure the caller isn't holding locks they shouldn't */
	ASSERT(MUTEX_NOT_HELD(&pidlock));

	mutex_enter(&sp->s_lock);
	if ((--sp->s_cnt) == 0)
		cv_broadcast(&sp->s_cnt_cv);
	mutex_exit(&sp->s_lock);

	sess_rele(sp, B_FALSE);
}

void
sess_create(void)
{
	proc_t *p = curproc;
	sess_t *sp, *old_sp;

	sp = kmem_zalloc(sizeof (sess_t), KM_SLEEP);

	mutex_init(&sp->s_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sp->s_cnt_cv, NULL, CV_DEFAULT, NULL);

	/*
	 * we need to grap p_lock to protect p_pgidp because
	 * /proc looks at p_pgidp while holding only p_lock.
	 *
	 * we don't need to hold p->p_sessp->s_lock or get a hold on the
	 * session structure since we're not actually updating any of
	 * the contents of the old session structure.
	 */
	mutex_enter(&pidlock);
	mutex_enter(&p->p_lock);
	mutex_enter(&p->p_splock);

	pgexit(p);

	sp->s_sidp = p->p_pidp;
	sp->s_ref = 1;
	sp->s_dev = NODEV;

	old_sp = p->p_sessp;
	p->p_sessp = sp;

	pgjoin(p, p->p_pidp);
	PID_HOLD(p->p_pidp);

	mutex_exit(&p->p_splock);
	mutex_exit(&p->p_lock);
	mutex_exit(&pidlock);

	sess_rele(old_sp, B_FALSE);
}

/*
 * Note that sess_ctty_clear() resets all the fields in the session
 * structure but doesn't release any holds or free any objects
 * that the session structure might currently point to.  it is the
 * callers responsibility to do this.
 */
static void
sess_ctty_clear(sess_t *sp, stdata_t *stp)
{
	/*
	 * Assert that we hold all the necessary locks.  We also need
	 * to be holding proc_t->p_splock for the process associated
	 * with this session, but since we don't have a proc pointer
	 * passed in we can't assert this here.
	 */
	ASSERT(MUTEX_HELD(&stp->sd_lock) && MUTEX_HELD(&pidlock) &&
	    MUTEX_HELD(&sp->s_lock));

	/* reset the session structure members to defaults */
	sp->s_sighuped = B_FALSE;
	sp->s_dev = NODEV;
	sp->s_vp = NULL;
	sp->s_cred = NULL;

	/* reset the stream session and group pointers */
	stp->sd_pgidp = NULL;
	stp->sd_sidp = NULL;
}

static void
sess_ctty_set(proc_t *p, sess_t *sp, stdata_t *stp)
{
	cred_t	*crp;

	/* Assert that we hold all the necessary locks. */
	ASSERT(MUTEX_HELD(&stp->sd_lock) && MUTEX_HELD(&pidlock) &&
	    MUTEX_HELD(&p->p_splock) && MUTEX_HELD(&sp->s_lock));

	/* get holds on structures */
	mutex_enter(&p->p_crlock);
	crhold(crp = p->p_cred);
	mutex_exit(&p->p_crlock);
	PID_HOLD(sp->s_sidp);	/* requires pidlock */
	PID_HOLD(sp->s_sidp);	/* requires pidlock */

	/* update the session structure members */
	sp->s_vp = makectty(stp->sd_vnode);
	sp->s_dev = sp->s_vp->v_rdev;
	sp->s_cred = crp;

	/* update the stream emebers */
	stp->sd_flag |= STRISTTY;	/* just to be sure */
	stp->sd_sidp = sp->s_sidp;
	stp->sd_pgidp = sp->s_sidp;
}

int
strctty(stdata_t *stp)
{
	sess_t		*sp;
	proc_t		*p = curproc;
	boolean_t	got_sig = B_FALSE;

	/*
	 * We are going to try to make stp the default ctty for the session
	 * associated with curproc.  Not only does this require holding a
	 * bunch of locks but it also requires waiting for any outstanding
	 * holds on the session structure (acquired via tty_hold()) to be
	 * released.  Hence, we have the following for(;;) loop that will
	 * acquire our locks, do some sanity checks, and wait for the hold
	 * count on the session structure to hit zero.  If we get a signal
	 * while waiting for outstanding holds to be released then we abort
	 * the operation and return.
	 */
	for (;;) {
		mutex_enter(&stp->sd_lock);	/* protects sd_pgidp/sd_sidp */
		mutex_enter(&pidlock);		/* protects p_pidp */
		mutex_enter(&p->p_splock);	/* protects p_sessp */
		sp = p->p_sessp;
		mutex_enter(&sp->s_lock);	/* protects sp->* */

		if (((stp->sd_flag & (STRHUP|STRDERR|STWRERR|STPLEX)) != 0) ||
		    (stp->sd_sidp != NULL) ||		/* stp already ctty? */
		    (p->p_pidp != sp->s_sidp) ||	/* we're not leader? */
		    (sp->s_vp != NULL)) {		/* session has ctty? */
			mutex_exit(&sp->s_lock);
			mutex_exit(&p->p_splock);
			mutex_exit(&pidlock);
			mutex_exit(&stp->sd_lock);
			return (ENOTTY);
		}

		/* sanity check.  we can't be exiting right now */
		ASSERT(!sp->s_exit);

		/*
		 * If no one else has a hold on this session structure
		 * then we now have exclusive access to it, so break out
		 * of this loop and update the session structure.
		 */
		if (sp->s_cnt == 0)
			break;

		/* need to hold the session so it can't be freed */
		sp->s_ref++;

		/* ain't locking order fun? */
		mutex_exit(&p->p_splock);
		mutex_exit(&pidlock);
		mutex_exit(&stp->sd_lock);

		if (!cv_wait_sig(&sp->s_cnt_cv, &sp->s_lock))
			got_sig = B_TRUE;
		mutex_exit(&sp->s_lock);
		sess_rele(sp, B_FALSE);

		if (got_sig)
			return (EINTR);
	}

	/* set the session ctty bindings */
	sess_ctty_set(p, sp, stp);

	mutex_exit(&sp->s_lock);
	mutex_exit(&p->p_splock);
	mutex_exit(&pidlock);
	mutex_exit(&stp->sd_lock);
	return (0);
}

/*
 * freectty_lock() attempts to acquire the army of locks required to free
 * the ctty associated with a given session leader process.  If it returns
 * successfully the following locks will be held:
 *	sd_lock, pidlock, p_splock, s_lock
 *
 * as a secondary bit of convenience, freectty_lock() will also return
 * pointers to the session, ctty, and ctty stream associated with the
 * specified session leader process.
 */
static boolean_t
freectty_lock(proc_t *p, sess_t **spp, vnode_t **vpp, stdata_t **stpp,
    boolean_t at_exit)
{
	sess_t		*sp;
	vnode_t		*vp;
	stdata_t	*stp;

	mutex_enter(&pidlock);			/* protect p_pidp */
	mutex_enter(&p->p_splock);		/* protect p->p_sessp */
	sp = p->p_sessp;
	mutex_enter(&sp->s_lock);		/* protect sp->* */

	if ((sp->s_sidp != p->p_pidp) ||	/* we're not leader? */
	    (sp->s_vp == NULL)) {		/* no ctty? */
		mutex_exit(&sp->s_lock);
		mutex_exit(&p->p_splock);
		mutex_exit(&pidlock);
		return (B_FALSE);
	}

	vp = sp->s_vp;
	stp = sp->s_vp->v_stream;

	if (at_exit) {
		/* stop anyone else calling tty_hold() */
		sp->s_exit = B_TRUE;
	} else {
		/*
		 * due to locking order we have to grab stp->sd_lock before
		 * grabbing all the other proc/session locks.  but after we
		 * drop all our current locks it's possible that someone
		 * could come in and change our current session or close
		 * the current ctty (vp) there by making sp or stp invalid.
		 * (a VN_HOLD on vp won't protect stp because that only
		 * prevents the vnode from being freed not closed.)  so
		 * to prevent this we bump s_ref and s_cnt here.
		 *
		 * course this doesn't matter if we're the last thread in
		 * an exiting process that is the session leader, since no
		 * one else can change our session or free our ctty.
		 */
		sp->s_ref++;	/* hold the session structure */
		sp->s_cnt++;	/* protect vp and stp */
	}

	/* drop our session locks */
	mutex_exit(&sp->s_lock);
	mutex_exit(&p->p_splock);
	mutex_exit(&pidlock);

	/* grab locks in the right order */
	mutex_enter(&stp->sd_lock);		/* protects sd_pgidp/sd_sidp */
	mutex_enter(&pidlock);			/* protect p_pidp */
	mutex_enter(&p->p_splock);		/* protects p->p_sessp */
	mutex_enter(&sp->s_lock);		/* protects sp->* */

	/* if the session has changed, abort mission */
	if (sp != p->p_sessp) {
		/*
		 * this can't happen during process exit since we're the
		 * only thread in the process and we sure didn't change
		 * our own session at this point.
		 */
		ASSERT(!at_exit);

		/* release our locks and holds */
		mutex_exit(&sp->s_lock);
		mutex_exit(&p->p_splock);
		mutex_exit(&pidlock);
		mutex_exit(&stp->sd_lock);
		tty_rele(sp);
		return (B_FALSE);
	}

	/*
	 * sanity checks.  none of this should have changed since we had
	 * holds on the current ctty.
	 */
	ASSERT(sp->s_sidp == p->p_pidp);	/* we're the leader */
	ASSERT(sp->s_vp != NULL);		/* a ctty exists */
	ASSERT(vp == sp->s_vp);
	ASSERT(stp == sp->s_vp->v_stream);

	/* release our holds */
	if (!at_exit) {
		if ((--(sp)->s_cnt) == 0)
			cv_broadcast(&sp->s_cnt_cv);
		sp->s_ref--;
		ASSERT(sp->s_ref > 0);
	}

	/* return our pointers */
	*spp = sp;
	*vpp = vp;
	*stpp = stp;

	return (B_TRUE);
}

/*
 * Returns B_FALSE if no signal is sent to the process group associated with
 * this ctty.  Returns B_TRUE if a signal is sent to the process group.
 * If it return B_TRUE it also means that all the locks we were holding
 * were dropped so that we could send the signal.
 */
static boolean_t
freectty_signal(proc_t *p, sess_t *sp, stdata_t *stp, boolean_t at_exit)
{
	/* Assert that we hold all the necessary locks. */
	ASSERT(MUTEX_HELD(&stp->sd_lock) && MUTEX_HELD(&pidlock) &&
	    MUTEX_HELD(&p->p_splock) && MUTEX_HELD(&sp->s_lock));

	/* check if we already signaled this group */
	if (sp->s_sighuped)
		return (B_FALSE);

	sp->s_sighuped = B_TRUE;

	if (!at_exit) {
		/*
		 * once again, we're about to drop our army of locks and we
		 * don't want sp or stp to be freed.  (see the comment in
		 * freectty_lock())
		 */
		sp->s_ref++;	/* hold the session structure */
		sp->s_cnt++;	/* protect vp and stp */
	}

	/* can't hold these locks while calling pgsignal() */
	mutex_exit(&sp->s_lock);
	mutex_exit(&p->p_splock);
	mutex_exit(&pidlock);

	/* signal anyone in the foreground process group */
	pgsignal(stp->sd_pgidp, SIGHUP);

	/* signal anyone blocked in poll on this stream */
	if (!(stp->sd_flag & STRHUP))
		strhup(stp);

	mutex_exit(&stp->sd_lock);

	/* release our holds */
	if (!at_exit)
		tty_rele(sp);

	return (B_TRUE);
}

int
freectty(boolean_t at_exit)
{
	proc_t		*p = curproc;
	stdata_t	*stp;
	vnode_t		*vp;
	cred_t		*cred;
	sess_t		*sp;
	struct pid	*pgidp, *sidp;
	boolean_t	got_sig = B_FALSE;

	/*
	 * If the current process is a session leader we are going to
	 * try to release the ctty associated our current session.  To
	 * do this we need to acquire a bunch of locks, signal any
	 * processes in the forground that are associated with the ctty,
	 * and make sure no one has any outstanding holds on the current
	 * session * structure (acquired via tty_hold()).  Hence, we have
	 * the following for(;;) loop that will do all this work for
	 * us and break out when the hold count on the session structure
	 * hits zero.
	 */
	for (;;) {
		if (!freectty_lock(p, &sp, &vp, &stp, at_exit))
			return (EIO);

		if (freectty_signal(p, sp, stp, at_exit)) {
			/* loop around to re-acquire locks */
			continue;
		}

		/*
		 * Only a session leader process can free a ctty.  So if
		 * we've made it here we know we're a session leader and
		 * if we're not actively exiting it impossible for another
		 * thread in this process to be exiting.  (Because that
		 * thread would have already stopped all other threads
		 * in the current process.)
		 */
		ASSERT(at_exit || !sp->s_exit);

		/*
		 * If no one else has a hold on this session structure
		 * then we now have exclusive access to it, so break out
		 * of this loop and update the session structure.
		 */
		if (sp->s_cnt == 0)
			break;

		if (!at_exit) {
			/* need to hold the session so it can't be freed */
			sp->s_ref++;
		}

		/* ain't locking order fun? */
		mutex_exit(&p->p_splock);
		mutex_exit(&pidlock);
		mutex_exit(&stp->sd_lock);

		if (at_exit) {
			/*
			 * if we're exiting then we can't allow this operation
			 * to fail so we do a cw_wait() instead of a
			 * cv_wait_sig().  if there are threads with active
			 * holds on this ctty that are blocked, then
			 * they should only be blocked in a cv_wait_sig()
			 * and hopefully they were in the foreground process
			 * group and recieved the SIGHUP we sent above.  of
			 * course it's possible that they weren't in the
			 * foreground process group and didn't get our
			 * signal (or they could be stopped by job control
			 * in which case our signal wouldn't matter until
			 * they are restarted).  in this case we won't
			 * exit until someone else sends them a signal.
			 */
			cv_wait(&sp->s_cnt_cv, &sp->s_lock);
			mutex_exit(&sp->s_lock);
			continue;
		}

		if (!cv_wait_sig(&sp->s_cnt_cv, &sp->s_lock)) {
			got_sig = B_TRUE;
		}

		mutex_exit(&sp->s_lock);
		sess_rele(sp, B_FALSE);

		if (got_sig)
			return (EINTR);
	}
	ASSERT(sp->s_cnt == 0);

	/* save some pointers for later */
	cred = sp->s_cred;
	pgidp = stp->sd_pgidp;
	sidp = stp->sd_sidp;

	/* clear the session ctty bindings */
	sess_ctty_clear(sp, stp);

	/* wake up anyone blocked in tty_hold() */
	if (at_exit) {
		ASSERT(sp->s_exit);
		sp->s_exit = B_FALSE;
		cv_broadcast(&sp->s_exit_cv);
	}

	/* we can drop these locks now */
	mutex_exit(&sp->s_lock);
	mutex_exit(&p->p_splock);
	mutex_exit(&pidlock);
	mutex_exit(&stp->sd_lock);

	/* This is the only remaining thread with access to this vnode */
	(void) VOP_CLOSE(vp, 0, 1, (offset_t)0, cred, NULL);
	VN_RELE(vp);
	crfree(cred);

	/* release our holds on assorted structures and return */
	mutex_enter(&pidlock);
	PID_RELE(pgidp);
	PID_RELE(sidp);
	mutex_exit(&pidlock);

	return (1);
}

/*
 *	++++++++++++++++++++++++
 *	++  SunOS4.1 Buyback  ++
 *	++++++++++++++++++++++++
 *
 * vhangup: Revoke access of the current tty by all processes
 * Used by privileged users to give a "clean" terminal at login
 */
int
vhangup(void)
{
	if (secpolicy_sys_config(CRED(), B_FALSE) != 0)
		return (set_errno(EPERM));
	/*
	 * This routine used to call freectty() under a condition that
	 * could never happen.  So this code has never actually done
	 * anything, and evidently nobody has ever noticed.
	 */
	return (0);
}

dev_t
cttydev(proc_t *pp)
{
	sess_t	*sp;
	dev_t	dev;

	mutex_enter(&pp->p_splock);	/* protects p->p_sessp */
	sp = pp->p_sessp;

#ifdef DEBUG
	mutex_enter(&sp->s_lock);	/* protects sp->* */
	if (sp->s_vp == NULL)
		ASSERT(sp->s_dev == NODEV);
	else
		ASSERT(sp->s_dev != NODEV);
	mutex_exit(&sp->s_lock);
#endif /* DEBUG */

	dev = sp->s_dev;
	mutex_exit(&pp->p_splock);
	return (dev);
}

void
ctty_clear_sighuped(void)
{
	ASSERT(MUTEX_HELD(&pidlock) || MUTEX_HELD(&curproc->p_splock));
	curproc->p_sessp->s_sighuped = B_FALSE;
}
