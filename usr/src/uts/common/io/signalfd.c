/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2017 Joyent, Inc.
 * Copyright 2023 Oxide Computer Company
 */

/*
 * Support for the signalfd facility, a Linux-borne facility for
 * file descriptor-based synchronous signal consumption.
 *
 * As described on the signalfd(3C) man page, the general idea behind these
 * file descriptors is that they can be used to synchronously consume signals
 * via the read(2) syscall.  While that capability already exists with the
 * sigwaitinfo(3C) function, signalfd holds an advantage since it is file
 * descriptor based: It is able use the event facilities (poll(2), /dev/poll,
 * event ports) to notify interested parties when consumable signals arrive.
 *
 * The signalfd lifecycle begins When a process opens /dev/signalfd.  A minor
 * will be allocated for them along with an associated signalfd_state_t struct.
 * It is there where the mask of desired signals resides.
 *
 * Reading from the signalfd is straightforward and mimics the kernel behavior
 * for sigtimedwait().  Signals continue to live on either the proc's p_sig, or
 * thread's t_sig, member.  During a read operation, those which match the mask
 * are consumed so they are no longer pending.
 *
 * The poll side is more complex.  Every time a signal is delivered, all of the
 * signalfds on the process need to be examined in order to pollwake threads
 * waiting for signal arrival.
 *
 * When a thread polling on a signalfd requires a pollhead, several steps must
 * be taken to safely ensure the proper result.  A sigfd_proc_state_t is
 * created for the calling process if it does not yet exist.  It is there where
 * a list of signalfd_poller_t structures reside which associate pollheads to
 * signalfd_state_t entries.  The sigfd_proc_state_t list is walked to find any
 * signalfd_poller_t which is both associated with the polling process and
 * corresponds to the signalfd resource being polled.  If none matching those
 * conditions is found, then a new one with the appropriate associations is
 * created.
 *
 * The complications imposed by fork(2) are why the pollhead is stored in the
 * associated signalfd_poller_t instead of directly in the signalfd_state_t.
 * More than one process can hold a reference to the signalfd at a time but
 * arriving signals should wake only process-local pollers.  Additionally,
 * signalfd_close is called only when the last referencing fd is closed, hiding
 * occurrences of preceeding threads which released their references.  This
 * necessitates a pollhead for each signalfd/process pair when being polled.
 * Doing so ensures that those pollheads will live long enough for the greater
 * poll machinery can act upon them without risk of use-after-free.  When a
 * signalfd is closed, existing signalfd_poller_t instances are dissociated from
 * their respective processes, causing pollwake() calls for any blocked pollers.
 *
 * When a signal arrives in a process polling on signalfd, signalfd_pollwake_cb
 * is called via the pointer in sigfd_proc_state_t.  It will walk over the
 * signalfd_poller_t entries present in the list, searching for any possessing a
 * signal mask which matches the incoming signal.  (Changes to the signal mask
 * held in signalfd_state_t is propagated to the signalfd_poller_t instance to
 * avoid the need for additional locks during the callback.) The approach of
 * keeping the poller list in p_sigfd was chosen because a process is likely to
 * use few signalfds relative to its total file descriptors.  It reduces the
 * work required for each received signal.
 *
 * When matching signalfd_poller_t entries are encountered in the poller list
 * during signalfd_pollwake_cb, they are dispatched into signalfd_wakeq to
 * perform the pollwake.  This is due to a lock ordering conflict between
 * signalfd_poll and signalfd_pollwake_cb.  The former acquires
 * pollcache_t`pc_lock before proc_t`p_lock.  The latter (via sigtoproc)
 * reverses the order.  Defering the pollwake into a taskq means it can be
 * performed without proc_t`p_lock held, avoiding the deadlock.
 *
 * Poller entries in sigfd_proc_state_t`sigfd_list are cleaned up under two
 * different circumstances.  When a signalfd instance is being closed, it will
 * dissociate all of its remaining signalfd_poller_t instances from their
 * polling processes.  When a process (which polled on signalfd instance(s)
 * which have not yet been closed) exits, the exit helper (signalfd_exit_helper)
 * is called, and it dissociates all signalfd_poller_t instances tied to the
 * existing process.
 *
 * The structures associated with signalfd state are designed to operate
 * correctly across fork, but there is one caveat that applies.  Using
 * fork-shared signalfd descriptors in conjuction with fork-shared caching poll
 * descriptors (such as /dev/poll or event ports) will result in missed poll
 * wake-ups.  This is caused by the pollhead identity of signalfd descriptors
 * being dependent on the process they are polled from.  Because it has a
 * thread-local cache, poll(2) is unaffected by this limitation.
 *
 * Lock ordering:
 *
 * Calling signalfd_poll:
 * 1. pollcache_t`pc_lock
 * 2. signalfd_state_t`sfd_lock
 * 3. proc_t`p_lock
 *
 * Signal delivery, waking a pollhead:
 * 1. proc_t`p_lock
 * 2. signalfd_poller_t`sp_lock
 *
 * Process exit, cleaning up signalfd pollers:
 * 1. proc_t`p_lock
 * 2. signalfd_poller_t`sp_lock
 *
 * Waking a pollhead, from taskq:
 * 1. signalfd_poller_t`sp_lock
 * ... Disjoint from signalfd_poller_t`sp_lock hold ...
 * 1. pollcache_t`pc_lock
 *
 * Closing signalfd, dissociating pollers:
 * 1. signalfd_state_t`sfd_lock
 * 2. pidlock
 * 3. proc_t`p_lock
 *
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/signalfd.h>
#include <sys/conf.h>
#include <sys/sysmacros.h>
#include <sys/filio.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/schedctl.h>
#include <sys/id_space.h>
#include <sys/sdt.h>
#include <sys/disp.h>
#include <sys/taskq_impl.h>
#include <sys/condvar.h>
#include <sys/stdbool.h>

/* Per-instance signalfd device state: */
typedef struct signalfd_state {
	kmutex_t	sfd_lock;	/* protects fields below */
	list_t		sfd_pollers;
	k_sigset_t	sfd_mask;	/* signal mask for this instance */
	minor_t		sfd_minor;	/* dev minor, fixed at creation */
} signalfd_state_t;

typedef struct signalfd_poller {
	/*
	 * List node referenced by containing signalfd_state_t
	 * Protected by signalfd_state`sfd_lock
	 */
	list_node_t	sp_state_node;

	/*
	 * List node referenced by containing sigfd_proc_state_t
	 * Protected by proc_t`plock
	 */
	list_node_t	sp_proc_node;

	pollhead_t	sp_pollhead;

	/*
	 * The signalfd_state_t to which this poller is associated.
	 * It remains fixed after its initialization at creation time.
	 */
	signalfd_state_t	*sp_state;

	/*
	 * The proc_t to which this poller is associated.
	 * It is initialized under the protection of proc_t`p_lock when this
	 * poller is created.  It is NULLed out, again under the protection of
	 * proc_t`p_lock, when the poller is dissociated from the process.
	 */
	proc_t		*sp_proc;

	kmutex_t	sp_lock;	/* protects fields below */
	kcondvar_t	sp_cv;		/* CV for cleaning up */
	short		sp_pollev;	/* Event(s) pending delivery */
	bool		sp_pending;	/* pollwakeup() via taskq in progress */
	taskq_ent_t	sp_taskent;	/* pollwakeup() dispatch taskq */
	k_sigset_t	sp_mask;	/* signal match mask */
} signalfd_poller_t;

static dev_info_t	*signalfd_devi;		/* device info */
static id_space_t	*signalfd_minors;	/* minor number arena */
static void		*signalfd_softstate;	/* softstate pointer */
static taskq_t		*signalfd_wakeq;	/* pollwake event taskq */

static void
signalfd_proc_clean(proc_t *p)
{
	sigfd_proc_state_t *pstate = p->p_sigfd;

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(pstate != NULL);
	VERIFY(list_is_empty(&pstate->sigfd_list));

	p->p_sigfd = NULL;
	list_destroy(&pstate->sigfd_list);
	kmem_free(pstate, sizeof (*pstate));
}

static void
signalfd_wake_task(void *arg)
{
	signalfd_poller_t *sp = arg;

	mutex_enter(&sp->sp_lock);
	VERIFY(sp->sp_pollev != 0);
	VERIFY(sp->sp_pending);
	do {
		const short pollev = sp->sp_pollev;
		const bool is_err = (pollev & POLLERR) != 0;
		sp->sp_pollev = 0;
		mutex_exit(&sp->sp_lock);

		/*
		 * Actions against the pollhead and associated pollcache(s) are
		 * taken without signalfd_poller_t`sp_lock held, since the chain
		 * of dependencies through pollcache_t`pc_lock and
		 * signalfd_state_t`sfd_lock form a potential for deadlock.
		 */
		pollwakeup(&sp->sp_pollhead, pollev);
		if (is_err) {
			pollhead_clean(&sp->sp_pollhead);
		}

		mutex_enter(&sp->sp_lock);
		/*
		 * Once pollhead/pollcache actions are complete, check for newly
		 * queued events which could have appeared in the mean time.  We
		 * can bail immediately if POLLER was being delivered, since the
		 * underlying resource is undergoing clean-up.
		 */
		if (is_err) {
			break;
		}
	} while (sp->sp_pollev != 0);

	/*
	 * Indicate that wake task processing is complete.
	 *
	 * Wake any thread waiting for event delivery to complete if this poller
	 * is being torn down.
	 */
	sp->sp_pending = false;
	cv_signal(&sp->sp_cv);
	mutex_exit(&sp->sp_lock);
}

static void
signalfd_poller_wake(signalfd_poller_t *sp, short ev)
{
	ASSERT(MUTEX_HELD(&sp->sp_lock));

	sp->sp_pollev |= ev;
	if (!sp->sp_pending) {
		sp->sp_pending = true;
		taskq_dispatch_ent(signalfd_wakeq, signalfd_wake_task, sp, 0,
		    &sp->sp_taskent);
	}
}

/*
 * Notification callback associated to processes which are being polled for
 * signalfd events.  Called by sigtoproc().
 */
static void
signalfd_pollwake_cb(void *arg0, int sig)
{
	proc_t *p = (proc_t *)arg0;
	sigfd_proc_state_t *pstate = (sigfd_proc_state_t *)p->p_sigfd;

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(pstate != NULL);

	list_t *pollers = &pstate->sigfd_list;
	for (signalfd_poller_t *sp = list_head(pollers); sp != NULL;
	    sp = list_next(pollers, sp)) {
		mutex_enter(&sp->sp_lock);
		if (sigismember(&sp->sp_mask, sig)) {
			signalfd_poller_wake(sp, POLLRDNORM | POLLIN);
		}
		mutex_exit(&sp->sp_lock);
	}
}

/*
 * Get the sigfd_proc_state_t for a given process, allocating one if necessary.
 *
 * Must be called with p_lock held, which may be dropped and reacquired during
 * the allocation.
 */
static sigfd_proc_state_t *
signalfd_proc_pstate(proc_t *p)
{
	ASSERT(MUTEX_HELD(&p->p_lock));

	sigfd_proc_state_t *pstate = p->p_sigfd;
	if (pstate == NULL) {
		mutex_exit(&p->p_lock);
		pstate = kmem_zalloc(sizeof (*pstate), KM_SLEEP);
		list_create(&pstate->sigfd_list,
		    sizeof (signalfd_poller_t),
		    offsetof(signalfd_poller_t, sp_proc_node));
		pstate->sigfd_pollwake_cb = signalfd_pollwake_cb;

		/* Check again, after blocking for the alloc. */
		mutex_enter(&p->p_lock);
		if (p->p_sigfd == NULL) {
			p->p_sigfd = pstate;
		} else {
			/* Someone beat us to it */
			list_destroy(&pstate->sigfd_list);
			kmem_free(pstate, sizeof (*pstate));
			pstate = p->p_sigfd;
		}
	}

	return (pstate);
}

static signalfd_poller_t *
signalfd_poller_associate(signalfd_state_t *state, proc_t *p)
{
	sigfd_proc_state_t *pstate;
	list_t *pollers;
	signalfd_poller_t *sp;

	ASSERT(MUTEX_HELD(&state->sfd_lock));

	mutex_enter(&p->p_lock);

	pstate = signalfd_proc_pstate(p);
	pollers = &pstate->sigfd_list;

	/*
	 * Check if there is already a signalfd_poller_t allocated for this
	 * signalfd_state_t/proc_t pair.
	 */
	for (sp = list_head(pollers); sp != NULL; sp = list_next(pollers, sp)) {
		if (sp->sp_state == state) {
			mutex_exit(&p->p_lock);
			return (sp);
		}
	}

	/*
	 * No existing poller found, so allocate one. Since sfd_lock remains
	 * held, there is no risk of some other operation racing with us to
	 * create such a poller.
	 */
	mutex_exit(&p->p_lock);

	sp = kmem_zalloc(sizeof (*sp), KM_SLEEP);
	mutex_init(&sp->sp_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sp->sp_cv, NULL, CV_DEFAULT, NULL);
	sigorset(&sp->sp_mask, &state->sfd_mask);
	sp->sp_state = state;
	sp->sp_proc = p;

	mutex_enter(&p->p_lock);
	/*
	 * Fetch the pstate again, since it could have been freed or reallocated
	 * in the time p_lock was dropped.
	 */
	pstate = signalfd_proc_pstate(p);

	list_insert_tail(&pstate->sigfd_list, sp);
	list_insert_tail(&state->sfd_pollers, sp);
	mutex_exit(&p->p_lock);

	return (sp);
}

static void
signalfd_pollers_dissociate(signalfd_state_t *state)
{
	ASSERT(MUTEX_HELD(&state->sfd_lock));

	mutex_enter(&pidlock);

	signalfd_poller_t *sp;
	list_t *pollers = &state->sfd_pollers;
	for (sp = list_head(pollers); sp != NULL; sp = list_next(pollers, sp)) {
		proc_t *p = sp->sp_proc;

		if (p == NULL) {
			continue;
		}

		/*
		 * Even if the process in question is racing us to clean-up in
		 * proc_exit(), it will be unable to exit (and free itself)
		 * since we hold pidlock.  This prevents us from otherwise
		 * attempting to lock a p_lock which was freed.
		 */
		mutex_enter(&p->p_lock);
		if (sp->sp_proc == NULL) {
			mutex_exit(&p->p_lock);
			continue;
		}
		VERIFY3P(sp->sp_proc, ==, p);
		VERIFY3P(sp->sp_state, ==, state);
		VERIFY3P(p->p_sigfd, !=, NULL);

		sigfd_proc_state_t *pstate = p->p_sigfd;
		list_remove(&pstate->sigfd_list, sp);
		sp->sp_proc = NULL;

		/* Wake any lingering pollers referencing the pollhead */
		mutex_enter(&sp->sp_lock);
		signalfd_poller_wake(sp, POLLERR);
		mutex_exit(&sp->sp_lock);

		if (list_is_empty(&pstate->sigfd_list)) {
			/*
			 * If this poller was the last associated against the
			 * process, then clean up its state as well.
			 */
			signalfd_proc_clean(p);
		}
		mutex_exit(&p->p_lock);
	}
	mutex_exit(&pidlock);
}

static void
signalfd_pollers_free(signalfd_state_t *state)
{
	ASSERT(MUTEX_HELD(&state->sfd_lock));

	signalfd_poller_t *sp;
	while ((sp = list_remove_head(&state->sfd_pollers)) != NULL) {
		ASSERT3P(sp->sp_proc, ==, NULL);

		mutex_enter(&sp->sp_lock);
		while (sp->sp_pending) {
			cv_wait(&sp->sp_cv, &sp->sp_lock);
		}
		/*
		 * With the poller dissociated from its polling process, and any
		 * lingering events delivered, the pollhead should be empty.
		 */
		ASSERT3P(sp->sp_pollhead.ph_list, ==, NULL);

		cv_destroy(&sp->sp_cv);
		mutex_destroy(&sp->sp_lock);
		kmem_free(sp, sizeof (*sp));
	}
}

/*
 * Callback for cleaning up signalfd state from a process during proc_exit().
 */
static void
signalfd_exit_helper(void)
{
	proc_t *p = curproc;

	mutex_enter(&p->p_lock);

	sigfd_proc_state_t *pstate = p->p_sigfd;
	if (pstate == NULL) {
		mutex_exit(&p->p_lock);
		return;
	}

	signalfd_poller_t *sp;
	while ((sp = list_remove_head(&pstate->sigfd_list)) != NULL) {
		/*
		 * Having been removed from the sigfd_list, make it clear that
		 * this signalfd_poller_t is disssociated from the process.
		 */
		sp->sp_proc = NULL;

		/* Wake any lingering pollers referencing the pollhead */
		mutex_enter(&sp->sp_lock);
		signalfd_poller_wake(sp, POLLERR);
		mutex_exit(&sp->sp_lock);
	}
	signalfd_proc_clean(p);
	mutex_exit(&p->p_lock);
}

_NOTE(ARGSUSED(1))
static int
signalfd_open(dev_t *devp, int flag, int otyp, cred_t *cr)
{
	if (getminor(*devp) != SIGNALFDMNRN_SIGNALFD) {
		return (ENXIO);
	}

	const minor_t minor = (minor_t)id_allocff_nosleep(signalfd_minors);
	if (minor == -1) {
		return (ENOMEM);
	}

	if (ddi_soft_state_zalloc(signalfd_softstate, minor) != DDI_SUCCESS) {
		id_free(signalfd_minors, minor);
		return (ENODEV);
	}

	signalfd_state_t *state = ddi_get_soft_state(signalfd_softstate, minor);
	mutex_init(&state->sfd_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&state->sfd_pollers, sizeof (signalfd_poller_t),
	    offsetof(signalfd_poller_t, sp_state_node));
	state->sfd_minor = minor;

	const major_t major = getemajor(*devp);
	*devp = makedevice(major, minor);

	return (0);
}

/*
 * Consume one signal from our set in a manner similar to sigtimedwait().
 * The block parameter is used to control whether we wait for a signal or
 * return immediately if no signal is pending. We use the thread's t_sigwait
 * member in the same way that it is used by sigtimedwait.
 *
 * Return 0 if we successfully consumed a signal or an errno if not.
 */
static int
signalfd_consume_signal(k_sigset_t set, uio_t *uio, bool should_block)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	proc_t *p = ttoproc(t);
	int ret = 0;

	/*
	 * Identify signals of interest so they can be processed, even if other
	 * parts of the machinery would be poised to ignore them.
	 */
	t->t_sigwait = set;

	mutex_enter(&p->p_lock);

	/* Set thread signal mask to unmask those in the specified set. */
	schedctl_finish_sigblock(t);
	const k_sigset_t oldmask = t->t_hold;
	sigdiffset(&t->t_hold, &t->t_sigwait);

	if (should_block) {
		do {
			ret = cv_waituntil_sig(&t->t_delay_cv, &p->p_lock,
			    NULL, 0);
		} while (ret > 0);
	} else {
		mutex_exit(&p->p_lock);
		if (issig(FORREAL) == 0) {
			ret = -1;
		}
		mutex_enter(&p->p_lock);
	}

	/*
	 * Restore thread's signal mask to its previous value.
	 * Set t_sig_check so post_syscall sees new t_hold mask.
	 */
	t->t_hold = oldmask;
	t->t_sig_check = 1;

	if (ret == -1) {
		/* no signals pending */
		mutex_exit(&p->p_lock);
		sigemptyset(&t->t_sigwait);
		return (EAGAIN);
	}

	/* Do not bother with signal if it is not in request set. */
	if (lwp->lwp_cursig == 0 ||
	    !sigismember(&t->t_sigwait, lwp->lwp_cursig)) {
		/*
		 * lwp_cursig is zero if pokelwps() awakened cv_wait_sig().
		 * This happens if some other thread in this process called
		 * forkall() or exit().
		 */
		mutex_exit(&p->p_lock);
		sigemptyset(&t->t_sigwait);
		return (EINTR);
	}

	/* Convert signal info into external, datamodel independent, struct. */
	signalfd_siginfo_t ssi;
	bzero(&ssi, sizeof (ssi));
	if (lwp->lwp_curinfo != NULL) {
		k_siginfo_t *infop = &lwp->lwp_curinfo->sq_info;

		ssi.ssi_signo	= infop->si_signo;
		ssi.ssi_errno	= infop->si_errno;
		ssi.ssi_code	= infop->si_code;
		ssi.ssi_pid	= infop->si_pid;
		ssi.ssi_uid	= infop->si_uid;
		ssi.ssi_fd	= infop->si_fd;
		ssi.ssi_band	= infop->si_band;
		ssi.ssi_trapno	= infop->si_trapno;
		ssi.ssi_status	= infop->si_status;
		ssi.ssi_utime	= infop->si_utime;
		ssi.ssi_stime	= infop->si_stime;
		ssi.ssi_addr	= (uint64_t)(intptr_t)infop->si_addr;

		DTRACE_PROC2(signal__clear, int, 0, ksiginfo_t *, infop);
	} else {
		/* Convert to the format expected by the probe. */
		k_siginfo_t info = {
			.si_signo = lwp->lwp_cursig,
			.si_code = SI_NOINFO,
		};

		ssi.ssi_signo = info.si_signo;
		ssi.ssi_code = info.si_code;

		DTRACE_PROC2(signal__clear, int, 0, ksiginfo_t *, &info);
	}

	lwp->lwp_ru.nsignals++;
	lwp->lwp_cursig = 0;
	lwp->lwp_extsig = 0;
	if (lwp->lwp_curinfo != NULL) {
		siginfofree(lwp->lwp_curinfo);
		lwp->lwp_curinfo = NULL;
	}
	mutex_exit(&p->p_lock);

	ret = uiomove(&ssi, sizeof (ssi), UIO_READ, uio);
	sigemptyset(&t->t_sigwait);
	return (ret);
}

/*
 * This is similar to sigtimedwait. Based on the fd mode, we may wait until a
 * signal within our specified set is posted. We consume as many available
 * signals within our set as we can.
 */
_NOTE(ARGSUSED(2))
static int
signalfd_read(dev_t dev, uio_t *uio, cred_t *cr)
{
	signalfd_state_t *state;
	k_sigset_t set;
	bool should_block = true, got_one = false;
	int res;

	state = ddi_get_soft_state(signalfd_softstate, getminor(dev));
	if (state == NULL) {
		return (ENXIO);
	}

	if (uio->uio_resid < sizeof (signalfd_siginfo_t)) {
		return (EINVAL);
	}

	if (uio->uio_fmode & (FNDELAY|FNONBLOCK)) {
		should_block = false;
	}

	mutex_enter(&state->sfd_lock);
	set = state->sfd_mask;
	mutex_exit(&state->sfd_lock);

	if (sigisempty(&set))
		return (set_errno(EINVAL));

	do  {
		res = signalfd_consume_signal(set, uio, should_block);

		if (res == 0) {
			/*
			 * After consuming one signal, do not block while
			 * trying to consume more.
			 */
			got_one = true;
			should_block = false;

			/*
			 * Refresh the matching signal set in case it was
			 * updated during the wait.
			 */
			mutex_enter(&state->sfd_lock);
			set = state->sfd_mask;
			mutex_exit(&state->sfd_lock);
			if (sigisempty(&set))
				break;
		}
	} while (res == 0 && uio->uio_resid >= sizeof (signalfd_siginfo_t));

	if (got_one)
		res = 0;

	return (res);
}

/*
 * If ksigset_t's were a single word, we would do:
 *      return (((p->p_sig | t->t_sig) & set) & fillset);
 */
static int
signalfd_sig_pending(proc_t *p, kthread_t *t, k_sigset_t set)
{
	return (((p->p_sig.__sigbits[0] | t->t_sig.__sigbits[0]) &
	    set.__sigbits[0]) |
	    ((p->p_sig.__sigbits[1] | t->t_sig.__sigbits[1]) &
	    set.__sigbits[1]) |
	    (((p->p_sig.__sigbits[2] | t->t_sig.__sigbits[2]) &
	    set.__sigbits[2]) & FILLSET2));
}

static int
signalfd_poll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	signalfd_state_t *state;
	short revents = 0;
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);

	state = ddi_get_soft_state(signalfd_softstate, getminor(dev));
	if (state == NULL) {
		return (ENXIO);
	}

	mutex_enter(&state->sfd_lock);
	if (signalfd_sig_pending(p, t, state->sfd_mask) != 0) {
		revents |= POLLRDNORM | POLLIN;
	}

	*reventsp = revents & events;
	if ((*reventsp == 0 && !anyyet) || (events & POLLET) != 0) {
		signalfd_poller_t *sp;

		sp = signalfd_poller_associate(state, p);
		*phpp = &sp->sp_pollhead;
	}
	mutex_exit(&state->sfd_lock);

	return (0);
}

static void
signalfd_set_mask(signalfd_state_t *state, const sigset_t *umask)
{
	k_sigset_t kmask;

	sigutok(umask, &kmask);

	mutex_enter(&state->sfd_lock);
	state->sfd_mask = kmask;
	list_t *pollers = &state->sfd_pollers;
	for (signalfd_poller_t *sp = list_head(pollers); sp != NULL;
	    sp = list_next(pollers, sp)) {
		mutex_enter(&sp->sp_lock);
		sp->sp_mask = kmask;
		mutex_exit(&sp->sp_lock);
	}
	mutex_exit(&state->sfd_lock);
}

_NOTE(ARGSUSED(4))
static int
signalfd_ioctl(dev_t dev, int cmd, intptr_t arg, int md, cred_t *cr, int *rv)
{
	signalfd_state_t *state;
	sigset_t mask;

	state = ddi_get_soft_state(signalfd_softstate, getminor(dev));
	if (state == NULL) {
		return (ENXIO);
	}

	switch (cmd) {
	case SIGNALFDIOC_MASK:
		if (ddi_copyin((caddr_t)arg, &mask, sizeof (mask), md) != 0) {
			return (EFAULT);
		}
		signalfd_set_mask(state, &mask);
		return (0);

	default:
		break;
	}

	return (ENOTTY);
}

_NOTE(ARGSUSED(1))
static int
signalfd_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	signalfd_state_t *state;
	const minor_t minor = getminor(dev);

	state = ddi_get_soft_state(signalfd_softstate, minor);
	if (state == NULL) {
		return (ENXIO);
	}

	/*
	 * With this signalfd instance being closed, sfd_lock is a formality, as
	 * nothing else should be reaching for it to add pollers at this point.
	 */
	mutex_enter(&state->sfd_lock);

	/* Dissociate any pollers from their respective processes */
	signalfd_pollers_dissociate(state);

	/* ... and free all those (now-dissociated) pollers */
	signalfd_pollers_free(state);
	ASSERT(list_is_empty(&state->sfd_pollers));

	mutex_destroy(&state->sfd_lock);
	ddi_soft_state_free(signalfd_softstate, minor);
	id_free(signalfd_minors, minor);

	return (0);
}

static int
signalfd_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH || signalfd_devi != NULL) {
		return (DDI_FAILURE);
	}

	signalfd_minors = id_space_create("signalfd_minors", 1, L_MAXMIN32 + 1);
	if (signalfd_minors == NULL) {
		cmn_err(CE_WARN, "signalfd couldn't create id space");
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_init(&signalfd_softstate,
	    sizeof (signalfd_state_t), 0) != 0) {
		cmn_err(CE_WARN, "signalfd failed to create soft state");
		id_space_destroy(signalfd_minors);
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(devi, "signalfd", S_IFCHR,
	    SIGNALFDMNRN_SIGNALFD, DDI_PSEUDO, 0) == DDI_FAILURE) {
		cmn_err(CE_NOTE, "signalfd couldn't create minor node");
		ddi_soft_state_fini(&signalfd_softstate);
		id_space_destroy(signalfd_minors);
		return (DDI_FAILURE);
	}


	sigfd_exit_helper = signalfd_exit_helper;

	signalfd_wakeq = taskq_create("signalfd_wake", 1, minclsyspri,
	    0, INT_MAX, TASKQ_PREPOPULATE);

	ddi_report_dev(devi);
	signalfd_devi = devi;

	return (DDI_SUCCESS);
}

_NOTE(ARGSUSED(0))
static int
signalfd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	/*
	 * With all of the instances gone, it is safe to both destroy the waker
	 * taskq (which must be empty) and tear down the exit helper (which must
	 * be unreachable with no proc_t`p_sigfd associations).
	 */
	taskq_destroy(signalfd_wakeq);
	sigfd_exit_helper = NULL;

	id_space_destroy(signalfd_minors);
	ddi_soft_state_fini(&signalfd_softstate);
	ddi_remove_minor_node(signalfd_devi, NULL);
	signalfd_devi = NULL;

	return (DDI_SUCCESS);
}

_NOTE(ARGSUSED(0))
static int
signalfd_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)signalfd_devi;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

static struct cb_ops signalfd_cb_ops = {
	signalfd_open,		/* open */
	signalfd_close,		/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nodev,			/* dump */
	signalfd_read,		/* read */
	nodev,			/* write */
	signalfd_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	signalfd_poll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP		/* Driver compatibility flag */
};

static struct dev_ops signalfd_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	signalfd_info,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	signalfd_attach,	/* attach */
	signalfd_detach,	/* detach */
	nodev,			/* reset */
	&signalfd_cb_ops,	/* driver operations */
	NULL,			/* bus operations */
	nodev,			/* dev power */
	ddi_quiesce_not_needed,	/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,		/* module type (this is a pseudo driver) */
	"signalfd support",	/* name of module */
	&signalfd_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}
