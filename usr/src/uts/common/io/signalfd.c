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
 * Copyright 2016 Joyent, Inc.
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
 * a list of sigfd_poll_waiter_t structures reside which associate pollheads to
 * signalfd_state_t entries.  The sigfd_proc_state_t list is walked to find a
 * sigfd_poll_waiter_t matching the signalfd_state_t which corresponds to the
 * polled resource.  If one is found, it is reused.  Otherwise a new one is
 * created, incrementing the refcount on the signalfd_state_t, and it is added
 * to the sigfd_poll_waiter_t list.
 *
 * The complications imposed by fork(2) are why the pollhead is stored in the
 * associated sigfd_poll_waiter_t instead of directly in the signalfd_state_t.
 * More than one process can hold a reference to the signalfd at a time but
 * arriving signals should wake only process-local pollers.  Additionally,
 * signalfd_close is called only when the last referencing fd is closed, hiding
 * occurrences of preceeding threads which released their references.  This
 * necessitates reference counting on the signalfd_state_t so it is able to
 * persist after close until all poll references have been cleansed.  Doing so
 * ensures that blocked pollers which hold references to the signalfd_state_t
 * will be able to do clean-up after the descriptor itself has been closed.
 *
 * When a signal arrives in a process polling on signalfd, signalfd_pollwake_cb
 * is called via the pointer in sigfd_proc_state_t.  It will walk over the
 * sigfd_poll_waiter_t entries present in the list, searching for any
 * associated with a signalfd_state_t with a matching signal mask.  The
 * approach of keeping the poller list in p_sigfd was chosen because a process
 * is likely to use few signalfds relative to its total file descriptors.  It
 * reduces the work required for each received signal.
 *
 * When matching sigfd_poll_waiter_t entries are encountered in the poller list
 * during signalfd_pollwake_cb, they are dispatched into signalfd_wakeq to
 * perform the pollwake.  This is due to a lock ordering conflict between
 * signalfd_poll and signalfd_pollwake_cb.  The former acquires
 * pollcache_t`pc_lock before proc_t`p_lock.  The latter (via sigtoproc)
 * reverses the order.  Defering the pollwake into a taskq means it can be
 * performed without proc_t`p_lock held, avoiding the deadlock.
 *
 * The sigfd_list is self-cleaning; as signalfd_pollwake_cb is called, the list
 * will clear out on its own.  Any remaining per-process state which remains
 * will be cleaned up by the exit helper (signalfd_exit_helper).
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
 * 1. signalfd_lock
 * 2. signalfd_state_t`sfd_lock
 *
 * 1. proc_t`p_lock (to walk p_sigfd)
 * 2. signalfd_state_t`sfd_lock
 * 2a. signalfd_lock (after sfd_lock is dropped, when sfd_count falls to 0)
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

typedef struct signalfd_state signalfd_state_t;

struct signalfd_state {
	list_node_t	sfd_list;		/* node in global list */
	kmutex_t	sfd_lock;		/* protects fields below */
	uint_t		sfd_count;		/* ref count */
	boolean_t	sfd_valid;		/* valid while open */
	k_sigset_t	sfd_set;		/* signals for this fd */
};

typedef struct sigfd_poll_waiter {
	list_node_t		spw_list;
	signalfd_state_t	*spw_state;
	pollhead_t		spw_pollhd;
	taskq_ent_t		spw_taskent;
	short			spw_pollev;
} sigfd_poll_waiter_t;

/*
 * Protects global state in signalfd_devi, signalfd_minor, signalfd_softstate,
 * and signalfd_state (including sfd_list field of members)
 */
static kmutex_t		signalfd_lock;
static dev_info_t	*signalfd_devi;		/* device info */
static id_space_t	*signalfd_minor;	/* minor number arena */
static void		*signalfd_softstate;	/* softstate pointer */
static list_t		signalfd_state;		/* global list of state */
static taskq_t		*signalfd_wakeq;	/* pollwake event taskq */


static void
signalfd_state_enter_locked(signalfd_state_t *state)
{
	ASSERT(MUTEX_HELD(&state->sfd_lock));
	ASSERT(state->sfd_count > 0);
	VERIFY(state->sfd_valid == B_TRUE);

	state->sfd_count++;
}

static void
signalfd_state_release(signalfd_state_t *state, boolean_t force_invalidate)
{
	mutex_enter(&state->sfd_lock);

	if (force_invalidate) {
		state->sfd_valid = B_FALSE;
	}

	ASSERT(state->sfd_count > 0);
	if (state->sfd_count == 1) {
		VERIFY(state->sfd_valid == B_FALSE);
		mutex_exit(&state->sfd_lock);
		if (force_invalidate) {
			/*
			 * The invalidation performed in signalfd_close is done
			 * while signalfd_lock is held.
			 */
			ASSERT(MUTEX_HELD(&signalfd_lock));
			list_remove(&signalfd_state, state);
		} else {
			ASSERT(MUTEX_NOT_HELD(&signalfd_lock));
			mutex_enter(&signalfd_lock);
			list_remove(&signalfd_state, state);
			mutex_exit(&signalfd_lock);
		}
		kmem_free(state, sizeof (*state));
		return;
	}
	state->sfd_count--;
	mutex_exit(&state->sfd_lock);
}

static sigfd_poll_waiter_t *
signalfd_wake_list_add(sigfd_proc_state_t *pstate, signalfd_state_t *state)
{
	list_t *lst = &pstate->sigfd_list;
	sigfd_poll_waiter_t *pw;

	for (pw = list_head(lst); pw != NULL; pw = list_next(lst, pw)) {
		if (pw->spw_state == state)
			break;
	}

	if (pw == NULL) {
		pw = kmem_zalloc(sizeof (*pw), KM_SLEEP);

		mutex_enter(&state->sfd_lock);
		signalfd_state_enter_locked(state);
		pw->spw_state = state;
		mutex_exit(&state->sfd_lock);
		list_insert_head(lst, pw);
	}
	return (pw);
}

static sigfd_poll_waiter_t *
signalfd_wake_list_rm(sigfd_proc_state_t *pstate, signalfd_state_t *state)
{
	list_t *lst = &pstate->sigfd_list;
	sigfd_poll_waiter_t *pw;

	for (pw = list_head(lst); pw != NULL; pw = list_next(lst, pw)) {
		if (pw->spw_state == state) {
			break;
		}
	}

	if (pw != NULL) {
		list_remove(lst, pw);
		pw->spw_state = NULL;
		signalfd_state_release(state, B_FALSE);
	}

	return (pw);
}

static void
signalfd_wake_list_cleanup(proc_t *p)
{
	sigfd_proc_state_t *pstate = p->p_sigfd;
	sigfd_poll_waiter_t *pw;
	list_t *lst;

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(pstate != NULL);

	lst = &pstate->sigfd_list;
	while ((pw = list_remove_head(lst)) != NULL) {
		signalfd_state_t *state = pw->spw_state;

		pw->spw_state = NULL;
		signalfd_state_release(state, B_FALSE);

		pollwakeup(&pw->spw_pollhd, POLLERR);
		pollhead_clean(&pw->spw_pollhd);
		kmem_free(pw, sizeof (*pw));
	}
	list_destroy(lst);

	p->p_sigfd = NULL;
	kmem_free(pstate, sizeof (*pstate));
}

static void
signalfd_exit_helper(void)
{
	proc_t *p = curproc;

	mutex_enter(&p->p_lock);
	signalfd_wake_list_cleanup(p);
	mutex_exit(&p->p_lock);
}

/*
 * Perform pollwake for a sigfd_poll_waiter_t entry.
 * Thanks to the strict and conflicting lock orders required for signalfd_poll
 * (pc_lock before p_lock) and signalfd_pollwake_cb (p_lock before pc_lock),
 * this is relegated to a taskq to avoid deadlock.
 */
static void
signalfd_wake_task(void *arg)
{
	sigfd_poll_waiter_t *pw = arg;
	signalfd_state_t *state = pw->spw_state;

	pw->spw_state = NULL;
	signalfd_state_release(state, B_FALSE);
	pollwakeup(&pw->spw_pollhd, pw->spw_pollev);
	pollhead_clean(&pw->spw_pollhd);
	kmem_free(pw, sizeof (*pw));
}

/*
 * Called every time a signal is delivered to the process so that we can
 * see if any signal stream needs a pollwakeup. We maintain a list of
 * signal state elements so that we don't have to look at every file descriptor
 * on the process. If necessary, a further optimization would be to maintain a
 * signal set mask that is a union of all of the sets in the list so that
 * we don't even traverse the list if the signal is not in one of the elements.
 * However, since the list is likely to be very short, this is not currently
 * being done. A more complex data structure might also be used, but it is
 * unclear what that would be since each signal set needs to be checked for a
 * match.
 */
static void
signalfd_pollwake_cb(void *arg0, int sig)
{
	proc_t *p = (proc_t *)arg0;
	sigfd_proc_state_t *pstate = (sigfd_proc_state_t *)p->p_sigfd;
	list_t *lst;
	sigfd_poll_waiter_t *pw;

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(pstate != NULL);

	lst = &pstate->sigfd_list;
	pw = list_head(lst);
	while (pw != NULL) {
		signalfd_state_t *state = pw->spw_state;
		sigfd_poll_waiter_t *next;

		mutex_enter(&state->sfd_lock);
		if (!state->sfd_valid) {
			pw->spw_pollev = POLLERR;
		} else if (sigismember(&state->sfd_set, sig)) {
			pw->spw_pollev = POLLRDNORM | POLLIN;
		} else {
			mutex_exit(&state->sfd_lock);
			pw = list_next(lst, pw);
			continue;
		}
		mutex_exit(&state->sfd_lock);

		/*
		 * Pull the sigfd_poll_waiter_t out of the list and dispatch it
		 * to perform a pollwake.  This cannot be done synchronously
		 * since signalfd_poll and signalfd_pollwake_cb have
		 * conflicting lock orders which can deadlock.
		 */
		next = list_next(lst, pw);
		list_remove(lst, pw);
		taskq_dispatch_ent(signalfd_wakeq, signalfd_wake_task, pw, 0,
		    &pw->spw_taskent);
		pw = next;
	}
}

_NOTE(ARGSUSED(1))
static int
signalfd_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	signalfd_state_t *state, **sstate;
	major_t major = getemajor(*devp);
	minor_t minor = getminor(*devp);

	if (minor != SIGNALFDMNRN_SIGNALFD)
		return (ENXIO);

	mutex_enter(&signalfd_lock);

	minor = (minor_t)id_allocff(signalfd_minor);
	if (ddi_soft_state_zalloc(signalfd_softstate, minor) != DDI_SUCCESS) {
		id_free(signalfd_minor, minor);
		mutex_exit(&signalfd_lock);
		return (ENODEV);
	}

	state = kmem_zalloc(sizeof (*state), KM_SLEEP);
	state->sfd_valid = B_TRUE;
	state->sfd_count = 1;
	list_insert_head(&signalfd_state, (void *)state);

	sstate = ddi_get_soft_state(signalfd_softstate, minor);
	*sstate = state;
	*devp = makedevice(major, minor);

	mutex_exit(&signalfd_lock);

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
consume_signal(k_sigset_t set, uio_t *uio, boolean_t block)
{
	k_sigset_t oldmask;
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	proc_t *p = ttoproc(t);
	timespec_t now;
	timespec_t *rqtp = NULL;	/* null means blocking */
	int timecheck = 0;
	int ret = 0;
	k_siginfo_t info, *infop;
	signalfd_siginfo_t ssi, *ssp = &ssi;

	if (block == B_FALSE) {
		timecheck = timechanged;
		gethrestime(&now);
		rqtp = &now;	/* non-blocking check for pending signals */
	}

	t->t_sigwait = set;

	mutex_enter(&p->p_lock);
	/*
	 * set the thread's signal mask to unmask those signals in the
	 * specified set.
	 */
	schedctl_finish_sigblock(t);
	oldmask = t->t_hold;
	sigdiffset(&t->t_hold, &t->t_sigwait);

	/*
	 * Based on rqtp, wait indefinitely until we take a signal in our set
	 * or return immediately if there are no signals pending from our set.
	 */
	while ((ret = cv_waituntil_sig(&t->t_delay_cv, &p->p_lock, rqtp,
	    timecheck)) > 0)
		continue;

	/* Restore thread's signal mask to its previous value. */
	t->t_hold = oldmask;
	t->t_sig_check = 1;	/* so post_syscall sees new t_hold mask */

	if (ret == -1) {
		/* no signals pending */
		mutex_exit(&p->p_lock);
		sigemptyset(&t->t_sigwait);
		return (EAGAIN);	/* no signals pending */
	}

	/* Don't bother with signal if it is not in request set. */
	if (lwp->lwp_cursig == 0 ||
	    !sigismember(&t->t_sigwait, lwp->lwp_cursig)) {
		mutex_exit(&p->p_lock);
		/*
		 * lwp_cursig is zero if pokelwps() awakened cv_wait_sig().
		 * This happens if some other thread in this process called
		 * forkall() or exit().
		 */
		sigemptyset(&t->t_sigwait);
		return (EINTR);
	}

	if (lwp->lwp_curinfo) {
		infop = &lwp->lwp_curinfo->sq_info;
	} else {
		infop = &info;
		bzero(infop, sizeof (info));
		infop->si_signo = lwp->lwp_cursig;
		infop->si_code = SI_NOINFO;
	}

	lwp->lwp_ru.nsignals++;

	DTRACE_PROC2(signal__clear, int, ret, ksiginfo_t *, infop);
	lwp->lwp_cursig = 0;
	lwp->lwp_extsig = 0;
	mutex_exit(&p->p_lock);

	/* Convert k_siginfo into external, datamodel independent, struct. */
	bzero(ssp, sizeof (*ssp));
	ssp->ssi_signo = infop->si_signo;
	ssp->ssi_errno = infop->si_errno;
	ssp->ssi_code = infop->si_code;
	ssp->ssi_pid = infop->si_pid;
	ssp->ssi_uid = infop->si_uid;
	ssp->ssi_fd = infop->si_fd;
	ssp->ssi_band = infop->si_band;
	ssp->ssi_trapno = infop->si_trapno;
	ssp->ssi_status = infop->si_status;
	ssp->ssi_utime = infop->si_utime;
	ssp->ssi_stime = infop->si_stime;
	ssp->ssi_addr = (uint64_t)(intptr_t)infop->si_addr;

	ret = uiomove(ssp, sizeof (*ssp), UIO_READ, uio);

	if (lwp->lwp_curinfo) {
		siginfofree(lwp->lwp_curinfo);
		lwp->lwp_curinfo = NULL;
	}
	sigemptyset(&t->t_sigwait);
	return (ret);
}

/*
 * This is similar to sigtimedwait. Based on the fd mode we may wait until a
 * signal within our specified set is posted. We consume as many available
 * signals within our set as we can.
 */
_NOTE(ARGSUSED(2))
static int
signalfd_read(dev_t dev, uio_t *uio, cred_t *cr)
{
	signalfd_state_t *state, **sstate;
	minor_t minor = getminor(dev);
	boolean_t block = B_TRUE;
	k_sigset_t set;
	boolean_t got_one = B_FALSE;
	int res;

	if (uio->uio_resid < sizeof (signalfd_siginfo_t))
		return (EINVAL);

	sstate = ddi_get_soft_state(signalfd_softstate, minor);
	state = *sstate;

	if (uio->uio_fmode & (FNDELAY|FNONBLOCK))
		block = B_FALSE;

	mutex_enter(&state->sfd_lock);
	set = state->sfd_set;
	mutex_exit(&state->sfd_lock);

	if (sigisempty(&set))
		return (set_errno(EINVAL));

	do  {
		res = consume_signal(set, uio, block);

		if (res == 0) {
			/*
			 * After consuming one signal, do not block while
			 * trying to consume more.
			 */
			got_one = B_TRUE;
			block = B_FALSE;

			/*
			 * Refresh the matching signal set in case it was
			 * updated during the wait.
			 */
			mutex_enter(&state->sfd_lock);
			set = state->sfd_set;
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

_NOTE(ARGSUSED(4))
static int
signalfd_poll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	signalfd_state_t *state, **sstate;
	minor_t minor = getminor(dev);
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);
	short revents = 0;

	sstate = ddi_get_soft_state(signalfd_softstate, minor);
	state = *sstate;

	mutex_enter(&state->sfd_lock);

	if (signalfd_sig_pending(p, t, state->sfd_set) != 0)
		revents |= POLLRDNORM | POLLIN;

	mutex_exit(&state->sfd_lock);

	if (!(*reventsp = revents & events) && !anyyet) {
		sigfd_proc_state_t *pstate;
		sigfd_poll_waiter_t *pw;

		/*
		 * Enable pollwakeup handling.
		 */
		mutex_enter(&p->p_lock);
		if ((pstate = (sigfd_proc_state_t *)p->p_sigfd) == NULL) {

			mutex_exit(&p->p_lock);
			pstate = kmem_zalloc(sizeof (*pstate), KM_SLEEP);
			list_create(&pstate->sigfd_list,
			    sizeof (sigfd_poll_waiter_t),
			    offsetof(sigfd_poll_waiter_t, spw_list));
			pstate->sigfd_pollwake_cb = signalfd_pollwake_cb;

			/* Check again, after blocking for the alloc. */
			mutex_enter(&p->p_lock);
			if (p->p_sigfd == NULL) {
				p->p_sigfd = pstate;
			} else {
				/* someone beat us to it */
				list_destroy(&pstate->sigfd_list);
				kmem_free(pstate, sizeof (*pstate));
				pstate = p->p_sigfd;
			}
		}

		pw = signalfd_wake_list_add(pstate, state);
		*phpp = &pw->spw_pollhd;
		mutex_exit(&p->p_lock);
	}

	return (0);
}

_NOTE(ARGSUSED(4))
static int
signalfd_ioctl(dev_t dev, int cmd, intptr_t arg, int md, cred_t *cr, int *rv)
{
	signalfd_state_t *state, **sstate;
	minor_t minor = getminor(dev);
	sigset_t mask;

	sstate = ddi_get_soft_state(signalfd_softstate, minor);
	state = *sstate;

	switch (cmd) {
	case SIGNALFDIOC_MASK:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&mask, sizeof (sigset_t),
		    md) != 0)
			return (set_errno(EFAULT));

		mutex_enter(&state->sfd_lock);
		sigutok(&mask, &state->sfd_set);
		mutex_exit(&state->sfd_lock);

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
	signalfd_state_t *state, **sstate;
	sigfd_poll_waiter_t *pw = NULL;
	minor_t minor = getminor(dev);
	proc_t *p = curproc;

	sstate = ddi_get_soft_state(signalfd_softstate, minor);
	state = *sstate;

	/* Make sure state is removed from this proc's pollwake list. */
	mutex_enter(&p->p_lock);
	if (p->p_sigfd != NULL) {
		sigfd_proc_state_t *pstate = p->p_sigfd;

		pw = signalfd_wake_list_rm(pstate, state);
		if (list_is_empty(&pstate->sigfd_list)) {
			signalfd_wake_list_cleanup(p);
		}
	}
	mutex_exit(&p->p_lock);

	if (pw != NULL) {
		pollwakeup(&pw->spw_pollhd, POLLERR);
		pollhead_clean(&pw->spw_pollhd);
		kmem_free(pw, sizeof (*pw));
	}

	mutex_enter(&signalfd_lock);

	*sstate = NULL;
	ddi_soft_state_free(signalfd_softstate, minor);
	id_free(signalfd_minor, minor);

	signalfd_state_release(state, B_TRUE);

	mutex_exit(&signalfd_lock);

	return (0);
}

static int
signalfd_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH || signalfd_devi != NULL)
		return (DDI_FAILURE);

	mutex_enter(&signalfd_lock);

	signalfd_minor = id_space_create("signalfd_minor", 1, L_MAXMIN32 + 1);
	if (signalfd_minor == NULL) {
		cmn_err(CE_WARN, "signalfd couldn't create id space");
		mutex_exit(&signalfd_lock);
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_init(&signalfd_softstate,
	    sizeof (signalfd_state_t *), 0) != 0) {
		cmn_err(CE_WARN, "signalfd failed to create soft state");
		id_space_destroy(signalfd_minor);
		mutex_exit(&signalfd_lock);
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(devi, "signalfd", S_IFCHR,
	    SIGNALFDMNRN_SIGNALFD, DDI_PSEUDO, NULL) == DDI_FAILURE) {
		cmn_err(CE_NOTE, "/dev/signalfd couldn't create minor node");
		ddi_soft_state_fini(&signalfd_softstate);
		id_space_destroy(signalfd_minor);
		mutex_exit(&signalfd_lock);
		return (DDI_FAILURE);
	}

	ddi_report_dev(devi);
	signalfd_devi = devi;

	sigfd_exit_helper = signalfd_exit_helper;

	list_create(&signalfd_state, sizeof (signalfd_state_t),
	    offsetof(signalfd_state_t, sfd_list));

	signalfd_wakeq = taskq_create("signalfd_wake", 1, minclsyspri,
	    0, INT_MAX, TASKQ_PREPOPULATE);

	mutex_exit(&signalfd_lock);

	return (DDI_SUCCESS);
}

_NOTE(ARGSUSED(0))
static int
signalfd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		break;

	default:
		return (DDI_FAILURE);
	}

	mutex_enter(&signalfd_lock);

	if (!list_is_empty(&signalfd_state)) {
		/*
		 * There are dangling poll waiters holding signalfd_state_t
		 * entries on the global list.  Detach is not possible until
		 * they purge themselves.
		 */
		mutex_exit(&signalfd_lock);
		return (DDI_FAILURE);
	}
	list_destroy(&signalfd_state);

	/*
	 * With no remaining entries in the signalfd_state list, the wake taskq
	 * should be empty with no possibility for new entries.
	 */
	taskq_destroy(signalfd_wakeq);

	id_space_destroy(signalfd_minor);

	ddi_remove_minor_node(signalfd_devi, NULL);
	signalfd_devi = NULL;
	sigfd_exit_helper = NULL;

	ddi_soft_state_fini(&signalfd_softstate);
	mutex_exit(&signalfd_lock);

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
