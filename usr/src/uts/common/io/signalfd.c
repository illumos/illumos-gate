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
 * Copyright 2015 Joyent, Inc.
 */

/*
 * Support for the signalfd facility, a Linux-borne facility for
 * file descriptor-based synchronous signal consumption.
 *
 * As described on the signalfd(3C) man page, the general idea behind these
 * file descriptors is that they can be used to synchronously consume signals
 * via the read(2) syscall. That capability already exists with the
 * sigwaitinfo(3C) function but the key advantage of signalfd is that, because
 * it is file descriptor based, poll(2) can be used to determine when signals
 * are available to be consumed.
 *
 * The general implementation uses signalfd_state to hold both the signal set
 * and poll head for an open file descriptor. Because a process can be using
 * different sigfds with different signal sets, each signalfd_state poll head
 * can be thought of as an independent signal stream and the thread(s) waiting
 * on that stream will get poll notification when any signal in the
 * corresponding set is received.
 *
 * The sigfd_proc_state_t struct lives on the proc_t and maintains per-proc
 * state for function callbacks and data when the proc needs to do work during
 * signal delivery for pollwakeup.
 *
 * The read side of the implementation is straightforward and mimics the
 * kernel behavior for sigtimedwait(). Signals continue to live on either
 * the proc's p_sig, or thread's t_sig, member. Read consumes the signal so
 * that it is no longer pending.
 *
 * The poll side is more complex since all of the sigfds on the process need
 * to be examined every time a signal is delivered to the process in order to
 * pollwake any thread waiting in poll for that signal.
 *
 * Because it is likely that a process will only be using one, or a few, sigfds,
 * but many total file descriptors, we maintain a list of sigfds which need
 * pollwakeup. The list lives on the proc's p_sigfd struct. In this way only
 * zero, or a few, of the state structs will need to be examined every time a
 * signal is delivered to the process, instead of having to examine all of the
 * file descriptors to find the state structs. When a state struct with a
 * matching signal set is found then pollwakeup is called.
 *
 * The sigfd_list is self-cleaning; as signalfd_pollwake_cb is called, the list
 * will clear out on its own. There is an exit helper (signalfd_exit_helper)
 * which cleans up any remaining per-proc state when the process exits.
 *
 * The main complexity with signalfd is the interaction of forking and polling.
 * This interaction is complex because now two processes have a fd that
 * references the same dev_t (and its associated signalfd_state), but signals
 * go to only one of those processes. Also, we don't know when one of the
 * processes closes its fd because our 'close' entry point is only called when
 * the last fd is closed (which could be by either process).
 *
 * Because the state struct is referenced by both file descriptors, and the
 * state struct represents a signal stream needing a pollwakeup, if both
 * processes were polling then both processes would get a pollwakeup when a
 * signal arrives for either process (that is, the pollhead is associated with
 * our dev_t so when a signal arrives the pollwakeup wakes up all waiters).
 *
 * Fortunately this is not a common problem in practice, but the implementation
 * attempts to mitigate unexpected behavior. The typical behavior is that the
 * parent has been polling the signalfd (which is why it was open in the first
 * place) and the parent might have a pending signalfd_state (with the
 * pollhead) on its per-process sigfd_list. After the fork the child will
 * simply close that fd (among others) as part of the typical fork/close/exec
 * pattern. Because the child will never poll that fd, it will never get any
 * state onto its own sigfd_list (the child starts with a null list). The
 * intention is that the child sees no pollwakeup activity for signals unless
 * it explicitly reinvokes poll on the sigfd.
 *
 * As background, there are two primary polling cases to consider when the
 * parent process forks:
 * 1) If any thread is blocked in poll(2) then both the parent and child will
 *    return from the poll syscall with EINTR. This means that if either
 *    process wants to re-poll on a sigfd then it needs to re-run poll and
 *    would come back in to the signalfd_poll entry point. The parent would
 *    already have the dev_t's state on its sigfd_list and the child would not
 *    have anything there unless it called poll again on its fd.
 * 2) If the process is using /dev/poll(7D) then the polling info is being
 *    cached by the poll device and the process might not currently be blocked
 *    on anything polling related. A subsequent DP_POLL ioctl will not invoke
 *    our signalfd_poll entry point again. Because the parent still has its
 *    sigfd_list setup, an incoming signal will hit our signalfd_pollwake_cb
 *    entry point, which in turn calls pollwake, and /dev/poll will do the
 *    right thing on DP_POLL. The child will not have a sigfd_list yet so the
 *    signal will not cause a pollwakeup. The dp code does its own handling for
 *    cleaning up its cache.
 *
 * This leaves only one odd corner case. If the parent and child both use
 * the dup-ed sigfd to poll then when a signal is delivered to either process
 * there is no way to determine which one should get the pollwakeup (since
 * both processes will be queued on the same signal stream poll head). What
 * happens in this case is that both processes will return from poll, but only
 * one of them will actually have a signal to read. The other will return
 * from read with EAGAIN, or block. This case is actually similar to the
 * situation within a single process which got two different sigfd's with the
 * same mask (or poll on two fd's that are dup-ed). Both would return from poll
 * when a signal arrives but only one read would consume the signal and the
 * other read would fail or block. Applications which poll on shared fd's
 * cannot assume that a subsequent read will actually obtain data.
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

typedef struct signalfd_state signalfd_state_t;

struct signalfd_state {
	kmutex_t sfd_lock;			/* lock protecting state */
	pollhead_t sfd_pollhd;			/* poll head */
	k_sigset_t sfd_set;			/* signals for this fd */
	signalfd_state_t *sfd_next;		/* next state on global list */
};

/*
 * Internal global variables.
 */
static kmutex_t		signalfd_lock;		/* lock protecting state */
static dev_info_t	*signalfd_devi;		/* device info */
static id_space_t	*signalfd_minor;	/* minor number arena */
static void		*signalfd_softstate;	/* softstate pointer */
static signalfd_state_t	*signalfd_state;	/* global list of state */

/*
 * If we don't already have an entry in the proc's list for this state, add one.
 */
static void
signalfd_wake_list_add(signalfd_state_t *state)
{
	proc_t *p = curproc;
	list_t *lst;
	sigfd_wake_list_t *wlp;

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(p->p_sigfd != NULL);

	lst = &((sigfd_proc_state_t *)p->p_sigfd)->sigfd_list;
	for (wlp = list_head(lst); wlp != NULL; wlp = list_next(lst, wlp)) {
		if (wlp->sigfd_wl_state == state)
			break;
	}

	if (wlp == NULL) {
		wlp = kmem_zalloc(sizeof (sigfd_wake_list_t), KM_SLEEP);
		wlp->sigfd_wl_state = state;
		list_insert_head(lst, wlp);
	}
}

static void
signalfd_wake_rm(list_t *lst, sigfd_wake_list_t *wlp)
{
	list_remove(lst, wlp);
	kmem_free(wlp, sizeof (sigfd_wake_list_t));
}

static void
signalfd_wake_list_rm(proc_t *p, signalfd_state_t *state)
{
	sigfd_wake_list_t *wlp;
	list_t *lst;

	ASSERT(MUTEX_HELD(&p->p_lock));

	if (p->p_sigfd == NULL)
		return;

	lst = &((sigfd_proc_state_t *)p->p_sigfd)->sigfd_list;
	for (wlp = list_head(lst); wlp != NULL; wlp = list_next(lst, wlp)) {
		if (wlp->sigfd_wl_state == state) {
			signalfd_wake_rm(lst, wlp);
			break;
		}
	}

	if (list_is_empty(lst)) {
		((sigfd_proc_state_t *)p->p_sigfd)->sigfd_pollwake_cb = NULL;
		list_destroy(lst);
		kmem_free(p->p_sigfd, sizeof (sigfd_proc_state_t));
		p->p_sigfd = NULL;
	}
}

static void
signalfd_wake_list_cleanup(proc_t *p)
{
	sigfd_wake_list_t *wlp;
	list_t *lst;

	ASSERT(MUTEX_HELD(&p->p_lock));

	((sigfd_proc_state_t *)p->p_sigfd)->sigfd_pollwake_cb = NULL;

	lst = &((sigfd_proc_state_t *)p->p_sigfd)->sigfd_list;
	while (!list_is_empty(lst)) {
		wlp = (sigfd_wake_list_t *)list_remove_head(lst);
		kmem_free(wlp, sizeof (sigfd_wake_list_t));
	}
}

static void
signalfd_exit_helper(void)
{
	proc_t *p = curproc;
	list_t *lst;

	/* This being non-null is the only way we can get here */
	ASSERT(p->p_sigfd != NULL);

	mutex_enter(&p->p_lock);
	lst = &((sigfd_proc_state_t *)p->p_sigfd)->sigfd_list;

	signalfd_wake_list_cleanup(p);
	list_destroy(lst);
	kmem_free(p->p_sigfd, sizeof (sigfd_proc_state_t));
	p->p_sigfd = NULL;
	mutex_exit(&p->p_lock);
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
	list_t *lst;
	sigfd_wake_list_t *wlp;

	ASSERT(MUTEX_HELD(&p->p_lock));

	if (p->p_sigfd == NULL)
		return;

	lst = &((sigfd_proc_state_t *)p->p_sigfd)->sigfd_list;
	wlp = list_head(lst);
	while (wlp != NULL) {
		signalfd_state_t *state = wlp->sigfd_wl_state;

		mutex_enter(&state->sfd_lock);

		if (sigismember(&state->sfd_set, sig) &&
		    state->sfd_pollhd.ph_list != NULL) {
			sigfd_wake_list_t *tmp = wlp;

			/* remove it from the list */
			wlp = list_next(lst, wlp);
			signalfd_wake_rm(lst, tmp);

			mutex_exit(&state->sfd_lock);
			pollwakeup(&state->sfd_pollhd, POLLRDNORM | POLLIN);
		} else {
			mutex_exit(&state->sfd_lock);
			wlp = list_next(lst, wlp);
		}
	}
}

_NOTE(ARGSUSED(1))
static int
signalfd_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	signalfd_state_t *state;
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

	state = ddi_get_soft_state(signalfd_softstate, minor);
	*devp = makedevice(major, minor);

	state->sfd_next = signalfd_state;
	signalfd_state = state;

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
	signalfd_state_t *state;
	minor_t minor = getminor(dev);
	boolean_t block = B_TRUE;
	k_sigset_t set;
	boolean_t got_one = B_FALSE;
	int res;

	if (uio->uio_resid < sizeof (signalfd_siginfo_t))
		return (EINVAL);

	state = ddi_get_soft_state(signalfd_softstate, minor);

	if (uio->uio_fmode & (FNDELAY|FNONBLOCK))
		block = B_FALSE;

	mutex_enter(&state->sfd_lock);
	set = state->sfd_set;
	mutex_exit(&state->sfd_lock);

	if (sigisempty(&set))
		return (set_errno(EINVAL));

	do  {
		res = consume_signal(state->sfd_set, uio, block);
		if (res == 0)
			got_one = B_TRUE;

		/*
		 * After consuming one signal we won't block trying to consume
		 * further signals.
		 */
		block = B_FALSE;
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
	signalfd_state_t *state;
	minor_t minor = getminor(dev);
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);
	short revents = 0;

	state = ddi_get_soft_state(signalfd_softstate, minor);

	mutex_enter(&state->sfd_lock);

	if (signalfd_sig_pending(p, t, state->sfd_set) != 0)
		revents |= POLLRDNORM | POLLIN;

	mutex_exit(&state->sfd_lock);

	if (!(*reventsp = revents & events) && !anyyet) {
		*phpp = &state->sfd_pollhd;

		/*
		 * Enable pollwakeup handling.
		 */
		if (p->p_sigfd == NULL) {
			sigfd_proc_state_t *pstate;

			pstate = kmem_zalloc(sizeof (sigfd_proc_state_t),
			    KM_SLEEP);
			list_create(&pstate->sigfd_list,
			    sizeof (sigfd_wake_list_t),
			    offsetof(sigfd_wake_list_t, sigfd_wl_lst));

			mutex_enter(&p->p_lock);
			/* check again now that we're locked */
			if (p->p_sigfd == NULL) {
				p->p_sigfd = pstate;
			} else {
				/* someone beat us to it */
				list_destroy(&pstate->sigfd_list);
				kmem_free(pstate, sizeof (sigfd_proc_state_t));
			}
			mutex_exit(&p->p_lock);
		}

		mutex_enter(&p->p_lock);
		if (((sigfd_proc_state_t *)p->p_sigfd)->sigfd_pollwake_cb ==
		    NULL) {
			((sigfd_proc_state_t *)p->p_sigfd)->sigfd_pollwake_cb =
			    signalfd_pollwake_cb;
		}
		signalfd_wake_list_add(state);
		mutex_exit(&p->p_lock);
	}

	return (0);
}

_NOTE(ARGSUSED(4))
static int
signalfd_ioctl(dev_t dev, int cmd, intptr_t arg, int md, cred_t *cr, int *rv)
{
	signalfd_state_t *state;
	minor_t minor = getminor(dev);
	sigset_t mask;

	state = ddi_get_soft_state(signalfd_softstate, minor);

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
	signalfd_state_t *state, **sp;
	minor_t minor = getminor(dev);
	proc_t *p = curproc;

	state = ddi_get_soft_state(signalfd_softstate, minor);

	if (state->sfd_pollhd.ph_list != NULL) {
		pollwakeup(&state->sfd_pollhd, POLLERR);
		pollhead_clean(&state->sfd_pollhd);
	}

	/* Make sure our state is removed from our proc's pollwake list. */
	mutex_enter(&p->p_lock);
	signalfd_wake_list_rm(p, state);
	mutex_exit(&p->p_lock);

	mutex_enter(&signalfd_lock);

	/* Remove our state from our global list. */
	for (sp = &signalfd_state; *sp != state; sp = &((*sp)->sfd_next))
		VERIFY(*sp != NULL);

	*sp = (*sp)->sfd_next;

	ddi_soft_state_free(signalfd_softstate, minor);
	id_free(signalfd_minor, minor);

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
	    sizeof (signalfd_state_t), 0) != 0) {
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

	/* list should be empty */
	VERIFY(signalfd_state == NULL);

	mutex_enter(&signalfd_lock);
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
