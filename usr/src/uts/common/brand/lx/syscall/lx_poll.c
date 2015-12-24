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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/zone.h>
#include <sys/brand.h>
#include <sys/sunddi.h>
#include <sys/lx_brand.h>
#include <sys/lx_types.h>
#include <sys/poll_impl.h>
#include <sys/schedctl.h>
#include <sys/lx_signal.h>


/* From uts/common/syscall/poll.c */
extern int poll_copyin(pollstate_t *, pollfd_t *, nfds_t);
extern int poll_common(pollstate_t *, pollfd_t *, nfds_t, timespec_t *, int *);

/*
 * These events are identical between Linux and SunOS
 */
#define	LX_POLLIN	0x001
#define	LX_POLLPRI	0x002
#define	LX_POLLOUT	0x004
#define	LX_POLLERR	0x008
#define	LX_POLLHUP	0x010
#define	LX_POLLNVAL	0x020
#define	LX_POLLRDNORM	0x040
#define	LX_POLLRDBAND	0x080

#define	LX_POLL_COMMON_EVENTS (LX_POLLIN | LX_POLLPRI | LX_POLLOUT |	\
	LX_POLLERR | LX_POLLHUP | LX_POLLNVAL | LX_POLLRDNORM | LX_POLLRDBAND)

/*
 * These events differ between Linux and SunOS
 */
#define	LX_POLLWRNORM	0x0100
#define	LX_POLLWRBAND	0x0200
#define	LX_POLLRDHUP	0x2000


#define	LX_POLL_SUPPORTED_EVENTS	\
	(LX_POLL_COMMON_EVENTS | LX_POLLWRNORM | LX_POLLWRBAND | LX_POLLRDHUP)


static int
lx_poll_copyin(pollstate_t *ps, pollfd_t *fds, nfds_t nfds, short *oldevt)
{
	int i, error = 0;
	pollfd_t *pollfdp;

	if ((error = poll_copyin(ps, fds, nfds)) != 0) {
		return (error);
	}
	pollfdp = ps->ps_pollfd;

	/* Convert the Linux events bitmask into SunOS equivalent. */
	for (i = 0; i < nfds; i++) {
		short lx_events = pollfdp[i].events;
		short events;

		/*
		 * If the caller is polling for an unsupported event, we
		 * have to bail out.
		 */
		if (lx_events & ~LX_POLL_SUPPORTED_EVENTS) {
			return (ENOTSUP);
		}

		events = lx_events & LX_POLL_COMMON_EVENTS;
		if (lx_events & LX_POLLWRNORM)
			events |= POLLWRNORM;
		if (lx_events & LX_POLLWRBAND)
			events |= POLLWRBAND;
		if (lx_events & LX_POLLRDHUP)
			events |= POLLRDHUP;
		pollfdp[i].events = events;
		oldevt[i] = lx_events;
	}
	return (0);
}

static int
lx_poll_copyout(pollfd_t *pollfdp, pollfd_t *fds, nfds_t nfds, short *oldevt)
{
	int i;

	/*
	 * Convert SunOS revents bitmask into Linux equivalent and restore
	 * cached events field which was swizzled by lx_poll_copyin.
	 */
	for (i = 0; i < nfds; i++) {
		short revents = pollfdp[i].revents;
		short lx_revents = revents & LX_POLL_COMMON_EVENTS;
		short orig_events = oldevt[i];

		if (revents & POLLWRBAND)
			lx_revents |= LX_POLLWRBAND;
		if (revents & POLLRDHUP)
			lx_revents |= LX_POLLRDHUP;
		/*
		 * Because POLLOUT and POLLWRNORM are native defined as the
		 * same value, care must be taken when translating them to
		 * Linux where they differ.
		 */
		if (revents & POLLOUT) {
			if ((orig_events & LX_POLLOUT) == 0)
				lx_revents &= ~LX_POLLOUT;
			if (orig_events & LX_POLLWRNORM)
				lx_revents |= LX_POLLWRNORM;
		}

		pollfdp[i].revents = lx_revents;
		pollfdp[i].events = orig_events;
	}

	if (copyout(pollfdp, fds, sizeof (pollfd_t) * nfds) != 0)
		return (EFAULT);

	return (0);
}

static long
lx_poll_common(pollfd_t *fds, nfds_t nfds, timespec_t *tsp, k_sigset_t *ksetp)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	proc_t *p = ttoproc(t);
	pollstate_t *ps = NULL;
	pollfd_t *pollfdp = NULL;
	short *oldevt = NULL;
	int error = 0, fdcnt = 0;

	/*
	 * Reset our signal mask, if requested.
	 */
	if (ksetp != NULL) {
		mutex_enter(&p->p_lock);
		schedctl_finish_sigblock(t);
		lwp->lwp_sigoldmask = t->t_hold;
		t->t_hold = *ksetp;
		t->t_flag |= T_TOMASK;
		/*
		 * Call cv_reltimedwait_sig() just to check for signals.
		 * We will return immediately with either 0 or -1.
		 */
		if (!cv_reltimedwait_sig(&t->t_delay_cv, &p->p_lock, 0,
		    TR_CLOCK_TICK)) {
			mutex_exit(&p->p_lock);
			error = EINTR;
			goto pollout;
		}
		mutex_exit(&p->p_lock);
	}

	/*
	 * Initialize pollstate and copy in pollfd data if present.
	 */
	if (nfds != 0) {
		if (nfds > p->p_fno_ctl) {
			mutex_enter(&p->p_lock);
			(void) rctl_action(rctlproc_legacy[RLIMIT_NOFILE],
			    p->p_rctls, p, RCA_SAFE);
			mutex_exit(&p->p_lock);
			error = EINVAL;
			goto pollout;
		}

		/*
		 * Need to allocate memory for pollstate before anything
		 * because the mutex and cv are created in this space
		 */
		ps = pollstate_create();
		if (ps->ps_pcache == NULL)
			ps->ps_pcache = pcache_alloc();

		/*
		 * Certain event types which are distinct on Linux are aliased
		 * against each other on illumos.  In order properly translate
		 * back into the Linux format, the original events of interest
		 * are stored in 'oldevt' for use during lx_poll_copyout.
		 */
		oldevt = kmem_alloc(nfds * sizeof (short), KM_SLEEP);
		if ((error = lx_poll_copyin(ps, fds, nfds, oldevt)) != 0)
			goto pollout;
		pollfdp = ps->ps_pollfd;
	}

	/*
	 * Perform the actual poll.
	 */
	error = poll_common(ps, fds, nfds, tsp, &fdcnt);

pollout:
	/*
	 * If we changed the signal mask but we received no signal then restore
	 * the signal mask.  Otherwise psig() will deal with the signal mask.
	 */
	if (ksetp != NULL) {
		mutex_enter(&p->p_lock);
		if (lwp->lwp_cursig == 0) {
			t->t_hold = lwp->lwp_sigoldmask;
			t->t_flag &= ~T_TOMASK;
		}
		mutex_exit(&p->p_lock);
	}

	/*
	 * Copy out the events and return the fdcnt to the user.
	 */
	if (nfds != 0 && error == 0) {
		error = lx_poll_copyout(pollfdp, fds, nfds, oldevt);
	}
	if (oldevt != NULL) {
		kmem_free(oldevt, nfds * sizeof (short));
	}
	if (error) {
		return (set_errno(error));
	}
	return (fdcnt);
}

long
lx_poll(pollfd_t *fds, nfds_t nfds, int timeout)
{
	timespec_t ts, *tsp = NULL;

	if (timeout >= 0) {
		ts.tv_sec = timeout / MILLISEC;
		ts.tv_nsec = (timeout % MILLISEC) * MICROSEC;
		tsp = &ts;
	}

	return (lx_poll_common(fds, nfds, tsp, NULL));
}

long
lx_ppoll(pollfd_t *fds, nfds_t nfds, timespec_t *timeoutp, lx_sigset_t *setp)
{
	timespec_t ts, *tsp = NULL;
	k_sigset_t kset, *ksetp = NULL;

	/*
	 * Copy in timeout and sigmask.
	 */
	if (timeoutp != NULL) {
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (copyin(timeoutp, &ts, sizeof (ts)))
				return (set_errno(EFAULT));
		} else {
			timespec32_t ts32;

			if (copyin(timeoutp, &ts32, sizeof (ts32)))
				return (set_errno(EFAULT));
			TIMESPEC32_TO_TIMESPEC(&ts, &ts32)
		}

		if (itimerspecfix(&ts))
			return (set_errno(EINVAL));
		tsp = &ts;
	}
	if (setp != NULL) {
		lx_sigset_t lset;

		if (copyin(setp, &lset, sizeof (lset)))
			return (set_errno(EFAULT));
		lx_ltos_sigset(&lset, &kset);
		ksetp = &kset;
	}

	return (lx_poll_common(fds, nfds, tsp, ksetp));
}

typedef struct lx_select_buf_s {
	long		*lsb_rfds;
	long		*lsb_wfds;
	long		*lsb_efds;
	unsigned int	lsb_size;
} lx_select_buf_t;

/*
 * Size (in bytes) of buffer appropriate for fd_set copyin/copyout.
 * Linux uses buffers of 'long' to accomplish this.
 */
#define	LX_FD_SET_BYTES		(sizeof (long))
#define	LX_FD_SET_BITS		(8 * LX_FD_SET_BYTES)
#define	LX_FD_SET_SIZE(nfds)	\
	((((nfds) + (LX_FD_SET_BITS - 1)) / LX_FD_SET_BITS) * LX_FD_SET_BYTES)

static int
lx_select_copyin(pollstate_t *ps, lx_select_buf_t *sbuf, int nfds,
    long *rfds, long *wfds, long *efds)
{
	int n;
	long *in, *out, *ex;
	long absent = 0;
	pollfd_t *pfd;
	nfds_t old_nfds;

	/*
	 * Just like pollsys and lx_poll, attempt to reuse ps_pollfd if it is
	 * appropriately sized.  See poll_copyin for more detail.
	 */
	old_nfds = ps->ps_nfds;
	if (nfds != old_nfds) {
		kmem_free(ps->ps_pollfd, old_nfds * sizeof (pollfd_t));
		pfd = kmem_alloc(nfds * sizeof (pollfd_t), KM_SLEEP);
		ps->ps_pollfd = pfd;
		ps->ps_nfds = nfds;
	} else {
		pfd = ps->ps_pollfd;
	}

	if (rfds != NULL) {
		if (copyin(rfds, sbuf->lsb_rfds, sbuf->lsb_size) != 0) {
			return (EFAULT);
		}
	}
	if (wfds != NULL) {
		if (copyin(wfds, sbuf->lsb_wfds, sbuf->lsb_size) != 0) {
			return (EFAULT);
		}
	}
	if (efds != NULL) {
		if (copyin(efds, sbuf->lsb_efds, sbuf->lsb_size) != 0) {
			return (EFAULT);
		}
	}

	/*
	 * For each fd, if any bits are set convert them into the appropriate
	 * pollfd struct. (Derived from libc's select logic)
	 */
	in = (rfds != NULL) ? sbuf->lsb_rfds : &absent;
	out = (wfds != NULL) ? sbuf->lsb_wfds : &absent;
	ex = (efds != NULL) ? sbuf->lsb_efds : &absent;
	for (n = 0; n < nfds; n += LX_FD_SET_BITS) {
		unsigned long b, m, j;

		b = (unsigned long)(*in | *out | *ex);
		m = 1;
		for (j = 0; j < LX_FD_SET_BITS; j++) {
			int fd = n + j;

			if (fd >= nfds)
				return (0);
			pfd->events = 0;
			if (b & 1) {
				pfd->fd = fd;
				if (*in & m)
					pfd->events |= POLLRDNORM;
				if (*out & m)
					pfd->events |= POLLWRNORM;
				if (*ex & m)
					pfd->events |= POLLRDBAND;
			} else {
				pfd->fd = -1;
			}
			pfd++;
			b >>= 1;
			m <<= 1;
		}

		if (rfds != NULL)
			in++;
		if (wfds != NULL)
			out++;
		if (efds != NULL)
			ex++;
	}
	return (0);
}

static int
lx_select_copyout(pollfd_t *pollfdp, lx_select_buf_t *sbuf, int nfds,
    long *rfds, long *wfds, long *efds, int *fdcnt)
{
	int n;
	pollfd_t *pfd;
	long rv = 0;

	/*
	 * If poll did not find any fds of interest, we can just zero out the
	 * fd_set fields for copyout.
	 */
	if (*fdcnt == 0) {
		if (rfds != NULL) {
			bzero(sbuf->lsb_rfds, sbuf->lsb_size);
		}
		if (wfds != NULL) {
			bzero(sbuf->lsb_wfds, sbuf->lsb_size);
		}
		if (efds != NULL) {
			bzero(sbuf->lsb_efds, sbuf->lsb_size);
		}
		goto copyout;
	}

	/*
	 * For each fd, if any bits are set convert them into the appropriate
	 * pollfd struct. (Derived from libc's select logic)
	 */
	pfd = pollfdp;
	for (n = 0; n < nfds; n += LX_FD_SET_BITS) {
		unsigned long m, j;
		long in = 0, out = 0, ex = 0;

		m = 1;
		for (j = 0; j < LX_FD_SET_BITS; j++) {
			if ((n + j) >= nfds)
				break;
			if (pfd->revents != 0) {
				if (pfd->revents & POLLNVAL) {
					return (EBADF);
				}
				if (pfd->revents & POLLRDNORM) {
					in |= m;
					rv++;
				}
				if (pfd->revents & POLLWRNORM) {
					out |= m;
					rv++;
				}
				if (pfd->revents & POLLRDBAND) {
					ex |= m;
					rv++;
				}
				/*
				 * Only set this bit on return if we asked
				 * about input conditions.
				 */
				if ((pfd->revents & (POLLHUP|POLLERR)) &&
				    (pfd->events & POLLRDNORM)) {
					if ((in & m) == 0) {
						/* wasn't already set */
						rv++;
					}
					in |= m;
				}
				/*
				 * Only set this bit on return if we asked
				 * about output conditions.
				 */
				if ((pfd->revents & (POLLHUP|POLLERR)) &&
				    (pfd->events & POLLWRNORM)) {
					if ((out & m) == 0) {
						/* wasn't already set */
						rv++;
					}
					out |= m;
				}
				/*
				 * Only set this bit on return if we asked
				 * about output conditions.
				 */
				if ((pfd->revents & (POLLHUP|POLLERR)) &&
				    (pfd->events & POLLRDBAND)) {
					if ((ex & m) == 0) {
						/* wasn't already set */
						rv++;
					}
					ex |= m;
				}
			}
			m <<= 1;
			pfd++;
		}
		if (rfds != NULL)
			sbuf->lsb_rfds[n / LX_FD_SET_BITS] = in;
		if (wfds != NULL)
			sbuf->lsb_wfds[n / LX_FD_SET_BITS] = out;
		if (efds != NULL)
			sbuf->lsb_efds[n / LX_FD_SET_BITS] = ex;
	}

copyout:
	if (rfds != NULL) {
		if (copyout(sbuf->lsb_rfds, rfds, sbuf->lsb_size) != 0) {
			return (EFAULT);
		}
	}
	if (wfds != NULL) {
		if (copyout(sbuf->lsb_wfds, wfds, sbuf->lsb_size) != 0) {
			return (EFAULT);
		}
	}
	if (efds != NULL) {
		if (copyout(sbuf->lsb_efds, efds, sbuf->lsb_size) != 0) {
			return (EFAULT);
		}
	}
	*fdcnt = rv;
	return (0);
}


static long
lx_select_common(int nfds, long *rfds, long *wfds, long *efds,
    timespec_t *tsp, k_sigset_t *ksetp)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	proc_t *p = ttoproc(t);
	pollstate_t *ps = NULL;
	pollfd_t *pollfdp = NULL, *fake_fds = NULL;
	lx_select_buf_t sbuf = {0};
	int error = 0, fdcnt = 0;

	if (nfds < 0) {
		return (set_errno(EINVAL));
	}

	/*
	 * Reset our signal mask, if requested.
	 */
	if (ksetp != NULL) {
		mutex_enter(&p->p_lock);
		schedctl_finish_sigblock(t);
		lwp->lwp_sigoldmask = t->t_hold;
		t->t_hold = *ksetp;
		t->t_flag |= T_TOMASK;
		/*
		 * Call cv_reltimedwait_sig() just to check for signals.
		 * We will return immediately with either 0 or -1.
		 */
		if (!cv_reltimedwait_sig(&t->t_delay_cv, &p->p_lock, 0,
		    TR_CLOCK_TICK)) {
			mutex_exit(&p->p_lock);
			error = EINTR;
			goto out;
		}
		mutex_exit(&p->p_lock);
	}

	/*
	 * Because poll caching uses the userspace pollfd_t pointer to verify
	 * cache reuse validity, a simulated value must be supplied when
	 * emulating Linux select(2).  The first non-NULL pointer from
	 * rfds/wfds/efds is used for this purpose.
	 */
	if (rfds != NULL) {
		fake_fds = (pollfd_t *)rfds;
	} else if (wfds != NULL) {
		fake_fds = (pollfd_t *)wfds;
	} else if (efds != NULL) {
		fake_fds = (pollfd_t *)efds;
	} else {
		/*
		 * A non-zero nfds was supplied but all three fd_set pointers
		 * were null.  Fall back to doing a simple timeout.
		 */
		nfds = 0;
	}

	/*
	 * Initialize pollstate and copy in pollfd data if present.
	 */
	if (nfds != 0) {
		if (nfds > p->p_fno_ctl) {
			mutex_enter(&p->p_lock);
			(void) rctl_action(rctlproc_legacy[RLIMIT_NOFILE],
			    p->p_rctls, p, RCA_SAFE);
			mutex_exit(&p->p_lock);
			error = EINVAL;
			goto out;
		}

		/*
		 * Need to allocate memory for pollstate before anything
		 * because the mutex and cv are created in this space
		 */
		ps = pollstate_create();
		if (ps->ps_pcache == NULL)
			ps->ps_pcache = pcache_alloc();

		sbuf.lsb_size = LX_FD_SET_SIZE(nfds);
		if (rfds != NULL)
			sbuf.lsb_rfds = kmem_alloc(sbuf.lsb_size, KM_SLEEP);
		if (wfds != NULL)
			sbuf.lsb_wfds = kmem_alloc(sbuf.lsb_size, KM_SLEEP);
		if (efds != NULL)
			sbuf.lsb_efds = kmem_alloc(sbuf.lsb_size, KM_SLEEP);

		error = lx_select_copyin(ps, &sbuf, nfds, rfds, wfds, efds);
		if (error != 0) {
			goto out;
		}

		pollfdp = ps->ps_pollfd;
	}

	/*
	 * Perform the actual poll.
	 */
	error = poll_common(ps, fake_fds, (nfds_t)nfds, tsp, &fdcnt);

out:
	/*
	 * If we changed the signal mask but we received no signal then restore
	 * the signal mask.  Otherwise psig() will deal with the signal mask.
	 */
	if (ksetp != NULL) {
		mutex_enter(&p->p_lock);
		if (lwp->lwp_cursig == 0) {
			t->t_hold = lwp->lwp_sigoldmask;
			t->t_flag &= ~T_TOMASK;
		}
		mutex_exit(&p->p_lock);
	}

	/*
	 * Copy out the events and return the fdcnt to the user.
	 */
	if (error == 0 && nfds != 0) {
		error = lx_select_copyout(pollfdp, &sbuf, nfds, rfds, wfds,
		    efds, &fdcnt);
	}
	if (sbuf.lsb_size != 0) {
		if (sbuf.lsb_rfds != NULL)
			kmem_free(sbuf.lsb_rfds, sbuf.lsb_size);
		if (sbuf.lsb_wfds != NULL)
			kmem_free(sbuf.lsb_wfds, sbuf.lsb_size);
		if (sbuf.lsb_efds != NULL)
			kmem_free(sbuf.lsb_efds, sbuf.lsb_size);
	}
	if (error) {
		return (set_errno(error));
	}
	return (fdcnt);
}

long
lx_select(int nfds, long *rfds, long *wfds, long *efds,
    struct timeval *timeoutp)
{
	timespec_t ts, *tsp = NULL;

	if (timeoutp != NULL) {
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			struct timeval tv;

			if (copyin(timeoutp, &tv, sizeof (tv)))
				return (set_errno(EFAULT));
			ts.tv_sec = tv.tv_sec;
			ts.tv_nsec = tv.tv_usec * (NANOSEC / MICROSEC);
		} else {
			struct timeval32 tv32;

			if (copyin(timeoutp, &tv32, sizeof (tv32)))
				return (set_errno(EFAULT));
			ts.tv_sec = tv32.tv_sec;
			ts.tv_nsec = tv32.tv_usec * (NANOSEC / MICROSEC);
		}

		if (itimerspecfix(&ts))
			return (set_errno(EINVAL));
		tsp = &ts;
	}

	return (lx_select_common(nfds, rfds, wfds, efds, tsp, NULL));
}

long
lx_pselect(int nfds, long *rfds, long *wfds, long *efds,
    timespec_t *timeoutp, lx_sigset_t *setp)
{
	timespec_t ts, *tsp = NULL;
	k_sigset_t kset, *ksetp = NULL;

	/*
	 * Copy in timeout and sigmask.
	 */
	if (timeoutp != NULL) {
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (copyin(timeoutp, &ts, sizeof (ts)))
				return (set_errno(EFAULT));
		} else {
			timespec32_t ts32;

			if (copyin(timeoutp, &ts32, sizeof (ts32)))
				return (set_errno(EFAULT));
			TIMESPEC32_TO_TIMESPEC(&ts, &ts32)
		}

		if (itimerspecfix(&ts))
			return (set_errno(EINVAL));
		tsp = &ts;
	}
	if (setp != NULL) {
		lx_sigset_t lset;

		if (copyin(setp, &lset, sizeof (lset)))
			return (set_errno(EFAULT));
		lx_ltos_sigset(&lset, &kset);
		ksetp = &kset;
	}

	return (lx_select_common(nfds, rfds, wfds, efds, tsp, ksetp));
}
