/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright 2018 Joyent, Inc.
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * Micro event library for FreeBSD, designed for a single i/o thread
 * using kqueue, and having events be persistent by default.
 */

#include <sys/cdefs.h>

#include <assert.h>
#ifndef WITHOUT_CAPSICUM
#include <capsicum_helpers.h>
#endif
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <sys/types.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif
#ifdef __FreeBSD__
#include <sys/event.h>
#else
#include <port.h>
#include <sys/poll.h>
#include <sys/siginfo.h>
#include <sys/queue.h>
#include <sys/debug.h>
#include <sys/stat.h>
#endif
#include <sys/time.h>

#include <pthread.h>
#include <pthread_np.h>

#include "mevent.h"

#define	MEVENT_MAX	64

#ifndef __FreeBSD__
#define	EV_ENABLE	0x01
#define	EV_ADD		EV_ENABLE
#define	EV_DISABLE	0x02
#define	EV_DELETE	0x04

static int mevent_file_poll_interval_ms = 5000;
#endif

static pthread_t mevent_tid;
static pthread_once_t mevent_once = PTHREAD_ONCE_INIT;
#ifdef __FreeBSD__
static int mevent_timid = 43;
#endif
static int mevent_pipefd[2];
static int mfd;
static pthread_mutex_t mevent_lmutex = PTHREAD_MUTEX_INITIALIZER;

struct mevent {
	void	(*me_func)(int, enum ev_type, void *);
#define me_msecs me_fd
	int	me_fd;
#ifdef __FreeBSD__
	int	me_timid;
#else
	timer_t me_timid;
#endif
	enum ev_type me_type;
	void    *me_param;
	int	me_cq;
	int	me_state; /* Desired kevent flags. */
	int	me_closefd;
	int	me_fflags;
#ifndef __FreeBSD__
	port_notify_t	me_notify;
	struct sigevent	me_sigev;
	boolean_t	me_auto_requeue;
	struct {
		int	mp_fd;
		off_t	mp_size;
		void	(*mp_func)(int, enum ev_type, void *);
		void    *mp_param;
	} me_poll;
#endif
	LIST_ENTRY(mevent) me_list;
};

static LIST_HEAD(listhead, mevent) global_head, change_head;

static void
mevent_qlock(void)
{
	pthread_mutex_lock(&mevent_lmutex);
}

static void
mevent_qunlock(void)
{
	pthread_mutex_unlock(&mevent_lmutex);
}

static void
mevent_pipe_read(int fd, enum ev_type type __unused, void *param __unused)
{
	char buf[MEVENT_MAX];
	int status;

	/*
	 * Drain the pipe read side. The fd is non-blocking so this is
	 * safe to do.
	 */
	do {
		status = read(fd, buf, sizeof(buf));
	} while (status == MEVENT_MAX);
}

static void
mevent_notify(void)
{
	char c = '\0';

	/*
	 * If calling from outside the i/o thread, write a byte on the
	 * pipe to force the i/o thread to exit the blocking kevent call.
	 */
	if (mevent_pipefd[1] != 0 && pthread_self() != mevent_tid) {
		write(mevent_pipefd[1], &c, 1);
	}
}

static void
mevent_init(void)
{
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
#endif

#ifdef __FreeBSD__
	mfd = kqueue();
#else
	mfd = port_create();
#endif
	assert(mfd > 0);

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_KQUEUE);
	if (caph_rights_limit(mfd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	LIST_INIT(&change_head);
	LIST_INIT(&global_head);
}


#ifdef __FreeBSD__
static int
mevent_kq_filter(struct mevent *mevp)
{
	int retval;

	retval = 0;

	if (mevp->me_type == EVF_READ)
		retval = EVFILT_READ;

	if (mevp->me_type == EVF_WRITE)
		retval = EVFILT_WRITE;

	if (mevp->me_type == EVF_TIMER)
		retval = EVFILT_TIMER;

	if (mevp->me_type == EVF_SIGNAL)
		retval = EVFILT_SIGNAL;

	if (mevp->me_type == EVF_VNODE)
		retval = EVFILT_VNODE;

	return (retval);
}

static int
mevent_kq_flags(struct mevent *mevp)
{
	int retval;

	retval = mevp->me_state;

	if (mevp->me_type == EVF_VNODE)
		retval |= EV_CLEAR;

	return (retval);
}

static int
mevent_kq_fflags(struct mevent *mevp)
{
	int retval;

	retval = 0;

	switch (mevp->me_type) {
	case EVF_VNODE:
		if ((mevp->me_fflags & EVFF_ATTRIB) != 0)
			retval |= NOTE_ATTRIB;
		break;
	case EVF_READ:
	case EVF_WRITE:
	case EVF_TIMER:
	case EVF_SIGNAL:
		break;
	}

	return (retval);
}

static void
mevent_populate(struct mevent *mevp, struct kevent *kev)
{
	if (mevp->me_type == EVF_TIMER) {
		kev->ident = mevp->me_timid;
		kev->data = mevp->me_msecs;
	} else {
		kev->ident = mevp->me_fd;
		kev->data = 0;
	}
	kev->filter = mevent_kq_filter(mevp);
	kev->flags = mevent_kq_flags(mevp);
	kev->fflags = mevent_kq_fflags(mevp);
	kev->udata = mevp;
}

static int
mevent_build(struct kevent *kev)
{
	struct mevent *mevp, *tmpp;
	int i;

	i = 0;

	mevent_qlock();

	LIST_FOREACH_SAFE(mevp, &change_head, me_list, tmpp) {
		if (mevp->me_closefd) {
			/*
			 * A close of the file descriptor will remove the
			 * event
			 */
			close(mevp->me_fd);
		} else {
			assert((mevp->me_state & EV_ADD) == 0);
			mevent_populate(mevp, &kev[i]);
			i++;
		}

		mevp->me_cq = 0;
		LIST_REMOVE(mevp, me_list);

		if (mevp->me_state & EV_DELETE) {
			free(mevp);
		} else {
			LIST_INSERT_HEAD(&global_head, mevp, me_list);
		}

		assert(i < MEVENT_MAX);
	}

	mevent_qunlock();

	return (i);
}

static void
mevent_handle(struct kevent *kev, int numev)
{
	struct mevent *mevp;
	int i;

	for (i = 0; i < numev; i++) {
		mevp = kev[i].udata;

		/* XXX check for EV_ERROR ? */

		(*mevp->me_func)(mevp->me_fd, mevp->me_type, mevp->me_param);
	}
}

#else /* __FreeBSD__ */

static boolean_t
mevent_clarify_state(struct mevent *mevp)
{
	const int state = mevp->me_state;

	if ((state & EV_DELETE) != 0) {
		/* All other intents are overriden by delete. */
		mevp->me_state = EV_DELETE;
		return (B_TRUE);
	}

	/*
	 * Without a distinction between EV_ADD and EV_ENABLE in our emulation,
	 * handling the add-disabled case means eliding the portfs operation
	 * when both flags are present.
	 *
	 * This is not a concern for subsequent enable/disable operations, as
	 * mevent_update() toggles the flags properly so they are not left in
	 * conflict.
	 */
	if (state == (EV_ENABLE|EV_DISABLE)) {
		mevp->me_state = EV_DISABLE;
		return (B_FALSE);
	}

	return (B_TRUE);
}

static void
mevent_poll_file_attrib(int fd, enum ev_type type, void *param)
{
	struct mevent *mevp = param;
	struct stat st;

	if (fstat(mevp->me_poll.mp_fd, &st) != 0) {
		(void) fprintf(stderr, "%s: fstat(%d) failed: %s\n",
		    __func__, fd, strerror(errno));
		return;
	}

	/*
	 * The only current consumer of file attribute monitoring is
	 * blockif, which wants to know about size changes.
	 */
	if (mevp->me_poll.mp_size != st.st_size) {
		mevp->me_poll.mp_size = st.st_size;

		(*mevp->me_poll.mp_func)(mevp->me_poll.mp_fd, EVF_VNODE,
		    mevp->me_poll.mp_param);
	}
}

static void
mevent_update_one_readwrite(struct mevent *mevp)
{
	int portfd = mevp->me_notify.portnfy_port;

	mevp->me_auto_requeue = B_FALSE;

	switch (mevp->me_state) {
	case EV_ENABLE:
	{
		const int events = (mevp->me_type == EVF_READ) ?
		    POLLIN : POLLOUT;

		if (port_associate(portfd, PORT_SOURCE_FD, mevp->me_fd,
		    events, mevp) != 0) {
			(void) fprintf(stderr,
			    "port_associate fd %d %p failed: %s\n",
			    mevp->me_fd, mevp, strerror(errno));
		}
		return;
	}
	case EV_DISABLE:
	case EV_DELETE:
		/*
		 * A disable that comes in while an event is being
		 * handled will result in an ENOENT.
		 */
		if (port_dissociate(portfd, PORT_SOURCE_FD,
		    mevp->me_fd) != 0 && errno != ENOENT) {
			(void) fprintf(stderr, "port_dissociate "
			    "portfd %d fd %d mevp %p failed: %s\n",
			    portfd, mevp->me_fd, mevp, strerror(errno));
		}
		return;
	default:
		(void) fprintf(stderr, "%s: unhandled state %d\n", __func__,
		    mevp->me_state);
		abort();
	}
}

static void
mevent_update_one_timer(struct mevent *mevp)
{
	mevp->me_auto_requeue = B_TRUE;

	switch (mevp->me_state) {
	case EV_ENABLE:
	{
		struct itimerspec it = { 0 };

		mevp->me_sigev.sigev_notify = SIGEV_PORT;
		mevp->me_sigev.sigev_value.sival_ptr = &mevp->me_notify;

		if (timer_create(CLOCK_REALTIME, &mevp->me_sigev,
		    &mevp->me_timid) != 0) {
			(void) fprintf(stderr, "timer_create failed: %s",
			    strerror(errno));
			return;
		}

		/* The first timeout */
		it.it_value.tv_sec = mevp->me_msecs / MILLISEC;
		it.it_value.tv_nsec =
			MSEC2NSEC(mevp->me_msecs % MILLISEC);
		/* Repeat at the same interval */
		it.it_interval = it.it_value;

		if (timer_settime(mevp->me_timid, 0, &it, NULL) != 0) {
			(void) fprintf(stderr, "timer_settime failed: %s",
			    strerror(errno));
		}
		return;
	}
	case EV_DISABLE:
	case EV_DELETE:
		if (timer_delete(mevp->me_timid) != 0) {
			(void) fprintf(stderr, "timer_delete failed: %s",
			    strerror(errno));
		}
		mevp->me_timid = -1;
		return;
	default:
		(void) fprintf(stderr, "%s: unhandled state %d\n", __func__,
		    mevp->me_state);
		abort();
	}
}

static void
mevent_update_one_vnode(struct mevent *mevp)
{
	switch (mevp->me_state) {
	case EV_ENABLE:
	{
		struct stat st;
		int events = 0;

		if ((mevp->me_fflags & EVFF_ATTRIB) != 0)
			events |= FILE_ATTRIB;

		assert(events != 0);

		/*
		 * It is tempting to use the PORT_SOURCE_FILE type for this in
		 * conjunction with the FILE_ATTRIB event type. Unfortunately
		 * this event type triggers on any change to the file's
		 * ctime, and therefore for every write as well as attribute
		 * changes. It also does not work for ZVOLs.
		 *
		 * Convert this to a timer event and poll for the file
		 * attribute changes that we care about.
		 */

		if (fstat(mevp->me_fd, &st) != 0) {
			(void) fprintf(stderr, "fstat(%d) failed: %s\n",
			    mevp->me_fd, strerror(errno));
			return;
		}

		mevp->me_poll.mp_fd = mevp->me_fd;
		mevp->me_poll.mp_size = st.st_size;

		mevp->me_poll.mp_func = mevp->me_func;
		mevp->me_poll.mp_param = mevp->me_param;
		mevp->me_func = mevent_poll_file_attrib;
		mevp->me_param = mevp;

		mevp->me_type = EVF_TIMER;
		mevp->me_timid = -1;
		mevp->me_msecs = mevent_file_poll_interval_ms;
		mevent_update_one_timer(mevp);

		return;
	}
	case EV_DISABLE:
	case EV_DELETE:
		/*
		 * These events do not really exist as they are converted to
		 * timers; fall through to abort.
		 */
	default:
		(void) fprintf(stderr, "%s: unhandled state %d\n", __func__,
		    mevp->me_state);
		abort();
	}
}

static void
mevent_update_one(struct mevent *mevp)
{
	switch (mevp->me_type) {
	case EVF_READ:
	case EVF_WRITE:
		mevent_update_one_readwrite(mevp);
		break;
	case EVF_TIMER:
		mevent_update_one_timer(mevp);
		break;
	case EVF_VNODE:
		mevent_update_one_vnode(mevp);
		break;
	case EVF_SIGNAL: /* EVF_SIGNAL not yet implemented. */
	default:
		(void) fprintf(stderr, "%s: unhandled event type %d\n",
		    __func__, mevp->me_type);
		abort();
	}
}

static void
mevent_populate(struct mevent *mevp)
{
	mevp->me_notify.portnfy_port = mfd;
	mevp->me_notify.portnfy_user = mevp;
}

static void
mevent_update_pending()
{
	struct mevent *mevp, *tmpp;

	mevent_qlock();

	LIST_FOREACH_SAFE(mevp, &change_head, me_list, tmpp) {
		mevent_populate(mevp);
		if (mevp->me_closefd) {
			/*
			 * A close of the file descriptor will remove the
			 * event
			 */
			(void) close(mevp->me_fd);
			mevp->me_fd = -1;
		} else {
			if (mevent_clarify_state(mevp)) {
				mevent_update_one(mevp);
			}
		}

		mevp->me_cq = 0;
		LIST_REMOVE(mevp, me_list);

		if (mevp->me_state & EV_DELETE) {
			free(mevp);
		} else {
			LIST_INSERT_HEAD(&global_head, mevp, me_list);
		}
	}

	mevent_qunlock();
}

static void
mevent_handle_pe(port_event_t *pe)
{
	struct mevent *mevp = pe->portev_user;

	(*mevp->me_func)(mevp->me_fd, mevp->me_type, mevp->me_param);

	mevent_qlock();
	if (!mevp->me_cq && !mevp->me_auto_requeue) {
		mevent_update_one(mevp);
	}
	mevent_qunlock();
}
#endif

static struct mevent *
mevent_add_state(int tfd, enum ev_type type,
	   void (*func)(int, enum ev_type, void *), void *param,
	   int state, int fflags)
{
#ifdef __FreeBSD__
	struct kevent kev;
#endif
	struct mevent *lp, *mevp;
#ifdef __FreeBSD__
	int ret;
#endif

	if (tfd < 0 || func == NULL) {
		return (NULL);
	}

	mevp = NULL;

	pthread_once(&mevent_once, mevent_init);

	mevent_qlock();

	/*
	 * Verify that the fd/type tuple is not present in any list
	 */
	LIST_FOREACH(lp, &global_head, me_list) {
		if (type != EVF_TIMER && lp->me_fd == tfd &&
		    lp->me_type == type) {
			goto exit;
		}
	}

	LIST_FOREACH(lp, &change_head, me_list) {
		if (type != EVF_TIMER && lp->me_fd == tfd &&
		    lp->me_type == type) {
			goto exit;
		}
	}

	/*
	 * Allocate an entry and populate it.
	 */
	mevp = calloc(1, sizeof(struct mevent));
	if (mevp == NULL) {
		goto exit;
	}

	if (type == EVF_TIMER) {
		mevp->me_msecs = tfd;
#ifdef __FreeBSD__
		mevp->me_timid = mevent_timid++;
#else
		mevp->me_timid = -1;
#endif
	} else
		mevp->me_fd = tfd;
	mevp->me_type = type;
	mevp->me_func = func;
	mevp->me_param = param;
	mevp->me_state = state;
	mevp->me_fflags = fflags;

	/*
	 * Try to add the event.  If this fails, report the failure to
	 * the caller.
	 */
#ifdef __FreeBSD__
	mevent_populate(mevp, &kev);
	ret = kevent(mfd, &kev, 1, NULL, 0, NULL);
	if (ret == -1) {
		free(mevp);
		mevp = NULL;
		goto exit;
	}
	mevp->me_state &= ~EV_ADD;
#else
	mevent_populate(mevp);
	if (mevent_clarify_state(mevp))
		mevent_update_one(mevp);
#endif

	LIST_INSERT_HEAD(&global_head, mevp, me_list);

exit:
	mevent_qunlock();

	return (mevp);
}

struct mevent *
mevent_add(int tfd, enum ev_type type,
	   void (*func)(int, enum ev_type, void *), void *param)
{

	return (mevent_add_state(tfd, type, func, param, EV_ADD, 0));
}

struct mevent *
mevent_add_flags(int tfd, enum ev_type type, int fflags,
		 void (*func)(int, enum ev_type, void *), void *param)
{

	return (mevent_add_state(tfd, type, func, param, EV_ADD, fflags));
}

struct mevent *
mevent_add_disabled(int tfd, enum ev_type type,
		    void (*func)(int, enum ev_type, void *), void *param)
{

	return (mevent_add_state(tfd, type, func, param, EV_ADD | EV_DISABLE, 0));
}

static int
mevent_update(struct mevent *evp, bool enable)
{
	int newstate;

	mevent_qlock();

	/*
	 * It's not possible to enable/disable a deleted event
	 */
	assert((evp->me_state & EV_DELETE) == 0);

	newstate = evp->me_state;
	if (enable) {
		newstate |= EV_ENABLE;
		newstate &= ~EV_DISABLE;
	} else {
		newstate |= EV_DISABLE;
		newstate &= ~EV_ENABLE;
	}

	/*
	 * No update needed if state isn't changing
	 */
	if (evp->me_state != newstate) {
		evp->me_state = newstate;

		/*
		 * Place the entry onto the changed list if not
		 * already there.
		 */
		if (evp->me_cq == 0) {
			evp->me_cq = 1;
			LIST_REMOVE(evp, me_list);
			LIST_INSERT_HEAD(&change_head, evp, me_list);
			mevent_notify();
		}
	}

	mevent_qunlock();

	return (0);
}

int
mevent_enable(struct mevent *evp)
{

	return (mevent_update(evp, true));
}

int
mevent_disable(struct mevent *evp)
{

	return (mevent_update(evp, false));
}

static int
mevent_delete_event(struct mevent *evp, int closefd)
{
	mevent_qlock();

	/*
         * Place the entry onto the changed list if not already there, and
	 * mark as to be deleted.
         */
        if (evp->me_cq == 0) {
		evp->me_cq = 1;
		LIST_REMOVE(evp, me_list);
		LIST_INSERT_HEAD(&change_head, evp, me_list);
		mevent_notify();
        }
	evp->me_state = EV_DELETE;

	if (closefd)
		evp->me_closefd = 1;

	mevent_qunlock();

	return (0);
}

int
mevent_delete(struct mevent *evp)
{

	return (mevent_delete_event(evp, 0));
}

int
mevent_delete_close(struct mevent *evp)
{

	return (mevent_delete_event(evp, 1));
}

static void
mevent_set_name(void)
{

	pthread_set_name_np(mevent_tid, "mevent");
}

void
mevent_dispatch(void)
{
#ifdef __FreeBSD__
	struct kevent changelist[MEVENT_MAX];
	struct kevent eventlist[MEVENT_MAX];
	struct mevent *pipev;
	int numev;
#else
	struct mevent *pipev;
#endif
	int ret;
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
#endif

	mevent_tid = pthread_self();
	mevent_set_name();

	pthread_once(&mevent_once, mevent_init);

	/*
	 * Open the pipe that will be used for other threads to force
	 * the blocking kqueue call to exit by writing to it. Set the
	 * descriptor to non-blocking.
	 */
	ret = pipe(mevent_pipefd);
	if (ret < 0) {
		perror("pipe");
		exit(0);
	}

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_EVENT, CAP_READ, CAP_WRITE);
	if (caph_rights_limit(mevent_pipefd[0], &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
	if (caph_rights_limit(mevent_pipefd[1], &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	/*
	 * Add internal event handler for the pipe write fd
	 */
	pipev = mevent_add(mevent_pipefd[0], EVF_READ, mevent_pipe_read, NULL);
	assert(pipev != NULL);

	for (;;) {
#ifdef __FreeBSD__
		/*
		 * Build changelist if required.
		 * XXX the changelist can be put into the blocking call
		 * to eliminate the extra syscall. Currently better for
		 * debug.
		 */
		numev = mevent_build(changelist);
		if (numev) {
			ret = kevent(mfd, changelist, numev, NULL, 0, NULL);
			if (ret == -1) {
				perror("Error return from kevent change");
			}
		}

		/*
		 * Block awaiting events
		 */
		ret = kevent(mfd, NULL, 0, eventlist, MEVENT_MAX, NULL);
		if (ret == -1 && errno != EINTR) {
			perror("Error return from kevent monitor");
		}

		/*
		 * Handle reported events
		 */
		mevent_handle(eventlist, ret);

#else /* __FreeBSD__ */
		port_event_t pev;

		/* Handle any pending updates */
		mevent_update_pending();

		/* Block awaiting events */
		ret = port_get(mfd, &pev, NULL);
		if (ret != 0) {
			if (errno != EINTR)
				perror("Error return from port_get");
			continue;
		}

		/* Handle reported event */
		mevent_handle_pe(&pev);
#endif /* __FreeBSD__ */
	}
}
