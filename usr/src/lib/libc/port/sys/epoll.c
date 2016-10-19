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

#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/devpoll.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

/*
 * Events that match their epoll(7) equivalents.
 */
#if EPOLLIN != POLLIN
#error value of EPOLLIN does not match value of POLLIN
#endif

#if EPOLLPRI != POLLPRI
#error value of EPOLLPRI does not match value of POLLPRI
#endif

#if EPOLLOUT != POLLOUT
#error value of EPOLLOUT does not match value of POLLOUT
#endif

#if EPOLLRDNORM != POLLRDNORM
#error value of EPOLLRDNORM does not match value of POLLRDNORM
#endif

#if EPOLLRDBAND != POLLRDBAND
#error value of EPOLLRDBAND does not match value of POLLRDBAND
#endif

#if EPOLLERR != POLLERR
#error value of EPOLLERR does not match value of POLLERR
#endif

#if EPOLLHUP != POLLHUP
#error value of EPOLLHUP does not match value of POLLHUP
#endif

/*
 * Events that we ignore entirely.  They can be set in events, but they will
 * never be returned.
 */
#define	EPOLLIGNORED 	(EPOLLMSG | EPOLLWAKEUP)

/*
 * Events that we swizzle into other bit positions.
 */
#define	EPOLLSWIZZLED	\
	(EPOLLRDHUP | EPOLLONESHOT | EPOLLET | EPOLLWRBAND | EPOLLWRNORM)

int
epoll_create(int size)
{
	int fd;

	/*
	 * From the epoll_create() man page:  "Since Linux 2.6.8, the size
	 * argument is ignored, but must be greater than zero."  You keep using
	 * that word "ignored"...
	 */
	if (size <= 0) {
		errno = EINVAL;
		return (-1);
	}

	if ((fd = open("/dev/poll", O_RDWR)) == -1)
		return (-1);

	if (ioctl(fd, DP_EPOLLCOMPAT, 0) == -1) {
		(void) close(fd);
		return (-1);
	}

	return (fd);
}

int
epoll_create1(int flags)
{
	int fd, oflags = O_RDWR;

	if (flags & EPOLL_CLOEXEC)
		oflags |= O_CLOEXEC;

	if ((fd = open("/dev/poll", oflags)) == -1)
		return (-1);

	if (ioctl(fd, DP_EPOLLCOMPAT, 0) == -1) {
		(void) close(fd);
		return (-1);
	}

	return (fd);
}

int
epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	dvpoll_epollfd_t epoll[2];
	uint32_t events, ev = 0;
	int i = 0, res;

	epoll[i].dpep_pollfd.fd = fd;

	switch (op) {
	case EPOLL_CTL_DEL:
		ev = POLLREMOVE;
		break;

	case EPOLL_CTL_MOD:
		/*
		 * In the modify case, we pass down two events:  one to
		 * remove the event and another to add it back.
		 */
		epoll[i++].dpep_pollfd.events = POLLREMOVE;
		epoll[i].dpep_pollfd.fd = fd;
		/* FALLTHROUGH */

	case EPOLL_CTL_ADD:
		/*
		 * Mask off the events that we ignore, and then swizzle the
		 * events for which our values differ from their epoll(7)
		 * equivalents.
		 */
		events = event->events;
		ev = events & ~(EPOLLIGNORED | EPOLLSWIZZLED);

		if (events & EPOLLRDHUP)
			ev |= POLLRDHUP;

		if (events & EPOLLET)
			ev |= POLLET;

		if (events & EPOLLONESHOT)
			ev |= POLLONESHOT;

		if (events & EPOLLWRNORM)
			ev |= POLLWRNORM;

		if (events & EPOLLWRBAND)
			ev |= POLLWRBAND;

		epoll[i].dpep_data = event->data.u64;
		break;

	default:
		errno = EOPNOTSUPP;
		return (-1);
	}

	epoll[i].dpep_pollfd.events = ev;
retry:
	res = write(epfd, epoll, sizeof (epoll[0]) * (i + 1));

	if (res == -1) {
		if (errno == EINTR) {
			/*
			 * Linux does not document EINTR as an allowed error
			 * for epoll_ctl.  The write must be retried if it is
			 * not done automatically via SA_RESTART.
			 */
			goto retry;
		}
		if (errno == ELOOP) {
			/*
			 * Convert the specific /dev/poll error about an fd
			 * loop into what is expected from the Linux epoll
			 * interface.
			 */
			errno = EINVAL;
		}
		return (-1);
	}
	return (0);
}

int
epoll_wait(int epfd, struct epoll_event *events,
    int maxevents, int timeout)
{
	struct dvpoll arg;

	if (maxevents <= 0) {
		errno = EINVAL;
		return (-1);
	}

	arg.dp_nfds = maxevents;
	arg.dp_timeout = timeout;
	arg.dp_fds = (pollfd_t *)events;

	return (ioctl(epfd, DP_POLL, &arg));
}

int
epoll_pwait(int epfd, struct epoll_event *events,
    int maxevents, int timeout, const sigset_t *sigmask)
{
	struct dvpoll arg;

	if (maxevents <= 0) {
		errno = EINVAL;
		return (-1);
	}

	arg.dp_nfds = maxevents;
	arg.dp_timeout = timeout;
	arg.dp_fds = (pollfd_t *)events;
	arg.dp_setp = (sigset_t *)sigmask;

	return (ioctl(epfd, DP_PPOLL, &arg));
}
