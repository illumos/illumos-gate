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
 * Event loop mechanism for our backend.
 *
 * For more information, see the big theory statement in
 * lib/varpd/svp/common/libvarpd_svp.c.
 */

#include <unistd.h>
#include <thread.h>
#include <port.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <umem.h>

#include <libvarpd_svp.h>

typedef struct svp_event_loop {
	int		sel_port;	/* RO */
	int		sel_nthread;	/* RO */
	thread_t	*sel_threads;	/* RO */
	boolean_t	sel_stop;	/* svp_elock */
	timer_t		sel_hosttimer;
} svp_event_loop_t;

static svp_event_loop_t svp_event;
static mutex_t svp_elock = ERRORCHECKMUTEX;

/* ARGSUSED */
static void *
svp_event_thr(void *arg)
{
	for (;;) {
		int ret;
		port_event_t pe;
		svp_event_t *sep;

		mutex_enter(&svp_elock);
		if (svp_event.sel_stop == B_TRUE) {
			mutex_exit(&svp_elock);
			break;
		}
		mutex_exit(&svp_elock);

		ret = port_get(svp_event.sel_port, &pe, NULL);
		if (ret != 0) {
			switch (errno) {
			case EFAULT:
			case EBADF:
			case EINVAL:
				libvarpd_panic("unexpected port_get errno: %d",
				    errno);
			default:
				break;
			}
		}

		if (pe.portev_user == NULL)
			libvarpd_panic("received event (%p) without "
			    "protev_user set", &pe);
		sep = (svp_event_t *)pe.portev_user;
		sep->se_func(&pe, sep->se_arg);
	}

	return (NULL);
}

int
svp_event_associate(svp_event_t *sep, int fd)
{
	int ret;

	ret = port_associate(svp_event.sel_port, PORT_SOURCE_FD, fd,
	    sep->se_events, sep);
	if (ret != 0) {
		switch (errno) {
		case EBADF:
		case EBADFD:
		case EINVAL:
		case EAGAIN:
			libvarpd_panic("unexpected port_associate error: %d",
			    errno);
		default:
			ret = errno;
			break;
		}
	}

	return (ret);
}

/* ARGSUSED */
int
svp_event_dissociate(svp_event_t *sep, int fd)
{
	int ret;

	ret = port_dissociate(svp_event.sel_port, PORT_SOURCE_FD, fd);
	if (ret != 0) {
		if (errno != ENOENT)
			libvarpd_panic("unexpected port_dissociate error: %d",
			    errno);
		ret = errno;
	}
	return (ret);
}

int
svp_event_inject(void *user)
{
	return (port_send(svp_event.sel_port, 0, user));
}

int
svp_event_timer_init(svp_event_t *sep)
{
	port_notify_t pn;
	struct sigevent evp;
	struct itimerspec ts;

	pn.portnfy_port = svp_event.sel_port;
	pn.portnfy_user = sep;
	evp.sigev_notify = SIGEV_PORT;
	evp.sigev_value.sival_ptr = &pn;

	if (timer_create(CLOCK_REALTIME, &evp, &svp_event.sel_hosttimer) != 0)
		return (errno);

	ts.it_value.tv_sec = svp_tickrate;
	ts.it_value.tv_nsec = 0;
	ts.it_interval.tv_sec = svp_tickrate;
	ts.it_interval.tv_nsec = 0;

	if (timer_settime(svp_event.sel_hosttimer, TIMER_RELTIME, &ts,
	    NULL) != 0) {
		int ret = errno;
		(void) timer_delete(svp_event.sel_hosttimer);
		return (ret);
	}

	return (0);
}

int
svp_event_init(void)
{
	long i, ncpus;

	svp_event.sel_port = port_create();
	if (svp_event.sel_port == -1)
		return (errno);

	ncpus = sysconf(_SC_NPROCESSORS_ONLN) * 2 + 1;
	if (ncpus <= 0)
		libvarpd_panic("sysconf for nprocs failed... %d/%d",
		    ncpus, errno);

	svp_event.sel_threads = umem_alloc(sizeof (thread_t) * ncpus,
	    UMEM_DEFAULT);
	if (svp_event.sel_threads == NULL) {
		int ret = errno;
		(void) timer_delete(svp_event.sel_hosttimer);
		(void) close(svp_event.sel_port);
		svp_event.sel_port = -1;
		return (ret);
	}

	for (i = 0; i < ncpus; i++) {
		int ret;
		thread_t *thr = &svp_event.sel_threads[i];

		ret = thr_create(NULL, 0, svp_event_thr, NULL,
		    THR_DETACHED | THR_DAEMON, thr);
		if (ret != 0) {
			ret = errno;
			(void) timer_delete(svp_event.sel_hosttimer);
			(void) close(svp_event.sel_port);
			svp_event.sel_port = -1;
			return (errno);
		}
	}

	return (0);
}

void
svp_event_fini(void)
{
	mutex_enter(&svp_elock);
	svp_event.sel_stop = B_TRUE;
	mutex_exit(&svp_elock);

	(void) timer_delete(svp_event.sel_hosttimer);
	(void) close(svp_event.sel_port);
}
