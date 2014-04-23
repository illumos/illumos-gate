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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/stropts.h>
#include <sys/socketvar.h>
#include <sys/ksocket.h>
#include <io/ksocket/ksocket_impl.h>
#include <fs/sockfs/sockcommon.h>
#include <fs/sockfs/sodirect.h>
#include <fs/sockfs/sockfilter_impl.h>

/*
 * There can only be a single thread waiting for data (enforced by
 * so_lock_read()), whereas for write there might be multiple threads
 * waiting for transmit buffers. So therefore we use cv_broadcast for
 * write and cv_signal for read.
 */
#define	SO_WAKEUP_READER(so) {				\
	if ((so)->so_rcv_wakeup) {			\
		(so)->so_rcv_wakeup = B_FALSE;		\
		cv_signal(&(so)->so_rcv_cv);		\
	}						\
}

#define	SO_WAKEUP_WRITER(so) {			\
	if ((so)->so_snd_wakeup) {		\
		(so)->so_snd_wakeup = B_FALSE;	\
		cv_broadcast(&(so)->so_snd_cv);	\
	}					\
}

static int i_so_notify_last_rx(struct sonode *, int *, int *);
static int i_so_notify_last_tx(struct sonode *, int *, int *);

/*
 * The notification functions must be called with so_lock held,
 * and they will all *drop* so_lock before returning.
 */

/*
 * Wake up anyone waiting for the connection to be established.
 */
void
so_notify_connected(struct sonode *so)
{
	ASSERT(MUTEX_HELD(&so->so_lock));

	if (IS_KERNEL_SOCKET(so)) {
		KSOCKET_CALLBACK(so, connected, 0);
		mutex_exit(&so->so_lock);
	} else {
		socket_sendsig(so, SOCKETSIG_WRITE);
		mutex_exit(&so->so_lock);
		pollwakeup(&so->so_poll_list, POLLOUT);
	}
	sof_sonode_notify_filters(so, SOF_EV_CONNECTED, 0);

	ASSERT(MUTEX_NOT_HELD(&so->so_lock));
}

/*
 * The socket is disconnecting, so no more data can be sent. Wake up
 * anyone that is waiting to send data.
 */
void
so_notify_disconnecting(struct sonode *so)
{
	int pollev = 0;
	int sigev = 0;

	ASSERT(MUTEX_HELD(&so->so_lock));
	(void) i_so_notify_last_tx(so, &pollev, &sigev);

	if (IS_KERNEL_SOCKET(so)) {
		KSOCKET_CALLBACK(so, cantsendmore, 0);
		mutex_exit(&so->so_lock);
	} else {
		if (sigev != 0)
			socket_sendsig(so, sigev);
		mutex_exit(&so->so_lock);

		if (pollev != 0)
			pollwakeup(&so->so_poll_list, pollev);
	}
	sof_sonode_notify_filters(so, SOF_EV_CANTSENDMORE, 0);

	ASSERT(MUTEX_NOT_HELD(&so->so_lock));
}

/*
 * The socket is disconnected, so not more data can be sent or received.
 * Wake up anyone that is waiting to send or receive data.
 */
void
so_notify_disconnected(struct sonode *so, boolean_t connfailed, int error)
{
	int pollev = 0;
	int sigev = 0;

	ASSERT(MUTEX_HELD(&so->so_lock));

	(void) i_so_notify_last_tx(so, &pollev, &sigev);
	(void) i_so_notify_last_rx(so, &pollev, &sigev);

	if (IS_KERNEL_SOCKET(so)) {
		if (connfailed) {
			KSOCKET_CALLBACK(so, disconnected, error);
		} else {
			KSOCKET_CALLBACK(so, connectfailed, error);
		}
		mutex_exit(&so->so_lock);
	} else {
		if (sigev != 0)
			socket_sendsig(so, sigev);
		mutex_exit(&so->so_lock);

		/*
		 * If we're here because the socket has become disconnected,
		 * we explicitly set POLLHUP.  At the same time, we also clear
		 * POLLOUT, as POLLOUT and POLLHUP are defined to be mutually
		 * exclusive with respect to one another.
		 */
		if (!connfailed)
			pollev = (pollev | POLLHUP) & ~POLLOUT;

		if (pollev != 0)
			pollwakeup(&so->so_poll_list, pollev);
	}
	sof_sonode_notify_filters(so, (connfailed) ? SOF_EV_CONNECTFAILED :
	    SOF_EV_DISCONNECTED, error);

	ASSERT(MUTEX_NOT_HELD(&so->so_lock));
}

/*
 * The socket is writeable. Wake up anyone waiting to send data.
 */
void
so_notify_writable(struct sonode *so)
{
	ASSERT(MUTEX_HELD(&so->so_lock));

	SO_WAKEUP_WRITER(so);

	if (IS_KERNEL_SOCKET(so)) {
		KSOCKET_CALLBACK(so, cansend, 0);
		mutex_exit(&so->so_lock);
	} else {
		socket_sendsig(so, SOCKETSIG_WRITE);
		mutex_exit(&so->so_lock);
		pollwakeup(&so->so_poll_list, POLLOUT);
	}

	ASSERT(MUTEX_NOT_HELD(&so->so_lock));

	/* filters can start injecting data */
	if (so->so_filter_active > 0)
		sof_sonode_notify_filters(so, SOF_EV_INJECT_DATA_OUT_OK, 0);
}

/*
 * Data is available, so wake up anyone waiting for data.
 */
void
so_notify_data(struct sonode *so, size_t qlen)
{
	ASSERT(MUTEX_HELD(&so->so_lock));

	SO_WAKEUP_READER(so);

	if (IS_KERNEL_SOCKET(so)) {
		KSOCKET_CALLBACK(so, newdata, qlen);
		mutex_exit(&so->so_lock);
	} else {
		socket_sendsig(so, SOCKETSIG_READ);
		if (so->so_pollev & (SO_POLLEV_IN|SO_POLLEV_ALWAYS)) {
			so->so_pollev &= ~SO_POLLEV_IN;
			mutex_exit(&so->so_lock);
			pollwakeup(&so->so_poll_list, POLLIN|POLLRDNORM);
		} else {
			mutex_exit(&so->so_lock);
		}
	}

	ASSERT(MUTEX_NOT_HELD(&so->so_lock));
}

/*
 * Transient error. Wake up anyone waiting to send or receive data.
 */
void
so_notify_error(struct sonode *so)
{
	ASSERT(MUTEX_HELD(&so->so_lock));

	SO_WAKEUP_WRITER(so);
	SO_WAKEUP_READER(so);

	if (IS_KERNEL_SOCKET(so)) {
		KSOCKET_CALLBACK(so, error, 0);
		mutex_exit(&so->so_lock);
	} else {
		socket_sendsig(so, SOCKETSIG_WRITE|SOCKETSIG_READ);
		so->so_pollev &= ~SO_POLLEV_IN;
		mutex_exit(&so->so_lock);
		pollwakeup(&so->so_poll_list, POLLOUT|POLLIN|POLLRDNORM);
	}

	ASSERT(MUTEX_NOT_HELD(&so->so_lock));
}

/*
 * Out-of-band data is incoming, notify any interested parties.
 */
void
so_notify_oobsig(struct sonode *so)
{
	socket_sendsig(so, SOCKETSIG_URG);
	mutex_exit(&so->so_lock);
	pollwakeup(&so->so_poll_list, POLLRDBAND);
}

/*
 * Received out-of-band data. If the OOB data is delivered inline, then
 * in addition of regular OOB notification, anyone waiting for normal
 * data is also notified.
 */
void
so_notify_oobdata(struct sonode *so, boolean_t oob_inline)
{
	ASSERT(MUTEX_HELD(&so->so_lock));
	if (so->so_direct != NULL)
		SOD_UIOAFINI(so->so_direct);

	SO_WAKEUP_READER(so);

	if (IS_KERNEL_SOCKET(so)) {
		KSOCKET_CALLBACK(so, oobdata, 0);
		mutex_exit(&so->so_lock);
	} else {
		if (oob_inline) {
			socket_sendsig(so, SOCKETSIG_READ);
			so->so_pollev &= ~SO_POLLEV_IN;
			mutex_exit(&so->so_lock);
			pollwakeup(&so->so_poll_list,
			    POLLRDBAND|POLLIN|POLLRDNORM);
		} else {
			mutex_exit(&so->so_lock);
			pollwakeup(&so->so_poll_list, POLLRDBAND);
		}
	}

	ASSERT(MUTEX_NOT_HELD(&so->so_lock));
}

/*
 * End-of-file has been reach, so peer will send no new data. Wake up
 * anyone that is waiting for data.
 */
void
so_notify_eof(struct sonode *so)
{
	int pollev = 0;
	int sigev = 0;

	ASSERT(MUTEX_HELD(&so->so_lock));

	(void) i_so_notify_last_rx(so, &pollev, &sigev);

	if (IS_KERNEL_SOCKET(so)) {
		KSOCKET_CALLBACK(so, cantrecvmore, 0);
		mutex_exit(&so->so_lock);
	} else {
		if (sigev != 0)
			socket_sendsig(so, sigev);
		mutex_exit(&so->so_lock);
		if (pollev != 0)
			pollwakeup(&so->so_poll_list, pollev);

	}
	sof_sonode_notify_filters(so, SOF_EV_CANTRECVMORE, 0);

	ASSERT(MUTEX_NOT_HELD(&so->so_lock));
}

/*
 * Wake up anyone waiting for a new connection.
 */
void
so_notify_newconn(struct sonode *so)
{
	ASSERT(MUTEX_HELD(&so->so_lock));

	if (IS_KERNEL_SOCKET(so)) {
		KSOCKET_CALLBACK(so, newconn, 0);
		mutex_exit(&so->so_lock);
	} else {
		socket_sendsig(so, SOCKETSIG_READ);
		if (so->so_pollev & (SO_POLLEV_IN|SO_POLLEV_ALWAYS)) {
			so->so_pollev &= ~SO_POLLEV_IN;
			mutex_exit(&so->so_lock);
			pollwakeup(&so->so_poll_list, POLLIN|POLLRDNORM);
		} else {
			mutex_exit(&so->so_lock);
		}
	}

	ASSERT(MUTEX_NOT_HELD(&so->so_lock));
}

/*
 * User initated shutdown/close, wake anyone that is trying to do
 * an operation that is no longer possible.
 */
void
so_notify_shutdown(struct sonode *so)
{
	int pollev = 0;
	int sigev = 0;

	ASSERT(MUTEX_HELD(&so->so_lock));
	ASSERT(so->so_state & (SS_CANTSENDMORE|SS_CANTRCVMORE));

	if (so->so_state & SS_CANTSENDMORE)
		(void) i_so_notify_last_tx(so, &pollev, &sigev);
	if (so->so_state & SS_CANTRCVMORE)
		(void) i_so_notify_last_rx(so, &pollev, &sigev);

	if (sigev != 0)
		socket_sendsig(so, sigev);
	mutex_exit(&so->so_lock);
	if (pollev != 0)
		pollwakeup(&so->so_poll_list, pollev);

	ASSERT(MUTEX_NOT_HELD(&so->so_lock));
}

/*
 * No more data will be coming in, and this will be the last notification
 * made.
 */
static int
i_so_notify_last_rx(struct sonode *so, int *pollev, int *sigev)
{
	if (!(so->so_state & SS_SENTLASTREADSIG)) {
		SOCKET_TIMER_CANCEL(so);
		SO_WAKEUP_READER(so);
		so->so_state |= SS_SENTLASTREADSIG;
		so->so_pollev &= ~SO_POLLEV_IN;

		*pollev |= POLLIN|POLLRDNORM|POLLRDHUP;
		*sigev |= SOCKETSIG_READ;

		return (1);
	} else {
		return (0);
	}
}

/*
 * The socket is un-writeable. Make one last notification.
 */
static int
i_so_notify_last_tx(struct sonode *so, int *pollev, int *sigev)
{
	if (!(so->so_state & SS_SENTLASTWRITESIG)) {
		SO_WAKEUP_WRITER(so);
		so->so_state |= SS_SENTLASTWRITESIG;

		*pollev |= POLLOUT;
		*sigev |= SOCKETSIG_WRITE;

		return (1);
	} else {
		return (0);
	}
}
