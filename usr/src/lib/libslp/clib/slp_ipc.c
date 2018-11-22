/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <thread.h>
#include <synch.h>
#include <netinet/in.h>
#include <signal.h>
#include <slp-internal.h>

#define	IPC_FD_LIFETIME	30

/*
 * Cached parameters and thread synchronization
 */
static int slpdfd;			/* cached FD to slpd */
static mutex_t ipc_lock = DEFAULTMUTEX;	/* serializes IPC */

/* synch for the FD management thread */
static mutex_t ipc_wait_lock = DEFAULTMUTEX;
static cond_t ipc_wait_var;
static int ipc_used;
static int ipc_thr_running;

static struct sockaddr_in *local_sin;	/* slpd addr, set on first use */

static SLPError open_ipc();
static void close_ipc();
static void get_localhost_sin();
static void *ipc_manage_thr(void *);

/*
 * Locking should be handled by the caller
 */
static SLPError open_ipc() {
	int terr;
	int retries = 0;

	if (slpdfd)
		return (SLP_OK);

	/* Make sure the local host's sockaddr_in is set */
	if (!local_sin) {
		get_localhost_sin();
		if (!local_sin) {
			slpdfd = 0;
			return (SLP_INTERNAL_SYSTEM_ERROR);
		}
	}

	for (;;) {
	    int errno_kept;

	    if ((slpdfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		slp_err(LOG_CRIT, 0, "slp_open_ipc",
			"could not create socket: %s", strerror(errno));
		slpdfd = 0;
		return (SLP_INTERNAL_SYSTEM_ERROR);
	    }


	    if (connect(slpdfd, (struct sockaddr *)local_sin,
			sizeof (*local_sin)) == 0) {
		break;
	    }

	    /* else error condition */
	    errno_kept = errno; /* in case errno is reset by slp_err */
	    if (retries++ == 2) {
		slp_err(LOG_INFO, 0, "slp_open_ipc",
			"could not connect to slpd: %s", strerror(errno));
		if (errno_kept == ECONNREFUSED)
		    slp_err(LOG_INFO, 0, "slp_open_ipc",
			    "is slpd running?");
		(void) close(slpdfd);
		slpdfd = 0;
		return (SLP_NETWORK_ERROR);
	    } else {
		/* back off a little */
		(void) close(slpdfd);
		(void) sleep(1);
	    }
	}

	/* We now know slpd is reachable; start the management thread */
	if (!ipc_thr_running) {
		if ((terr = thr_create(0, 0, ipc_manage_thr,
		    NULL, 0, NULL)) != 0) {
			slp_err(LOG_CRIT, 0, "slp_open_ipc",
				"could not start thread: %s",
				strerror(terr));
			return (SLP_INTERNAL_SYSTEM_ERROR);
		}
	}
	ipc_thr_running = 1;

	return (SLP_OK);
}

static void close_ipc() {
	(void) mutex_lock(&ipc_lock);
	if (!slpdfd) {
		(void) mutex_unlock(&ipc_lock);
		return;
	}
	(void) close(slpdfd);
	slpdfd = 0;
	(void) mutex_unlock(&ipc_lock);
}

/*
 * Sends 'msg' to slpd, placing the response in 'reply'. Caller should
 * free memory associated with 'reply'. All IPC is handled transparantly
 * by this call. Note that this call is a wrapper for slp_send2slpd_iov.
 * Returns SLP_NETWORK_ERROR if slpd is unreachable, SLP_OK otherwise.
 */
SLPError slp_send2slpd(const char *msg, char **reply) {
	struct iovec iov[1];
	iov->iov_base = (caddr_t)msg;
	iov->iov_len = slp_get_length(msg);

	return (slp_send2slpd_iov(iov, 1, reply));
}

SLPError slp_send2slpd_iov(struct iovec *msg, int iovlen, char **reply) {
	SLPError err;
	int retries = 0;
	struct msghdr msghdr[1];
	struct sigaction new, old;

	*reply = NULL;

	(void) mutex_lock(&ipc_lock);
	/* is the connection open? */
	if (!slpdfd) {
		if ((err = open_ipc()) != SLP_OK) {
			(void) mutex_unlock(&ipc_lock);
			return (err);
		}
	}

	/* populate the msghdr for sendmsg */
	msghdr->msg_name = NULL;
	msghdr->msg_namelen = 0;
	msghdr->msg_iov = msg;
	msghdr->msg_iovlen = iovlen;
	msghdr->msg_accrights = NULL;
	msghdr->msg_accrightslen = 0;

	/*
	 * If slpd has been restarted while this connection is
	 * still open, we will get a SIGPIPE when we try to write
	 * to it. So we need to ignore SIGPIPEs for the duration of
	 * the communication with slpd.
	 */
	new.sa_handler = SIG_IGN;
	new.sa_flags = 0;
	(void) sigemptyset(&new.sa_mask);
	(void) sigaction(SIGPIPE, &new, &old);	/* preserve old disposition */

	while (sendmsg(slpdfd, msghdr, 0) == -1) {
		int errno_kept = errno;

		switch (errno) {
		case EINTR:
		case ENOBUFS:
		case ENOSR:
			continue;
		case EBADF:
		case ECONNRESET:
		case ENOTCONN:
		default:
			(void) mutex_unlock(&ipc_lock);
			close_ipc();
			if (retries++) {
				slp_err(LOG_CRIT, 0, "slp_send2slpd",
					"could not talk to slpd: %s",
					strerror(errno_kept));
				err = SLP_NETWORK_ERROR;
				goto done;
			}
			/* try re-opening the connection to slpd */
			if (open_ipc() == SLP_OK) {
				(void) mutex_lock(&ipc_lock);
				continue;
			} else {
				err = SLP_NETWORK_ERROR;
				goto done;
			}
		}
	}

	err = slp_tcp_read(slpdfd, reply);

	/*
	 * On error slpd may close the socket; there can be a race
	 * condition here where a following call (attempting to reuse
	 * the socket) may send to slpd before it has closed the socket.
	 * To prevent this, we must also close the socket on error.
	 */
	if (err == SLP_OK && slp_get_errcode(*reply) != 0) {
		(void) mutex_unlock(&ipc_lock);
		close_ipc();
		(void) mutex_lock(&ipc_lock);
	}

	/* notify ipc thread of call */
	(void) mutex_lock(&ipc_wait_lock);
	ipc_used = 1;
	(void) cond_signal(&ipc_wait_var);
	(void) mutex_unlock(&ipc_wait_lock);

	(void) mutex_unlock(&ipc_lock);

done:
	/* restore original signal disposition for SIGPIPE */
	(void) sigaction(SIGPIPE, &old, NULL);
	return (err);
}

/*
 * Sets up a sockaddr_in pointing at slpd.
 * After the first call, the address of slpd is cached in local_sin.
 *
 * side effect: local_sin is set to an address for slpd.
 */
static void get_localhost_sin() {
	struct sockaddr_in *sin;
	static mutex_t lhlock = DEFAULTMUTEX;

	(void) mutex_lock(&lhlock);
	if (local_sin) {
		(void) mutex_unlock(&lhlock);
		return;
	}

	if (!(sin = calloc(1, sizeof (*sin)))) {
		slp_err(LOG_CRIT, 0, "get_localhost_sin", "out of memory");
		goto done;
	}

	IN_SET_LOOPBACK_ADDR(sin);
	sin->sin_family = AF_INET;
	sin->sin_port = htons(SLP_PORT);

done:
	local_sin = sin;
	(void) mutex_unlock(&lhlock);
}

/*
 * IPC management: the FD to slpd is kept open and cached to improve
 * performance on successive calls. The IPC management thread waits
 * on a condition variable; the condition is if an IPC call has been
 * made. If so, the thread advances the FD's expiration by IPC_FD_LIFETIME
 * and continues waiting for the next IPC call. After the FD has expired,
 * the thread closes IPC and shuts itself down.
 */
static void *
ipc_manage_thr(void *arg __unused)
{
	timestruc_t timeout;

	timeout.tv_nsec = 0;
	(void) mutex_lock(&ipc_wait_lock);
	ipc_used = 0;

	while (ipc_used == 0) {
		int err;

		timeout.tv_sec = IPC_FD_LIFETIME;
		err = cond_reltimedwait(&ipc_wait_var, &ipc_wait_lock,
		    &timeout);

		if (err == ETIME) {
			/* shutdown */
			close_ipc();
			ipc_thr_running = 0;
			(void) mutex_unlock(&ipc_wait_lock);
			thr_exit(NULL);
		} else {
			/* reset condition variable */
			ipc_used = 0;
		}
	}
	return (NULL);
}
