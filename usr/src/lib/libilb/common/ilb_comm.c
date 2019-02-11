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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <stddef.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <thread.h>
#include <synch.h>
#include <libilb_impl.h>
#include <libilb.h>

/* Assertion: the calling thread has a hold on the handle */
static void
i_ilb_socket_set_err(ilb_handle_t h, ilb_status_t err)
{
	ilb_handle_impl_t	*hi = (ilb_handle_impl_t *)h;

	if (h == ILB_INVALID_HANDLE)
		return;
	hi->h_valid = B_FALSE;
	hi->h_error = err;
}

ilb_status_t
ilb_open(ilb_handle_t *hp)
{
	ilb_handle_impl_t	*hi = NULL;
	int			s = -1;
	struct sockaddr_un sa = {AF_UNIX, SOCKET_PATH};
	ilb_status_t		rc = ILB_STATUS_OK;
	int			sobufsz;

	if (hp == NULL)
		return (ILB_STATUS_EINVAL);

	hi = calloc(1, sizeof (*hi));
	if (hi == NULL)
		return (ILB_STATUS_ENOMEM);

	if (cond_init(&hi->h_cv, USYNC_THREAD, NULL) != 0) {
		rc = ILB_STATUS_INTERNAL;
		goto out;
	}

	if (mutex_init(&hi->h_lock, USYNC_THREAD | LOCK_ERRORCHECK, NULL)
	    != 0) {
		rc = ILB_STATUS_INTERNAL;
		goto out;
	}

	hi->h_busy = B_FALSE;

	if ((s = socket(PF_UNIX, SOCK_SEQPACKET, 0)) == -1 ||
	    connect(s, (struct sockaddr *)&sa, sizeof (sa.sun_path))
	    == -1) {
		rc = ILB_STATUS_SOCKET;
		goto out;
	}

	/* The socket buffer must be at least the max size of a message */
	sobufsz = ILBD_MSG_SIZE;
	if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sobufsz,
	    sizeof (sobufsz)) != 0) {
		rc = ILB_STATUS_SOCKET;
		(void) close(s);
		goto out;
	}
	if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &sobufsz,
	    sizeof (sobufsz)) != 0) {
		rc = ILB_STATUS_SOCKET;
		(void) close(s);
		goto out;
	}

	hi->h_socket = s;
	hi->h_valid = B_TRUE;

out:
	if (rc != ILB_STATUS_OK && s != -1)
		(void) close(s);

	if (rc == ILB_STATUS_OK) {
		*hp = (ilb_handle_t)hi;
	} else {
		free(hi);
		*hp = ILB_INVALID_HANDLE;
	}
	return (rc);
}

ilb_status_t
ilb_close(ilb_handle_t h)
{
	ilb_handle_impl_t	*hi = (ilb_handle_impl_t *)h;

	if (h == ILB_INVALID_HANDLE)
		return (ILB_STATUS_EINVAL);

	if (mutex_lock(&hi->h_lock) != 0)
		return (ILB_STATUS_INTERNAL);

	/* Somebody has done a close, no need to do anything. */
	if (hi->h_closing) {
		return (ILB_STATUS_OK);
	} else {
		hi->h_closing = B_TRUE;
		hi->h_error = ILB_STATUS_HANDLE_CLOSING;
	}

	/* Wait until there is nobody waiting. */
	while (hi->h_waiter > 0) {
		if (cond_wait(&hi->h_cv, &hi->h_lock) != 0) {
			(void) mutex_unlock(&hi->h_lock);
			return (ILB_STATUS_INTERNAL);
		}
	}
	/* No one is waiting, proceed to free the handle. */

	(void) close(hi->h_socket);
	(void) mutex_destroy(&hi->h_lock);
	(void) cond_destroy(&hi->h_cv);
	free(hi);
	return (ILB_STATUS_OK);
}

/*
 * Unified routine to communicate with ilbd.
 *
 * If ic is non-NULL, it means that the caller wants to send something
 * to ilbd and expects a reply.  If ic is NULL, it means that the caller
 * only expects to receive from ilbd.
 *
 * The rbuf is the buffer supplied by the caller for receiving.  If it
 * is NULL, it means that there is no reply expected.
 *
 * This function will not close() the socket to kernel unless there is
 * an error.  If the transaction only consists of one exchange, the caller
 * can use i_ilb_close_comm() to close() the socket when done.
 */
ilb_status_t
i_ilb_do_comm(ilb_handle_t h, ilb_comm_t *ic, size_t ic_sz, ilb_comm_t *rbuf,
    size_t *rbufsz)
{
	ilb_status_t		rc = ILB_STATUS_OK;
	int			r, s;
	ilb_handle_impl_t	*hi = (ilb_handle_impl_t *)h;

	assert(rbuf != NULL);
	if (h == ILB_INVALID_HANDLE)
		return (ILB_STATUS_EINVAL);

	if (mutex_lock(&hi->h_lock) != 0)
		return (ILB_STATUS_INTERNAL);

	hi->h_waiter++;
	while (hi->h_busy) {
		if (cond_wait(&hi->h_cv, &hi->h_lock) != 0) {
			hi->h_waiter--;
			(void) cond_signal(&hi->h_cv);
			(void) mutex_unlock(&hi->h_lock);
			return (ILB_STATUS_INTERNAL);
		}
	}

	if (!hi->h_valid || hi->h_closing) {
		hi->h_waiter--;
		(void) cond_signal(&hi->h_cv);
		(void) mutex_unlock(&hi->h_lock);
		return (hi->h_error);
	}

	hi->h_busy = B_TRUE;
	(void) mutex_unlock(&hi->h_lock);

	s = hi->h_socket;

	r = send(s, ic, ic_sz, 0);
	if (r < ic_sz) {
		rc = ILB_STATUS_WRITE;
		goto socket_error;
	}
	rc = ILB_STATUS_OK;

	if ((r = recv(s, rbuf, *rbufsz, 0)) <= 0) {
		rc = ILB_STATUS_READ;
	} else {
		*rbufsz = r;
		goto out;
	}

socket_error:
	i_ilb_socket_set_err(h, rc);

out:
	(void) mutex_lock(&hi->h_lock);
	hi->h_busy = B_FALSE;
	hi->h_waiter--;
	(void) cond_signal(&hi->h_cv);
	(void) mutex_unlock(&hi->h_lock);

	return (rc);
}

void
i_ilb_close_comm(ilb_handle_t h)
{
	(void) ilb_close(h);
}
