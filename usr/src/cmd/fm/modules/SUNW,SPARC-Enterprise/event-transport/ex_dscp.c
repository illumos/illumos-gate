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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * FMA Event Transport Module Transport Layer API implementation.
 *
 * Library for establishing connections and transporting FMA events between
 * ETMs (event-transport modules) in separate fault domains.
 *
 * The transport for this library is internet socket based and uses the DSCP
 * client services library (libdscp).
 */

#include "ex_dscp.h"

/*
 * On the SP, there is one DSCP interface for every domain.
 * Each domain has one and only one DSCP interface to the SP.
 *
 * The DSCP interface is created when the domain powers-on.  On the SP,
 * a sysevent will be generated when the DSCP interface is up.  On the domain,
 * the DSCP interface should be up when ETM loads.
 */

exs_hdl_t *Exh_head = NULL;		/* Head of ex_hdl_t list */
pthread_mutex_t	List_lock = PTHREAD_MUTEX_INITIALIZER;
					/* Protects linked list of ex_hdl_t */

/*
 * * * * * * * * * * * * * *
 * Module specific routines
 * * * * * * * * * * * * * *
 */

/*
 * Allocate and initialize a transport instance handle.
 * Return hdl pointer for success, NULL for failure.
 */
static exs_hdl_t *
exs_hdl_alloc(fmd_hdl_t *hdl, char *endpoint_id,
    int (*cb_func)(fmd_hdl_t *hdl, etm_xport_conn_t conn, etm_cb_flag_t flag,
    void *arg), void *cb_func_arg, int dom)
{
	exs_hdl_t *hp;

	hp = fmd_hdl_zalloc(hdl, sizeof (exs_hdl_t), FMD_SLEEP);

	hp->h_endpt_id = fmd_hdl_strdup(hdl, endpoint_id, FMD_SLEEP);
	hp->h_dom = dom;
	hp->h_accept.c_sd = EXS_SD_FREE;
	hp->h_client.c_sd = EXS_SD_FREE;
	hp->h_server.c_sd = EXS_SD_FREE;
	hp->h_tid = EXS_TID_FREE;
	hp->h_destroy = 0;
	hp->h_hdl = hdl;
	hp->h_cb_func = cb_func;
	hp->h_cb_func_arg = cb_func_arg;
	hp->h_quit = 0;

	return (hp);
}

/*
 * Translate endpoint_id string to int.
 * Return the domain ID via "dom_id".
 * Return 0 for success, nonzero for failure
 */
static int
exs_get_id(fmd_hdl_t *hdl, char *endpoint_id, int *dom_id)
{
	char *ptr;

	if (strstr(endpoint_id, EXS_SP_PREFIX) != NULL) {
		/* Remote endpoint is the SP */
		*dom_id = DSCP_IDENT_SP;
		return (0);
	} else {
		if ((ptr = strstr(endpoint_id, EXS_DOMAIN_PREFIX)) == NULL) {
			fmd_hdl_error(hdl, "xport - %s not found in %s\n",
			    EXS_DOMAIN_PREFIX, endpoint_id);
			return (1);
		}

		ptr += EXS_DOMAIN_PREFIX_LEN;

		if ((sscanf(ptr, "%d", dom_id)) != 1) {
			fmd_hdl_error(hdl, "xport - no integer found in %s\n",
			    endpoint_id);
			return (1);
		}
	}

	return (0);
}

/*
 * Prepare the client connection.
 * Return 0 for success, nonzero for failure.
 */
static int
exs_prep_client(exs_hdl_t *hp)
{
	int rv;

	/* Find the DSCP address for the remote endpoint */
	if ((rv = dscpAddr(hp->h_dom, DSCP_ADDR_REMOTE,
	    (struct sockaddr *)&hp->h_client.c_saddr,
	    &hp->h_client.c_len)) != DSCP_OK) {
		fmd_hdl_error(hp->h_hdl, "xport - dscpAddr on client socket "
		    "failed for %s : rv = %d\n", hp->h_endpt_id, rv);
		return (1);
	}

	if ((hp->h_client.c_sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fmd_hdl_error(hp->h_hdl, "xport - client socket create failed "
		    "for %s",  hp->h_endpt_id);
		return (2);
	}

	/* Bind the socket to the local IP address of the DSCP link */
	if ((rv = dscpBind(hp->h_dom, hp->h_client.c_sd,
	    EXS_CLIENT_PORT)) != DSCP_OK) {
		fmd_hdl_error(hp->h_hdl, "xport - dscpBind on client socket "
		    "failed for %s : rv = %d\n", hp->h_endpt_id, rv);
		(void) close(hp->h_client.c_sd);
		hp->h_client.c_sd = EXS_SD_FREE;
		return (3);
	}

	hp->h_client.c_saddr.sin_port = htons(EXS_SERVER_PORT);

	/* Set IPsec security policy for this socket */
	if ((rv = dscpSecure(hp->h_dom, hp->h_client.c_sd)) != DSCP_OK) {
		fmd_hdl_error(hp->h_hdl, "xport - dscpSecure on client socket "
		    "failed for %s : rv = %d\n", hp->h_endpt_id, rv);
		(void) close(hp->h_client.c_sd);
		hp->h_client.c_sd = EXS_SD_FREE;
		return (4);
	}

	return (0);
}

/*
 * Prepare to accept a connection.
 * Return 0 for success, nonzero for failure.
 */
int
exs_prep_accept(exs_hdl_t *hp)
{

	int flags, optval = 1;
	int rv;

	if ((hp->h_accept.c_sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fmd_hdl_error(hp->h_hdl, "xport - accept socket create failed "
		    "for %s", hp->h_endpt_id);
		return (1);
	}

	if (setsockopt(hp->h_accept.c_sd, SOL_SOCKET, SO_REUSEADDR,
	    &optval, sizeof (optval))) {
		fmd_hdl_error(hp->h_hdl, "xport - set REUSEADDR failed for %s",
		    hp->h_endpt_id);
		(void) close(hp->h_accept.c_sd);
		hp->h_accept.c_sd = EXS_SD_FREE;
		return (2);
	}

	/* Bind the socket to the local IP address of the DSCP link */
	if ((rv = dscpBind(hp->h_dom, hp->h_accept.c_sd,
	    EXS_SERVER_PORT)) != DSCP_OK) {
		fmd_hdl_error(hp->h_hdl, "xport - dscpBind on accept socket "
		    "failed for %s : rv = %d\n", hp->h_endpt_id, rv);
		(void) close(hp->h_accept.c_sd);
		hp->h_accept.c_sd = EXS_SD_FREE;
		return (3);
	}

	/* Activate IPsec security policy for this socket */
	if ((rv = dscpSecure(hp->h_dom, hp->h_accept.c_sd)) != DSCP_OK) {
		fmd_hdl_error(hp->h_hdl, "xport - dscpSecure on accept socket "
		    "failed for %s : rv = %d\n", hp->h_endpt_id, rv);
		(void) close(hp->h_accept.c_sd);
		hp->h_accept.c_sd = EXS_SD_FREE;
		return (4);
	}

	if ((listen(hp->h_accept.c_sd, EXS_NUM_SOCKS)) == -1) {
		fmd_hdl_debug(hp->h_hdl, "xport - listen on accept socket "
		    "failed for %s", hp->h_endpt_id);
		(void) close(hp->h_accept.c_sd);
		hp->h_accept.c_sd = EXS_SD_FREE;
		return (5);
	}

	flags = fcntl(hp->h_accept.c_sd, F_GETFL, 0);
	(void) fcntl(hp->h_accept.c_sd, F_SETFL, flags | O_NONBLOCK);

	return (0);
}

/*
 * Notify ETM that incoming data is available on server connection.
 */
static void
exs_recv(exs_hdl_t *hp)
{
	if (hp->h_cb_func(hp->h_hdl, &hp->h_server, ETM_CBFLAG_RECV,
	    hp->h_cb_func_arg)) {
		/* Any non-zero return means to close the connection */
		(void) close(hp->h_server.c_sd);
		hp->h_server.c_sd = EXS_SD_FREE;
	}
}

/*
 * Accept a new incoming connection.
 */
static void
exs_accept(exs_hdl_t *hp)
{
	int new_sd, dom, flags, rv;
	struct sockaddr_in new_saddr;
	socklen_t new_len = sizeof (struct sockaddr);

	if ((new_sd = accept(hp->h_accept.c_sd, (struct sockaddr *)&new_saddr,
	    &new_len)) != -1) {
		/* Translate saddr to domain id */
		if ((rv = dscpIdent((struct sockaddr *)&new_saddr, (int)new_len,
		    &dom)) != DSCP_OK) {
			fmd_hdl_error(hp->h_hdl, "xport - dscpIdent failed "
			    "for %s : rv = %d\n", hp->h_endpt_id, rv);
			return;
		}

		if (hp->h_dom != dom) {
			fmd_hdl_debug(hp->h_hdl, "xport - domain id (%d) does "
			    "not match dscpIdent (%d)", hp->h_dom, dom);
			return;
		}

		/* Authenticate this connection request */
		if ((rv = dscpAuth(dom, (struct sockaddr *)&new_saddr,
		    (int)new_len)) != DSCP_OK) {
			fmd_hdl_error(hp->h_hdl, "xport - dscpAuth failed "
			    "for %s : rv = %d\n", hp->h_endpt_id, rv);
			return;
		}

		if (hp->h_server.c_sd != EXS_SD_FREE) {
			(void) close(hp->h_server.c_sd);
			hp->h_server.c_sd = EXS_SD_FREE;
		}

		/* Set the socket to be non-blocking */
		flags = fcntl(new_sd, F_GETFL, 0);
		(void) fcntl(new_sd, F_SETFL, flags | O_NONBLOCK);

		hp->h_server.c_sd = new_sd;

	} else {
		fmd_hdl_debug(hp->h_hdl, "xport - accept failed");
	}
}

/*
 * Server function/thread.  There is one thread per endpoint.
 * Accepts incoming connections and notifies ETM of incoming data.
 */
void
exs_server(void *arg)
{
	exs_hdl_t *hp = (exs_hdl_t *)arg;
	struct pollfd pfd[2];
	nfds_t nfds;

	while (!hp->h_quit) {
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		pfd[0].fd = hp->h_accept.c_sd;
		pfd[1].events = POLLIN;
		pfd[1].revents = 0;
		pfd[1].fd = hp->h_server.c_sd;

		nfds = (hp->h_server.c_sd != EXS_SD_FREE ? 2 : 1);

		if (poll(pfd, nfds, -1) <= 0)
			continue; /* loop around and check h_quit */

		if (pfd[0].revents & (POLLHUP | POLLERR)) {
			fmd_hdl_debug(hp->h_hdl, "xport - poll hangup/err for "
			    "%s accept socket", hp->h_endpt_id);
			hp->h_destroy++;
			break;
		}

		if (pfd[1].revents & (POLLHUP | POLLERR)) {
			fmd_hdl_debug(hp->h_hdl, "xport - poll hangup/err for "
			    "%s server socket", hp->h_endpt_id);

			if (hp->h_server.c_sd != EXS_SD_FREE) {
				(void) close(hp->h_server.c_sd);
				hp->h_server.c_sd = EXS_SD_FREE;
			}

			continue;
		}

		if (pfd[0].revents & POLLIN)
			exs_accept(hp);

		if (pfd[1].revents & POLLIN)
			exs_recv(hp);
	}

	fmd_hdl_debug(hp->h_hdl, "xport - exiting server thread for %s",
	    hp->h_endpt_id);

	if (hp->h_accept.c_sd != EXS_SD_FREE)
		(void) close(hp->h_accept.c_sd);

	if (hp->h_server.c_sd != EXS_SD_FREE)
		(void) close(hp->h_server.c_sd);
}

/*
 * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * ETM-to-Transport API Connection Management routines
 * * * * * * * * * * * * * * * * * * * * * * * * * * *
 */

/*
 * Initialize and setup any transport infrastructure before any connections
 * are opened.
 * Return etm_xport_hdl_t for success, NULL for failure.
 */
etm_xport_hdl_t
etm_xport_init(fmd_hdl_t *hdl, char *endpoint_id,
    int (*cb_func)(fmd_hdl_t *hdl, etm_xport_conn_t conn, etm_cb_flag_t flag,
    void *arg), void *cb_func_arg)
{
	exs_hdl_t *hp, *curr;
	int dom;

	if ((exs_get_id(hdl, endpoint_id, &dom)) == -1)
		return (NULL);

	(void) pthread_mutex_lock(&List_lock);

	/* Check for a duplicate endpoint_id on the list */
	for (curr = Exh_head; curr; curr = curr->h_next) {
		if (dom == curr->h_dom) {
			fmd_hdl_debug(hdl, "xport - init failed, "
			    "duplicate domain id : %d\n", dom);
			(void) pthread_mutex_unlock(&List_lock);
			return (NULL);
		}
	}

	hp = exs_hdl_alloc(hdl, endpoint_id, cb_func, cb_func_arg, dom);

	/* Add this transport instance handle to the list */
	hp->h_next = Exh_head;
	Exh_head = hp;

	if (exs_prep_accept(hp) == 0)
		/* A server thread is created for every endpoint */
		hp->h_tid = fmd_thr_create(hdl, exs_server, hp);

	(void) pthread_mutex_unlock(&List_lock);

	return ((etm_xport_hdl_t)hp);
}

/*
 * Teardown any transport infrastructure after all connections are closed.
 * Return 0 for success, or nonzero for failure.
 */
int
etm_xport_fini(fmd_hdl_t *hdl, etm_xport_hdl_t tlhdl)
{
	exs_hdl_t *hp = (exs_hdl_t *)tlhdl;
	exs_hdl_t *xp, **ppx = &Exh_head;

	(void) pthread_mutex_lock(&List_lock);

	for (xp = *ppx; xp; xp = xp->h_next) {
		if (xp != hp)
			ppx = &xp->h_next;
		else
			break;
	}

	if (xp != hp) {
		(void) pthread_mutex_unlock(&List_lock);
		fmd_hdl_abort(hdl, "xport - fini failed, tlhdl %p not on list",
		    (void *)hp);
	}

	*ppx = hp->h_next;
	hp->h_next = NULL;

	if (hp->h_tid != EXS_TID_FREE) {
		hp->h_quit = 1;
		fmd_thr_signal(hdl, hp->h_tid);
		fmd_thr_destroy(hdl, hp->h_tid);
	}

	/* Socket descr for h_accept and h_server are closed in exs_server */
	if (hp->h_client.c_sd != EXS_SD_FREE)
		(void) close(hp->h_client.c_sd);

	fmd_hdl_strfree(hdl, hp->h_endpt_id);
	fmd_hdl_free(hdl, hp, sizeof (exs_hdl_t));

	(void) pthread_mutex_unlock(&List_lock);

	return (0);
}

/*
 * Open a connection with the given endpoint,
 * Return etm_xport_conn_t for success, NULL and set errno for failure.
 */
etm_xport_conn_t
etm_xport_open(fmd_hdl_t *hdl, etm_xport_hdl_t tlhdl)
{
	int flags;
	exs_hdl_t *hp = (exs_hdl_t *)tlhdl;

	if (hp->h_destroy) {
		fmd_thr_destroy(hp->h_hdl, hp->h_tid);
		hp->h_tid = EXS_TID_FREE;
		hp->h_destroy = 0;
	}

	if (hp->h_tid == EXS_TID_FREE) {
		if (exs_prep_accept(hp) == 0)
			hp->h_tid = fmd_thr_create(hdl, exs_server, hp);
	}

	if (hp->h_client.c_sd == EXS_SD_FREE) {
		if (exs_prep_client(hp) != 0)
			return (NULL);
	}

	/* Set the socket to be non-blocking */
	flags = fcntl(hp->h_client.c_sd, F_GETFL, 0);
	(void) fcntl(hp->h_client.c_sd, F_SETFL, flags | O_NONBLOCK);

	if ((connect(hp->h_client.c_sd,
	    (struct sockaddr *)&hp->h_client.c_saddr,
	    hp->h_client.c_len)) == -1) {
		if (errno != EINPROGRESS) {
			fmd_hdl_error(hdl, "xport - failed server connect : %s",
			    hp->h_endpt_id);
			(void) close(hp->h_client.c_sd);
			hp->h_client.c_sd = EXS_SD_FREE;
			return (NULL);
		}
	}

	fmd_hdl_debug(hdl, "xport - connected client socket for %s",
	    hp->h_endpt_id);

	return (&hp->h_client);
}

/*
 * Close a connection from either endpoint.
 * Return zero for success, nonzero for failure.
 */
/*ARGSUSED*/
int
etm_xport_close(fmd_hdl_t *hdl, etm_xport_conn_t conn)
{
	exs_conn_t *cp = (exs_conn_t *)conn;

	if (cp->c_sd == EXS_SD_FREE)
		return (0);	/* Connection already closed */

	(void) close(cp->c_sd);
	cp->c_sd = EXS_SD_FREE;

	return (0);
}

/*
 * * * * * * * * * * * * * * * * * *
 * ETM-to-Transport API I/O routines
 * * * * * * * * * * * * * * * * * *
 */

/*
 * Try to read byte_cnt bytes from the connection into the given buffer.
 * Return how many bytes actually read for success, negative value for failure.
 */
ssize_t
etm_xport_read(fmd_hdl_t *hdl, etm_xport_conn_t conn, hrtime_t timeout,
    void *buf, size_t byte_cnt)
{
	ssize_t len, nbytes = 0;
	hrtime_t endtime, sleeptime;
	struct timespec tms;
	char *ptr = (char *)buf;
	exs_conn_t *cp = (exs_conn_t *)conn;

	if (cp->c_sd == EXS_SD_FREE) {
		fmd_hdl_debug(hdl, "xport - read socket %d is closed\n",
		    cp->c_sd);
		return (-EBADF);
	}

	endtime = gethrtime() + timeout;
	sleeptime = timeout / EXS_IO_SLEEP_DIV;

	tms.tv_sec = 0;
	tms.tv_nsec = sleeptime;

	while (nbytes < byte_cnt) {
		if (gethrtime() < endtime) {
			if ((len = recv(cp->c_sd, ptr, byte_cnt - nbytes,
			    0)) < 0) {
				if (errno != EINTR && errno != EWOULDBLOCK) {
					fmd_hdl_debug(hdl, "xport - recv "
					    "failed for socket %d", cp->c_sd);
				}

				(void) nanosleep(&tms, 0);
				continue;
			} else if (len == 0) {
				fmd_hdl_debug(hdl, "xport - remote endpt "
				    "closed for socket %d", cp->c_sd);
				return (0);
			}

			ptr += len;
			nbytes += len;
		} else {
			fmd_hdl_debug(hdl, "xport - read timed out for socket "
			    "%d", cp->c_sd);
			break;
		}
	}

	if (nbytes)
		return (nbytes);
	else
		return (-1);
}

/*
 * Try to write byte_cnt bytes to the connection from the given buffer.
 * Return how many bytes actually written for success, negative value
 * for failure.
 */
ssize_t
etm_xport_write(fmd_hdl_t *hdl, etm_xport_conn_t conn, hrtime_t timeout,
    void *buf, size_t byte_cnt)
{
	ssize_t len, nbytes = 0;
	hrtime_t endtime, sleeptime;
	struct timespec tms;
	char *ptr = (char *)buf;
	exs_conn_t *cp = (exs_conn_t *)conn;

	if (cp->c_sd == EXS_SD_FREE) {
		fmd_hdl_debug(hdl, "xport - write socket %d is closed\n",
		    cp->c_sd);
		return (-EBADF);
	}

	endtime = gethrtime() + timeout;
	sleeptime = timeout / EXS_IO_SLEEP_DIV;

	tms.tv_sec = 0;
	tms.tv_nsec = sleeptime;

	while (nbytes < byte_cnt) {
		if (gethrtime() < endtime) {
			if ((len = send(cp->c_sd, ptr, byte_cnt - nbytes,
			    0)) < 0) {
				if (errno != EINTR && errno != EWOULDBLOCK) {
					fmd_hdl_debug(hdl, "xport - send "
					    "failed for socket %d", cp->c_sd);
				}

				(void) nanosleep(&tms, 0);
				continue;
			}

			ptr += len;
			nbytes += len;
		} else {
			fmd_hdl_debug(hdl, "xport - write timed out for socket "
			    "%d", cp->c_sd);
			break;
		}
	}

	if (nbytes)
		return (nbytes);
	else
		return (-1);
}
