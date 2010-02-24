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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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

exs_conn_t Acc;				/* Connection for accepting/listening */
pthread_t Acc_tid;			/* Thread ID for accepting conns */
int Acc_quit;				/* Signal to quit the acceptor thread */
int Acc_destroy;			/* Destroy accept/listen thread? */
exs_hdl_t *Exh_head = NULL;		/* Head of ex_hdl_t list */
pthread_mutex_t	List_lock = PTHREAD_MUTEX_INITIALIZER;
					/* Protects linked list of ex_hdl_t */
static void *Dlp = NULL;		/* Handle for dlopen/dlclose/dlsym */
static int (*Send_filter)(fmd_hdl_t *hdl, nvlist_t *event, const char *dest);
static int (*Post_filter)(fmd_hdl_t *hdl, nvlist_t *event, const char *src);

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
 * dlopen() the platform filter library and dlsym() the filter funcs.
 */
static void
exs_filter_init(fmd_hdl_t *hdl)
{
	char *propstr = fmd_prop_get_string(hdl, "filter_path");

	if (propstr == NULL) {
		fmd_hdl_debug(hdl, "No filter plugin specified");
		Send_filter = NULL;
		Post_filter = NULL;
		return;
	} else {
		if ((Dlp = dlopen(propstr, RTLD_LOCAL | RTLD_NOW)) == NULL) {
			fmd_hdl_debug(hdl, "Failed to dlopen filter plugin");
			Send_filter = NULL;
			Post_filter = NULL;
			fmd_prop_free_string(hdl, propstr);
			return;
		}

		if ((Send_filter = (int (*)())dlsym(Dlp, "send_filter"))
		    == NULL) {
			fmd_hdl_debug(hdl, "failed to dlsym send_filter()");
			Send_filter = NULL;
		}

		if ((Post_filter = (int (*)())dlsym(Dlp, "post_filter"))
		    == NULL) {
			fmd_hdl_debug(hdl, "failed to dlsym post_filter()");
			Post_filter = NULL;
		}
	}

	fmd_prop_free_string(hdl, propstr);
}

/*
 * If open, dlclose() the platform filter library.
 */
/*ARGSUSED*/
static void
exs_filter_fini(fmd_hdl_t *hdl)
{
	if (Dlp != NULL)
		(void) dlclose(Dlp);
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
			fmd_hdl_error(hdl, "Property parsing error : %s not "
			    "found in %s. Check event-transport.conf\n",
			    EXS_DOMAIN_PREFIX, endpoint_id);
			return (1);
		}

		ptr += EXS_DOMAIN_PREFIX_LEN;

		if ((sscanf(ptr, "%d", dom_id)) != 1) {
			fmd_hdl_error(hdl, "Property parsing error : no "
			    "integer found in %s. Check event-transport.conf\n",
			    endpoint_id);
			return (2);
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
	int rv, optval = 1;
	struct linger ling;

	/* Find the DSCP address for the remote endpoint */
	if ((rv = dscpAddr(hp->h_dom, DSCP_ADDR_REMOTE,
	    (struct sockaddr *)&hp->h_client.c_saddr,
	    &hp->h_client.c_len)) != DSCP_OK) {
		fmd_hdl_debug(hp->h_hdl, "dscpAddr on the client socket "
		    "failed for %s : rv = %d\n", hp->h_endpt_id, rv);
		return (1);
	}

	if ((hp->h_client.c_sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fmd_hdl_error(hp->h_hdl, "Failed to create the client socket "
		    "for %s",  hp->h_endpt_id);
		return (2);
	}

	if (setsockopt(hp->h_client.c_sd, SOL_SOCKET, SO_REUSEADDR,
	    &optval, sizeof (optval))) {
		fmd_hdl_error(hp->h_hdl, "Failed to set REUSEADDR on the "
		    "client socket for %s", hp->h_endpt_id);
		EXS_CLOSE_CLR(hp->h_client);
		return (3);
	}

	/*
	 * Set SO_LINGER so TCP aborts the connection when closed.
	 * If the domain's client socket goes into the TIME_WAIT state,
	 * ETM will be unable to connect to the SP until this clears.
	 * This connection is over DSCP, which is a simple point-to-point
	 * connection and therefore has no routers or multiple forwarding.
	 * The risk of receiving old packets from a previously terminated
	 * connection is very small.
	 */
	ling.l_onoff = 1;
	ling.l_linger = 0;
	if (setsockopt(hp->h_client.c_sd, SOL_SOCKET, SO_LINGER, &ling,
	    sizeof (ling))) {
		fmd_hdl_error(hp->h_hdl, "Failed to set SO_LINGER on the "
		    "client socket for %s", hp->h_endpt_id);
		EXS_CLOSE_CLR(hp->h_client);
		return (4);
	}

	/* Bind the socket to the local IP address of the DSCP link */
	if ((rv = dscpBind(hp->h_dom, hp->h_client.c_sd,
	    EXS_CLIENT_PORT)) != DSCP_OK) {
		if (rv == DSCP_ERROR_DOWN) {
			fmd_hdl_debug(hp->h_hdl, "xport - dscp link for %s "
			    "is down", hp->h_endpt_id);
		} else {
			fmd_hdl_debug(hp->h_hdl, "dscpBind on the client "
			    "socket failed : rv = %d\n", rv);
		}
		EXS_CLOSE_CLR(hp->h_client);
		return (5);
	}

	hp->h_client.c_saddr.sin_port = htons(EXS_SERVER_PORT);

	/* Set IPsec security policy for this socket */
	if ((rv = dscpSecure(hp->h_dom, hp->h_client.c_sd)) != DSCP_OK) {
		fmd_hdl_error(hp->h_hdl, "dscpSecure on the client socket "
		    "failed for %s : rv = %d\n", hp->h_endpt_id, rv);
		EXS_CLOSE_CLR(hp->h_client);
		return (6);
	}

	return (0);
}

/*
 * Server function/thread.  There is one thread per endpoint.
 * Accepts incoming connections and notifies ETM of incoming data.
 */
void
exs_server(void *arg)
{
	exs_hdl_t *hp = (exs_hdl_t *)arg;
	struct pollfd pfd;

	while (!hp->h_quit) {
		pfd.events = POLLIN;
		pfd.revents = 0;
		pfd.fd = hp->h_server.c_sd;

		if (poll(&pfd, 1, -1) <= 0)
			continue; /* loop around and check h_quit */

		if (pfd.revents & (POLLHUP | POLLERR)) {
			fmd_hdl_debug(hp->h_hdl, "xport - poll hangup/err for "
			    "%s server socket", hp->h_endpt_id);
			EXS_CLOSE_CLR(hp->h_server);
			hp->h_destroy++;
			break;	/* thread exits */
		}

		if (pfd.revents & POLLIN) {
			/* Notify ETM that incoming data is available */
			if (hp->h_cb_func(hp->h_hdl, &hp->h_server,
			    ETM_CBFLAG_RECV, hp->h_cb_func_arg)) {
				/*
				 * For any non-zero return, close the
				 * connection and exit the thread.
				 */
				EXS_CLOSE_CLR(hp->h_server);
				hp->h_destroy++;
				break;	/* thread exits */
			}
		}
	}

	fmd_hdl_debug(hp->h_hdl, "xport - exiting server thread for %s",
	    hp->h_endpt_id);
}

/*
 * Accept a new incoming connection.
 */
static void
exs_accept(fmd_hdl_t *hdl)
{
	int new_sd, dom, flags, rv;
	struct sockaddr_in new_saddr;
	socklen_t new_len = sizeof (struct sockaddr);
	exs_hdl_t *hp;

	if ((new_sd = accept(Acc.c_sd, (struct sockaddr *)&new_saddr,
	    &new_len)) != -1) {
		/* Translate saddr to domain id */
		if ((rv = dscpIdent((struct sockaddr *)&new_saddr, (int)new_len,
		    &dom)) != DSCP_OK) {
			fmd_hdl_error(hdl, "dscpIdent failed : rv = %d\n", rv);
			(void) close(new_sd);
			return;
		}

		/* Find the exs_hdl_t for the domain trying to connect */
		(void) pthread_mutex_lock(&List_lock);
		for (hp = Exh_head; hp; hp = hp->h_next) {
			if (hp->h_dom == dom)
				break;
		}
		(void) pthread_mutex_unlock(&List_lock);

		if (hp == NULL) {
			fmd_hdl_error(hdl, "Not configured to accept a "
			    "connection from domain %d. Check "
			    "event-transport.conf\n", dom);
			(void) close(new_sd);
			return;
		}

		/* Authenticate this connection request */
		if ((rv = dscpAuth(dom, (struct sockaddr *)&new_saddr,
		    (int)new_len)) != DSCP_OK) {
			fmd_hdl_error(hdl, "dscpAuth failed for %s : rv = %d ",
			    " Possible spoofing attack\n", hp->h_endpt_id, rv);
			(void) close(new_sd);
			return;
		}

		if (hp->h_tid != EXS_TID_FREE) {
			hp->h_quit = 1;
			fmd_thr_signal(hp->h_hdl, hp->h_tid);
			fmd_thr_destroy(hp->h_hdl, hp->h_tid);
			hp->h_destroy = 0;
			hp->h_quit = 0;
		}

		if (hp->h_server.c_sd != EXS_SD_FREE)
			EXS_CLOSE_CLR(hp->h_server);

		/* Set the socket to be non-blocking */
		flags = fcntl(new_sd, F_GETFL, 0);
		(void) fcntl(new_sd, F_SETFL, flags | O_NONBLOCK);

		hp->h_server.c_sd = new_sd;

		hp->h_tid = fmd_thr_create(hdl, exs_server, hp);

	} else {
		fmd_hdl_error(hdl, "Failed to accept() a new connection");
	}
}

/*
 * Listen for and accept incoming connections.
 * There is only one such thread.
 */
void
exs_listen(void *arg)
{
	fmd_hdl_t *hdl = (fmd_hdl_t *)arg;
	struct pollfd pfd;

	while (!Acc_quit) {
		pfd.events = POLLIN;
		pfd.revents = 0;
		pfd.fd = Acc.c_sd;

		if (poll(&pfd, 1, -1) <= 0)
			continue; /* loop around and check Acc_quit */

		if (pfd.revents & (POLLHUP | POLLERR)) {
			fmd_hdl_debug(hdl, "xport - poll hangup/err on "
			    "accept socket");
			EXS_CLOSE_CLR(Acc);
			Acc_destroy++;
			break;	/* thread exits */
		}

		if (pfd.revents & POLLIN)
			exs_accept(hdl);
	}

	fmd_hdl_debug(hdl, "xport - exiting accept-listen thread");
}

/*
 * Prepare to accept a connection.
 * Return 0 for success, nonzero for failure.
 */
void
exs_prep_accept(fmd_hdl_t *hdl, int dom)
{
	int flags, optval = 1;
	int rv;

	if (Acc.c_sd != EXS_SD_FREE)
		return;	/* nothing to do */

	if (Acc_destroy) {
		fmd_thr_destroy(hdl, Acc_tid);
		Acc_tid = EXS_TID_FREE;
	}

	/* Check to see if the DSCP interface is configured */
	if ((rv = dscpAddr(dom, DSCP_ADDR_LOCAL,
	    (struct sockaddr *)&Acc.c_saddr, &Acc.c_len)) != DSCP_OK) {
		fmd_hdl_debug(hdl, "xport - dscpAddr on the accept socket "
		    "failed for domain %d : rv = %d", dom, rv);
		return;
	}

	if ((Acc.c_sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fmd_hdl_error(hdl, "Failed to create the accept socket");
		return;
	}

	if (setsockopt(Acc.c_sd, SOL_SOCKET, SO_REUSEADDR, &optval,
	    sizeof (optval))) {
		fmd_hdl_error(hdl, "Failed to set REUSEADDR for the accept "
		    "socket");
		EXS_CLOSE_CLR(Acc);
		return;
	}

	/* Bind the socket to the local IP address of the DSCP link */
	if ((rv = dscpBind(dom, Acc.c_sd, EXS_SERVER_PORT)) != DSCP_OK) {
		if (rv == DSCP_ERROR_DOWN) {
			fmd_hdl_debug(hdl, "xport - dscp link for domain %d "
			    "is down", dom);
		} else {
			fmd_hdl_debug(hdl, "dscpBind on the accept socket "
			    "failed : rv = %d\n", rv);
		}
		EXS_CLOSE_CLR(Acc);
		return;
	}

	/* Activate IPsec security policy for this socket */
	if ((rv = dscpSecure(dom, Acc.c_sd)) != DSCP_OK) {
		fmd_hdl_error(hdl, "dscpSecure on the accept socket failed : "
		    "rv = %d\n", dom, rv);
		EXS_CLOSE_CLR(Acc);
		return;
	}

	if ((listen(Acc.c_sd, EXS_NUM_SOCKS)) == -1) {
		fmd_hdl_debug(hdl, "Failed to listen() for connections");
		EXS_CLOSE_CLR(Acc);
		return;
	}

	flags = fcntl(Acc.c_sd, F_GETFL, 0);
	(void) fcntl(Acc.c_sd, F_SETFL, flags | O_NONBLOCK);

	Acc_tid = fmd_thr_create(hdl, exs_listen, hdl);
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

	if (exs_get_id(hdl, endpoint_id, &dom))
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

	if (Exh_head == NULL) {
		/* Do one-time initializations */
		exs_filter_init(hdl);

		/* Initialize the accept/listen vars */
		Acc.c_sd = EXS_SD_FREE;
		Acc_tid = EXS_TID_FREE;
		Acc_destroy = 0;
		Acc_quit = 0;
	}

	hp = exs_hdl_alloc(hdl, endpoint_id, cb_func, cb_func_arg, dom);

	/* Add this transport instance handle to the list */
	hp->h_next = Exh_head;
	Exh_head = hp;

	(void) pthread_mutex_unlock(&List_lock);

	exs_prep_accept(hdl, dom);

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
	exs_hdl_t *xp, **ppx;

	(void) pthread_mutex_lock(&List_lock);

	ppx = &Exh_head;

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

	if (hp->h_server.c_sd != EXS_SD_FREE)
		(void) close(hp->h_server.c_sd);

	if (hp->h_client.c_sd != EXS_SD_FREE)
		(void) close(hp->h_client.c_sd);

	fmd_hdl_strfree(hdl, hp->h_endpt_id);
	fmd_hdl_free(hdl, hp, sizeof (exs_hdl_t));

	if (Exh_head == NULL) {
		/* Undo one-time initializations */
		exs_filter_fini(hdl);

		/* Destroy the accept/listen thread */
		if (Acc_tid != EXS_TID_FREE) {
			Acc_quit = 1;
			fmd_thr_signal(hdl, Acc_tid);
			fmd_thr_destroy(hdl, Acc_tid);
		}

		if (Acc.c_sd != EXS_SD_FREE)
			EXS_CLOSE_CLR(Acc);
	}

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
			fmd_hdl_debug(hdl, "xport - failed to connect to %s",
			    hp->h_endpt_id);
			EXS_CLOSE_CLR(hp->h_client);
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

/*
 * * * * * * * * * * * * * * * * * * * *
 * ETM-to-Transport API Filter routines
 * * * * * * * * * * * * * * * * * * * *
 */

/*
 * Call the platform's send_filter function.
 * Otherwise return ETM_XPORT_FILTER_OK.
 */
int
etm_xport_send_filter(fmd_hdl_t *hdl, nvlist_t *event, const char *dest)
{
	if (Send_filter != NULL)
		return (Send_filter(hdl, event, dest));
	else
		return (ETM_XPORT_FILTER_OK);
}

/*
 * Call the platform's post_filter function.
 * Otherwise return ETM_XPORT_FILTER_OK.
 */
int
etm_xport_post_filter(fmd_hdl_t *hdl, nvlist_t *event, const char *src)
{
	if (Post_filter != NULL)
		return (Post_filter(hdl, event, src));
	else
		return (ETM_XPORT_FILTER_OK);
}
