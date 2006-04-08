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

#include <unistd.h>
#include <strings.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <libdscp.h>
#include "etm_xport_api.h"

/*
 * Transport Layer handle implementations
 */
/* Connection handle */
typedef struct etm_xport_sock_conn {
	int c_len;			/* Length of saddr */
	int c_sd;			/* Socket descriptor */
	struct sockaddr_in c_saddr;	/* Sockaddr for DSCP connection */
} exs_conn_t;

typedef enum etm_xport_sock_status {
	S_WAITING,			/* Server thread is waiting to start */
	S_RUNNING,			/* Server thread is running */
	S_DOEXIT			/* Server thread needs to exit */
} exs_status_t;

/* Transport instance handle */
typedef struct etm_xport_sock_hdl {
	exs_conn_t h_client;		/* Sending connection handle */
	exs_conn_t h_server;		/* Receiving connection handle */
	char *h_endpt_id;		/* Endpoint id from ETM common */
	int h_domain_id;		/* Domain ID from platform (libdscp) */
	pthread_mutex_t h_lock;		/* Lock for instance handle */
	fmd_hdl_t *h_hdl;		/* fmd handle */
	int (*h_cb_func)(fmd_hdl_t *, etm_xport_conn_t, etm_cb_flag_t, void *);
					/* Callback function for ETM common */
	void *h_cb_func_arg;		/* Arg to pass when calling h_cb_func */
	struct etm_xport_sock_hdl *h_next;
} exs_hdl_t;

/* For the socket */
#define	EXS_SERVER_PORT 24		/* Port number for server */
#define	EXS_SERVER_ADDR in6addr_any	/* Address for server */
#define	EXS_CLIENT_PORT 0		/* Port number for client */
#define	EXS_NUM_SOCKS 5			/* Length of socket queue */
#define	EXS_SD_FREE -1			/* Socket descr value when unset */

#define	EXS_DOMAIN_PREFIX "dom"		/* Domain auth prefix in FMRI string */
#define	EXS_DOMAIN_PREFIX_LEN 3		/* Length of domain prefix */
#define	EXS_SP_PREFIX "sp"		/* SP auth prefix in FMRI string */
#define	EXS_IO_SLEEP_DIV 100		/* Divisor for I/O sleeptime */

/*
 * Global variables
 */
static exs_status_t Server_status = S_WAITING;
					/* Status of Server */
static pthread_t Server_tid = 0;	/* Thread ID of Server */
static exs_conn_t Acceptor_conn;	/* Connection handle for Acceptor */
static fd_set Conn_set;			/* Set of accepted connections */
static pthread_mutex_t Mod_lock = PTHREAD_MUTEX_INITIALIZER;
					/* Protects globals (above) */
static exs_hdl_t *Exh_head = NULL;	/* Head of ex_hdl_t list */
static pthread_mutex_t	List_lock = PTHREAD_MUTEX_INITIALIZER;
					/* Protects linked list of ex_hdl_t */
/*
 * Mutex lock order
 *	(1) List_lock
 *	(2) hp->h_lock
 *	(3) Mod_lock
 */

/*
 * Module specific routines.
 */

/*
 * Allocate and initialize a transport instance handle.
 * Return hdl pointer for success, NULL for failure.
 */
static exs_hdl_t *
exs_hdl_alloc(fmd_hdl_t *hdl, char *endpoint_id,
    int (*cb_func)(fmd_hdl_t *hdl, etm_xport_conn_t conn, etm_cb_flag_t flag,
    void *arg), void *cb_func_arg, int domain_id)
{
	exs_hdl_t *hp;

	hp = fmd_hdl_zalloc(hdl, sizeof (exs_hdl_t), FMD_SLEEP);

	(void) pthread_mutex_init(&hp->h_lock, NULL);

	hp->h_endpt_id = fmd_hdl_strdup(hdl, endpoint_id, FMD_SLEEP);
	hp->h_domain_id = domain_id;
	hp->h_client.c_sd = EXS_SD_FREE;
	hp->h_server.c_sd = EXS_SD_FREE;
	hp->h_hdl = hdl;
	hp->h_cb_func = cb_func;
	hp->h_cb_func_arg = cb_func_arg;

	return (hp);
}

/*
 * Prepare the client connection.
 * Return 0 for success, nonzero for failure.
 */
static int
exs_prep_client(fmd_hdl_t *hdl, exs_hdl_t *hp)
{
	int rv;

	/* Find the DSCP address for the remote endpoint */
	if ((rv = dscpAddr(hp->h_domain_id, DSCP_ADDR_REMOTE,
	    (struct sockaddr *)&hp->h_client.c_saddr,
	    &hp->h_client.c_len)) != DSCP_OK) {
		fmd_hdl_debug(hdl, "xport - dscpAddr for %s failed: %d",
		    hp->h_endpt_id, rv);
		return (1);
	}

	if ((hp->h_client.c_sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fmd_hdl_debug(hdl, "xport - client socket failed for %s",
		    hp->h_endpt_id);
		return (1);
	}

	/* Bind the socket to the local IP address of the DSCP link */
	if ((rv = dscpBind(hp->h_domain_id, hp->h_client.c_sd,
	    EXS_CLIENT_PORT)) != DSCP_OK) {
		fmd_hdl_debug(hdl, "xport - client bind for %s failed: %d",
		    hp->h_endpt_id, rv);
		(void) close(hp->h_client.c_sd);
		hp->h_client.c_sd = EXS_SD_FREE;
		return (1);
	}

	hp->h_client.c_saddr.sin_port = htons(EXS_SERVER_PORT);

	/* Set IPsec security policy for this socket */
	if ((rv = dscpSecure(hp->h_domain_id, hp->h_client.c_sd)) != DSCP_OK) {
		fmd_hdl_debug(hdl, "xport - dscpSecure for %s failed: %d",
		    hp->h_endpt_id, rv);
		(void) close(hp->h_client.c_sd);
		hp->h_client.c_sd = EXS_SD_FREE;
		return (1);
	}

	return (0);
}

/*
 * Prepare to accept a connection.
 * Assume Mod_lock is held by caller.
 * Return 0 for success, nonzero for failure.
 */
static int
exs_prep_accept(fmd_hdl_t *hdl)
{

	int flags, domain = 0, optval = 1;
	int rv;

	if ((Acceptor_conn.c_sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fmd_hdl_debug(hdl, "xport - acceptor socket failed");
		return (1);
	}

	if (setsockopt(Acceptor_conn.c_sd, SOL_SOCKET, SO_REUSEADDR,
	    &optval, sizeof (optval))) {
		fmd_hdl_debug(hdl, "xport - set REUSEADDR failed");
		(void) close(Acceptor_conn.c_sd);
		Acceptor_conn.c_sd = EXS_SD_FREE;
		return (1);
	}

	/* Bind the socket to the local IP address of the DSCP link */
	if ((rv = dscpBind(domain, Acceptor_conn.c_sd,
	    EXS_SERVER_PORT)) != DSCP_OK) {
		fmd_hdl_debug(hdl, "xport - acceptor bind failed: %d", rv);
		(void) close(Acceptor_conn.c_sd);
		Acceptor_conn.c_sd = EXS_SD_FREE;
		return (1);
	}

	/* Activate IPsec security policy for this socket */
	if ((rv = dscpSecure(domain, Acceptor_conn.c_sd)) != DSCP_OK) {
		fmd_hdl_debug(hdl, "xport - dscpSecure for acceptor failed: %d",
		    rv);
		(void) close(Acceptor_conn.c_sd);
		Acceptor_conn.c_sd = EXS_SD_FREE;
		return (1);
	}

	if ((listen(Acceptor_conn.c_sd, EXS_NUM_SOCKS)) == -1) {
		fmd_hdl_debug(hdl, "xport - acceptor listen failed");
		(void) close(Acceptor_conn.c_sd);
		Acceptor_conn.c_sd = EXS_SD_FREE;
		return (1);
	}

	flags = fcntl(Acceptor_conn.c_sd, F_GETFL, 0);
	(void) fcntl(Acceptor_conn.c_sd, F_SETFL, flags | O_NONBLOCK);

	return (0);
}

/*
 * Translate endpoint_id str to int.
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
			fmd_hdl_debug(hdl, "xport - %s not found in %s\n",
			    EXS_DOMAIN_PREFIX, endpoint_id);
			return (1);
		}

		ptr += EXS_DOMAIN_PREFIX_LEN;

		if ((sscanf(ptr, "%d", dom_id)) != 1) {
			fmd_hdl_debug(hdl, "xport - no integer found in %s\n",
			    endpoint_id);
			return (1);
		}
	}

	return (0);
}

/*
 * Build set of socket descriptors based on the current list of exs_hdl_t.
 * Return the largest descriptor.
 */
static int
exs_build_set(fmd_hdl_t *hdl)
{
	exs_hdl_t *curr;
	struct sockaddr sa;
	socklen_t slen = sizeof (struct sockaddr);
	fd_set rset;
	int max_sd = 0;

	fmd_hdl_debug(hdl, "xport - building set of socket descr");

	FD_ZERO(&rset);
	FD_SET(Acceptor_conn.c_sd, &rset);

	(void) pthread_mutex_lock(&List_lock);

	for (curr = Exh_head; curr; curr = curr->h_next) {
		(void) pthread_mutex_lock(&curr->h_lock);
		if (curr->h_server.c_sd != EXS_SD_FREE) {
			/* Use getsockname to test for valid socket descr */
			if (getsockname(curr->h_server.c_sd, &sa, &slen) == 0)
				FD_SET(curr->h_server.c_sd, &rset);
			else if ((errno == EBADF) || (errno == ENOTSOCK))
				curr->h_server.c_sd = EXS_SD_FREE;
			else
				fmd_hdl_error(hdl, "xport - getsockname fail");

			if (curr->h_server.c_sd > max_sd)
				max_sd = curr->h_server.c_sd;
		}
		(void) pthread_mutex_unlock(&curr->h_lock);
	}

	(void) pthread_mutex_unlock(&List_lock);

	(void) pthread_mutex_lock(&Mod_lock);
	Conn_set = rset;
	(void) pthread_mutex_unlock(&Mod_lock);

	if (max_sd > FD_SETSIZE)
		fmd_hdl_abort(hdl, "xport - max_sd too big");

	return (max_sd);
}

/*
 * Find the exs_hdl_t associated with the given sockaddr_in.
 * Assume caller holds lock on List_lock.
 * Return the exs_hdl_t for success, NULL for failure.
 */
static exs_hdl_t *
exs_find_hdl(fmd_hdl_t *hdl, struct sockaddr_in *saddr, socklen_t salen)
{
	exs_hdl_t *curr;
	int domain_id, rv;

	/* Translate saddr to a domain id string */
	if ((rv = dscpIdent((struct sockaddr *)saddr, (int)salen,
	    &domain_id)) != DSCP_OK) {
		fmd_hdl_debug(hdl, "xport - dscpIdent failed for 0x%x : %d",
		    saddr->sin_addr.s_addr, rv);
		return (NULL);
	}

	if ((rv = dscpAuth(domain_id, (struct sockaddr *)saddr,
	    (int)salen)) != DSCP_OK) {
		fmd_hdl_debug(hdl, "xport - dscpAuth failed for 0x%x : %d",
		    saddr->sin_addr.s_addr, rv);
		return (NULL);
	}

	/* Lookup this domain id */
	for (curr = Exh_head; curr; curr = curr->h_next) {
		if (curr->h_domain_id == domain_id)
			break;
	}

	return (curr);
}

/*
 * Main server function, runs on thread started at init.
 * Accepts incoming connections and notifies ETM of incoming data.
 * Thread/function runs until Server_status changes to S_DOEXIT.
 */
static void
exs_server(void *arg)
{
	int new_sd;			/* Socket desc of new conn */
	int nready;			/* Num readable sockets from select */
	int max_sd;			/* Max socket desc : for select */
	fd_set rset;			/* Read socket desc set for select */
	struct sockaddr_in new_saddr;	/* Sockaddr of remote endpt */
	exs_hdl_t *hp;
	fmd_hdl_t *hdl = (fmd_hdl_t *)arg;
	socklen_t new_len = sizeof (struct sockaddr);
	int flags, old_sd = 0;

	(void) pthread_mutex_lock(&Mod_lock);
	Server_status = S_RUNNING;
	FD_ZERO(&Conn_set);
	FD_SET(Acceptor_conn.c_sd, &Conn_set);
	max_sd = Acceptor_conn.c_sd;

	while (Server_status != S_DOEXIT) {
		rset = Conn_set;
		(void) pthread_mutex_unlock(&Mod_lock);

		if ((nready = select(max_sd + 1, &rset, NULL, NULL,
		    NULL)) == -1) {
			if (errno == EINTR)
				fmd_hdl_debug(hdl, "xport - select EINTR");
			else
				max_sd = exs_build_set(hdl);

			(void) pthread_mutex_lock(&Mod_lock);
			continue;
		}

		/* First check if a new connection has arrived */
		if (FD_ISSET(Acceptor_conn.c_sd, &rset)) {
			if ((new_sd = accept(Acceptor_conn.c_sd,
			    (struct sockaddr *)&new_saddr, &new_len)) != -1) {
				(void) pthread_mutex_lock(&List_lock);

				if ((hp = exs_find_hdl(hdl, &new_saddr,
				    new_len)) != NULL) {
					fmd_hdl_debug(hdl, "xport - new server "
					    "connection for %s",
					    hp->h_endpt_id);

					(void) pthread_mutex_lock(&hp->h_lock);

					if (hp->h_server.c_sd != EXS_SD_FREE) {
						(void) close(hp->h_server.c_sd);
						old_sd = hp->h_server.c_sd;
					}

					hp->h_server.c_sd = new_sd;

					/* Set the socket to be non-blocking */
					flags = fcntl(hp->h_server.c_sd,
					    F_GETFL, 0);
					(void) fcntl(hp->h_server.c_sd,
					    F_SETFL, flags | O_NONBLOCK);

					(void) pthread_mutex_unlock(
					    &hp->h_lock);
					(void) pthread_mutex_unlock(&List_lock);

					/*
					 * Add this socket descriptor to the
					 * fd_set and remove the old one.
					 */
					(void) pthread_mutex_lock(&Mod_lock);
					FD_SET(new_sd, &Conn_set);
					if (old_sd) {
						FD_CLR(old_sd, &Conn_set);
						old_sd = 0;
					}
					(void) pthread_mutex_unlock(&Mod_lock);

					if (new_sd > max_sd)
						max_sd = new_sd;
				} else {
					(void) pthread_mutex_unlock(&List_lock);
					fmd_hdl_debug(hdl,
					    "xport - no tlhdl for endpt 0x%x",
					    new_saddr.sin_addr.s_addr);
					(void) close(new_sd);
				}
			} else {
				fmd_hdl_debug(hdl,
				    "xport - accept failed");
			}

			if (--nready <= 0) {
				/* No more sockets to check */
				(void) pthread_mutex_lock(&Mod_lock);
				continue;
			}
		}

		/* Check if any of the other sockets have data to recv */
		(void) pthread_mutex_lock(&List_lock);
		for (hp = Exh_head; hp; hp = hp->h_next) {
			(void) pthread_mutex_lock(&hp->h_lock);

			if (hp->h_server.c_sd == EXS_SD_FREE) {
				(void) pthread_mutex_unlock(&hp->h_lock);
				continue;
			}

			if (FD_ISSET(hp->h_server.c_sd, &rset)) {
				/*
				 * Data is available on this socket
				 * or the remote side has closed.
				 */
				if ((hp->h_cb_func(hp->h_hdl,
				    &hp->h_server, ETM_CBFLAG_RECV,
				    hp->h_cb_func_arg)) != 0) {
					/*
					 * Remove the socket descriptor from
					 * the fd_set
					 */
					(void) pthread_mutex_lock(&Mod_lock);
					FD_CLR(hp->h_server.c_sd, &Conn_set);
					(void) pthread_mutex_unlock(&Mod_lock);

					/* Close the server socket */
					(void) close(hp->h_server.c_sd);
					hp->h_server.c_sd = EXS_SD_FREE;
				}

				if (--nready <= 0) {
					/* No more sockets to check */
					(void) pthread_mutex_unlock(
					    &hp->h_lock);
					break;
				}
			}

			(void) pthread_mutex_unlock(&hp->h_lock);
		}

		(void) pthread_mutex_unlock(&List_lock);
		(void) pthread_mutex_lock(&Mod_lock);
	}

	fmd_hdl_debug(hdl, "xport - exiting server thread %d", Server_tid);
	(void) close(Acceptor_conn.c_sd);
	Acceptor_conn.c_sd = EXS_SD_FREE;
	Server_tid = 0;
	Server_status = S_WAITING;
	(void) pthread_mutex_unlock(&Mod_lock);
	/* Thread dies */
}

/*
 * ETM-to-Transport API Connection Management routines
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
	int domain_id;

	if ((exs_get_id(hdl, endpoint_id, &domain_id)) == -1)
		return (NULL);

	(void) pthread_mutex_lock(&List_lock);
	if (Exh_head == NULL) {
		/* This is the first init */
		(void) pthread_mutex_lock(&Mod_lock);
		if (exs_prep_accept(hdl)) {
			(void) pthread_mutex_unlock(&Mod_lock);
			(void) pthread_mutex_unlock(&List_lock);
			return (NULL);
		}
		(void) pthread_mutex_unlock(&Mod_lock);
	} else {
		/* Check for a duplicate endpoint_id on the list */
		for (curr = Exh_head; curr; curr = curr->h_next) {
			if (domain_id == curr->h_domain_id) {
				fmd_hdl_debug(hdl, "xport - init failed, "
				    "duplicate domain_id : %d\n", domain_id);
				(void) pthread_mutex_unlock(&List_lock);
				return (NULL);
			}
		}
	}

	/* Alloc and init a transport instance handle */
	hp = exs_hdl_alloc(hdl, endpoint_id, cb_func, cb_func_arg,
	    domain_id);

	/* Prep the client-side connection */
	if (exs_prep_client(hdl, hp)) {
		if (Exh_head == NULL) {
			(void) pthread_mutex_lock(&Mod_lock);
			if (Acceptor_conn.c_sd != EXS_SD_FREE) {
				(void) close(Acceptor_conn.c_sd);
				Acceptor_conn.c_sd = EXS_SD_FREE;
			}
			(void) pthread_mutex_unlock(&Mod_lock);
		}

		fmd_hdl_strfree(hdl, hp->h_endpt_id);
		(void) pthread_mutex_unlock(&hp->h_lock);
		(void) pthread_mutex_destroy(&hp->h_lock);
		fmd_hdl_free(hdl, hp, sizeof (exs_hdl_t));
		(void) pthread_mutex_unlock(&List_lock);
		return (NULL);
	}

	/* Add this transport instance handle to the list */
	hp->h_next = Exh_head;
	Exh_head = hp;
	(void) pthread_mutex_unlock(&List_lock);

	/* Create the Server thread, if necessary */
	(void) pthread_mutex_lock(&Mod_lock);
	if (Server_tid == 0)
		Server_tid = fmd_thr_create(hdl, exs_server, hdl);

	(void) pthread_mutex_unlock(&Mod_lock);

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
	exs_hdl_t *prev, *curr;

	/* Remove this handle from the list */
	prev = NULL;

	(void) pthread_mutex_lock(&List_lock);

	for (curr = Exh_head; curr; curr = curr->h_next) {
		if (curr == hp)
			break;

		prev = curr;
	}

	if (curr == NULL) {
		(void) pthread_mutex_unlock(&List_lock);
		fmd_hdl_debug(hdl, "xport - fini failed, tlhdl %p not on list",
		    curr);
		return (1);
	}

	if (prev == NULL)
		Exh_head = Exh_head->h_next;
	else
		prev->h_next = hp->h_next;

	/* If this is the last handle, cleanup and exit the Server thread */
	if (Exh_head == NULL) {
		(void) pthread_mutex_lock(&Mod_lock);
		Server_status = S_DOEXIT;
		(void) pthread_mutex_unlock(&Mod_lock);
		fmd_thr_signal(hdl, Server_tid);
		fmd_thr_destroy(hdl, Server_tid);
	}

	(void) pthread_mutex_unlock(&List_lock);

	/* Close the handle's client connection */
	(void) pthread_mutex_lock(&hp->h_lock);
	if (hp->h_client.c_sd != EXS_SD_FREE)
		(void) close(hp->h_client.c_sd);

	/*
	 * Close the handle's server connection and remove it from the fd_set
	 * used in the Server thread.
	 */
	if (hp->h_server.c_sd != EXS_SD_FREE) {
		(void) close(hp->h_server.c_sd);
		(void) pthread_mutex_lock(&Mod_lock);
		FD_CLR(hp->h_server.c_sd, &Conn_set);
		(void) pthread_mutex_unlock(&Mod_lock);
	}

	fmd_hdl_strfree(hdl, hp->h_endpt_id);
	(void) pthread_mutex_unlock(&hp->h_lock);
	(void) pthread_mutex_destroy(&hp->h_lock);
	fmd_hdl_free(hdl, hp, sizeof (exs_hdl_t));

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

	if (hp->h_client.c_sd == EXS_SD_FREE) {
		if (exs_prep_client(hdl, hp) != 0)
			return (NULL);
	}

	if ((connect(hp->h_client.c_sd,
	    (struct sockaddr *)&hp->h_client.c_saddr,
	    hp->h_client.c_len)) == -1) {
		fmd_hdl_error(hdl, "xport - failed connect to server for %s",
		    hp->h_endpt_id);
		(void) close(hp->h_client.c_sd);
		hp->h_client.c_sd = EXS_SD_FREE;
		return (NULL);
	}

	/* Set the socket to be non-blocking */
	flags = fcntl(hp->h_client.c_sd, F_GETFL, 0);
	(void) fcntl(hp->h_client.c_sd, F_SETFL, flags | O_NONBLOCK);

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
 * ETM-to-Transport API I/O routines
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
