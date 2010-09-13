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

/*
 * FMA Event Transport Module Transport Layer API implementation.
 *
 * Library for establishing connections and transporting FMA events between
 * ETMs (event-transport modules) in separate fault domains.
 *
 * The transport for this library is internet socket based and uses the DSCP
 * client services library (libdscp).
 */

#ifndef _EX_DSCP_H
#define	_EX_DSCP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>
#include <strings.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <dlfcn.h>
#include <libdscp.h>
#include "etm_xport_api.h"

/* Connection handle */
typedef struct etm_xport_sock_conn {
	int c_len;			/* Length of saddr */
	int c_sd;			/* Socket descriptor */
	struct sockaddr_in c_saddr;	/* Sockaddr for DSCP connection */
} exs_conn_t;

/* Transport instance handle */
typedef struct etm_xport_sock_hdl {
	exs_conn_t h_client;		/* Sending connection handle */
	exs_conn_t h_server;		/* Receiving connection handle */
	pthread_t h_tid;		/* Thread ID of server thread */
	int h_destroy;			/* Destroy the server thread? */
	char *h_endpt_id;		/* Endpoint id from ETM common */
	int h_dom;			/* Domain ID from platform (libdscp) */
	fmd_hdl_t *h_hdl;		/* fmd handle */
	int (*h_cb_func)(fmd_hdl_t *, etm_xport_conn_t, etm_cb_flag_t, void *);
					/* Callback function for ETM common */
	void *h_cb_func_arg;		/* Arg to pass when calling h_cb_func */
	int h_quit;			/* Signal to quit */
	struct etm_xport_sock_hdl *h_next;
} exs_hdl_t;

#define	EXS_SERVER_PORT 24		/* Port number for server */
#define	EXS_SERVER_ADDR in6addr_any	/* Address for server */
#define	EXS_CLIENT_PORT 12		/* Port number for client */
#define	EXS_NUM_SOCKS 24		/* Length of socket queue */
#define	EXS_SD_FREE -1			/* Socket descr value when unset */
#define	EXS_TID_FREE 0			/* Thread ID value when unset */
#define	EXS_DOMAIN_PREFIX "dom"		/* Domain auth prefix in FMRI string */
#define	EXS_DOMAIN_PREFIX_LEN 3		/* Length of domain prefix */
#define	EXS_SP_PREFIX "sp"		/* SP auth prefix in FMRI string */
#define	EXS_IO_SLEEP_DIV 100		/* Divisor for I/O sleeptime */

#define	EXS_CLOSE_CLR(x) { (void) close(x.c_sd); x.c_sd = EXS_SD_FREE; }

#ifdef __cplusplus
}
#endif

#endif /* _EX_DSCP_H */
