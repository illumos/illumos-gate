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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

/*
 * svc_raw.c,   This is a toy for simple testing and timing.
 * Interface to create an rpc client and server in the same UNIX process.
 * This lets us simulate rpc and get rpc (round trip) overhead, without
 * any interference from the kernal.
 */

#include "mt.h"
#include "rpc_mt.h"
#include <stdlib.h>
#include <rpc/rpc.h>
#include <sys/types.h>
#include <syslog.h>

#ifndef UDPMSGSIZE
#define	UDPMSGSIZE 8800
#endif

/*
 * This is the "network" that we will be moving data over
 */
static struct svc_raw_private {
	struct netbuf	*raw_netbuf;
	SVCXPRT	*server;
	XDR	xdr_stream;
	char	verf_body[MAX_AUTH_BYTES];
} *svc_raw_private;

static struct xp_ops *svc_raw_ops();
extern mutex_t	svcraw_lock;

/*
 * This netbuf is shared with the raw client.
 */
struct netbuf _rawcomnetbuf;

SVCXPRT *
svc_raw_create(void)
{
	struct svc_raw_private *srp;

/* VARIABLES PROTECTED BY svcraw_lock: svc_raw_private, srp */
	(void) mutex_lock(&svcraw_lock);
	srp = svc_raw_private;
	if (srp != NULL) {
		(void) mutex_unlock(&svcraw_lock);
		return (srp->server);
	}

	srp = calloc(1, sizeof (*srp));
	if (srp == NULL) {
		syslog(LOG_ERR, "svc_raw_create: out of memory");

		(void) mutex_unlock(&svcraw_lock);
		return (NULL);
	}

	srp->raw_netbuf = &_rawcomnetbuf;
	srp->raw_netbuf->buf = malloc(UDPMSGSIZE);
	if (srp->raw_netbuf->buf == NULL) {
		free(srp);
		syslog(LOG_ERR, "svc_raw_create: out of memory");

		(void) mutex_unlock(&svcraw_lock);
		return (NULL);
	}
	srp->raw_netbuf->maxlen = UDPMSGSIZE;
	srp->raw_netbuf->len = 0;

	if ((srp->server = svc_xprt_alloc()) == NULL) {
		free(srp->raw_netbuf->buf);
		srp->raw_netbuf->buf = NULL;
		srp->raw_netbuf->maxlen = 0;

		free(srp);

		(void) mutex_unlock(&svcraw_lock);
		return (NULL);
	}

	/*
	 * By convention, using FD_SETSIZE as the pseudo file descriptor
	 */
	srp->server->xp_fd = FD_SETSIZE;
	srp->server->xp_port = 0;
	srp->server->xp_ops = svc_raw_ops();
	srp->server->xp_verf.oa_base = srp->verf_body;
	xprt_register(srp->server);

	svc_raw_private = srp;

	(void) mutex_unlock(&svcraw_lock);
	return (srp->server);
}

/*ARGSUSED*/
static enum xprt_stat
svc_raw_stat(SVCXPRT *xprt)
{
	return (XPRT_IDLE);
}

/*ARGSUSED*/
static bool_t
svc_raw_recv(SVCXPRT *xprt, struct rpc_msg *msg)
{
	struct svc_raw_private *srp;
	XDR *xdrs;

	(void) mutex_lock(&svcraw_lock);
	srp = svc_raw_private;
	if (srp == NULL) {
		(void) mutex_unlock(&svcraw_lock);
		return (FALSE);
	}
	(void) mutex_unlock(&svcraw_lock);

	xdrs = &srp->xdr_stream;

	xdrmem_create(xdrs, srp->raw_netbuf->buf, srp->raw_netbuf->len,
	    XDR_DECODE);

	if (!xdr_callmsg(xdrs, msg)) {
		XDR_DESTROY(xdrs);
		return (FALSE);
	}

	return (TRUE);
}

/*ARGSUSED*/
static bool_t
svc_raw_reply(SVCXPRT *xprt, struct rpc_msg *msg)
{
	struct svc_raw_private *srp;
	XDR *xdrs;
	uint_t start;

	(void) mutex_lock(&svcraw_lock);
	srp = svc_raw_private;
	if (srp == NULL) {
		(void) mutex_unlock(&svcraw_lock);
		return (FALSE);
	}
	(void) mutex_unlock(&svcraw_lock);

	xdrs = &srp->xdr_stream;

	XDR_DESTROY(xdrs);
	xdrmem_create(xdrs, srp->raw_netbuf->buf, srp->raw_netbuf->maxlen,
	    XDR_ENCODE);

	start = XDR_GETPOS(xdrs);
	if (!xdr_replymsg(xdrs, msg)) {
		XDR_DESTROY(xdrs);
		return (FALSE);
	}
	srp->raw_netbuf->len = XDR_GETPOS(xdrs) - start;

	return (TRUE);
}

/*ARGSUSED*/
static bool_t
svc_raw_getargs(SVCXPRT *xprt, xdrproc_t xdr_args, caddr_t args_ptr)
{
	struct svc_raw_private *srp;

	(void) mutex_lock(&svcraw_lock);
	srp = svc_raw_private;
	if (srp == NULL) {
		(void) mutex_unlock(&svcraw_lock);
		return (FALSE);
	}
	(void) mutex_unlock(&svcraw_lock);

	return ((*xdr_args)(&srp->xdr_stream, args_ptr));
}

/*ARGSUSED*/
static bool_t
svc_raw_freeargs(SVCXPRT *xprt, xdrproc_t xdr_args, caddr_t args_ptr)
{
	struct svc_raw_private *srp;

	(void) mutex_lock(&svcraw_lock);
	srp = svc_raw_private;
	if (srp == NULL) {
		(void) mutex_unlock(&svcraw_lock);
		return (FALSE);
	}
	(void) mutex_unlock(&svcraw_lock);

	XDR_DESTROY(&srp->xdr_stream);

	xdr_free(xdr_args, args_ptr);

	return (TRUE);
}

/*ARGSUSED*/
static void
svc_raw_destroy(SVCXPRT *xprt)
{
}

/*ARGSUSED*/
static bool_t
svc_raw_control(SVCXPRT *xprt, const uint_t rq, void *in)
{
	switch (rq) {
	case SVCGET_XID: /* fall through for now */
	default:
		return (FALSE);
	}
}

static struct xp_ops *
svc_raw_ops(void)
{
	static struct xp_ops ops;
	extern mutex_t ops_lock;

/* VARIABLES PROTECTED BY ops_lock: ops */

	(void) mutex_lock(&ops_lock);
	if (ops.xp_recv == NULL) {
		ops.xp_recv = svc_raw_recv;
		ops.xp_stat = svc_raw_stat;
		ops.xp_getargs = svc_raw_getargs;
		ops.xp_reply = svc_raw_reply;
		ops.xp_freeargs = svc_raw_freeargs;
		ops.xp_destroy = svc_raw_destroy;
		ops.xp_control = svc_raw_control;
	}
	(void) mutex_unlock(&ops_lock);
	return (&ops);
}
