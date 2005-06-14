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
 *
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * svc_raw.c,   This a toy for simple testing and timing.
 * Interface to create an rpc client and server in the same UNIX process.
 * This lets us similate rpc and get rpc (round trip) overhead, without
 * any interference from the kernal.
 *
 */

#include "mt.h"
#include "rpc_mt.h"
#include <rpc/rpc.h>
#include <sys/types.h>
#include <rpc/trace.h>
#include <rpc/raw.h>
#include <syslog.h>

#ifndef UDPMSGSIZE
#define	UDPMSGSIZE 8800
#endif

/*
 * This is the "network" that we will be moving data over
 */
static struct svc_raw_private {
	char	*raw_buf;	/* should be shared with the cl handle */
	SVCXPRT	*server;
	XDR	xdr_stream;
	char	verf_body[MAX_AUTH_BYTES];
} *svc_raw_private;

static struct xp_ops *svc_raw_ops();
extern char *calloc();
extern void free();
extern mutex_t	svcraw_lock;



SVCXPRT *
svc_raw_create()
{
	struct svc_raw_private *srp;
	bool_t flag1 = FALSE, flag2 = FALSE;

/* VARIABLES PROTECTED BY svcraw_lock: svc_raw_private, srp */
	trace1(TR_svc_raw_create, 0);
	mutex_lock(&svcraw_lock);
	srp = svc_raw_private;
	if (srp == NULL) {
/* LINTED pointer alignment */
		srp = (struct svc_raw_private *)calloc(1, sizeof (*srp));
		if (srp == NULL) {
			syslog(LOG_ERR, "svc_raw_create: out of memory");
			mutex_unlock(&svcraw_lock);
			trace1(TR_svc_raw_create, 1);
			return ((SVCXPRT *)NULL);
		}
		flag1 = TRUE;
		if (_rawcombuf == NULL) {
			_rawcombuf = (char *)calloc(UDPMSGSIZE, sizeof (char));
			if (_rawcombuf == NULL) {
				free((char *)srp);
				syslog(LOG_ERR, "svc_raw_create: "
					"out of memory");
				mutex_unlock(&svcraw_lock);
				trace1(TR_svc_raw_create, 1);
				return ((SVCXPRT *)NULL);
			}
			flag2 = TRUE;
		}
		srp->raw_buf = _rawcombuf; /* Share it with the client */
		svc_raw_private = srp;
	}
	if ((srp->server = svc_xprt_alloc()) == NULL) {
		if (flag2)
			free(svc_raw_private->raw_buf);
		if (flag1)
			free(svc_raw_private);
		mutex_unlock(&svcraw_lock);
		trace1(TR_svc_raw_create, 1);
		return ((SVCXPRT *)NULL);
	}
	/*
	 * By convention, using FD_SETSIZE as the psuedo file descriptor
	 */
	srp->server->xp_fd = FD_SETSIZE;
	srp->server->xp_port = 0;
	srp->server->xp_ops = svc_raw_ops();
	srp->server->xp_verf.oa_base = srp->verf_body;
	xdrmem_create(&srp->xdr_stream, srp->raw_buf, UDPMSGSIZE, XDR_DECODE);
	xprt_register(srp->server);
	mutex_unlock(&svcraw_lock);
	trace1(TR_svc_raw_create, 1);
	return (srp->server);
}

/*ARGSUSED*/
static enum xprt_stat
svc_raw_stat(xprt)
SVCXPRT *xprt; /* args needed to satisfy ANSI-C typechecking */
{
	trace1(TR_svc_raw_stat, 0);
	trace1(TR_svc_raw_stat, 1);
	return (XPRT_IDLE);
}

/*ARGSUSED*/
static bool_t
svc_raw_recv(xprt, msg)
	SVCXPRT *xprt;
	struct rpc_msg *msg;
{
	struct svc_raw_private *srp;
	XDR *xdrs;

	trace1(TR_svc_raw_recv, 0);
	mutex_lock(&svcraw_lock);
	srp = svc_raw_private;
	if (srp == NULL) {
		mutex_unlock(&svcraw_lock);
		trace1(TR_svc_raw_recv, 1);
		return (FALSE);
	}
	mutex_unlock(&svcraw_lock);

	xdrs = &srp->xdr_stream;
	xdrs->x_op = XDR_DECODE;
	(void) XDR_SETPOS(xdrs, 0);
	if (! xdr_callmsg(xdrs, msg)) {
		trace1(TR_svc_raw_recv, 1);
		return (FALSE);
	}
	trace1(TR_svc_raw_recv, 1);
	return (TRUE);
}

/*ARGSUSED*/
static bool_t
svc_raw_reply(xprt, msg)
	SVCXPRT *xprt;
	struct rpc_msg *msg;
{
	struct svc_raw_private *srp;
	XDR *xdrs;

	trace1(TR_svc_raw_reply, 0);
	mutex_lock(&svcraw_lock);
	srp = svc_raw_private;
	if (srp == NULL) {
		mutex_unlock(&svcraw_lock);
		trace1(TR_svc_raw_reply, 1);
		return (FALSE);
	}
	mutex_unlock(&svcraw_lock);

	xdrs = &srp->xdr_stream;
	xdrs->x_op = XDR_ENCODE;
	(void) XDR_SETPOS(xdrs, 0);
	if (! xdr_replymsg(xdrs, msg)) {
		trace1(TR_svc_raw_reply, 1);
		return (FALSE);
	}
	(void) XDR_GETPOS(xdrs);  /* called just for overhead */
	trace1(TR_svc_raw_reply, 1);
	return (TRUE);
}

/*ARGSUSED*/
static bool_t
svc_raw_getargs(xprt, xdr_args, args_ptr)
	SVCXPRT *xprt;
	xdrproc_t xdr_args;
	caddr_t args_ptr;
{
	struct svc_raw_private *srp;
	bool_t dummy1;

	trace1(TR_svc_raw_getargs, 0);
	mutex_lock(&svcraw_lock);
	srp = svc_raw_private;
	if (srp == NULL) {
		mutex_unlock(&svcraw_lock);
		trace1(TR_svc_raw_getargs, 1);
		return (FALSE);
	}
	mutex_unlock(&svcraw_lock);
	dummy1 = (*xdr_args)(&srp->xdr_stream, args_ptr);
	trace1(TR_svc_raw_getargs, 1);
	return (dummy1);
}

/*ARGSUSED*/
static bool_t
svc_raw_freeargs(xprt, xdr_args, args_ptr)
	SVCXPRT *xprt;
	xdrproc_t xdr_args;
	caddr_t args_ptr;
{
	struct svc_raw_private *srp;
	XDR *xdrs;
	bool_t dummy2;

	trace1(TR_svc_raw_freeargs, 0);
	mutex_lock(&svcraw_lock);
	srp = svc_raw_private;
	if (srp == NULL) {
		mutex_unlock(&svcraw_lock);
		trace1(TR_svc_raw_freeargs, 1);
		return (FALSE);
	}
	mutex_unlock(&svcraw_lock);

	xdrs = &srp->xdr_stream;
	xdrs->x_op = XDR_FREE;
	dummy2 = (*xdr_args)(xdrs, args_ptr);
	trace1(TR_svc_raw_freeargs, 1);
	return (dummy2);
}

/*ARGSUSED*/
static void
svc_raw_destroy(xprt)
SVCXPRT *xprt;
{
	trace1(TR_svc_raw_destroy, 0);
	trace1(TR_svc_raw_destroy, 1);
}

/*ARGSUSED*/
static bool_t
svc_raw_control(xprt, rq, in)
	SVCXPRT *xprt;
	const uint_t	rq;
	void		*in;
{
	trace3(TR_svc_raw_control, 0, xprt, rq);
	switch (rq) {
	case SVCGET_XID: /* fall through for now */
	default:
		trace1(TR_svc_raw_control, 1);
		return (FALSE);
	}
}

static struct xp_ops *
svc_raw_ops()
{
	static struct xp_ops ops;
	extern mutex_t ops_lock;

/* VARIABLES PROTECTED BY ops_lock: ops */

	trace1(TR_svc_raw_ops, 0);
	mutex_lock(&ops_lock);
	if (ops.xp_recv == NULL) {
		ops.xp_recv = svc_raw_recv;
		ops.xp_stat = svc_raw_stat;
		ops.xp_getargs = svc_raw_getargs;
		ops.xp_reply = svc_raw_reply;
		ops.xp_freeargs = svc_raw_freeargs;
		ops.xp_destroy = svc_raw_destroy;
		ops.xp_control = svc_raw_control;
	}
	mutex_unlock(&ops_lock);
	trace1(TR_svc_raw_ops, 1);
	return (&ops);
}
