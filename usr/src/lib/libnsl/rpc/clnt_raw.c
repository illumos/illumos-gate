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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * clnt_raw.c
 *
 * Memory based rpc for simple testing and timing.
 * Interface to create an rpc client and server in the same process.
 * This lets us similate rpc and get round trip overhead, without
 * any interference from the kernel.
 */
#include "mt.h"
#include "rpc_mt.h"
#include <stdlib.h>
#include <rpc/rpc.h>
#include <rpc/raw.h>
#include <syslog.h>

extern mutex_t	clntraw_lock;
#define	MCALL_MSG_SIZE 24
#ifndef UDPMSGSIZE
#define	UDPMSGSIZE 8800
#endif

/*
 * This is the "network" we will be moving stuff over.
 */
static struct clnt_raw_private {
	CLIENT	client_object;
	XDR	xdr_stream;
	char	*raw_buf;	/* should be shared with server handle */
	char	mashl_callmsg[MCALL_MSG_SIZE];
	uint_t	mcnt;
} *clnt_raw_private;

static struct clnt_ops *clnt_raw_ops();

extern void svc_getreq_common(int);
extern bool_t xdr_opaque_auth();

/*
 * Create a client handle for memory based rpc.
 */
CLIENT *
clnt_raw_create(const rpcprog_t prog, const rpcvers_t vers)
{
	struct clnt_raw_private *clp;
	struct rpc_msg call_msg;
	XDR *xdrs;
	CLIENT *client;

/* VARIABLES PROTECTED BY clntraw_lock: clp */

	(void) mutex_lock(&clntraw_lock);
	clp = clnt_raw_private;
	if (clp == NULL) {
		clp = calloc(1, sizeof (*clp));
		if (clp == NULL) {
			(void) mutex_unlock(&clntraw_lock);
			return (NULL);
		}
		if (_rawcombuf == NULL) {
			_rawcombuf = calloc(UDPMSGSIZE, sizeof (char));
			if (_rawcombuf == NULL) {
				syslog(LOG_ERR, "clnt_raw_create: "
					"out of memory.");
				if (clp)
					free(clp);
				(void) mutex_unlock(&clntraw_lock);
				return (NULL);
			}
		}
		clp->raw_buf = _rawcombuf; /* Share it with the server */
		clnt_raw_private = clp;
	}
	xdrs = &clp->xdr_stream;
	client = &clp->client_object;

	/*
	 * pre-serialize the static part of the call msg and stash it away
	 */
	call_msg.rm_direction = CALL;
	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
	call_msg.rm_call.cb_prog = prog;
	call_msg.rm_call.cb_vers = vers;
	xdrmem_create(xdrs, clp->mashl_callmsg, MCALL_MSG_SIZE, XDR_ENCODE);
	if (!xdr_callhdr(xdrs, &call_msg))
		(void) syslog(LOG_ERR,
			(const char *) "clnt_raw_create :  \
			Fatal header serialization error.");

	clp->mcnt = XDR_GETPOS(xdrs);
	XDR_DESTROY(xdrs);

	/*
	 * Set xdrmem for client/server shared buffer
	 */
	xdrmem_create(xdrs, clp->raw_buf, UDPMSGSIZE, XDR_FREE);

	/*
	 * create client handle
	 */
	client->cl_ops = clnt_raw_ops();
	client->cl_auth = authnone_create();
	(void) mutex_unlock(&clntraw_lock);
	return (client);
}

/*ARGSUSED*/
static enum clnt_stat
clnt_raw_call(CLIENT *h, rpcproc_t proc, xdrproc_t xargs, caddr_t argsp,
	xdrproc_t xresults, caddr_t resultsp, struct timeval timeout)
{
	struct clnt_raw_private *clp;
	XDR *xdrs;
	struct rpc_msg msg;
	enum clnt_stat status;
	struct rpc_err error;

	(void) mutex_lock(&clntraw_lock);
	clp = clnt_raw_private;
	xdrs = &clp->xdr_stream;
	if (clp == NULL) {
		(void) mutex_unlock(&clntraw_lock);
		return (RPC_FAILED);
	}
	(void) mutex_unlock(&clntraw_lock);

call_again:
	/*
	 * send request
	 */
	xdrs->x_op = XDR_ENCODE;
	XDR_SETPOS(xdrs, 0);
/* LINTED pointer alignment */
	((struct rpc_msg *)clp->mashl_callmsg)->rm_xid++;
	if ((!XDR_PUTBYTES(xdrs, clp->mashl_callmsg, clp->mcnt)) ||
	    (!XDR_PUTINT32(xdrs, (int32_t *)&proc)) ||
	    (!AUTH_MARSHALL(h->cl_auth, xdrs)) ||
	    (!(*xargs)(xdrs, argsp)))
		return (RPC_CANTENCODEARGS);
	(void) XDR_GETPOS(xdrs);  /* called just to cause overhead */

	/*
	 * We have to call server input routine here because this is
	 * all going on in one process.
	 * By convention using FD_SETSIZE as the psuedo file descriptor.
	 */
	svc_getreq_common(FD_SETSIZE);

	/*
	 * get results
	 */
	xdrs->x_op = XDR_DECODE;
	XDR_SETPOS(xdrs, 0);
	msg.acpted_rply.ar_verf = _null_auth;
	msg.acpted_rply.ar_results.where = resultsp;
	msg.acpted_rply.ar_results.proc = xresults;
	if (!xdr_replymsg(xdrs, &msg))
		return (RPC_CANTDECODERES);
	if ((msg.rm_reply.rp_stat == MSG_ACCEPTED) &&
		    (msg.acpted_rply.ar_stat == SUCCESS))
		status = RPC_SUCCESS;
	else {
		__seterr_reply(&msg, &error);
		status = error.re_status;
	}

	if (status == RPC_SUCCESS) {
		if (!AUTH_VALIDATE(h->cl_auth, &msg.acpted_rply.ar_verf)) {
			status = RPC_AUTHERROR;
		}
		/* end successful completion */
	} else {
		if (AUTH_REFRESH(h->cl_auth, &msg))
			goto call_again;
		/* end of unsuccessful completion */
	}

	if (status == RPC_SUCCESS) {
		if (!AUTH_VALIDATE(h->cl_auth, &msg.acpted_rply.ar_verf)) {
			status = RPC_AUTHERROR;
		}
		if (msg.acpted_rply.ar_verf.oa_base != NULL) {
			xdrs->x_op = XDR_FREE;
			(void) xdr_opaque_auth(xdrs,
					&(msg.acpted_rply.ar_verf));
		}
	}
	return (status);
}

/*ARGSUSED*/
static enum clnt_stat
clnt_raw_send(CLIENT *h, rpcproc_t proc, xdrproc_t xargs, caddr_t argsp)
{
	struct clnt_raw_private *clp;
	XDR *xdrs;

	(void) mutex_lock(&clntraw_lock);
	clp = clnt_raw_private;
	xdrs = &clp->xdr_stream;
	if (clp == NULL) {
		(void) mutex_unlock(&clntraw_lock);
		return (RPC_FAILED);
	}
	(void) mutex_unlock(&clntraw_lock);

	/*
	 * send request
	 */
	xdrs->x_op = XDR_ENCODE;
	XDR_SETPOS(xdrs, 0);
/* LINTED pointer alignment */
	((struct rpc_msg *)clp->mashl_callmsg)->rm_xid++;
	if ((!XDR_PUTBYTES(xdrs, clp->mashl_callmsg, clp->mcnt)) ||
	    (!XDR_PUTINT32(xdrs, (int32_t *)&proc)) ||
	    (!AUTH_MARSHALL(h->cl_auth, xdrs)) ||
	    (!(*xargs)(xdrs, argsp)))
		return (RPC_CANTENCODEARGS);
	(void) XDR_GETPOS(xdrs);  /* called just to cause overhead */

	/*
	 * We have to call server input routine here because this is
	 * all going on in one process.
	 * By convention using FD_SETSIZE as the psuedo file descriptor.
	 */
	svc_getreq_common(FD_SETSIZE);

	return (RPC_SUCCESS);
}

/*ARGSUSED*/
static void
clnt_raw_geterr(CLIENT *cl, struct rpc_err *errp)
{
}

/*ARGSUSED*/
static bool_t
clnt_raw_freeres(CLIENT *cl, xdrproc_t xdr_res, caddr_t res_ptr)
{
	struct clnt_raw_private *clp;
	XDR *xdrs;

	(void) mutex_lock(&clntraw_lock);
	clp = clnt_raw_private;
	xdrs = &clp->xdr_stream;
	if (clp == NULL) {
		(void) mutex_unlock(&clntraw_lock);
		return (FALSE);
	}
	(void) mutex_unlock(&clntraw_lock);
	xdrs->x_op = XDR_FREE;
	return ((*xdr_res)(xdrs, res_ptr));
}

/*ARGSUSED*/
static void
clnt_raw_abort(CLIENT *cl, struct rpc_err *errp)
{
}

/*ARGSUSED*/
static bool_t
clnt_raw_control(CLIENT *cl, int request, char *info)
{
	return (FALSE);
}

/*ARGSUSED*/
static void
clnt_raw_destroy(CLIENT *cl)
{
}

static struct clnt_ops *
clnt_raw_ops(void)
{
	static struct clnt_ops ops;
	extern mutex_t	ops_lock;

	/* VARIABLES PROTECTED BY ops_lock: ops */

	(void) mutex_lock(&ops_lock);
	if (ops.cl_call == NULL) {
		ops.cl_call = clnt_raw_call;
		ops.cl_send = clnt_raw_send;
		ops.cl_abort = clnt_raw_abort;
		ops.cl_geterr = clnt_raw_geterr;
		ops.cl_freeres = clnt_raw_freeres;
		ops.cl_destroy = clnt_raw_destroy;
		ops.cl_control = clnt_raw_control;
	}
	(void) mutex_unlock(&ops_lock);
	return (&ops);
}
