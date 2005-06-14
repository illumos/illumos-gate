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
 * clnt_raw.c
 *
 * Memory based rpc for simple testing and timing.
 * Interface to create an rpc client and server in the same process.
 * This lets us similate rpc and get round trip overhead, without
 * any interference from the kernel.
 */
#include "mt.h"
#include "rpc_mt.h"
#include <rpc/rpc.h>
#include <rpc/trace.h>
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

extern char	*calloc();
extern void	free();
extern void svc_getreq_common(int);
extern bool_t xdr_opaque_auth();

/*
 * Create a client handle for memory based rpc.
 */
CLIENT *
clnt_raw_create(rpcprog_t prog, rpcvers_t vers)
{
	struct clnt_raw_private *clp;
	struct rpc_msg call_msg;
	XDR *xdrs;
	CLIENT *client;

/* VARIABLES PROTECTED BY clntraw_lock: clp */

	trace3(TR_clnt_raw_create, 0, prog, vers);
	mutex_lock(&clntraw_lock);
	clp = clnt_raw_private;
	if (clp == NULL) {
/* LINTED pointer alignment */
		clp = (struct clnt_raw_private *)calloc(1, sizeof (*clp));
		if (clp == NULL) {
			mutex_unlock(&clntraw_lock);
			trace3(TR_clnt_raw_create, 1, prog, vers);
			return ((CLIENT *)NULL);
		}
		if (_rawcombuf == NULL) {
			_rawcombuf = (char *)calloc(UDPMSGSIZE, sizeof (char));
			if (_rawcombuf == NULL) {
				syslog(LOG_ERR, "clnt_raw_create: "
					"out of memory.");
				if (clp)
					free(clp);
				mutex_unlock(&clntraw_lock);
				trace3(TR_clnt_raw_create, 1, prog, vers);
				return ((CLIENT *)NULL);
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
	if (! xdr_callhdr(xdrs, &call_msg))
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
	mutex_unlock(&clntraw_lock);
	trace3(TR_clnt_raw_create, 1, prog, vers);
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

	trace3(TR_clnt_raw_call, 0, h, proc);
	mutex_lock(&clntraw_lock);
	clp = clnt_raw_private;
	xdrs = &clp->xdr_stream;
	if (clp == NULL) {
		mutex_unlock(&clntraw_lock);
		trace3(TR_clnt_raw_call, 1, h, proc);
		return (RPC_FAILED);
	}
	mutex_unlock(&clntraw_lock);

call_again:
	/*
	 * send request
	 */
	xdrs->x_op = XDR_ENCODE;
	XDR_SETPOS(xdrs, 0);
/* LINTED pointer alignment */
	((struct rpc_msg *)clp->mashl_callmsg)->rm_xid++;
	if ((! XDR_PUTBYTES(xdrs, clp->mashl_callmsg, clp->mcnt)) ||
	    (! XDR_PUTINT32(xdrs, (int32_t *)&proc)) ||
	    (! AUTH_MARSHALL(h->cl_auth, xdrs)) ||
	    (! (*xargs)(xdrs, argsp))) {
		trace3(TR_clnt_raw_call, 1, h, proc);
		return (RPC_CANTENCODEARGS);
	}
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
	if (! xdr_replymsg(xdrs, &msg)) {
		trace3(TR_clnt_raw_call, 1, h, proc);
		return (RPC_CANTDECODERES);
	}
	if ((msg.rm_reply.rp_stat == MSG_ACCEPTED) &&
		    (msg.acpted_rply.ar_stat == SUCCESS))
		status = RPC_SUCCESS;
	else {
		__seterr_reply(&msg, &error);
		status = error.re_status;
	}

	if (status == RPC_SUCCESS) {
		if (! AUTH_VALIDATE(h->cl_auth, &msg.acpted_rply.ar_verf)) {
			status = RPC_AUTHERROR;
		}
		/* end successful completion */
	} else {
		if (AUTH_REFRESH(h->cl_auth, &msg))
			goto call_again;
		/* end of unsuccessful completion */
	}

	if (status == RPC_SUCCESS) {
		if (! AUTH_VALIDATE(h->cl_auth, &msg.acpted_rply.ar_verf)) {
			status = RPC_AUTHERROR;
		}
		if (msg.acpted_rply.ar_verf.oa_base != NULL) {
			xdrs->x_op = XDR_FREE;
			(void) xdr_opaque_auth(xdrs,
					&(msg.acpted_rply.ar_verf));
		}
	}
	trace3(TR_clnt_raw_call, 1, h, proc);
	return (status);
}

/*ARGSUSED*/
static enum clnt_stat
clnt_raw_send(CLIENT *h, rpcproc_t proc, xdrproc_t xargs, caddr_t argsp)
{
	struct clnt_raw_private *clp;
	XDR *xdrs;

	trace3(TR_clnt_raw_send, 0, h, proc);

	mutex_lock(&clntraw_lock);
	clp = clnt_raw_private;
	xdrs = &clp->xdr_stream;
	if (clp == NULL) {
		mutex_unlock(&clntraw_lock);
		trace3(TR_clnt_raw_send, 1, h, proc);
		return (RPC_FAILED);
	}
	mutex_unlock(&clntraw_lock);

	/*
	 * send request
	 */
	xdrs->x_op = XDR_ENCODE;
	XDR_SETPOS(xdrs, 0);
/* LINTED pointer alignment */
	((struct rpc_msg *)clp->mashl_callmsg)->rm_xid++;
	if ((! XDR_PUTBYTES(xdrs, clp->mashl_callmsg, clp->mcnt)) ||
	    (! XDR_PUTINT32(xdrs, (int32_t *)&proc)) ||
	    (! AUTH_MARSHALL(h->cl_auth, xdrs)) ||
	    (! (*xargs)(xdrs, argsp))) {
		trace3(TR_clnt_raw_send, 1, h, proc);
		return (RPC_CANTENCODEARGS);
	}
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
	trace1(TR_clnt_raw_geterr, 0);
	trace1(TR_clnt_raw_geterr, 1);
}

/*ARGSUSED*/
static bool_t
clnt_raw_freeres(CLIENT *cl, xdrproc_t xdr_res, caddr_t res_ptr)
{
	struct clnt_raw_private *clp;
	XDR *xdrs;
	static bool_t dummy;

	trace2(TR_clnt_raw_freeres, 0, cl);
	mutex_lock(&clntraw_lock);
	clp = clnt_raw_private;
	xdrs = &clp->xdr_stream;
	if (clp == NULL) {
		mutex_unlock(&clntraw_lock);
		trace2(TR_clnt_raw_freeres, 1, cl);
		return (FALSE);
	}
	mutex_unlock(&clntraw_lock);
	xdrs->x_op = XDR_FREE;
	dummy  = (*xdr_res)(xdrs, res_ptr);
	trace2(TR_clnt_raw_freeres, 1, cl);
	return (dummy);
}

/*ARGSUSED*/
static void
clnt_raw_abort(CLIENT *cl, struct rpc_err *errp)
{
	trace1(TR_clnt_raw_abort, 0);
	trace1(TR_clnt_raw_abort, 1);
}

/*ARGSUSED*/
static bool_t
clnt_raw_control(CLIENT *cl, int request, char *info)
{
	trace1(TR_clnt_raw_control, 0);
	trace1(TR_clnt_raw_control, 1);
	return (FALSE);
}

/*ARGSUSED*/
static void
clnt_raw_destroy(CLIENT *cl)
{
	trace1(TR_clnt_raw_destroy, 0);
	trace1(TR_clnt_raw_destroy, 1);
}

static struct clnt_ops *
clnt_raw_ops(void)
{
	static struct clnt_ops ops;
	extern mutex_t	ops_lock;

	/* VARIABLES PROTECTED BY ops_lock: ops */

	trace1(TR_clnt_raw_ops, 0);
	mutex_lock(&ops_lock);
	if (ops.cl_call == NULL) {
		ops.cl_call = clnt_raw_call;
		ops.cl_send = clnt_raw_send;
		ops.cl_abort = clnt_raw_abort;
		ops.cl_geterr = clnt_raw_geterr;
		ops.cl_freeres = clnt_raw_freeres;
		ops.cl_destroy = clnt_raw_destroy;
		ops.cl_control = clnt_raw_control;
	}
	mutex_unlock(&ops_lock);
	trace1(TR_clnt_raw_ops, 1);
	return (&ops);
}
