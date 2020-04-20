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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * Boot subsystem client side rpc (TCP)
 */

#include <sys/salib.h>
#include <sys/errno.h>
#include <rpc/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "socket_inet.h"
#include "ipv4.h"
#include "clnt.h"
#include <rpc/rpc.h>
#include "brpc.h"
#include "pmap.h"
#include <sys/promif.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/auth_sys.h>
#include "auth_inet.h"
#include <rpc/rpc_msg.h>
#include <sys/bootdebug.h>

#define	dprintf if (boothowto & RB_DEBUG) printf

#define	MCALL_MSG_SIZE 24

extern int errno;

extern void xdrrec_create();
extern bool_t xdrrec_endofrecord();
extern bool_t xdrrec_skiprecord();

/*
 * If we create another clnt type this should be
 * moved to a common file
 */
struct rpc_createerr rpc_createerr;

static int readtcp();
static int writetcp();

static struct clnt_ops *clntbtcp_ops();

/*
 * Private data kept per client handle
 */
struct ct_data {
	int			ct_sock;
	bool_t			ct_closeit;
	struct sockaddr_in	ct_raddr;
	uint_t			ct_wait_msec;
	struct timeval		ct_total;
	struct rpc_err		ct_error;
	XDR			ct_xdrs;
	char			ct_mcall[MCALL_MSG_SIZE];
	uint_t			ct_mpos;
	uint_t			ct_xdrpos;
};

/*
 * Create a TCP based client handle.
 * If *sockp<0, *sockp is set to a newly created TCP socket.
 * If raddr->sin_port is 0 a binder on the remote machine
 * is consulted for the correct port number.
 * NB: It is the clients responsibility to close *sockp.
 * NB: The rpch->cl_auth is initialized to null authentication.
 *	Caller may wish to set this something more useful.
 *
 * wait is the amount of time used between retransmitting a call if
 * no response has been heard;  retransmition occurs until the actual
 * rpc call times out.
 *
 * sendsz and recvsz are the maximum allowable packet sizes that can be
 * sent and received.
 */
CLIENT *
clntbtcp_create(
	struct sockaddr_in *raddr,
	rpcprog_t program,
	rpcvers_t version,
	struct timeval wait,
	int *sockp,
	uint_t sendsz,
	uint_t recvsz)
{
	CLIENT *cl;
	struct ct_data *ct;
	struct rpc_msg call_msg;
#if 0	/* XXX not yet */
	int min_buf_sz;
	int pref_buf_sz = 64 * 1024; /* 64 KB */
	socklen_t optlen;
#endif /* not yet */
	cl = (CLIENT *)bkmem_alloc(sizeof (CLIENT));
	if (cl == NULL) {
		errno = ENOMEM;
		rpc_createerr.cf_stat = RPC_SYSTEMERROR;
		rpc_createerr.cf_error.re_errno = errno;
		return ((CLIENT *)NULL);
	}

	ct = (struct ct_data *)bkmem_alloc(sizeof (*ct));
	if (ct == NULL) {
		errno = ENOMEM;
		rpc_createerr.cf_stat = RPC_SYSTEMERROR;
		rpc_createerr.cf_error.re_errno = errno;
		goto fooy;
	}

	if (raddr->sin_port == 0) {
		ushort_t port;
		if ((port = bpmap_getport(program, version,
				&(rpc_createerr.cf_stat), raddr, NULL)) == 0) {
			goto fooy;
		}
		raddr->sin_port = htons(port);
	}

	if (*sockp < 0) {
		struct sockaddr_in from;

		*sockp = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (*sockp < 0) {
			rpc_createerr.cf_stat = RPC_SYSTEMERROR;
			rpc_createerr.cf_error.re_errno = errno;
			goto fooy;
		}
		/*
		 * Bootparams assumes a local net, so be sure to let lower
		 * layer protocols know not to route.
		 */
		if (dontroute) {
			(void) setsockopt(*sockp, SOL_SOCKET, SO_DONTROUTE,
				(const void *)&dontroute, sizeof (dontroute));
		}

		/* attempt to bind to priv port */
		from.sin_family = AF_INET;
		ipv4_getipaddr(&from.sin_addr);
		from.sin_addr.s_addr = htonl(from.sin_addr.s_addr);
		from.sin_port = get_source_port(TRUE);

		if (bind(*sockp, (struct sockaddr *)&from, sizeof (from)) < 0) {
			rpc_createerr.cf_stat = RPC_SYSTEMERROR;
			rpc_createerr.cf_error.re_errno = errno;
			if (*sockp > 0)
				(void) close(*sockp);
			goto fooy;
		}

		if (connect(*sockp, (struct sockaddr *)raddr,
			    sizeof (struct sockaddr_in)) < 0) {
			rpc_createerr.cf_stat = RPC_SYSTEMERROR;
			rpc_createerr.cf_error.re_errno = errno;
			if (*sockp > 0)
				(void) close(*sockp);
			goto fooy;
		}

#if 0 /* XXX not yet */
		/*
		 * In the future we may want RPC to use larger transfer sizes
		 * over TCP.  In this case we will want to increase the
		 * window size.
		 */
		/*
		 * Resize the receive window if possible
		 */
		optlen = sizeof (int);
		if (getsockopt(*sockp, SOL_SOCKET, SO_RCVBUF,
				(void *)&min_buf_sz, &optlen) != 0)
			goto keep_going;

		if (min_buf_sz < pref_buf_sz)
			(void) setsockopt(*sockp, SOL_SOCKET, SO_RCVBUF,
				(const void *)&pref_buf_sz, sizeof (int));

keep_going:
#endif		/* not yet */
		ct->ct_closeit = TRUE;
	} else
		ct->ct_closeit = FALSE;

	/*
	 * Set up the private data
	 */
	ct->ct_sock = *sockp;
	ct->ct_wait_msec = 0;
	ct->ct_total.tv_sec = wait.tv_sec;
	ct->ct_total.tv_usec = -1;
	ct->ct_raddr = *raddr;

	/*
	 * Initialize the call message
	 */

	/*
	 * XXX - The xid might need to be randomized more.  Imagine if there
	 * are a rack of blade servers all booting at the same time.  They
	 * may cause havoc on the server with xid replays.
	 */
	call_msg.rm_xid = (uint_t)prom_gettime() + 1;
	call_msg.rm_direction = CALL;
	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
	call_msg.rm_call.cb_prog = program;
	call_msg.rm_call.cb_vers = version;

	/*
	 * pre-serialize the static part of the call msg and stash it away
	 */
	xdrmem_create(&(ct->ct_xdrs), ct->ct_mcall, MCALL_MSG_SIZE,
			XDR_ENCODE);
	if (! xdr_callhdr(&(ct->ct_xdrs), &call_msg)) {
		if (ct->ct_closeit)
			(void) close(*sockp);
		goto fooy;
	}
	ct->ct_mpos = XDR_GETPOS(&(ct->ct_xdrs));
	XDR_DESTROY(&(ct->ct_xdrs));

	/*
	 * XXX - Memory allocations can fail in xdrrec_create, so we need to
	 * be able to catch those errors.
	 */
	xdrrec_create(&(ct->ct_xdrs), sendsz, recvsz, (caddr_t)ct, readtcp,
			writetcp);

	cl->cl_ops = clntbtcp_ops();
	cl->cl_private = (caddr_t)ct;
	cl->cl_auth = authnone_create();
	return (cl);

fooy:
	if (ct)
		bkmem_free((caddr_t)ct, sizeof (*ct));
	if (cl)
		bkmem_free((caddr_t)cl, sizeof (CLIENT));
	return ((CLIENT *)NULL);
}

static enum clnt_stat
clntbtcp_call(
	CLIENT *cl,
	rpcproc_t proc,
	xdrproc_t xargs,
	caddr_t argsp,
	xdrproc_t xdr_results,
	caddr_t resultsp,
	struct timeval utimeout)
{
	struct ct_data *ct;
	XDR *xdrs;
	struct rpc_msg reply_msg;
	uint32_t x_id;
	uint32_t *msg_x_id;
	bool_t shipnow;
	int nrefreshes = 2;	/* number of times to refresh cred */
	struct timeval timeout;

	ct = (struct ct_data *)cl->cl_private;
	msg_x_id = (uint32_t *)ct->ct_mcall;

	xdrs = &(ct->ct_xdrs);

	ct->ct_total = utimeout;

	/*
	 * We have to be able to wait for some non-zero period of time, so
	 * use a default timeout.
	 */
	if (ct->ct_total.tv_sec == 0)
		ct->ct_total.tv_sec = RPC_RCVWAIT_MSEC / 1000;

	ct->ct_wait_msec = ct->ct_total.tv_sec * 1000 +
		ct->ct_total.tv_usec / 1000;

	timeout = ct->ct_total;

	shipnow = (xdr_results == (xdrproc_t)0 && timeout.tv_sec == 0 &&
			timeout.tv_usec == 0) ? FALSE : TRUE;

call_again:
	xdrs->x_op = XDR_ENCODE;
	ct->ct_error.re_status = RPC_SUCCESS;
	x_id = ntohl(++(*msg_x_id));
	if ((! XDR_PUTBYTES(xdrs, ct->ct_mcall, ct->ct_mpos)) ||
	    (! XDR_PUTINT32(xdrs, (int32_t *)&proc)) ||
	    (! AUTH_MARSHALL(cl->cl_auth, xdrs, NULL)) ||
	    (! (*xargs)(xdrs, argsp))) {
		(void) xdrrec_endofrecord(xdrs, TRUE);
		ct->ct_error.re_status = RPC_CANTENCODEARGS;
		printf("clntbtcp_call: xdr encode args failed\n");
		return (ct->ct_error.re_status);
	}

	if (!xdrrec_endofrecord(xdrs, shipnow)) {
		printf("clntbtcp_call: rpc cansend error\n");
		ct->ct_error.re_status = RPC_CANTSEND;
		return (ct->ct_error.re_status);
	}

	if (!shipnow)
		return (RPC_SUCCESS);

	if (timeout.tv_sec == 0 && timeout.tv_usec == 0) {
		ct->ct_error.re_status = RPC_TIMEDOUT;
		return (ct->ct_error.re_status);
	}

	xdrs->x_op = XDR_DECODE;

	/* CONSTCOND */
	while (TRUE) {
		reply_msg.acpted_rply.ar_verf = _null_auth;
		reply_msg.acpted_rply.ar_results.where = NULL;
		reply_msg.acpted_rply.ar_results.proc = xdr_void;
		if (!xdrrec_skiprecord(xdrs)) {
			return (ct->ct_error.re_status);
		}

		if (!xdr_replymsg(xdrs, &reply_msg)) {
			if (ct->ct_error.re_status == RPC_SUCCESS)
				continue;
			return (ct->ct_error.re_status);
		}
		if (reply_msg.rm_xid == x_id) {
			break;
		}
	}

	/*
	 * process header
	 */
	_seterr_reply(&reply_msg, &(ct->ct_error));
	if (ct->ct_error.re_status == RPC_SUCCESS) {
		if (!AUTH_VALIDATE(cl->cl_auth,
				&reply_msg.acpted_rply.ar_verf)) {
			ct->ct_error.re_status = RPC_AUTHERROR;
			ct->ct_error.re_why = AUTH_INVALIDRESP;
		} else if (!(*xdr_results)(xdrs, resultsp)) {
			if (ct->ct_error.re_status == RPC_SUCCESS) {
				ct->ct_error.re_status = RPC_CANTDECODERES;
			}
		}
		if (reply_msg.acpted_rply.ar_verf.oa_base != NULL) {
			xdrs->x_op = XDR_FREE;
			(void) xdr_opaque_auth(xdrs,
				&(reply_msg.acpted_rply.ar_verf));
		}
	} else {
		if (nrefreshes-- && AUTH_REFRESH(cl->cl_auth, &reply_msg,
						NULL)) {
			goto call_again;
		}
	}
	return (ct->ct_error.re_status);
}

/*
 * Interface between xdr serializer and tcp connection.
 * Behaves like the system calls, read & write, but keeps some error state
 * around for the rpc level.
 */
static int
readtcp(struct ct_data *ct,
	caddr_t buf,
	int len)
{
	int inlen = 0;
	uint_t start, diff;
	struct sockaddr from;
	uint_t fromlen = sizeof (from);

	if (len <= 0)
		return (0);

	/*
	 * Do non-blocking reads here until we get some data or timeout
	 */
	start = prom_gettime();
	while ((inlen = recvfrom(ct->ct_sock, buf, len, 0, &from,
					&fromlen)) == 0) {
		diff = (uint_t)(prom_gettime() - start);
		if (diff > ct->ct_wait_msec) {
			errno = ETIMEDOUT;
			inlen = -1;
			break;
		}
	}
#ifdef DEBUG
	printf("readtcp: inlen = %d\n", inlen);
#endif
	switch (inlen) {
	case 0:
		/* premature eof */
		ct->ct_error.re_errno = ECONNRESET;
		ct->ct_error.re_status = RPC_CANTRECV;
		inlen = -1;  /* it's really an error */
		break;
	case -1:
		ct->ct_error.re_errno = errno;
		ct->ct_error.re_status = RPC_CANTRECV;
		break;
	}

	return (inlen);
}

static int
writetcp(ct, buf, len)
	struct ct_data *ct;
	caddr_t buf;
	int len;
{
	register int i, cnt;

	for (cnt = len; cnt > 0; cnt -= i, buf += i) {
		if ((i = sendto(ct->ct_sock, (void *)buf, cnt, 0,
				(struct sockaddr *)&(ct->ct_raddr),
				sizeof (ct->ct_raddr))) == -1) {
			ct->ct_error.re_errno = errno;
			ct->ct_error.re_status = RPC_CANTSEND;
			return (-1);
		}
	}
	return (len);
}

static void
clntbtcp_geterr(
	CLIENT *cl,
	struct rpc_err *errp)
{
	struct ct_data *ct = (struct ct_data *)cl->cl_private;

	*errp = ct->ct_error;
}


static bool_t
clntbtcp_freeres(
	CLIENT *cl,
	xdrproc_t xdr_res,
	caddr_t res_ptr)
{
	struct ct_data *ct = (struct ct_data *)cl->cl_private;
	XDR *xdrs = &(ct->ct_xdrs);

	xdrs->x_op = XDR_FREE;
	return ((*xdr_res)(xdrs, res_ptr));
}

static void
clntbtcp_abort()
	/* CLIENT *h; */
{
}

/* ARGSUSED */
static bool_t
clntbtcp_control(
	CLIENT *cl,
	int request,
	char *info)
{
	/* Not implemented in boot */
	return (FALSE);
}

static void
clntbtcp_destroy(CLIENT *cl)
{
	struct ct_data *ct = (struct ct_data *)cl->cl_private;

	if (ct->ct_closeit) {
		(void) socket_close(ct->ct_sock);
	}
	XDR_DESTROY(&(ct->ct_xdrs));
	bkmem_free((caddr_t)ct, (sizeof (struct ct_data)));
	bkmem_free((caddr_t)cl, sizeof (CLIENT));
}

static struct clnt_ops *
clntbtcp_ops()
{
	static struct clnt_ops ops;

	if (ops.cl_call == NULL) {
		ops.cl_call = clntbtcp_call;
		ops.cl_abort = clntbtcp_abort;
		ops.cl_geterr = clntbtcp_geterr;
		ops.cl_freeres = clntbtcp_freeres;
		ops.cl_destroy = clntbtcp_destroy;
		ops.cl_control = clntbtcp_control;
	}
	return (&ops);
}
