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

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * Boot subsystem client side rpc
 */

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
#include <sys/salib.h>
#include <sys/bootdebug.h>

#define	dprintf if (boothowto & RB_DEBUG) printf

/* retries to send RPC message when sendto fails */
#define	RPC_UDP_SEND_RETRIES	3

extern int errno;

/*
 * If we create another clnt type this should be
 * moved to a common file
 */
struct rpc_createerr rpc_createerr;

static struct clnt_ops *clntbudp_ops();

/*
 * Private data kept per client handle
 */
struct cu_data {
	int		   cu_sock;
	bool_t		   cu_closeit;
	struct sockaddr_in cu_raddr;
	int		   cu_rlen;
	struct timeval	   cu_wait;
	struct timeval	   cu_total;
	struct rpc_err	   cu_error;
	XDR		   cu_outxdrs;
	uint_t		   cu_xdrpos;
	uint_t		   cu_sendsz;
	char		   *cu_outbuf;
	uint_t		   cu_recvsz;
	char		   cu_inbuf[1];
};

/*
 * Create a UDP based client handle.
 * If *sockp<0, *sockp is set to a newly created UPD socket.
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
clntbudp_bufcreate(raddr, program, version, wait, sockp, sendsz, recvsz)
	struct sockaddr_in *raddr;
	rpcprog_t program;
	rpcvers_t version;
	struct timeval wait;
	int *sockp;
	uint_t sendsz;
	uint_t recvsz;
{
	CLIENT *cl;
	struct cu_data *cu;
	struct rpc_msg call_msg;

	cl = (CLIENT *)bkmem_alloc(sizeof (CLIENT));
	if (cl == NULL) {
		errno = ENOMEM;
		rpc_createerr.cf_stat = RPC_SYSTEMERROR;
		rpc_createerr.cf_error.re_errno = errno;
		return ((CLIENT *)NULL);
	}
	sendsz = ((sendsz + 3) / 4) * 4;
	recvsz = ((recvsz + 3) / 4) * 4;
	cu = (struct cu_data *)bkmem_alloc(sizeof (*cu) + sendsz + recvsz);
	if (cu == NULL) {
		errno = ENOMEM;
		rpc_createerr.cf_stat = RPC_SYSTEMERROR;
		rpc_createerr.cf_error.re_errno = errno;
		goto fooy;
	}
	cu->cu_outbuf = &cu->cu_inbuf[recvsz];

	if (raddr->sin_port == 0) {
		ushort_t port;
		if ((port = bpmap_getport(program, version,
				&(rpc_createerr.cf_stat), raddr, NULL)) == 0) {
			goto fooy;
		}
		raddr->sin_port = htons(port);
	}
	cl->cl_ops = clntbudp_ops();
	cl->cl_private = (caddr_t)cu;
	cu->cu_raddr = *raddr;
	cu->cu_rlen = sizeof (cu->cu_raddr);
	cu->cu_wait = wait;
	cu->cu_total.tv_sec = -1;
	cu->cu_total.tv_usec = -1;
	cu->cu_sendsz = sendsz;
	cu->cu_recvsz = recvsz;
	call_msg.rm_xid = (uint_t)prom_gettime() + 1;
	call_msg.rm_direction = CALL;
	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
	call_msg.rm_call.cb_prog = program;
	call_msg.rm_call.cb_vers = version;
	xdrmem_create(&(cu->cu_outxdrs), cu->cu_outbuf,
	    sendsz, XDR_ENCODE);
	if (! xdr_callhdr(&(cu->cu_outxdrs), &call_msg)) {
		goto fooy;
	}
	cu->cu_xdrpos = XDR_GETPOS(&(cu->cu_outxdrs));
	cu->cu_closeit = FALSE;

	if (*sockp < 0) {
		struct sockaddr_in from;

		*sockp = socket(PF_INET, SOCK_DGRAM, 0);
		if (*sockp < 0) {
			rpc_createerr.cf_stat = RPC_SYSTEMERROR;
			rpc_createerr.cf_error.re_errno = errno;
			goto fooy;
		}

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
			goto fooy;
		}

		cu->cu_closeit = TRUE;
	}

	cu->cu_sock = *sockp;
	cl->cl_auth = authnone_create();
	return (cl);
fooy:
	if (cu)
		bkmem_free((caddr_t)cu, sizeof (*cu) + sendsz + recvsz);
	if (cl)
		bkmem_free((caddr_t)cl, sizeof (CLIENT));
	return ((CLIENT *)NULL);
}

CLIENT *
clntbudp_create(raddr, program, version, wait, sockp)
	struct sockaddr_in *raddr;
	rpcprog_t program;
	rpcvers_t version;
	struct timeval wait;
	int *sockp;
{

	return (clntbudp_bufcreate(raddr, program, version, wait, sockp,
	    UDPMSGSIZE, UDPMSGSIZE));
}

static enum clnt_stat
clntbudp_call(cl, proc, xargs, argsp, xresults, resultsp, utimeout)
	CLIENT		*cl;		/* client handle */
	rpcproc_t	proc;		/* procedure number */
	xdrproc_t	xargs;		/* xdr routine for args */
	caddr_t		argsp;		/* pointer to args */
	xdrproc_t	xresults;	/* xdr routine for results */
	caddr_t		resultsp;	/* pointer to results */
	struct timeval	utimeout;	/* seconds to wait before giving up */
{
	struct cu_data *cu;
	XDR *xdrs;
	int outlen;
	int inlen;
	socklen_t fromlen;
	struct sockaddr_in from;
	struct rpc_msg reply_msg;
	XDR reply_xdrs;
	uint_t xdelay;
	int wait_time;
	bool_t ok;
	int nrefreshes = 2;	/* number of times to refresh cred */
	struct timeval timeout;
	int errors;
	short send_retries = RPC_UDP_SEND_RETRIES;

	cu = (struct cu_data *)cl->cl_private;
	if (cu->cu_total.tv_usec == -1)
		timeout = utimeout;	/* use supplied timeout */
	else
		timeout = cu->cu_total; /* use default timeout */

	/*
	 * set a media level timeout
	 */
	xdelay = cu->cu_wait.tv_sec + 1000 + cu->cu_wait.tv_usec / 1000;
	(void) setsockopt(cu->cu_sock, SOL_SOCKET, SO_RCVTIMEO,
				(void *)&xdelay, sizeof (xdelay));

	wait_time = (timeout.tv_sec * 1000) + (timeout.tv_usec / 1000);
	if (wait_time == 0)
		wait_time = RPC_RCVWAIT_MSEC;
	wait_time += prom_gettime();

	errors = 0;

call_again:
	xdrs = &(cu->cu_outxdrs);
	xdrs->x_op = XDR_ENCODE;
	(void) XDR_SETPOS(xdrs, cu->cu_xdrpos);
	/*
	 * the transaction is the first thing in the out buffer
	 */
	(*(ushort_t *)(cu->cu_outbuf))++;
	if ((! XDR_PUTINT32(xdrs, (int32_t *)&proc)) ||
	    (! AUTH_MARSHALL(cl->cl_auth, xdrs, NULL)) ||
	    (! (*xargs)(xdrs, argsp)))
		return (cu->cu_error.re_status = RPC_CANTENCODEARGS);
	outlen = (int)XDR_GETPOS(xdrs);

send_again:
	if (sendto(cu->cu_sock, cu->cu_outbuf, outlen, 0,
	    (struct sockaddr *)&(cu->cu_raddr), cu->cu_rlen)
	    != outlen) {
		if (errno == ETIMEDOUT) {
			/*
			 * sendto() times out probably because
			 * ARP times out while waiting for reply.
			 * We retry sending RPC message again.
			 */
			if (send_retries-- > 0) {
				dprintf("clntbudp_call: timedout, try sending"
				    "RPC again\n");
				errno = 0;
				goto send_again;
			}
			cu->cu_error.re_status = RPC_TIMEDOUT;
		} else {
			cu->cu_error.re_status = RPC_CANTSEND;
		}
		cu->cu_error.re_errno = errno;
		return (cu->cu_error.re_status);
	}

	/*
	 * sub-optimal code appears here because we have
	 * some clock time to spare while the packets are in flight.
	 * (We assume that this is actually only executed once.)
	 */
recv_again:
	reply_msg.acpted_rply.ar_verf = _null_auth;
	reply_msg.acpted_rply.ar_results.where = resultsp;
	reply_msg.acpted_rply.ar_results.proc = xresults;

	for (;;) {
		if (errors >= RPC_ALLOWABLE_ERRORS)
			return (cu->cu_error.re_status);

		if (prom_gettime() >= wait_time) {
			cu->cu_error.re_errno = ETIMEDOUT;
			return (cu->cu_error.re_status = RPC_TIMEDOUT);
		}

		/*
		 * Use MSG_DONTWAIT because we have set
		 * a media level timeout above.
		 */
		fromlen = sizeof (struct sockaddr);

		inlen = recvfrom(cu->cu_sock, cu->cu_inbuf,
				(int)cu->cu_recvsz, MSG_DONTWAIT,
				(struct sockaddr *)&from, &fromlen);

		if (inlen < 0) {
			if (errno == EWOULDBLOCK) {
				/*
				 * Media level has timedout
				 * and no more data in buffers.
				 */
				goto send_again;
			}

			cu->cu_error.re_status = RPC_CANTRECV;
			if (errno == ETIMEDOUT) {
				errno = ETIMEDOUT;
				cu->cu_error.re_status = RPC_TIMEDOUT;
			}

			cu->cu_error.re_errno = errno;
			return (cu->cu_error.re_status);
		}

		if (inlen < sizeof (uint32_t))
			continue;

		/* see if reply transaction id matches sent id */
		if (*((uint32_t *)(cu->cu_inbuf)) !=
				*((uint32_t *)(cu->cu_outbuf))) {
			dprintf("clntbudp_call: xid: 0x%x != 0x%x\n",
				*(uint32_t *)(cu->cu_inbuf),
				*(uint32_t *)(cu->cu_outbuf));
			continue;
		}
		/* we now assume we have the proper reply */
		break;
	}

	/*
	 * now decode and validate the response
	 */
	xdrmem_create(&reply_xdrs, cu->cu_inbuf, (uint_t)inlen, XDR_DECODE);
	ok = xdr_replymsg(&reply_xdrs, &reply_msg);
	/* XDR_DESTROY(&reply_xdrs);  save a few cycles on noop destroy */
	if (!ok) {
		cu->cu_error.re_status = RPC_CANTDECODERES;
		return (cu->cu_error.re_status);
	}

	_seterr_reply(&reply_msg, &(cu->cu_error));
	if (cu->cu_error.re_status == RPC_SUCCESS) {
		if (! AUTH_VALIDATE(cl->cl_auth,
			&reply_msg.acpted_rply.ar_verf)) {
			cu->cu_error.re_status = RPC_AUTHERROR;
			cu->cu_error.re_why = AUTH_INVALIDRESP;
			errors++;
			goto call_again;
		}
		if (reply_msg.acpted_rply.ar_verf.oa_base != NULL) {
			xdrs->x_op = XDR_FREE;
			(void) xdr_opaque_auth(xdrs,
			    &(reply_msg.acpted_rply.ar_verf));
		}
		return (cu->cu_error.re_status);
	}  /* end successful completion */

	if (cu->cu_error.re_status == RPC_AUTHERROR) {
		/* maybe our credentials need to be refreshed ... */
		if (nrefreshes > 0 &&
			AUTH_REFRESH(cl->cl_auth, NULL, NULL)) {
			nrefreshes--;
		}
		errors++;
		goto call_again;
	}

	/* Just keep trying till there's no data... */
	errors++;
	dprintf("clntbudp_call: from: %s, error: ",
		inet_ntoa(from.sin_addr));
	rpc_disperr(&cu->cu_error);
	goto recv_again;
}

static void
clntbudp_geterr(cl, errp)
	CLIENT *cl;
	struct rpc_err *errp;
{
	struct cu_data *cu = (struct cu_data *)cl->cl_private;

	*errp = cu->cu_error;
}


static bool_t
clntbudp_freeres(cl, xdr_res, res_ptr)
	CLIENT *cl;
	xdrproc_t xdr_res;
	caddr_t res_ptr;
{
	struct cu_data *cu = (struct cu_data *)cl->cl_private;
	XDR *xdrs = &(cu->cu_outxdrs);

	xdrs->x_op = XDR_FREE;
	return ((*xdr_res)(xdrs, res_ptr));
}

static void
clntbudp_abort()
	/* CLIENT *h; */
{
}

/* ARGSUSED */
static bool_t
clntbudp_control(cl, request, info)
	CLIENT *cl;
	int request;
	char *info;
{
	/* CLNT_CONTROL is not used in boot */
	return (FALSE);
}

static void
clntbudp_destroy(cl)
	CLIENT *cl;
{
	struct cu_data *cu = (struct cu_data *)cl->cl_private;

	if (cu->cu_closeit) {
		(void) socket_close(cu->cu_sock);
	}
	XDR_DESTROY(&(cu->cu_outxdrs));
	bkmem_free((caddr_t)cu, (sizeof (*cu) + cu->cu_sendsz + cu->cu_recvsz));
	bkmem_free((caddr_t)cl, sizeof (CLIENT));
}

static struct clnt_ops *
clntbudp_ops()
{
	static struct clnt_ops ops;

	if (ops.cl_call == NULL) {
		ops.cl_call = clntbudp_call;
		ops.cl_abort = clntbudp_abort;
		ops.cl_geterr = clntbudp_geterr;
		ops.cl_freeres = clntbudp_freeres;
		ops.cl_destroy = clntbudp_destroy;
		ops.cl_control = clntbudp_control;
	}
	return (&ops);
}
