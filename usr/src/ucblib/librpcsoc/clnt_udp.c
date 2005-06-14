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

/*
 * Copyright (c) 1984, 1986, 1987, 1988, 1989, 1996 AT&T
 * All Rights Reserved
 */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * clnt_udp.c, Implements a UDP/IP based, client side RPC.
 */

#include <rpc/rpc.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <errno.h>
#include <rpc/pmap_clnt.h>
#include <rpc/clnt_soc.h>
#include <syslog.h>
#include <sys/filio.h>
#include <malloc.h>
#include <unistd.h>
#include <stropts.h>
#include <stdio.h>


extern int errno;

extern int _socket(int, int, int);
extern pid_t getpid();
extern int bindresvport(int, struct sockaddr_in *);
extern bool_t   xdr_opaque_auth(XDR *, struct opaque_auth *);
extern int _sendto(int, const char *, int, int,
	const struct sockaddr *, int);
extern int _recvfrom(int, char *, int, int,
	struct sockaddr *, int *);


static struct clnt_ops *clntudp_ops();

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
	u_int		   cu_xdrpos;
	u_int		   cu_sendsz;
	char		   *cu_outbuf;
	u_int		   cu_recvsz;
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
clntudp_bufcreate(raddr, program, version, wait, sockp, sendsz, recvsz)
	struct sockaddr_in *raddr;
	rpcprog_t program;
	rpcvers_t version;
	struct timeval wait;
	register int *sockp;
	u_int sendsz;
	u_int recvsz;
{
	CLIENT *cl;
	register struct cu_data *cu;
	struct timeval now;
	struct rpc_msg call_msg;

	cl = (CLIENT *)mem_alloc(sizeof (CLIENT));
	if (cl == NULL) {
		(void) syslog(LOG_ERR, "clntudp_create: out of memory");
		rpc_createerr.cf_stat = RPC_SYSTEMERROR;
		rpc_createerr.cf_error.re_errno = errno;
		goto fooy;
	}
	sendsz = ((sendsz + 3) / 4) * 4;
	recvsz = ((recvsz + 3) / 4) * 4;
	cu = (struct cu_data *)mem_alloc(sizeof (*cu) + sendsz + recvsz);
	if (cu == NULL) {
		(void) syslog(LOG_ERR, "clntudp_create: out of memory");
		rpc_createerr.cf_stat = RPC_SYSTEMERROR;
		rpc_createerr.cf_error.re_errno = errno;
		goto fooy;
	}
	cu->cu_outbuf = &cu->cu_inbuf[recvsz];

	(void) gettimeofday(&now, (struct timezone *)0);
	if (raddr->sin_port == 0) {
		u_short port;
		if ((port =
		    pmap_getport(raddr, program, version, IPPROTO_UDP)) == 0) {
			goto fooy;
		}
		raddr->sin_port = htons(port);
	}
	cl->cl_ops = clntudp_ops();
	cl->cl_private = (caddr_t)cu;
	cu->cu_raddr = *raddr;
	cu->cu_rlen = sizeof (cu->cu_raddr);
	cu->cu_wait = wait;
	cu->cu_total.tv_sec = -1;
	cu->cu_total.tv_usec = -1;
	cu->cu_sendsz = sendsz;
	cu->cu_recvsz = recvsz;
	call_msg.rm_xid = getpid() ^ now.tv_sec ^ now.tv_usec;
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
	if (*sockp < 0) {
		int dontblock = 1;

		*sockp = _socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (*sockp < 0) {
			rpc_createerr.cf_stat = RPC_SYSTEMERROR;
			rpc_createerr.cf_error.re_errno = errno;
			goto fooy;
		}
		/* attempt to bind to prov port */
		(void) bindresvport(*sockp, (struct sockaddr_in *)0);
		/* the sockets rpc controls are non-blocking */
		(void) ioctl(*sockp, FIONBIO, (char *) &dontblock);
		cu->cu_closeit = TRUE;
	} else {
		cu->cu_closeit = FALSE;
	}
	cu->cu_sock = *sockp;
	cl->cl_auth = authnone_create();
	return (cl);
fooy:
	if (cu)
		mem_free((caddr_t)cu, sizeof (*cu) + sendsz + recvsz);
	if (cl)
		mem_free((caddr_t)cl, sizeof (CLIENT));
	return ((CLIENT *)NULL);
}

CLIENT *
clntudp_create(raddr, program, version, wait, sockp)
	struct sockaddr_in *raddr;
	rpcprog_t program;
	rpcvers_t version;
	struct timeval wait;
	register int *sockp;
{

	return (clntudp_bufcreate(raddr, program, version, wait, sockp,
	    UDPMSGSIZE, UDPMSGSIZE));
}

static enum clnt_stat
clntudp_call(cl, proc, xargs, argsp, xresults, resultsp, utimeout)
	register CLIENT	*cl;		/* client handle */
	rpcproc_t	proc;		/* procedure number */
	xdrproc_t	xargs;		/* xdr routine for args */
	caddr_t		argsp;		/* pointer to args */
	xdrproc_t	xresults;	/* xdr routine for results */
	caddr_t		resultsp;	/* pointer to results */
	struct timeval	utimeout;	/* seconds to wait before giving up */
{
	register struct cu_data *cu = (struct cu_data *)cl->cl_private;
	register XDR *xdrs;
	register int outlen;
	register int inlen;
	int fromlen;
	fd_set readfds;
	fd_set mask;
	struct sockaddr_in from;
	struct rpc_msg reply_msg;
	XDR reply_xdrs;
	struct timeval startime, curtime;
	int firsttimeout = 1;
	struct timeval time_waited;
	struct timeval retransmit_time;
	bool_t ok;
	int nrefreshes = 2;	/* number of times to refresh cred */
	struct timeval timeout;

	if (cu->cu_total.tv_usec == -1) {
		timeout = utimeout;	/* use supplied timeout */
	} else {
		timeout = cu->cu_total; /* use default timeout */
	}

	time_waited.tv_sec = 0;
	time_waited.tv_usec = 0;
	retransmit_time = cu->cu_wait;

call_again:
	xdrs = &(cu->cu_outxdrs);
	xdrs->x_op = XDR_ENCODE;
	XDR_SETPOS(xdrs, cu->cu_xdrpos);
	/*
	 * the transaction is the first thing in the out buffer
	 */
	(*(u_short *)(cu->cu_outbuf))++;
	if ((! XDR_PUTINT32(xdrs, (int32_t *)&proc)) ||
	    (! AUTH_MARSHALL(cl->cl_auth, xdrs)) ||
	    (! (*xargs)(xdrs, argsp)))
		return (cu->cu_error.re_status = RPC_CANTENCODEARGS);
	outlen = (int)XDR_GETPOS(xdrs);

send_again:
	if (_sendto(cu->cu_sock, cu->cu_outbuf, outlen, 0,
	    (struct sockaddr *)&(cu->cu_raddr), cu->cu_rlen)
	    != outlen) {
		cu->cu_error.re_errno = errno;
		return (cu->cu_error.re_status = RPC_CANTSEND);
	}

	/*
	 * Hack to provide rpc-based message passing
	 */
	if (timeout.tv_sec == 0 && timeout.tv_usec == 0) {
		return (cu->cu_error.re_status = RPC_TIMEDOUT);
	}
	/*
	 * sub-optimal code appears here because we have
	 * some clock time to spare while the packets are in flight.
	 * (We assume that this is actually only executed once.)
	 */
	reply_msg.acpted_rply.ar_verf = _null_auth;
	reply_msg.acpted_rply.ar_results.where = resultsp;
	reply_msg.acpted_rply.ar_results.proc = xresults;
	FD_ZERO(&mask);
	FD_SET(cu->cu_sock, &mask);
	for (;;) {
		readfds = mask;
		switch (select(__rpc_dtbsize(), &readfds, NULL,
		    NULL, &(retransmit_time))) {

		case 0:
			time_waited.tv_sec += retransmit_time.tv_sec;
			time_waited.tv_usec += retransmit_time.tv_usec;
			while (time_waited.tv_usec >= 1000000) {
				time_waited.tv_sec++;
				time_waited.tv_usec -= 1000000;
			}

			/* update retransmit_time */

			if (retransmit_time.tv_sec < RPC_MAX_BACKOFF) {
			retransmit_time.tv_usec += retransmit_time.tv_usec;
			retransmit_time.tv_sec += retransmit_time.tv_sec;
			while (retransmit_time.tv_usec >= 1000000) {
				retransmit_time.tv_sec++;
				retransmit_time.tv_usec -= 1000000;
				}
			}

			if ((time_waited.tv_sec < timeout.tv_sec) ||
				((time_waited.tv_sec == timeout.tv_sec) &&
				(time_waited.tv_usec < timeout.tv_usec)))
				goto send_again;
			return (cu->cu_error.re_status = RPC_TIMEDOUT);

		/*
		 * buggy in other cases because time_waited is not being
		 * updated.
		 */
		case -1:
			if (errno != EINTR) {
				cu->cu_error.re_errno = errno;
				return (cu->cu_error.re_status = RPC_CANTRECV);
			}

			/* interrupted by another signal, update time_waited */
			if (firsttimeout) {
				/*
				 * Could have done gettimeofday before clnt_call
				 * but that means 1 more system call per each
				 * clnt_call, so do it after first time out
				 */
				if (gettimeofday(&startime,
					(struct timezone *) NULL) == -1) {
					errno = 0;
					continue;
				}
				firsttimeout = 0;
				errno = 0;
				continue;
			};

			if (gettimeofday(&curtime,
				(struct timezone *) NULL) == -1) {
				errno = 0;
				continue;
			};

			time_waited.tv_sec += curtime.tv_sec - startime.tv_sec;
			time_waited.tv_usec += curtime.tv_usec -
							startime.tv_usec;
			while (time_waited.tv_usec < 0) {
				time_waited.tv_sec--;
				time_waited.tv_usec += 1000000;
			};
			while (time_waited.tv_usec >= 1000000) {
				time_waited.tv_sec++;
				time_waited.tv_usec -= 1000000;
			}
			startime.tv_sec = curtime.tv_sec;
			startime.tv_usec = curtime.tv_usec;
			if ((time_waited.tv_sec > timeout.tv_sec) ||
				((time_waited.tv_sec == timeout.tv_sec) &&
				(time_waited.tv_usec > timeout.tv_usec))) {
				return (cu->cu_error.re_status = RPC_TIMEDOUT);
			}
			errno = 0; /* reset it */
			continue;

		}
		do {
			fromlen = sizeof (struct sockaddr);
			inlen = _recvfrom(cu->cu_sock, cu->cu_inbuf,
				(int) cu->cu_recvsz, 0,
				(struct sockaddr *)&from, &fromlen);
		} while (inlen < 0 && errno == EINTR);
		if (inlen < 0) {
			if (errno == EWOULDBLOCK)
				continue;
			cu->cu_error.re_errno = errno;
			return (cu->cu_error.re_status = RPC_CANTRECV);
		}
		if (inlen < sizeof (uint32_t))
			continue;
		/* see if reply transaction id matches sent id */
		if (*((uint32_t *)(cu->cu_inbuf)) !=
				*((uint32_t *)(cu->cu_outbuf)))
			continue;
		/* we now assume we have the proper reply */
		break;
	}

	/*
	 * now decode and validate the response
	 */
	xdrmem_create(&reply_xdrs, cu->cu_inbuf, (u_int)inlen, XDR_DECODE);
	ok = xdr_replymsg(&reply_xdrs, &reply_msg);
	/* XDR_DESTROY(&reply_xdrs);  save a few cycles on noop destroy */
	if (ok) {
		__seterr_reply(&reply_msg, &(cu->cu_error));
		if (cu->cu_error.re_status == RPC_SUCCESS) {
			if (! AUTH_VALIDATE(cl->cl_auth,
				&reply_msg.acpted_rply.ar_verf)) {
				cu->cu_error.re_status = RPC_AUTHERROR;
				cu->cu_error.re_why = AUTH_INVALIDRESP;
			}
			if (reply_msg.acpted_rply.ar_verf.oa_base != NULL) {
				xdrs->x_op = XDR_FREE;
				(void) xdr_opaque_auth(xdrs,
				    &(reply_msg.acpted_rply.ar_verf));
			}
		}  /* end successful completion */
		else {
			/* maybe our credentials need to be refreshed ... */
			if (nrefreshes > 0 &&
				AUTH_REFRESH(cl->cl_auth, &reply_msg)) {
				nrefreshes--;
				goto call_again;
			}
		}  /* end of unsuccessful completion */
	}  /* end of valid reply message */
	else {
		cu->cu_error.re_status = RPC_CANTDECODERES;
	}
	return (cu->cu_error.re_status);
}

static void
clntudp_geterr(cl, errp)
	CLIENT *cl;
	struct rpc_err *errp;
{
	register struct cu_data *cu = (struct cu_data *)cl->cl_private;

	*errp = cu->cu_error;
}


static bool_t
clntudp_freeres(cl, xdr_res, res_ptr)
	CLIENT *cl;
	xdrproc_t xdr_res;
	caddr_t res_ptr;
{
	register struct cu_data *cu = (struct cu_data *)cl->cl_private;
	register XDR *xdrs = &(cu->cu_outxdrs);

	xdrs->x_op = XDR_FREE;
	return ((*xdr_res)(xdrs, res_ptr));
}

static void
clntudp_abort()
	/* CLIENT *h; */
{
}

static bool_t
clntudp_control(cl, request, info)
	CLIENT *cl;
	int request;
	char *info;
{
	register struct cu_data *cu = (struct cu_data *)cl->cl_private;

	switch (request) {
	case CLSET_TIMEOUT:
		cu->cu_total = *(struct timeval *)info;
		break;
	case CLGET_TIMEOUT:
		*(struct timeval *)info = cu->cu_total;
		break;
	case CLSET_RETRY_TIMEOUT:
		cu->cu_wait = *(struct timeval *)info;
		break;
	case CLGET_RETRY_TIMEOUT:
		*(struct timeval *)info = cu->cu_wait;
		break;
	case CLGET_SERVER_ADDR:
		*(struct sockaddr_in *)info = cu->cu_raddr;
		break;
	case CLGET_FD:
		*(int *)info = cu->cu_sock;
		break;
	case CLSET_FD_CLOSE:
		cu->cu_closeit = TRUE;
		break;
	case CLSET_FD_NCLOSE:
		cu->cu_closeit = FALSE;
		break;
	default:
		return (FALSE);
	}
	return (TRUE);
}

static void
clntudp_destroy(cl)
	CLIENT *cl;
{
	register struct cu_data *cu = (struct cu_data *)cl->cl_private;

	if (cu->cu_closeit) {
		(void) close(cu->cu_sock);
	}
	XDR_DESTROY(&(cu->cu_outxdrs));
	mem_free((caddr_t)cu, (sizeof (*cu) + cu->cu_sendsz + cu->cu_recvsz));
	mem_free((caddr_t)cl, sizeof (CLIENT));
}

static struct clnt_ops *
clntudp_ops()
{
	static struct clnt_ops ops;

	if (ops.cl_call == NULL) {
		ops.cl_call = clntudp_call;
		ops.cl_abort = clntudp_abort;
		ops.cl_geterr = clntudp_geterr;
		ops.cl_freeres = clntudp_freeres;
		ops.cl_destroy = clntudp_destroy;
		ops.cl_control = clntudp_control;
	}
	return (&ops);
}
