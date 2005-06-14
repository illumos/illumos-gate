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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

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
 * svc_tcp.c, Server side for TCP/IP based RPC.
 *
 * Actually implements two flavors of transporter -
 * a tcp rendezvouser (a listner and connection establisher)
 * and a record/tcp stream.
 */

#include <rpc/rpc.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <syslog.h>
#include <malloc.h>
#include <stdio.h>

extern bool_t abort();
extern int errno;
extern SVCXPRT *svc_xprt_alloc();
extern void svc_xprt_free();
extern int _socket(int, int, int);
extern int _bind(int, const struct sockaddr *, int);
extern int _getsockname(int, struct sockaddr *, int *);
extern int _listen(int, int);
extern int _accept(int, struct sockaddr *, int *);
extern int bindresvport(int, struct sockaddr_in *);

static struct xp_ops *svctcp_ops();
static struct xp_ops *svctcp_rendezvous_ops();

static int readtcp(), writetcp();
static SVCXPRT *makefd_xprt();

struct tcp_rendezvous { /* kept in xprt->xp_p1 */
	u_int sendsize;
	u_int recvsize;
};

struct tcp_conn {  /* kept in xprt->xp_p1 */
	enum xprt_stat strm_stat;
	uint32_t x_id;
	XDR xdrs;
	char verf_body[MAX_AUTH_BYTES];
};

/*
 * Usage:
 *	xprt = svctcp_create(sock, send_buf_size, recv_buf_size);
 *
 * Creates, registers, and returns a (rpc) tcp based transporter.
 * Once *xprt is initialized, it is registered as a transporter
 * see (svc.h, xprt_register).  This routine returns
 * a NULL if a problem occurred.
 *
 * If sock<0 then a socket is created, else sock is used.
 * If the socket, sock is not bound to a port then svctcp_create
 * binds it to an arbitrary port.  The routine then starts a tcp
 * listener on the socket's associated port.  In any (successful) case,
 * xprt->xp_sock is the registered socket number and xprt->xp_port is the
 * associated port number.
 *
 * Since tcp streams do buffered io similar to stdio, the caller can specify
 * how big the send and receive buffers are via the second and third parms;
 * 0 => use the system default.
 */
SVCXPRT *
svctcp_create(sock, sendsize, recvsize)
	register int sock;
	u_int sendsize;
	u_int recvsize;
{
	bool_t madesock = FALSE;
	register SVCXPRT *xprt;
	register struct tcp_rendezvous *r;
	struct sockaddr_in addr;
	int len = sizeof (struct sockaddr_in);

	if (sock == RPC_ANYSOCK) {
		if ((sock = _socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
			(void) syslog(LOG_ERR, "svctcp_create - tcp",
				" socket creation problem: %m");
			return ((SVCXPRT *)NULL);
		}
		madesock = TRUE;
	}
	memset((char *)&addr, 0, sizeof (addr));
	addr.sin_family = AF_INET;
	if (bindresvport(sock, &addr)) {
		addr.sin_port = 0;
		(void) _bind(sock, (struct sockaddr *)&addr, len);
	}
	if ((_getsockname(sock, (struct sockaddr *)&addr, &len) != 0) ||
	    (_listen(sock, 2) != 0)) {
		(void) syslog(LOG_ERR, "svctcp_create - cannot",
			" getsockname or listen: %m");
		if (madesock)
			(void) close(sock);
		return ((SVCXPRT *)NULL);
	}
	r = (struct tcp_rendezvous *)mem_alloc(sizeof (*r));
	if (r == NULL) {
		(void) syslog(LOG_ERR, "svctcp_create: out of memory");
		if (madesock)
			(void) close(sock);
		return (NULL);
	}
	r->sendsize = sendsize;
	r->recvsize = recvsize;
	xprt = svc_xprt_alloc();
	if (xprt == NULL) {
		(void) syslog(LOG_ERR, "svctcp_create: out of memory");
		mem_free((char *) r, sizeof (*r));
		if (madesock)
			(void) close(sock);
		return (NULL);
	}
	xprt->xp_p2 = NULL;
	xprt->xp_netid = NULL;
	xprt->xp_p1 = (caddr_t)r;
	xprt->xp_verf = _null_auth;
	xprt->xp_ops = svctcp_rendezvous_ops();
	xprt->xp_port = ntohs(addr.sin_port);
	xprt->xp_sock = sock;
	xprt->xp_rtaddr.buf = xprt->xp_raddr;
	xprt_register(xprt);
	return (xprt);
}

/*
 * Like svtcp_create(), except the routine takes any *open* UNIX file
 * descriptor as its first input.
 */
SVCXPRT *
svcfd_create(fd, sendsize, recvsize)
	int fd;
	u_int sendsize;
	u_int recvsize;
{

	return (makefd_xprt(fd, sendsize, recvsize));
}

static SVCXPRT *
makefd_xprt(fd, sendsize, recvsize)
	int fd;
	u_int sendsize;
	u_int recvsize;
{
	register SVCXPRT *xprt;
	register struct tcp_conn *cd;

	xprt = svc_xprt_alloc();
	if (xprt == (SVCXPRT *)NULL) {
		(void) syslog(LOG_ERR, "svc_tcp: makefd_xprt: out of memory");
		goto done;
	}
	cd = (struct tcp_conn *)mem_alloc(sizeof (struct tcp_conn));
	if (cd == (struct tcp_conn *)NULL) {
		(void) syslog(LOG_ERR, "svc_tcp: makefd_xprt: out of memory");
		svc_xprt_free(xprt);
		xprt = (SVCXPRT *)NULL;
		goto done;
	}
	cd->strm_stat = XPRT_IDLE;
	xdrrec_create(&(cd->xdrs), sendsize, recvsize,
	    (caddr_t)xprt, readtcp, writetcp);
	xprt->xp_p2 = NULL;
	xprt->xp_netid = NULL;
	xprt->xp_p1 = (caddr_t)cd;
	xprt->xp_verf.oa_base = cd->verf_body;
	xprt->xp_addrlen = 0;
	xprt->xp_ops = svctcp_ops();  /* truely deals with calls */
	xprt->xp_port = 0;  /* this is a connection, not a rendezvouser */
	xprt->xp_sock = fd;
	/* to handle svc_getcaller() properly */
	xprt->xp_rtaddr.buf = xprt->xp_raddr;
	xprt_register(xprt);
	done:
	return (xprt);
}

static bool_t
rendezvous_request(xprt, rpc_msg)
	register SVCXPRT *xprt;
	struct rpc_msg	*rpc_msg;
{
	int sock;
	struct tcp_rendezvous *r;
	struct sockaddr_in addr;
	int len;

	r = (struct tcp_rendezvous *)xprt->xp_p1;
	again:
	len = sizeof (struct sockaddr_in);
	if ((sock = _accept(xprt->xp_sock, (struct sockaddr *)&addr,
	    &len)) < 0) {
		if (errno == EINTR)
			goto again;
		return (FALSE);
	}
	/*
	 * make a new transporter (re-uses xprt)
	 */
	xprt = makefd_xprt(sock, r->sendsize, r->recvsize);

	memcpy((char *)&xprt->xp_raddr, (char *)&addr, len);
	xprt->xp_addrlen = len;
	return (FALSE); /* there is never an rpc msg to be processed */
}

static enum xprt_stat
rendezvous_stat(xprt)
	SVCXPRT *xprt;
{

	return (XPRT_IDLE);
}

static void
svctcp_destroy(xprt)
	register SVCXPRT *xprt;
{
	register struct tcp_conn *cd = (struct tcp_conn *)xprt->xp_p1;

	xprt_unregister(xprt);
	(void) close(xprt->xp_sock);
	if (xprt->xp_port != 0) {
		/* a rendezvouser socket */
		xprt->xp_port = 0;
	} else {
		/* an actual connection socket */
		XDR_DESTROY(&(cd->xdrs));
	}
	mem_free((caddr_t)cd, sizeof (struct tcp_conn));
	svc_xprt_free(xprt);
}

/*
 * All read operations timeout after 35 seconds.
 * A timeout is fatal for the connection.
 */
static struct timeval wait_per_try = { 35, 0 };

/*
 * reads data from the tcp conection.
 * any error is fatal and the connection is closed.
 * (And a read of zero bytes is a half closed stream => error.)
 */
static int
readtcp(xprt, buf, len)
	register SVCXPRT *xprt;
	caddr_t buf;
	register int len;
{
	register int sock = xprt->xp_sock;
	fd_set mask;
	fd_set readfds;

	FD_ZERO(&mask);
	FD_SET(sock, &mask);
	do {
		readfds = mask;
		if (select(__rpc_dtbsize(), &readfds, NULL, NULL,
			&wait_per_try) <= 0) {
			if (errno == EINTR) {
				continue;
			}
			goto fatal_err;
		}
	} while (!FD_ISSET(sock, &readfds));
	if ((len = read(sock, buf, len)) > 0) {
		return (len);
	}
fatal_err:
	((struct tcp_conn *)(xprt->xp_p1))->strm_stat = XPRT_DIED;
	return (-1);
}

/*
 * writes data to the tcp connection.
 * Any error is fatal and the connection is closed.
 */
static int
writetcp(xprt, buf, len)
	register SVCXPRT *xprt;
	caddr_t buf;
	int len;
{
	register int i, cnt;

	for (cnt = len; cnt > 0; cnt -= i, buf += i) {
		if ((i = write(xprt->xp_sock, buf, cnt)) < 0) {
			((struct tcp_conn *)(xprt->xp_p1))->strm_stat =
			    XPRT_DIED;
			return (-1);
		}
	}
	return (len);
}

static enum xprt_stat
svctcp_stat(xprt)
	SVCXPRT *xprt;
{
	register struct tcp_conn *cd =
	    (struct tcp_conn *)(xprt->xp_p1);

	if (cd->strm_stat == XPRT_DIED)
		return (XPRT_DIED);
	if (! xdrrec_eof(&(cd->xdrs)))
		return (XPRT_MOREREQS);
	return (XPRT_IDLE);
}

static bool_t
svctcp_recv(xprt, msg)
	SVCXPRT *xprt;
	register struct rpc_msg *msg;
{
	register struct tcp_conn *cd =
	    (struct tcp_conn *)(xprt->xp_p1);
	register XDR *xdrs = &(cd->xdrs);

	xdrs->x_op = XDR_DECODE;
	(void) xdrrec_skiprecord(xdrs);
	if (xdr_callmsg(xdrs, msg)) {
		cd->x_id = msg->rm_xid;
		return (TRUE);
	}
	return (FALSE);
}

static bool_t
svctcp_getargs(xprt, xdr_args, args_ptr)
	SVCXPRT *xprt;
	xdrproc_t xdr_args;
	caddr_t args_ptr;
{

	return ((*xdr_args)(&(((struct tcp_conn *)(xprt->xp_p1))->xdrs),
		args_ptr));
}

static bool_t
svctcp_freeargs(xprt, xdr_args, args_ptr)
	SVCXPRT *xprt;
	xdrproc_t xdr_args;
	caddr_t args_ptr;
{
	register XDR *xdrs =
	    &(((struct tcp_conn *)(xprt->xp_p1))->xdrs);

	xdrs->x_op = XDR_FREE;
	return ((*xdr_args)(xdrs, args_ptr));
}

static bool_t
svctcp_reply(xprt, msg)
	SVCXPRT *xprt;
	register struct rpc_msg *msg;
{
	register struct tcp_conn *cd =
	    (struct tcp_conn *)(xprt->xp_p1);
	register XDR *xdrs = &(cd->xdrs);
	register bool_t stat;

	xdrs->x_op = XDR_ENCODE;
	msg->rm_xid = cd->x_id;
	stat = xdr_replymsg(xdrs, msg);
	(void) xdrrec_endofrecord(xdrs, TRUE);
	return (stat);
}


static struct xp_ops *
svctcp_ops()
{
	static struct xp_ops ops;

	if (ops.xp_recv == NULL) {
		ops.xp_recv = svctcp_recv;
		ops.xp_stat = svctcp_stat;
		ops.xp_getargs = svctcp_getargs;
		ops.xp_reply = svctcp_reply;
		ops.xp_freeargs = svctcp_freeargs;
		ops.xp_destroy = svctcp_destroy;
	}
	return (&ops);
}


static struct xp_ops *
svctcp_rendezvous_ops()
{
	static struct xp_ops ops;

	if (ops.xp_recv == NULL) {
		ops.xp_recv = rendezvous_request;
		ops.xp_stat = rendezvous_stat;
		ops.xp_getargs = abort;
		ops.xp_reply = abort;
		ops.xp_freeargs = abort,
		ops.xp_destroy = svctcp_destroy;
	}
	return (&ops);
}
