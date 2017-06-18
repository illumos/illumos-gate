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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

/*
 * Server side for Connection Oriented RPC.
 *
 * Actually implements two flavors of transporter -
 * a rendezvouser (a listener and connection establisher)
 * and a record stream.
 */

#include "mt.h"
#include "rpc_mt.h"
#include <stdio.h>
#include <stdlib.h>
#include <rpc/rpc.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <sys/poll.h>
#include <syslog.h>
#include <rpc/nettype.h>
#include <tiuser.h>
#include <string.h>
#include <stropts.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/timod.h>
#include <limits.h>

#ifndef MIN
#define	MIN(a, b)	(((a) < (b)) ? (a) : (b))
#endif

#define	CLEANUP_SIZE	1024

extern int nsvc_xdrs;
extern int __rpc_connmaxrec;
extern int __rpc_irtimeout;

extern SVCXPRT	**svc_xports;
extern int	__td_setnodelay(int);
extern bool_t	__xdrrec_getbytes_nonblock(XDR *, enum xprt_stat *);
extern bool_t	__xdrrec_set_conn_nonblock(XDR *, uint32_t);
extern int	__rpc_legal_connmaxrec(int);
/* Structure used to initialize SVC_XP_AUTH(xprt).svc_ah_ops. */
extern struct svc_auth_ops svc_auth_any_ops;
extern void	__xprt_unregister_private(const SVCXPRT *, bool_t);

static struct xp_ops 	*svc_vc_ops(void);
static struct xp_ops 	*svc_vc_rendezvous_ops(void);
static void		svc_vc_destroy(SVCXPRT *);
static bool_t		svc_vc_nonblock(SVCXPRT *, SVCXPRT *);
static int		read_vc(SVCXPRT *, caddr_t, int);
static int		write_vc(SVCXPRT *, caddr_t, int);
static SVCXPRT		*makefd_xprt(int, uint_t, uint_t, t_scalar_t, char *);
static void		update_nonblock_timestamps(SVCXPRT *);

struct cf_rendezvous { /* kept in xprt->xp_p1 for rendezvouser */
	uint_t sendsize;
	uint_t recvsize;
	struct t_call *t_call;
	struct t_bind *t_bind;
	t_scalar_t cf_tsdu;
	char *cf_cache;
	int tcp_flag;
	int tcp_keepalive;
	int cf_connmaxrec;
};

struct cf_conn {	/* kept in xprt->xp_p1 for actual connection */
	uint_t sendsize;
	uint_t recvsize;
	enum xprt_stat strm_stat;
	uint32_t x_id;
	t_scalar_t cf_tsdu;
	XDR xdrs;
	char *cf_cache;
	char verf_body[MAX_AUTH_BYTES];
	bool_t cf_conn_nonblock;
	time_t cf_conn_nonblock_timestamp;
};

static int t_rcvall(int, char *, int);
static int t_rcvnonblock(SVCXPRT *, caddr_t, int);
static void svc_timeout_nonblock_xprt_and_LRU(bool_t);

extern int __xdrrec_setfirst(XDR *);
extern int __xdrrec_resetfirst(XDR *);
extern int __is_xdrrec_first(XDR *);

/*
 * This is intended as a performance improvement on the old string handling
 * stuff by read only moving data into the  text segment.
 * Format = <routine> : <error>
 */

static const char errstring[] = " %s : %s";

/* Routine names */

static const char svc_vc_create_str[] = "svc_vc_create";
static const char svc_fd_create_str[] = "svc_fd_create";
static const char makefd_xprt_str[] = "svc_vc_create: makefd_xprt ";
static const char rendezvous_request_str[] = "rendezvous_request";
static const char svc_vc_fderr[] =
		"fd > FD_SETSIZE; Use rpc_control(RPC_SVC_USE_POLLFD,...);";
static const char do_accept_str[] = "do_accept";

/* error messages */

static const char no_mem_str[] = "out of memory";
static const char no_tinfo_str[] = "could not get transport information";
static const char no_fcntl_getfl_str[] = "could not get status flags and modes";
static const char no_nonblock_str[] = "could not set transport non-blocking";

/*
 * Used to determine whether the time-out logic should be executed.
 */
static bool_t check_nonblock_timestamps = FALSE;

void
svc_vc_xprtfree(SVCXPRT *xprt)
{
/* LINTED pointer alignment */
	SVCXPRT_EXT		*xt = xprt ? SVCEXT(xprt) : NULL;
	struct cf_rendezvous	*r = xprt ?
/* LINTED pointer alignment */
	    (struct cf_rendezvous *)xprt->xp_p1 : NULL;

	if (!xprt)
		return;

	if (xprt->xp_tp)
		free(xprt->xp_tp);
	if (xprt->xp_netid)
		free(xprt->xp_netid);
	if (xt && (xt->parent == NULL)) {
		if (xprt->xp_ltaddr.buf)
			free(xprt->xp_ltaddr.buf);
		if (xprt->xp_rtaddr.buf)
			free(xprt->xp_rtaddr.buf);
	}
	if (r) {
		if (r->t_call)
			(void) t_free((char *)r->t_call, T_CALL);
		if (r->t_bind)
			(void) t_free((char *)r->t_bind, T_BIND);
		free(r);
	}
	svc_xprt_free(xprt);
}

/*
 * Usage:
 *	xprt = svc_vc_create(fd, sendsize, recvsize);
 * Since connection streams do buffered io similar to stdio, the caller
 * can specify how big the send and receive buffers are. If recvsize
 * or sendsize are 0, defaults will be chosen.
 * fd should be open and bound.
 */
SVCXPRT *
svc_vc_create_private(int fd, uint_t sendsize, uint_t recvsize)
{
	struct cf_rendezvous *r;
	SVCXPRT *xprt;
	struct t_info tinfo;

	if (RPC_FD_NOTIN_FDSET(fd)) {
		errno = EBADF;
		t_errno = TBADF;
		(void) syslog(LOG_ERR, errstring, svc_vc_create_str,
		    svc_vc_fderr);
		return (NULL);
	}
	if ((xprt = svc_xprt_alloc()) == NULL) {
		(void) syslog(LOG_ERR, errstring,
		    svc_vc_create_str, no_mem_str);
		return (NULL);
	}
/* LINTED pointer alignment */
	svc_flags(xprt) |= SVC_RENDEZVOUS;

	r = calloc(1, sizeof (*r));
	if (r == NULL) {
		(void) syslog(LOG_ERR, errstring,
		    svc_vc_create_str, no_mem_str);
		svc_vc_xprtfree(xprt);
		return (NULL);
	}
	if (t_getinfo(fd, &tinfo) == -1) {
		char errorstr[100];

		__tli_sys_strerror(errorstr, sizeof (errorstr),
		    t_errno, errno);
		(void) syslog(LOG_ERR, "%s : %s : %s",
		    svc_vc_create_str, no_tinfo_str, errorstr);
		free(r);
		svc_vc_xprtfree(xprt);
		return (NULL);
	}
	/*
	 * Find the receive and the send size
	 */
	r->sendsize = __rpc_get_t_size((int)sendsize, tinfo.tsdu);
	r->recvsize = __rpc_get_t_size((int)recvsize, tinfo.tsdu);
	if ((r->sendsize == 0) || (r->recvsize == 0)) {
		syslog(LOG_ERR,
		    "svc_vc_create:  transport does not support "
		    "data transfer");
		free(r);
		svc_vc_xprtfree(xprt);
		return (NULL);
	}

/* LINTED pointer alignment */
	r->t_call = (struct t_call *)t_alloc(fd, T_CALL, T_ADDR | T_OPT);
	if (r->t_call == NULL) {
		(void) syslog(LOG_ERR, errstring,
		    svc_vc_create_str, no_mem_str);
		free(r);
		svc_vc_xprtfree(xprt);
		return (NULL);
	}

/* LINTED pointer alignment */
	r->t_bind = (struct t_bind *)t_alloc(fd, T_BIND, T_ADDR);
	if (r->t_bind == NULL) {
		(void) syslog(LOG_ERR, errstring,
		    svc_vc_create_str, no_mem_str);
		(void) t_free((char *)r->t_call, T_CALL);
		free(r);
		svc_vc_xprtfree(xprt);
		return (NULL);
	}

	r->cf_tsdu = tinfo.tsdu;
	r->tcp_flag = FALSE;
	r->tcp_keepalive = FALSE;
	r->cf_connmaxrec = __rpc_connmaxrec;
	xprt->xp_fd = fd;
	xprt->xp_p1 = (caddr_t)r;
	xprt->xp_p2 = NULL;
	xprt->xp_verf = _null_auth;
	xprt->xp_ops = svc_vc_rendezvous_ops();
/* LINTED pointer alignment */
	SVC_XP_AUTH(xprt).svc_ah_ops = svc_auth_any_ops;
/* LINTED pointer alignment */
	SVC_XP_AUTH(xprt).svc_ah_private = NULL;

	return (xprt);
}

SVCXPRT *
svc_vc_create(const int fd, const uint_t sendsize, const uint_t recvsize)
{
	SVCXPRT *xprt;

	if ((xprt = svc_vc_create_private(fd, sendsize, recvsize)) != NULL)
		xprt_register(xprt);
	return (xprt);
}

SVCXPRT *
svc_vc_xprtcopy(SVCXPRT *parent)
{
	SVCXPRT			*xprt;
	struct cf_rendezvous	*r, *pr;
	int			fd = parent->xp_fd;

	if ((xprt = svc_xprt_alloc()) == NULL)
		return (NULL);

/* LINTED pointer alignment */
	SVCEXT(xprt)->parent = parent;
/* LINTED pointer alignment */
	SVCEXT(xprt)->flags = SVCEXT(parent)->flags;

	xprt->xp_fd = fd;
	xprt->xp_ops = svc_vc_rendezvous_ops();
	if (parent->xp_tp) {
		xprt->xp_tp = (char *)strdup(parent->xp_tp);
		if (xprt->xp_tp == NULL) {
			syslog(LOG_ERR, "svc_vc_xprtcopy: strdup failed");
			svc_vc_xprtfree(xprt);
			return (NULL);
		}
	}
	if (parent->xp_netid) {
		xprt->xp_netid = (char *)strdup(parent->xp_netid);
		if (xprt->xp_netid == NULL) {
			syslog(LOG_ERR, "svc_vc_xprtcopy: strdup failed");
			if (xprt->xp_tp)
				free(xprt->xp_tp);
			svc_vc_xprtfree(xprt);
			return (NULL);
		}
	}

	/*
	 * can share both local and remote address
	 */
	xprt->xp_ltaddr = parent->xp_ltaddr;
	xprt->xp_rtaddr = parent->xp_rtaddr; /* XXX - not used for rendezvous */
	xprt->xp_type = parent->xp_type;
	xprt->xp_verf = parent->xp_verf;

	if ((r = calloc(1, sizeof (*r))) == NULL) {
		svc_vc_xprtfree(xprt);
		return (NULL);
	}
	xprt->xp_p1 = (caddr_t)r;
/* LINTED pointer alignment */
	pr = (struct cf_rendezvous *)parent->xp_p1;
	r->sendsize = pr->sendsize;
	r->recvsize = pr->recvsize;
	r->cf_tsdu = pr->cf_tsdu;
	r->cf_cache = pr->cf_cache;
	r->tcp_flag = pr->tcp_flag;
	r->tcp_keepalive = pr->tcp_keepalive;
	r->cf_connmaxrec = pr->cf_connmaxrec;
/* LINTED pointer alignment */
	r->t_call = (struct t_call *)t_alloc(fd, T_CALL, T_ADDR | T_OPT);
	if (r->t_call == NULL) {
		svc_vc_xprtfree(xprt);
		return (NULL);
	}
/* LINTED pointer alignment */
	r->t_bind = (struct t_bind *)t_alloc(fd, T_BIND, T_ADDR);
	if (r->t_bind == NULL) {
		svc_vc_xprtfree(xprt);
		return (NULL);
	}

	return (xprt);
}

/*
 * XXX : Used for setting flag to indicate that this is TCP
 */

/*ARGSUSED*/
int
__svc_vc_setflag(SVCXPRT *xprt, int flag)
{
	struct cf_rendezvous *r;

/* LINTED pointer alignment */
	r = (struct cf_rendezvous *)xprt->xp_p1;
	r->tcp_flag = TRUE;
	return (1);
}

/*
 * used for the actual connection.
 */
SVCXPRT *
svc_fd_create_private(int fd, uint_t sendsize, uint_t recvsize)
{
	struct t_info tinfo;
	SVCXPRT *dummy;
	struct netbuf tres = {0};

	if (RPC_FD_NOTIN_FDSET(fd)) {
		errno = EBADF;
		t_errno = TBADF;
		(void) syslog(LOG_ERR, errstring,
		    svc_fd_create_str, svc_vc_fderr);
		return (NULL);
	}
	if (t_getinfo(fd, &tinfo) == -1) {
		char errorstr[100];

		__tli_sys_strerror(errorstr, sizeof (errorstr),
		    t_errno, errno);
		(void) syslog(LOG_ERR, "%s : %s : %s",
		    svc_fd_create_str, no_tinfo_str, errorstr);
		return (NULL);
	}
	/*
	 * Find the receive and the send size
	 */
	sendsize = __rpc_get_t_size((int)sendsize, tinfo.tsdu);
	recvsize = __rpc_get_t_size((int)recvsize, tinfo.tsdu);
	if ((sendsize == 0) || (recvsize == 0)) {
		syslog(LOG_ERR, errstring, svc_fd_create_str,
		    "transport does not support data transfer");
		return (NULL);
	}
	dummy = makefd_xprt(fd, sendsize, recvsize, tinfo.tsdu, NULL);
				/* NULL signifies no dup cache */
	/* Assign the local bind address */
	if (t_getname(fd, &tres, LOCALNAME) == -1)
		tres.len = 0;
	dummy->xp_ltaddr = tres;
	/* Fill in type of service */
	dummy->xp_type = tinfo.servtype;
	return (dummy);
}

SVCXPRT *
svc_fd_create(const int fd, const uint_t sendsize, const uint_t recvsize)
{
	SVCXPRT *xprt;

	if ((xprt = svc_fd_create_private(fd, sendsize, recvsize)) != NULL)
		xprt_register(xprt);
	return (xprt);
}

void
svc_fd_xprtfree(SVCXPRT *xprt)
{
/* LINTED pointer alignment */
	SVCXPRT_EXT	*xt = xprt ? SVCEXT(xprt) : NULL;
/* LINTED pointer alignment */
	struct cf_conn	*cd = xprt ? (struct cf_conn *)xprt->xp_p1 : NULL;

	if (!xprt)
		return;

	if (xprt->xp_tp)
		free(xprt->xp_tp);
	if (xprt->xp_netid)
		free(xprt->xp_netid);
	if (xt && (xt->parent == NULL)) {
		if (xprt->xp_ltaddr.buf)
			free(xprt->xp_ltaddr.buf);
		if (xprt->xp_rtaddr.buf)
			free(xprt->xp_rtaddr.buf);
	}
	if (cd) {
		XDR_DESTROY(&(cd->xdrs));
		free(cd);
	}
	if (xt && (xt->parent == NULL) && xprt->xp_p2) {
/* LINTED pointer alignment */
		free(((struct netbuf *)xprt->xp_p2)->buf);
		free(xprt->xp_p2);
	}
	svc_xprt_free(xprt);
}

static SVCXPRT *
makefd_xprt(int fd, uint_t sendsize, uint_t recvsize, t_scalar_t tsdu,
    char *cache)
{
	SVCXPRT *xprt;
	struct cf_conn *cd;

	xprt = svc_xprt_alloc();
	if (xprt == NULL) {
		(void) syslog(LOG_ERR, errstring, makefd_xprt_str, no_mem_str);
		return (NULL);
	}
/* LINTED pointer alignment */
	svc_flags(xprt) |= SVC_CONNECTION;

	cd = malloc(sizeof (struct cf_conn));
	if (cd == NULL) {
		(void) syslog(LOG_ERR, errstring, makefd_xprt_str, no_mem_str);
		svc_fd_xprtfree(xprt);
		return (NULL);
	}
	cd->sendsize = sendsize;
	cd->recvsize = recvsize;
	cd->strm_stat = XPRT_IDLE;
	cd->cf_tsdu = tsdu;
	cd->cf_cache = cache;
	cd->cf_conn_nonblock = FALSE;
	cd->cf_conn_nonblock_timestamp = 0;
	cd->xdrs.x_ops = NULL;
	xdrrec_create(&(cd->xdrs), sendsize, 0, (caddr_t)xprt,
	    (int(*)())NULL, (int(*)(void *, char *, int))write_vc);
	if (cd->xdrs.x_ops == NULL) {
		(void) syslog(LOG_ERR, errstring, makefd_xprt_str, no_mem_str);
		free(cd);
		svc_fd_xprtfree(xprt);
		return (NULL);
	}

	(void) rw_wrlock(&svc_fd_lock);
	if (svc_xdrs == NULL) {
		svc_xdrs = calloc(FD_INCREMENT,  sizeof (XDR *));
		if (svc_xdrs == NULL) {
			(void) syslog(LOG_ERR, errstring, makefd_xprt_str,
			    no_mem_str);
			XDR_DESTROY(&(cd->xdrs));
			free(cd);
			svc_fd_xprtfree(xprt);
			(void) rw_unlock(&svc_fd_lock);
			return (NULL);
		}
		nsvc_xdrs = FD_INCREMENT;
	}

	while (fd >= nsvc_xdrs) {
		XDR **tmp_xdrs = realloc(svc_xdrs,
		    sizeof (XDR *) * (nsvc_xdrs + FD_INCREMENT));
		if (tmp_xdrs == NULL) {
			(void) syslog(LOG_ERR, errstring, makefd_xprt_str,
			    no_mem_str);
			XDR_DESTROY(&(cd->xdrs));
			free(cd);
			svc_fd_xprtfree(xprt);
			(void) rw_unlock(&svc_fd_lock);
			return (NULL);
		}

		svc_xdrs = tmp_xdrs;
		/* initial the new array to 0 from the last allocated array */
		(void) memset(&svc_xdrs[nsvc_xdrs], 0,
		    sizeof (XDR *) * FD_INCREMENT);
		nsvc_xdrs += FD_INCREMENT;
	}

	if (svc_xdrs[fd] != NULL) {
		XDR_DESTROY(svc_xdrs[fd]);
	} else if ((svc_xdrs[fd] = malloc(sizeof (XDR))) == NULL) {
		(void) syslog(LOG_ERR, errstring, makefd_xprt_str, no_mem_str);
		XDR_DESTROY(&(cd->xdrs));
		free(cd);
		svc_fd_xprtfree(xprt);
		(void) rw_unlock(&svc_fd_lock);
		return (NULL);
	}
	(void) memset(svc_xdrs[fd], 0, sizeof (XDR));
	xdrrec_create(svc_xdrs[fd], 0, recvsize, (caddr_t)xprt,
	    (int(*)(void *, char *, int))read_vc, (int(*)())NULL);
	if (svc_xdrs[fd]->x_ops == NULL) {
		free(svc_xdrs[fd]);
		svc_xdrs[fd] = NULL;
		XDR_DESTROY(&(cd->xdrs));
		free(cd);
		svc_fd_xprtfree(xprt);
		(void) rw_unlock(&svc_fd_lock);
		return (NULL);
	}
	(void) rw_unlock(&svc_fd_lock);

	xprt->xp_p1 = (caddr_t)cd;
	xprt->xp_p2 = NULL;
	xprt->xp_verf.oa_base = cd->verf_body;
	xprt->xp_ops = svc_vc_ops();	/* truely deals with calls */
	xprt->xp_fd = fd;
	return (xprt);
}

SVCXPRT *
svc_fd_xprtcopy(SVCXPRT *parent)
{
	SVCXPRT			*xprt;
	struct cf_conn		*cd, *pcd;

	if ((xprt = svc_xprt_alloc()) == NULL)
		return (NULL);

/* LINTED pointer alignment */
	SVCEXT(xprt)->parent = parent;
/* LINTED pointer alignment */
	SVCEXT(xprt)->flags = SVCEXT(parent)->flags;

	xprt->xp_fd = parent->xp_fd;
	xprt->xp_ops = svc_vc_ops();
	if (parent->xp_tp) {
		xprt->xp_tp = (char *)strdup(parent->xp_tp);
		if (xprt->xp_tp == NULL) {
			syslog(LOG_ERR, "svc_fd_xprtcopy: strdup failed");
			svc_fd_xprtfree(xprt);
			return (NULL);
		}
	}
	if (parent->xp_netid) {
		xprt->xp_netid = (char *)strdup(parent->xp_netid);
		if (xprt->xp_netid == NULL) {
			syslog(LOG_ERR, "svc_fd_xprtcopy: strdup failed");
			if (xprt->xp_tp)
				free(xprt->xp_tp);
			svc_fd_xprtfree(xprt);
			return (NULL);
		}
	}
	/*
	 * share local and remote addresses with parent
	 */
	xprt->xp_ltaddr = parent->xp_ltaddr;
	xprt->xp_rtaddr = parent->xp_rtaddr;
	xprt->xp_type = parent->xp_type;

	if ((cd = malloc(sizeof (struct cf_conn))) == NULL) {
		svc_fd_xprtfree(xprt);
		return (NULL);
	}
/* LINTED pointer alignment */
	pcd = (struct cf_conn *)parent->xp_p1;
	cd->sendsize = pcd->sendsize;
	cd->recvsize = pcd->recvsize;
	cd->strm_stat = pcd->strm_stat;
	cd->x_id = pcd->x_id;
	cd->cf_tsdu = pcd->cf_tsdu;
	cd->cf_cache = pcd->cf_cache;
	cd->cf_conn_nonblock = pcd->cf_conn_nonblock;
	cd->cf_conn_nonblock_timestamp = pcd->cf_conn_nonblock_timestamp;
	cd->xdrs.x_ops = NULL;
	xdrrec_create(&(cd->xdrs), cd->sendsize, 0, (caddr_t)xprt,
	    (int(*)())NULL, (int(*)(void *, char *, int))write_vc);
	if (cd->xdrs.x_ops == NULL) {
		free(cd);
		svc_fd_xprtfree(xprt);
		return (NULL);
	}
	xprt->xp_verf.oa_base = cd->verf_body;
	xprt->xp_p1 = (char *)cd;
	xprt->xp_p2 = parent->xp_p2;	/* shared */

	return (xprt);
}

static void do_accept();

/*
 * This routine is called by svc_getreqset(), when a packet is recd.
 * The listener process creates another end point on which the actual
 * connection is carried. It returns FALSE to indicate that it was
 * not a rpc packet (falsely though), but as a side effect creates
 * another endpoint which is also registered, which then always
 * has a request ready to be served.
 */
/* ARGSUSED1 */
static bool_t
rendezvous_request(SVCXPRT *xprt, struct rpc_msg *msg)
{
	struct cf_rendezvous *r;
	char *tpname = NULL;
	char devbuf[256];

/* LINTED pointer alignment */
	r = (struct cf_rendezvous *)xprt->xp_p1;

again:
	switch (t_look(xprt->xp_fd)) {
	case T_DISCONNECT:
		(void) t_rcvdis(xprt->xp_fd, NULL);
		return (FALSE);

	case T_LISTEN:

		if (t_listen(xprt->xp_fd, r->t_call) == -1) {
			if ((t_errno == TSYSERR) && (errno == EINTR))
				goto again;

			if (t_errno == TLOOK) {
				if (t_look(xprt->xp_fd) == T_DISCONNECT)
					(void) t_rcvdis(xprt->xp_fd, NULL);
			}
			return (FALSE);
		}
		break;
	default:
		return (FALSE);
	}
	/*
	 * Now create another endpoint, and accept the connection
	 * on it.
	 */

	if (xprt->xp_tp) {
		tpname = xprt->xp_tp;
	} else {
		/*
		 * If xprt->xp_tp is NULL, then try to extract the
		 * transport protocol information from the transport
		 * protcol corresponding to xprt->xp_fd
		 */
		struct netconfig *nconf;
		tpname = devbuf;
		if ((nconf = __rpcfd_to_nconf(xprt->xp_fd, xprt->xp_type))
		    == NULL) {
			(void) syslog(LOG_ERR, errstring,
			    rendezvous_request_str, "no suitable transport");
			goto err;
		}
		(void) strcpy(tpname, nconf->nc_device);
		freenetconfigent(nconf);
	}

	do_accept(xprt->xp_fd, tpname, xprt->xp_netid, r);

err:
	return (FALSE); /* there is never an rpc msg to be processed */
}

struct entry {
	struct t_call *t_call;
	struct entry *next;
};

static void
do_accept(int srcfd, char *tpname, char *netid, struct cf_rendezvous *r)
{
	int	destfd;
	struct t_call	t_call;
	struct t_call	*tcp2 = NULL;
	struct t_info	tinfo;
	SVCXPRT	*xprt;
	SVCXPRT	*xprt_srcfd;
	struct entry *head = NULL;
	struct entry *tail = NULL;
	struct entry *e;
	struct t_call *tcp;

restart:
	tcp = r->t_call;

	destfd = t_open(tpname, O_RDWR, &tinfo);
	if (check_nonblock_timestamps) {
		if (destfd == -1 && t_errno == TSYSERR && errno == EMFILE) {
			/*
			 * Since there are nonblocking connection xprts and
			 * too many open files, the LRU connection xprt should
			 * get destroyed in case an attacker has been creating
			 * many connections.
			 */
			(void) mutex_lock(&svc_mutex);
			svc_timeout_nonblock_xprt_and_LRU(TRUE);
			(void) mutex_unlock(&svc_mutex);
			destfd = t_open(tpname, O_RDWR, &tinfo);
		} else {
			/*
			 * Destroy/timeout all nonblock connection xprts
			 * that have not had recent activity.
			 * Do not destroy LRU xprt unless there are
			 * too many open files.
			 */
			(void) mutex_lock(&svc_mutex);
			svc_timeout_nonblock_xprt_and_LRU(FALSE);
			(void) mutex_unlock(&svc_mutex);
		}
	}
	if (destfd == -1) {
		char errorstr[100];

		__tli_sys_strerror(errorstr, sizeof (errorstr), t_errno, errno);
		(void) syslog(LOG_ERR, "%s : %s : %s", do_accept_str,
		    "can't open connection", errorstr);
		(void) t_snddis(srcfd, tcp);

		goto end;
	}
	if (RPC_FD_NOTIN_FDSET(destfd)) {
		(void) syslog(LOG_ERR, errstring, do_accept_str, svc_vc_fderr);
		(void) t_close(destfd);
		(void) t_snddis(srcfd, tcp);

		goto end;
	}
	(void) fcntl(destfd, F_SETFD, FD_CLOEXEC);
	if ((tinfo.servtype != T_COTS) && (tinfo.servtype != T_COTS_ORD)) {
		/* Not a connection oriented mode */
		(void) syslog(LOG_ERR, errstring, do_accept_str,
		    "do_accept:  illegal transport");
		(void) t_close(destfd);
		(void) t_snddis(srcfd, tcp);

		goto end;
	}


	if (t_bind(destfd, NULL, r->t_bind) == -1) {
		char errorstr[100];

		__tli_sys_strerror(errorstr, sizeof (errorstr), t_errno, errno);
		(void) syslog(LOG_ERR, " %s : %s : %s", do_accept_str,
		    "t_bind failed", errorstr);
		(void) t_close(destfd);
		(void) t_snddis(srcfd, tcp);

		goto end;
	}

	if (r->tcp_flag)	/* if TCP, set NODELAY flag */
		(void) __td_setnodelay(destfd);

	/*
	 * This connection is not listening, hence no need to set
	 * the qlen.
	 */

	/*
	 * XXX: The local transport chokes on its own listen
	 * options so we zero them for now
	 */
	t_call = *tcp;
	t_call.opt.len = 0;
	t_call.opt.maxlen = 0;
	t_call.opt.buf = NULL;

	while (t_accept(srcfd, destfd, &t_call) == -1) {
		char errorstr[100];

		switch (t_errno) {
		case TLOOK:
again:
			switch (t_look(srcfd)) {
			case T_CONNECT:
			case T_DATA:
			case T_EXDATA:
				/* this should not happen */
				break;

			case T_DISCONNECT:
				(void) t_rcvdis(srcfd, NULL);
				break;

			case T_LISTEN:
				if (tcp2 == NULL)
/* LINTED pointer alignment */
					tcp2 = (struct t_call *)t_alloc(srcfd,
					    T_CALL, T_ADDR | T_OPT);
				if (tcp2 == NULL) {
					(void) t_close(destfd);
					(void) t_snddis(srcfd, tcp);
					syslog(LOG_ERR, errstring,
					    do_accept_str, no_mem_str);

					goto end;
				}
				if (t_listen(srcfd, tcp2) == -1) {
					switch (t_errno) {
					case TSYSERR:
						if (errno == EINTR)
							goto again;
						break;

					case TLOOK:
						goto again;
					}
					(void) t_close(destfd);
					(void) t_snddis(srcfd, tcp);

					goto end;
				}

				e = malloc(sizeof (struct entry));
				if (e == NULL) {
					(void) t_snddis(srcfd, tcp2);
					(void) t_free((char *)tcp2, T_CALL);
					tcp2 = NULL;

					break;
				}

				e->t_call = tcp2;
				tcp2 = NULL;
				e->next = NULL;

				if (head == NULL)
					head = e;
				else
					tail->next = e;
				tail = e;

				break;

			case T_ORDREL:
				(void) t_rcvrel(srcfd);
				(void) t_sndrel(srcfd);
				break;
			}
			break;

		case TBADSEQ:
			/*
			 * This can happen if the remote side has
			 * disconnected before the connection is
			 * accepted.  In this case, a disconnect
			 * should not be sent on srcfd (important!
			 * the listening fd will be hosed otherwise!).
			 * This error is not logged since this is an
			 * operational situation that is recoverable.
			 */
			(void) t_close(destfd);

			goto end;

		case TOUTSTATE:
			/*
			 * This can happen if the t_rcvdis() or t_rcvrel()/
			 * t_sndrel() put srcfd into the T_IDLE state.
			 */
			if (t_getstate(srcfd) == T_IDLE) {
				(void) t_close(destfd);
				(void) t_snddis(srcfd, tcp);

				goto end;
			}
			/* else FALL THROUGH TO */

		default:
			__tli_sys_strerror(errorstr, sizeof (errorstr),
			    t_errno, errno);
			(void) syslog(LOG_ERR,
			    "cannot accept connection:  %s (current state %d)",
			    errorstr, t_getstate(srcfd));
			(void) t_close(destfd);
			(void) t_snddis(srcfd, tcp);

			goto end;
		}
	}

	if (r->tcp_flag && r->tcp_keepalive) {
		char *option;
		char *option_ret;

		option = malloc(sizeof (struct opthdr) + sizeof (int));
		option_ret = malloc(sizeof (struct opthdr) + sizeof (int));
		if (option != NULL && option_ret != NULL) {
			struct opthdr *opt;
			struct t_optmgmt optreq, optret;
			int *p_optval;

			/* LINTED pointer cast */
			opt = (struct opthdr *)option;
			opt->level = SOL_SOCKET;
			opt->name  = SO_KEEPALIVE;
			opt->len  = sizeof (int);
			p_optval = (int *)(opt + 1);
			*p_optval = SO_KEEPALIVE;
			optreq.opt.maxlen = optreq.opt.len =
			    sizeof (struct opthdr) + sizeof (int);
			optreq.opt.buf = (char *)option;
			optreq.flags = T_NEGOTIATE;
			optret.opt.maxlen = sizeof (struct opthdr)
			    + sizeof (int);
			optret.opt.buf = (char *)option_ret;
			(void) t_optmgmt(destfd, &optreq, &optret);
		}
		free(option);
		free(option_ret);
	}


	/*
	 * make a new transporter
	 */
	xprt = makefd_xprt(destfd, r->sendsize, r->recvsize, r->cf_tsdu,
	    r->cf_cache);
	if (xprt == NULL) {
		/*
		 * makefd_xprt() returns a NULL xprt only when
		 * it's out of memory.
		 */
		goto memerr;
	}

	/*
	 * Copy the new local and remote bind information
	 */

	xprt->xp_rtaddr.len = tcp->addr.len;
	xprt->xp_rtaddr.maxlen = tcp->addr.len;
	if ((xprt->xp_rtaddr.buf = malloc(tcp->addr.len)) == NULL)
		goto memerr;
	(void) memcpy(xprt->xp_rtaddr.buf, tcp->addr.buf, tcp->addr.len);

	if (strcmp(netid, "tcp") == 0) {
		xprt->xp_ltaddr.maxlen = sizeof (struct sockaddr_in);
		if ((xprt->xp_ltaddr.buf =
		    malloc(xprt->xp_ltaddr.maxlen)) == NULL)
			goto memerr;
		if (t_getname(destfd, &xprt->xp_ltaddr, LOCALNAME) < 0) {
			(void) syslog(LOG_ERR,
			    "do_accept: t_getname for tcp failed!");
			goto xprt_err;
		}
	} else if (strcmp(netid, "tcp6") == 0) {
		xprt->xp_ltaddr.maxlen = sizeof (struct sockaddr_in6);
		if ((xprt->xp_ltaddr.buf =
		    malloc(xprt->xp_ltaddr.maxlen)) == NULL)
			goto memerr;
		if (t_getname(destfd, &xprt->xp_ltaddr, LOCALNAME) < 0) {
			(void) syslog(LOG_ERR,
			    "do_accept: t_getname for tcp6 failed!");
			goto xprt_err;
		}
	}

	xprt->xp_tp = strdup(tpname);
	xprt->xp_netid = strdup(netid);
	if ((xprt->xp_tp == NULL) ||
	    (xprt->xp_netid == NULL)) {
		goto memerr;
	}
	if (tcp->opt.len > 0) {
		xprt->xp_p2 = malloc(sizeof (struct netbuf));

		if (xprt->xp_p2 != NULL) {
/* LINTED pointer alignment */
			struct netbuf *netptr = (struct netbuf *)xprt->xp_p2;

			netptr->len = tcp->opt.len;
			netptr->maxlen = tcp->opt.len;
			if ((netptr->buf = malloc(tcp->opt.len)) == NULL)
				goto memerr;
			(void) memcpy(netptr->buf, tcp->opt.buf, tcp->opt.len);
		} else
			goto memerr;
	}
/*	(void) ioctl(destfd, I_POP, NULL);    */

	/*
	 * If a nonblocked connection fd has been requested,
	 * perform the necessary operations.
	 */
	xprt_srcfd = svc_xports[srcfd];
	/* LINTED pointer cast */
	if (((struct cf_rendezvous *)(xprt_srcfd->xp_p1))->cf_connmaxrec) {
		if (!svc_vc_nonblock(xprt_srcfd, xprt))
			goto xprt_err;
	}

	/*
	 * Copy the call back declared for the service to the current
	 * connection
	 */
	xprt->xp_closeclnt = xprt_srcfd->xp_closeclnt;
	xprt_register(xprt);

end:
	if (head != NULL) {
		(void) t_free((char *)r->t_call, T_CALL);
		r->t_call = head->t_call;
		e = head;
		head = head->next;
		free(e);
		goto restart;
	}

	if (tcp2)
		(void) t_free((char *)tcp2, T_CALL);

	return;

memerr:
	(void) syslog(LOG_ERR, errstring, do_accept_str, no_mem_str);
xprt_err:
	if (xprt)
		svc_vc_destroy(xprt);
	(void) t_close(destfd);

	goto end;
}

/*
 * This routine performs the necessary fcntl() operations to create
 * a nonblocked connection fd.
 * It also adjusts the sizes and allocates the buffer
 * for the nonblocked operations, and updates the associated
 * timestamp field in struct cf_conn for timeout bookkeeping.
 */
static bool_t
svc_vc_nonblock(SVCXPRT *xprt_rendezvous, SVCXPRT *xprt_conn)
{
	int nn;
	int fdconn = xprt_conn->xp_fd;
	struct cf_rendezvous *r =
	    /* LINTED pointer cast */
	    (struct cf_rendezvous *)xprt_rendezvous->xp_p1;
	/* LINTED pointer cast */
	struct cf_conn *cd = (struct cf_conn *)xprt_conn->xp_p1;
	uint32_t maxrecsz;

	if ((nn = fcntl(fdconn, F_GETFL, 0)) < 0) {
		(void) syslog(LOG_ERR, "%s : %s : %m", do_accept_str,
		    no_fcntl_getfl_str);
		return (FALSE);
	}

	if (fcntl(fdconn, F_SETFL, nn|O_NONBLOCK) != 0) {
		(void) syslog(LOG_ERR, "%s : %s : %m", do_accept_str,
		    no_nonblock_str);
		return (FALSE);
	}

	cd->cf_conn_nonblock = TRUE;
	/*
	 * If the max fragment size has not been set via
	 * rpc_control(), use the default.
	 */
	if ((maxrecsz = r->cf_connmaxrec) == 0)
		maxrecsz = r->recvsize;
	/* Set XDR stream to use non-blocking semantics. */
	if (__xdrrec_set_conn_nonblock(svc_xdrs[fdconn], maxrecsz)) {
		check_nonblock_timestamps = TRUE;
		update_nonblock_timestamps(xprt_conn);
		return (TRUE);
	}
	return (FALSE);
}

/* ARGSUSED */
static enum xprt_stat
rendezvous_stat(SVCXPRT *xprt)
{
	return (XPRT_IDLE);
}

static void
svc_vc_destroy(SVCXPRT *xprt)
{
	(void) mutex_lock(&svc_mutex);
	_svc_vc_destroy_private(xprt, TRUE);
	(void) svc_timeout_nonblock_xprt_and_LRU(FALSE);
	(void) mutex_unlock(&svc_mutex);
}

void
_svc_vc_destroy_private(SVCXPRT *xprt, bool_t lock_not_held)
{
	if (svc_mt_mode != RPC_SVC_MT_NONE) {
/* LINTED pointer alignment */
		if (SVCEXT(xprt)->parent)
/* LINTED pointer alignment */
			xprt = SVCEXT(xprt)->parent;
/* LINTED pointer alignment */
		svc_flags(xprt) |= SVC_DEFUNCT;
/* LINTED pointer alignment */
		if (SVCEXT(xprt)->refcnt > 0)
			return;
	}

	if (xprt->xp_closeclnt != NULL) {
		svc_errorhandler_t cb = xprt->xp_closeclnt;

		/*
		 * Reset the pointer here to avoid reentrance on the same
		 * SVCXPRT handle.
		 */
		xprt->xp_closeclnt = NULL;
		cb(xprt, (xprt->xp_rtaddr.len != 0));
	}

	__xprt_unregister_private(xprt, lock_not_held);
	(void) t_close(xprt->xp_fd);

	if (svc_mt_mode != RPC_SVC_MT_NONE) {
		svc_xprt_destroy(xprt);
	} else {
/* LINTED pointer alignment */
		if (svc_type(xprt) == SVC_RENDEZVOUS)
			svc_vc_xprtfree(xprt);
		else
			svc_fd_xprtfree(xprt);
	}
}

/*ARGSUSED*/
static bool_t
svc_vc_control(SVCXPRT *xprt, const uint_t rq, void *in)
{
	switch (rq) {
	case SVCSET_RECVERRHANDLER:
		xprt->xp_closeclnt = (svc_errorhandler_t)in;
		return (TRUE);
	case SVCGET_RECVERRHANDLER:
		*(svc_errorhandler_t *)in = xprt->xp_closeclnt;
		return (TRUE);
	case SVCGET_XID:
		if (xprt->xp_p1 == NULL)
			return (FALSE);
		/* LINTED pointer alignment */
		*(uint32_t *)in = ((struct cf_conn *)(xprt->xp_p1))->x_id;
		return (TRUE);
	default:
		return (FALSE);
	}
}

static bool_t
rendezvous_control(SVCXPRT *xprt, const uint_t rq, void *in)
{
	struct cf_rendezvous *r;
	int tmp;

	switch (rq) {
	case SVCSET_RECVERRHANDLER:
		xprt->xp_closeclnt = (svc_errorhandler_t)in;
		return (TRUE);
	case SVCGET_RECVERRHANDLER:
		*(svc_errorhandler_t *)in = xprt->xp_closeclnt;
		return (TRUE);
	case SVCSET_KEEPALIVE:
		/* LINTED pointer cast */
		r = (struct cf_rendezvous *)xprt->xp_p1;
		if (r->tcp_flag) {
			r->tcp_keepalive = (int)(intptr_t)in;
			return (TRUE);
		}
		return (FALSE);
	case SVCSET_CONNMAXREC:
		/*
		 * Override the default maximum record size, set via
		 * rpc_control(), for this connection. Only appropriate
		 * for connection oriented transports, but is ignored for
		 * the connectionless case, so no need to check the
		 * connection type here.
		 */
		/* LINTED pointer cast */
		r = (struct cf_rendezvous *)xprt->xp_p1;
		tmp = __rpc_legal_connmaxrec(*(int *)in);
		if (r != 0 && tmp >= 0) {
			r->cf_connmaxrec = tmp;
			return (TRUE);
		}
		return (FALSE);
	case SVCGET_CONNMAXREC:
		/* LINTED pointer cast */
		r = (struct cf_rendezvous *)xprt->xp_p1;
		if (r != 0) {
			*(int *)in = r->cf_connmaxrec;
			return (TRUE);
		}
		return (FALSE);
	case SVCGET_XID:	/* fall through for now */
	default:
		return (FALSE);
	}
}

/*
 * All read operations timeout after 35 seconds.
 * A timeout is fatal for the connection.
 * update_nonblock_timestamps() is used for nonblocked
 * connection fds.
 */
#define	WAIT_PER_TRY	35000	/* milliseconds */

static  void
update_nonblock_timestamps(SVCXPRT *xprt_conn)
{
	struct timeval tv;
	/* LINTED pointer cast */
	struct cf_conn *cd = (struct cf_conn *)xprt_conn->xp_p1;

	(void) gettimeofday(&tv, NULL);
	cd->cf_conn_nonblock_timestamp = tv.tv_sec;
}

/*
 * reads data from the vc conection.
 * any error is fatal and the connection is closed.
 * (And a read of zero bytes is a half closed stream => error.)
 */
static int
read_vc(SVCXPRT *xprt, caddr_t buf, int len)
{
	int fd = xprt->xp_fd;
	XDR *xdrs = svc_xdrs[fd];
	struct pollfd pfd;
	int ret;

	/*
	 * Make sure the connection is not already dead.
	 */
/* LINTED pointer alignment */
	if (svc_failed(xprt))
		return (-1);

	/* LINTED pointer cast */
	if (((struct cf_conn *)(xprt->xp_p1))->cf_conn_nonblock) {
		/*
		 * For nonblocked reads, only update the
		 * timestamps to record the activity so the
		 * connection will not be timedout.
		 * Up to "len" bytes are requested.
		 * If fewer than "len" bytes are received, the
		 * connection is poll()ed again.
		 * The poll() for the connection fd is performed
		 * in the main poll() so that all outstanding fds
		 * are polled rather than just the vc connection.
		 * Polling on only the vc connection until the entire
		 * fragment has been read can be exploited in
		 * a Denial of Service Attack such as telnet <host> 111.
		 */
		if ((len = t_rcvnonblock(xprt, buf, len)) >= 0) {
			if (len > 0) {
				update_nonblock_timestamps(xprt);
			}
			return (len);
		}
		goto fatal_err;
	}

	if (!__is_xdrrec_first(xdrs)) {

		pfd.fd = fd;
		pfd.events = MASKVAL;

		do {
			if ((ret = poll(&pfd, 1, WAIT_PER_TRY)) <= 0) {
				/*
				 * If errno is EINTR, ERESTART, or EAGAIN
				 * ignore error and repeat poll
				 */
				if (ret < 0 && (errno == EINTR ||
				    errno == ERESTART || errno == EAGAIN))
					continue;
				goto fatal_err;
			}
		} while (pfd.revents == 0);
		if (pfd.revents & POLLNVAL)
			goto fatal_err;
	}
	(void) __xdrrec_resetfirst(xdrs);
	if ((len = t_rcvall(fd, buf, len)) > 0) {
		return (len);
	}

fatal_err:
/* LINTED pointer alignment */
	((struct cf_conn *)(xprt->xp_p1))->strm_stat = XPRT_DIED;
/* LINTED pointer alignment */
	svc_flags(xprt) |= SVC_FAILED;
	return (-1);
}

/*
 * Requests up to "len" bytes of data.
 * Returns number of bytes actually received, or error indication.
 */
static int
t_rcvnonblock(SVCXPRT *xprt, caddr_t buf, int len)
{
	int fd = xprt->xp_fd;
	int flag;
	int res;

	res = t_rcv(fd, buf, (unsigned)len, &flag);
	if (res == -1) {
		switch (t_errno) {
		case TLOOK:
			switch (t_look(fd)) {
			case T_DISCONNECT:
				(void) t_rcvdis(fd, NULL);
				break;
			case T_ORDREL:
				(void) t_rcvrel(fd);
				(void) t_sndrel(fd);
				break;
			default:
				break;
			}
			break;
		case TNODATA:
			/*
			 * Either poll() lied, or the xprt/fd was closed and
			 * re-opened under our feet. Return 0, so that we go
			 * back to waiting for data.
			 */
			res = 0;
			break;
		/* Should handle TBUFOVFLW TSYSERR ? */
		default:
			break;
		}
	}
	return (res);
}

/*
 * Timeout out nonblocked connection fds
 * If there has been no activity on the fd for __rpc_irtimeout
 * seconds, timeout the fd  by destroying its xprt.
 * If the caller gets an EMFILE error, the caller may also request
 * that the least busy xprt gets destroyed as well.
 * svc_thr_mutex is held when this is called.
 * svc_mutex is held when this is called.
 */
static void
svc_timeout_nonblock_xprt_and_LRU(bool_t destroy_lru)
{
	SVCXPRT *xprt;
	SVCXPRT *dead_xprt[CLEANUP_SIZE];
	SVCXPRT *candidate_xprt = NULL;
	struct cf_conn *cd;
	int i, fd_idx = 0, dead_idx = 0;
	struct timeval now;
	time_t lasttime, maxctime = 0;
	extern rwlock_t svc_fd_lock;

	if (!check_nonblock_timestamps)
		return;

	(void) gettimeofday(&now, NULL);
	if (svc_xports == NULL)
		return;
	/*
	 * Hold svc_fd_lock to protect
	 * svc_xports, svc_maxpollfd, svc_max_pollfd
	 */
	(void) rw_wrlock(&svc_fd_lock);
	for (;;) {
		/*
		 * Timeout upto CLEANUP_SIZE connection fds per
		 * iteration for the while(1) loop
		 */
		for (dead_idx = 0; fd_idx < svc_max_pollfd; fd_idx++) {
			if ((xprt = svc_xports[fd_idx]) == NULL) {
				continue;
			}
			/* Only look at connection fds */
			/* LINTED pointer cast */
			if (svc_type(xprt) != SVC_CONNECTION) {
				continue;
			}
			/* LINTED pointer cast */
			cd = (struct cf_conn *)xprt->xp_p1;
			if (!cd->cf_conn_nonblock)
				continue;
			lasttime = now.tv_sec - cd->cf_conn_nonblock_timestamp;
			if (lasttime >= __rpc_irtimeout &&
			    __rpc_irtimeout != 0) {
				/* Enter in timedout/dead array */
				dead_xprt[dead_idx++] = xprt;
				if (dead_idx >= CLEANUP_SIZE)
					break;
			} else
			if (lasttime > maxctime) {
				/* Possible LRU xprt */
				candidate_xprt = xprt;
				maxctime = lasttime;
			}
		}

		for (i = 0; i < dead_idx; i++) {
			/* Still holding svc_fd_lock */
			_svc_vc_destroy_private(dead_xprt[i], FALSE);
		}

		/*
		 * If all the nonblocked fds have been checked, we're done.
		 */
		if (fd_idx++ >= svc_max_pollfd)
			break;
	}
	if ((destroy_lru) && (candidate_xprt != NULL)) {
		_svc_vc_destroy_private(candidate_xprt, FALSE);
	}
	(void) rw_unlock(&svc_fd_lock);
}
/*
 * Receive the required bytes of data, even if it is fragmented.
 */
static int
t_rcvall(int fd, char *buf, int len)
{
	int flag;
	int final = 0;
	int res;

	do {
		res = t_rcv(fd, buf, (unsigned)len, &flag);
		if (res == -1) {
			if (t_errno == TLOOK) {
				switch (t_look(fd)) {
				case T_DISCONNECT:
					(void) t_rcvdis(fd, NULL);
					break;
				case T_ORDREL:
					(void) t_rcvrel(fd);
					(void) t_sndrel(fd);
					break;
				default:
					break;
				}
			}
			break;
		}
		final += res;
		buf += res;
		len -= res;
	} while (len && (flag & T_MORE));
	return (res == -1 ? -1 : final);
}

/*
 * writes data to the vc connection.
 * Any error is fatal and the connection is closed.
 */
static int
write_vc(SVCXPRT *xprt, caddr_t buf, int len)
{
	int i, cnt;
	int flag;
	int maxsz;
	int nonblock;
	struct pollfd pfd;

/* LINTED pointer alignment */
	maxsz = ((struct cf_conn *)(xprt->xp_p1))->cf_tsdu;
	/* LINTED pointer cast */
	nonblock = ((struct cf_conn *)(xprt->xp_p1))->cf_conn_nonblock;
	if (nonblock && maxsz <= 0)
		maxsz = len;
	if ((maxsz == 0) || (maxsz == -1)) {
		if ((len = t_snd(xprt->xp_fd, buf, (unsigned)len,
		    (int)0)) == -1) {
			if (t_errno == TLOOK) {
				switch (t_look(xprt->xp_fd)) {
				case T_DISCONNECT:
					(void) t_rcvdis(xprt->xp_fd, NULL);
					break;
				case T_ORDREL:
					(void) t_rcvrel(xprt->xp_fd);
					(void) t_sndrel(xprt->xp_fd);
					break;
				default:
					break;
				}
			}
/* LINTED pointer alignment */
			((struct cf_conn *)(xprt->xp_p1))->strm_stat =
			    XPRT_DIED;
/* LINTED pointer alignment */
			svc_flags(xprt) |= SVC_FAILED;
		}
		return (len);
	}

	/*
	 * Setup for polling. We want to be able to write normal
	 * data to the transport
	 */
	pfd.fd = xprt->xp_fd;
	pfd.events = POLLWRNORM;

	/*
	 * This for those transports which have a max size for data,
	 * and for the non-blocking case, where t_snd() may send less
	 * than requested.
	 */
	for (cnt = len, i = 0; cnt > 0; cnt -= i, buf += i) {
		flag = cnt > maxsz ? T_MORE : 0;
		if ((i = t_snd(xprt->xp_fd, buf,
		    (unsigned)MIN(cnt, maxsz), flag)) == -1) {
			if (t_errno == TLOOK) {
				switch (t_look(xprt->xp_fd)) {
				case T_DISCONNECT:
					(void) t_rcvdis(xprt->xp_fd, NULL);
					break;
				case T_ORDREL:
					(void) t_rcvrel(xprt->xp_fd);
					break;
				default:
					break;
				}
			} else if (t_errno == TFLOW) {
				/* Try again */
				i = 0;
				/* Wait till we can write to the transport */
				do {
					if (poll(&pfd, 1, WAIT_PER_TRY) < 0) {
						/*
						 * If errno is ERESTART, or
						 * EAGAIN ignore error and
						 * repeat poll
						 */
						if (errno == ERESTART ||
						    errno == EAGAIN)
							continue;
						else
							goto fatal_err;
					}
				} while (pfd.revents == 0);
				if (pfd.revents & (POLLNVAL | POLLERR |
				    POLLHUP))
					goto fatal_err;
				continue;
			}
fatal_err:
/* LINTED pointer alignment */
			((struct cf_conn *)(xprt->xp_p1))->strm_stat =
			    XPRT_DIED;
/* LINTED pointer alignment */
			svc_flags(xprt) |= SVC_FAILED;
			return (-1);
		}
	}
	return (len);
}

static enum xprt_stat
svc_vc_stat(SVCXPRT *xprt)
{
/* LINTED pointer alignment */
	SVCXPRT *parent = SVCEXT(xprt)->parent ? SVCEXT(xprt)->parent : xprt;

/* LINTED pointer alignment */
	if (svc_failed(parent) || svc_failed(xprt))
		return (XPRT_DIED);
	if (!xdrrec_eof(svc_xdrs[xprt->xp_fd]))
		return (XPRT_MOREREQS);
	/*
	 * xdrrec_eof could have noticed that the connection is dead, so
	 * check status again.
	 */
/* LINTED pointer alignment */
	if (svc_failed(parent) || svc_failed(xprt))
		return (XPRT_DIED);
	return (XPRT_IDLE);
}



static bool_t
svc_vc_recv(SVCXPRT *xprt, struct rpc_msg *msg)
{
/* LINTED pointer alignment */
	struct cf_conn *cd = (struct cf_conn *)(xprt->xp_p1);
	XDR *xdrs = svc_xdrs[xprt->xp_fd];

	xdrs->x_op = XDR_DECODE;

	if (cd->cf_conn_nonblock) {
		/* Get the next input */
		if (!__xdrrec_getbytes_nonblock(xdrs, &cd->strm_stat)) {
			/*
			 * The entire record has not been received.
			 * If the xprt has died, pass it along in svc_flags.
			 * Return FALSE; For nonblocked vc connection,
			 * xdr_callmsg() is called only after the entire
			 * record has been received.  For blocked vc
			 * connection, the data is received on the fly as it
			 * is being processed through the xdr routines.
			 */
			if (cd->strm_stat == XPRT_DIED)
				/* LINTED pointer cast */
				svc_flags(xprt) |= SVC_FAILED;
			return (FALSE);
		}
	} else {
		if (!xdrrec_skiprecord(xdrs))
			return (FALSE);
		(void) __xdrrec_setfirst(xdrs);
	}

	if (xdr_callmsg(xdrs, msg)) {
		cd->x_id = msg->rm_xid;
		return (TRUE);
	}

	/*
	 * If a non-blocking connection, drop it when message decode fails.
	 * We are either under attack, or we're talking to a broken client.
	 */
	if (cd->cf_conn_nonblock) {
		/* LINTED pointer cast */
		svc_flags(xprt) |= SVC_FAILED;
	}

	return (FALSE);
}

static bool_t
svc_vc_getargs(SVCXPRT *xprt, xdrproc_t xdr_args, caddr_t args_ptr)
{
	bool_t dummy;

/* LINTED pointer alignment */
	dummy = SVCAUTH_UNWRAP(&SVC_XP_AUTH(xprt), svc_xdrs[xprt->xp_fd],
	    xdr_args, args_ptr);
	if (svc_mt_mode != RPC_SVC_MT_NONE)
		svc_args_done(xprt);
	return (dummy);
}

static bool_t
svc_vc_freeargs(SVCXPRT *xprt, xdrproc_t xdr_args, caddr_t args_ptr)
{
/* LINTED pointer alignment */
	XDR *xdrs = &(((struct cf_conn *)(xprt->xp_p1))->xdrs);

	xdrs->x_op = XDR_FREE;
	return ((*xdr_args)(xdrs, args_ptr));
}

static bool_t
svc_vc_reply(SVCXPRT *xprt, struct rpc_msg *msg)
{
/* LINTED pointer alignment */
	struct cf_conn *cd = (struct cf_conn *)(xprt->xp_p1);
	XDR *xdrs = &(cd->xdrs);
	bool_t stat = FALSE;
	xdrproc_t xdr_results;
	caddr_t xdr_location;
	bool_t has_args;

	if (svc_mt_mode != RPC_SVC_MT_NONE)
/* LINTED pointer alignment */
		(void) mutex_lock(&svc_send_mutex(SVCEXT(xprt)->parent));

	if (msg->rm_reply.rp_stat == MSG_ACCEPTED &&
	    msg->rm_reply.rp_acpt.ar_stat == SUCCESS) {
		has_args = TRUE;
		xdr_results = msg->acpted_rply.ar_results.proc;
		xdr_location = msg->acpted_rply.ar_results.where;
		msg->acpted_rply.ar_results.proc = xdr_void;
		msg->acpted_rply.ar_results.where = NULL;
	} else
		has_args = FALSE;

	xdrs->x_op = XDR_ENCODE;
	msg->rm_xid = cd->x_id;
/* LINTED pointer alignment */
	if (xdr_replymsg(xdrs, msg) && (!has_args || SVCAUTH_WRAP(
	    &SVC_XP_AUTH(xprt), xdrs, xdr_results, xdr_location))) {
		stat = TRUE;
	}
	(void) xdrrec_endofrecord(xdrs, TRUE);

	if (svc_mt_mode != RPC_SVC_MT_NONE)
/* LINTED pointer alignment */
		(void) mutex_unlock(&svc_send_mutex(SVCEXT(xprt)->parent));

	return (stat);
}

static struct xp_ops *
svc_vc_ops(void)
{
	static struct xp_ops ops;
	extern mutex_t ops_lock;

/* VARIABLES PROTECTED BY ops_lock: ops */

	(void) mutex_lock(&ops_lock);
	if (ops.xp_recv == NULL) {
		ops.xp_recv = svc_vc_recv;
		ops.xp_stat = svc_vc_stat;
		ops.xp_getargs = svc_vc_getargs;
		ops.xp_reply = svc_vc_reply;
		ops.xp_freeargs = svc_vc_freeargs;
		ops.xp_destroy = svc_vc_destroy;
		ops.xp_control = svc_vc_control;
	}
	(void) mutex_unlock(&ops_lock);
	return (&ops);
}

static struct xp_ops *
svc_vc_rendezvous_ops(void)
{
	static struct xp_ops ops;
	extern mutex_t ops_lock;

	(void) mutex_lock(&ops_lock);
	if (ops.xp_recv == NULL) {
		ops.xp_recv = rendezvous_request;
		ops.xp_stat = rendezvous_stat;
		ops.xp_getargs = (bool_t (*)())abort;
		ops.xp_reply = (bool_t (*)())abort;
		ops.xp_freeargs = (bool_t (*)())abort;
		ops.xp_destroy = svc_vc_destroy;
		ops.xp_control = rendezvous_control;
	}
	(void) mutex_unlock(&ops_lock);
	return (&ops);
}

/*
 * dup cache wrapper functions for vc requests. The set of dup
 * functions were written with the view that they may be expanded
 * during creation of a generic svc_vc_enablecache routine
 * which would have a size based cache, rather than a time based cache.
 * The real work is done in generic svc.c
 */
bool_t
__svc_vc_dupcache_init(SVCXPRT *xprt, void *condition, int basis)
{
	return (__svc_dupcache_init(condition, basis,
	    /* LINTED pointer alignment */
	    &(((struct cf_rendezvous *)xprt->xp_p1)->cf_cache)));
}

int
__svc_vc_dup(struct svc_req *req, caddr_t *resp_buf, uint_t *resp_bufsz)
{
	return (__svc_dup(req, resp_buf, resp_bufsz,
	    /* LINTED pointer alignment */
	    ((struct cf_conn *)req->rq_xprt->xp_p1)->cf_cache));
}

int
__svc_vc_dupdone(struct svc_req *req, caddr_t resp_buf, uint_t resp_bufsz,
				int status)
{
	return (__svc_dupdone(req, resp_buf, resp_bufsz, status,
	    /* LINTED pointer alignment */
	    ((struct cf_conn *)req->rq_xprt->xp_p1)->cf_cache));
}
