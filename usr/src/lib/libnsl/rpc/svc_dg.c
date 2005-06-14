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
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * svc_dg.c, Server side for connectionless RPC.
 *
 * Does some caching in the hopes of achieving execute-at-most-once semantics.
 */

#include "mt.h"
#include "rpc_mt.h"
#include <stdio.h>
#include <sys/types.h>
#include <rpc/trace.h>
#include <rpc/rpc.h>
#include <errno.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef RPC_CACHE_DEBUG
#include <netconfig.h>
#include <netdir.h>
#endif

#ifndef MAX
#define	MAX(a, b)	(((a) > (b)) ? (a) : (b))
#endif

static struct xp_ops *svc_dg_ops();
static void cache_set();
static int cache_get();

#define	MAX_OPT_WORDS	128		/* needs to fit a ucred */

/*
 * kept in xprt->xp_p2
 */
struct svc_dg_data {
	/* XXX: optbuf should be the first field, used by ti_opts.c code */
	struct	netbuf optbuf;			/* netbuf for options */
	int	opts[MAX_OPT_WORDS];		/* options */
	uint_t   su_iosz;			/* size of send.recv buffer */
	uint32_t	su_xid;			/* transaction id */
	XDR	su_xdrs;			/* XDR handle */
	char	su_verfbody[MAX_AUTH_BYTES];	/* verifier body */
	char 	*su_cache;			/* cached data, NULL if none */
	struct t_unitdata   su_tudata;		/* tu_data for recv */
};
#define	su_data(xprt)	((struct svc_dg_data *)(xprt->xp_p2))
#define	rpc_buffer(xprt) ((xprt)->xp_p1)

/*
 * Usage:
 *	xprt = svc_dg_create(sock, sendsize, recvsize);
 * Does other connectionless specific initializations.
 * Once *xprt is initialized, it is registered.
 * see (svc.h, xprt_register). If recvsize or sendsize are 0 suitable
 * system defaults are chosen.
 * The routines returns NULL if a problem occurred.
 */
static const char svc_dg_str[] = "svc_dg_create: %s";
static const char svc_dg_err1[] = "could not get transport information";
static const char svc_dg_err2[] = " transport does not support data transfer";
static const char svc_dg_err3[] =
		"fd > FD_SETSIZE; Use rpc_control(RPC_SVC_USE_POLLFD,...);";
static const char __no_mem_str[] = "out of memory";

/* Structure used to initialize SVC_XP_AUTH(xprt).svc_ah_ops. */
extern struct svc_auth_ops svc_auth_any_ops;
extern int __rpc_get_ltaddr(struct netbuf *, struct netbuf *);

void
svc_dg_xprtfree(xprt)
	SVCXPRT			*xprt;
{
/* LINTED pointer alignment */
	SVCXPRT_EXT		*xt = xprt ? SVCEXT(xprt) : NULL;
/* LINTED pointer alignment */
	struct svc_dg_data	*su = xprt ? su_data(xprt) : NULL;

	if (xprt == NULL)
		return;
	if (xprt->xp_netid)
		free((char *)xprt->xp_netid);
	if (xprt->xp_tp)
		free((char *)xprt->xp_tp);
	if (xt->parent == NULL)
		if (xprt->xp_ltaddr.buf)
			free(xprt->xp_ltaddr.buf);
	if (xprt->xp_rtaddr.buf)
		free(xprt->xp_rtaddr.buf);
	if (su != NULL) {
		XDR_DESTROY(&(su->su_xdrs));
		free((char *)su);
	}
	if (rpc_buffer(xprt))
		free((char *)rpc_buffer(xprt));
	svc_xprt_free(xprt);
}

SVCXPRT *
svc_dg_create_private(fd, sendsize, recvsize)
	int fd;
	uint_t sendsize;
	uint_t recvsize;
{
	SVCXPRT *xprt;
	struct svc_dg_data *su = NULL;
	struct t_info tinfo;

	trace4(TR_svc_dg_create, 0, fd, sendsize, recvsize);
	if (RPC_FD_NOTIN_FDSET(fd)) {
		errno = EBADF;
		t_errno = TBADF;
		syslog(LOG_ERR, svc_dg_str, svc_dg_err3);
		trace2(TR_svc_dg_create, 1, fd);
		return ((SVCXPRT *)NULL);
	}

	if (t_getinfo(fd, &tinfo) == -1) {
		syslog(LOG_ERR, svc_dg_str, svc_dg_err1);
		trace2(TR_svc_dg_create, 1, fd);
		return ((SVCXPRT *)NULL);
	}
	/*
	 * Find the receive and the send size
	 */
	sendsize = __rpc_get_t_size((int)sendsize, tinfo.tsdu);
	recvsize = __rpc_get_t_size((int)recvsize, tinfo.tsdu);
	if ((sendsize == 0) || (recvsize == 0)) {
		syslog(LOG_ERR, svc_dg_str, svc_dg_err2);
		trace2(TR_svc_dg_create, 1, fd);
		return ((SVCXPRT *)NULL);
	}

	if ((xprt = svc_xprt_alloc()) == NULL)
		goto freedata;
/* LINTED pointer alignment */
	svc_flags(xprt) |= SVC_DGRAM;

	su = (struct svc_dg_data *)mem_alloc(sizeof (*su));
	if (su == NULL)
		goto freedata;
	su->su_iosz = ((MAX(sendsize, recvsize) + 3) / 4) * 4;
	if ((rpc_buffer(xprt) = (char *)mem_alloc(su->su_iosz)) == NULL)
		goto freedata;
	xdrmem_create(&(su->su_xdrs), rpc_buffer(xprt), su->su_iosz,
		XDR_DECODE);
	su->su_cache = NULL;
	xprt->xp_fd = fd;
	xprt->xp_p2 = (caddr_t)su;
	xprt->xp_verf.oa_base = su->su_verfbody;
	xprt->xp_ops = svc_dg_ops();

	su->su_tudata.addr.maxlen =  0; /* Fill in later */

	su->su_tudata.udata.buf = (char *)rpc_buffer(xprt);
	su->su_tudata.opt.buf = (char *)su->opts;
	su->su_tudata.udata.maxlen = su->su_iosz;
	su->su_tudata.opt.maxlen = MAX_OPT_WORDS << 2;  /* no of bytes */
/* LINTED pointer alignment */
	SVC_XP_AUTH(xprt).svc_ah_ops = svc_auth_any_ops;
/* LINTED pointer alignment */
	SVC_XP_AUTH(xprt).svc_ah_private = NULL;
	trace2(TR_svc_dg_create, 1, fd);
	return (xprt);
freedata:
	(void) syslog(LOG_ERR, svc_dg_str, __no_mem_str);
	if (xprt)
		svc_dg_xprtfree(xprt);
	trace2(TR_svc_dg_create, 1, fd);
	return ((SVCXPRT *)NULL);
}

SVCXPRT *
svc_dg_create(fd, sendsize, recvsize)
	int fd;
	uint_t sendsize;
	uint_t recvsize;
{
	SVCXPRT *xprt;

	if ((xprt = svc_dg_create_private(fd, sendsize, recvsize)) != NULL)
		xprt_register(xprt);
	return (xprt);
}

SVCXPRT *
svc_dg_xprtcopy(parent)
	SVCXPRT			*parent;
{
	SVCXPRT			*xprt;
	struct svc_dg_data	*su;

	if ((xprt = svc_xprt_alloc()) == NULL)
		return (NULL);

/* LINTED pointer alignment */
	SVCEXT(xprt)->parent = parent;
/* LINTED pointer alignment */
	SVCEXT(xprt)->flags = SVCEXT(parent)->flags;

	xprt->xp_fd = parent->xp_fd;
	xprt->xp_port = parent->xp_port;
	xprt->xp_ops = svc_dg_ops();
	if (parent->xp_tp) {
		xprt->xp_tp = (char *)strdup(parent->xp_tp);
		if (xprt->xp_tp == NULL) {
			syslog(LOG_ERR, "svc_dg_xprtcopy: strdup failed");
			svc_dg_xprtfree(xprt);
			return (NULL);
		}
	}
	if (parent->xp_netid) {
		xprt->xp_netid = (char *)strdup(parent->xp_netid);
		if (xprt->xp_netid == NULL) {
			syslog(LOG_ERR, "svc_dg_xprtcopy: strdup failed");
			if (parent->xp_tp)
				free(parent->xp_tp);
			svc_dg_xprtfree(xprt);
			return (NULL);
		}
	}
	xprt->xp_ltaddr = parent->xp_ltaddr;	/* shared with parent */

	xprt->xp_rtaddr = parent->xp_rtaddr;
	xprt->xp_rtaddr.buf = (char *)malloc(xprt->xp_rtaddr.maxlen);
	if (xprt->xp_rtaddr.buf == NULL) {
		svc_dg_xprtfree(xprt);
		return (NULL);
	}
	memcpy(xprt->xp_rtaddr.buf, parent->xp_rtaddr.buf,
						xprt->xp_rtaddr.maxlen);
	xprt->xp_type = parent->xp_type;

	if ((su = (struct svc_dg_data *)malloc(sizeof (struct svc_dg_data)))
		== NULL) {
		svc_dg_xprtfree(xprt);
		return (NULL);
	}
/* LINTED pointer alignment */
	su->su_iosz = su_data(parent)->su_iosz;
	if ((rpc_buffer(xprt) = (char *)mem_alloc(su->su_iosz)) == NULL) {
		svc_dg_xprtfree(xprt);
		free((char *)su);
		return (NULL);
	}
	xdrmem_create(&(su->su_xdrs), rpc_buffer(xprt), su->su_iosz,
		XDR_DECODE);
	su->su_cache = NULL;
	su->su_tudata.addr.maxlen =  0; /* Fill in later */
	su->su_tudata.udata.buf = (char *)rpc_buffer(xprt);
	su->su_tudata.opt.buf = (char *)su->opts;
	su->su_tudata.udata.maxlen = su->su_iosz;
	su->su_tudata.opt.maxlen = MAX_OPT_WORDS << 2;  /* no of bytes */
	xprt->xp_p2 = (caddr_t)su;	/* su_data(xprt) = su */
	xprt->xp_verf.oa_base = su->su_verfbody;

	return (xprt);
}

/*ARGSUSED*/
static enum xprt_stat
svc_dg_stat(xprt)
	SVCXPRT *xprt;
{
	trace1(TR_svc_dg_stat, 0);
	trace1(TR_svc_dg_stat, 1);
	return (XPRT_IDLE);
}

static bool_t
svc_dg_recv(xprt, msg)
	SVCXPRT *xprt;
	struct rpc_msg *msg;
{
/* LINTED pointer alignment */
	struct svc_dg_data *su = su_data(xprt);
	XDR *xdrs = &(su->su_xdrs);
	struct t_unitdata *tu_data = &(su->su_tudata);
	int moreflag;
	struct netbuf *nbufp;
	struct netconfig *nconf;

	/* XXX: tudata should have been made a part of the server handle */
	trace1(TR_svc_dg_recv, 0);

	if (tu_data->addr.maxlen == 0)
		tu_data->addr = xprt->xp_rtaddr;
again:
	tu_data->addr.len = 0;
	tu_data->opt.len  = 0;
	tu_data->udata.len  = 0;

	moreflag = 0;
	if (t_rcvudata(xprt->xp_fd, tu_data, &moreflag) == -1) {
#ifdef RPC_DEBUG
		syslog(LOG_ERR, "svc_dg_recv: t_rcvudata t_errno=%d errno=%d\n",
				t_errno, errno);
#endif
		if (t_errno == TLOOK) {
			int lookres;

			lookres = t_look(xprt->xp_fd);
			if ((lookres & T_UDERR) &&
				(t_rcvuderr(xprt->xp_fd,
					(struct t_uderr *)0) < 0)) {
				/*EMPTY*/
#ifdef RPC_DEBUG
				syslog(LOG_ERR,
				"svc_dg_recv: t_rcvuderr t_errno = %d\n",
					t_errno);
#endif
			}
			if (lookres & T_DATA)
				goto again;
		} else if ((errno == EINTR) && (t_errno == TSYSERR))
			goto again;
		else {
			trace1(TR_svc_dg_recv, 1);
			return (FALSE);
		}
	}

	if ((moreflag) ||
		(tu_data->udata.len < 4 * (uint_t)sizeof (uint32_t))) {
		/*
		 * If moreflag is set, drop that data packet. Something wrong
		 */
		trace1(TR_svc_dg_recv, 1);
		return (FALSE);
	}
	su->optbuf = tu_data->opt;
	xprt->xp_rtaddr.len = tu_data->addr.len;
	xdrs->x_op = XDR_DECODE;
	XDR_SETPOS(xdrs, 0);
	if (! xdr_callmsg(xdrs, msg)) {
		trace1(TR_svc_dg_recv, 1);
		return (FALSE);
	}
	su->su_xid = msg->rm_xid;
	if (su->su_cache != NULL) {
		char *reply;
		uint32_t replylen;

		if (cache_get(xprt, msg, &reply, &replylen)) {
			/* tu_data.addr is already set */
			tu_data->udata.buf = reply;
			tu_data->udata.len = (uint_t)replylen;
			tu_data->opt.len = 0;
			(void) t_sndudata(xprt->xp_fd, tu_data);
			tu_data->udata.buf = (char *)rpc_buffer(xprt);
			trace1(TR_svc_dg_recv, 1);
			return (FALSE);
		}
	}

	/*
	 * get local ip address
	 */

	if ((nconf = getnetconfigent(xprt->xp_netid)) != NULL) {
	    if (strcmp(nconf->nc_protofmly, NC_INET) == 0 ||
		strcmp(nconf->nc_protofmly, NC_INET6) == 0) {
		if (nconf->nc_semantics == NC_TPI_CLTS) {
		    nbufp = (struct netbuf *)(xprt->xp_p2);
		    if (__rpc_get_ltaddr(nbufp, &xprt->xp_ltaddr) < 0) {
			if (strcmp(nconf->nc_protofmly, NC_INET) == 0) {
			    syslog(LOG_ERR,
				"svc_dg_recv: ip(udp), t_errno=%d, errno=%d",
					t_errno, errno);
			}
			if (strcmp(nconf->nc_protofmly, NC_INET6) == 0) {
			    syslog(LOG_ERR,
				"svc_dg_recv: ip (udp6), t_errno=%d, errno=%d",
					t_errno, errno);
			}
			freenetconfigent(nconf);
			trace1(TR_svc_dg_recv, 1);
			return (FALSE);
		    }
		}
	    }
	    freenetconfigent(nconf);
	}
	trace1(TR_svc_dg_recv, 1);
	return (TRUE);
}

static bool_t
svc_dg_reply(xprt, msg)
	SVCXPRT *xprt;
	struct rpc_msg *msg;
{
/* LINTED pointer alignment */
	struct svc_dg_data *su = su_data(xprt);
	XDR *xdrs = &(su->su_xdrs);
	bool_t stat = FALSE;
	xdrproc_t xdr_results;
	caddr_t xdr_location;
	bool_t has_args;

	trace1(TR_svc_dg_reply, 0);
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
	XDR_SETPOS(xdrs, 0);
	msg->rm_xid = su->su_xid;
	if (xdr_replymsg(xdrs, msg) && (!has_args ||
/* LINTED pointer alignment */
		SVCAUTH_WRAP(&SVC_XP_AUTH(xprt), xdrs, xdr_results,
							xdr_location))) {
		int slen;
		struct t_unitdata *tu_data = &(su->su_tudata);

		slen = (int)XDR_GETPOS(xdrs);
		tu_data->udata.len = slen;
		tu_data->opt.len = 0;
try_again:
		if (t_sndudata(xprt->xp_fd, tu_data) == 0) {
			stat = TRUE;
			if (su->su_cache && slen >= 0) {
				cache_set(xprt, (uint32_t)slen);
			}
		} else {
			if (errno == EINTR)
				goto try_again;

			syslog(LOG_ERR,
			"svc_dg_reply: t_sndudata error t_errno=%d errno=%d\n",
				t_errno, errno);
		}
	}
	trace1(TR_svc_dg_reply, 1);
	return (stat);
}

static bool_t
svc_dg_getargs(xprt, xdr_args, args_ptr)
	SVCXPRT *xprt;
	xdrproc_t xdr_args;
	caddr_t args_ptr;
{
	bool_t dummy_stat1;

	trace1(TR_svc_dg_getargs, 0);
	if (svc_mt_mode != RPC_SVC_MT_NONE)
		svc_args_done(xprt);
/* LINTED pointer alignment */
	dummy_stat1 = SVCAUTH_UNWRAP(&SVC_XP_AUTH(xprt),
				&(su_data(xprt)->su_xdrs), xdr_args, args_ptr);
	trace1(TR_svc_dg_getargs, 1);
	return (dummy_stat1);
}

static bool_t
svc_dg_freeargs(xprt, xdr_args, args_ptr)
	SVCXPRT *xprt;
	xdrproc_t xdr_args;
	caddr_t args_ptr;
{
/* LINTED pointer alignment */
	XDR *xdrs = &(su_data(xprt)->su_xdrs);
	bool_t dummy_stat2;

	trace1(TR_svc_dg_freeargs, 0);
	xdrs->x_op = XDR_FREE;
	dummy_stat2 =  (*xdr_args)(xdrs, args_ptr);
	trace1(TR_svc_dg_freeargs, 1);
	return (dummy_stat2);
}

static void
svc_dg_destroy(xprt)
	SVCXPRT *xprt;
{
	trace1(TR_svc_dg_destroy, 0);
	mutex_lock(&svc_mutex);
	_svc_dg_destroy_private(xprt);
	mutex_unlock(&svc_mutex);
	trace1(TR_svc_dg_destroy, 1);
}

void
_svc_dg_destroy_private(xprt)
	SVCXPRT *xprt;
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

	xprt_unregister(xprt);
	(void) t_close(xprt->xp_fd);

	if (svc_mt_mode != RPC_SVC_MT_NONE)
		svc_xprt_destroy(xprt);
	else
		svc_dg_xprtfree(xprt);
}

/*ARGSUSED*/
static bool_t
svc_dg_control(xprt, rq, in)
	SVCXPRT *xprt;
	const uint_t	rq;
	void		*in;
{
	trace3(TR_svc_dg_control, 0, xprt, rq);
	switch (rq) {
	case SVCGET_XID:
		if (xprt->xp_p2 == NULL) {
			trace1(TR_svc_dg_control, 1);
			return (FALSE);
		} else {
			*(uint32_t *)in =
			/* LINTED pointer alignment */
			((struct svc_dg_data *)(xprt->xp_p2))->su_xid;
			trace1(TR_svc_dg_control, 1);
			return (TRUE);
		}
	default:
		trace1(TR_svc_dg_control, 1);
		return (FALSE);
	}
}

static struct xp_ops *
svc_dg_ops()
{
	static struct xp_ops ops;
	extern mutex_t ops_lock;

/* VARIABLES PROTECTED BY ops_lock: ops */

	trace1(TR_svc_dg_ops, 0);
	mutex_lock(&ops_lock);
	if (ops.xp_recv == NULL) {
		ops.xp_recv = svc_dg_recv;
		ops.xp_stat = svc_dg_stat;
		ops.xp_getargs = svc_dg_getargs;
		ops.xp_reply = svc_dg_reply;
		ops.xp_freeargs = svc_dg_freeargs;
		ops.xp_destroy = svc_dg_destroy;
		ops.xp_control = svc_dg_control;
	}
	mutex_unlock(&ops_lock);
	trace1(TR_svc_dg_ops, 1);
	return (&ops);
}

/*  The CACHING COMPONENT */

/*
 * Could have been a separate file, but some part of it depends upon the
 * private structure of the client handle.
 *
 * Fifo cache for cl server
 * Copies pointers to reply buffers into fifo cache
 * Buffers are sent again if retransmissions are detected.
 */

#define	SPARSENESS 4	/* 75% sparse */

#define	ALLOC(type, size)	\
	(type *)mem_alloc((unsigned)(sizeof (type) * (size)))

#define	MEMZERO(addr, type, size)	 \
	(void) memset((char *)(addr), 0, sizeof (type) * (int)(size))

#define	FREE(addr, type, size)	\
	mem_free((char *)(addr), (sizeof (type) * (size)))

/*
 * An entry in the cache
 */
typedef struct cache_node *cache_ptr;
struct cache_node {
	/*
	 * Index into cache is xid, proc, vers, prog and address
	 */
	uint32_t cache_xid;
	rpcproc_t cache_proc;
	rpcvers_t cache_vers;
	rpcprog_t cache_prog;
	struct netbuf cache_addr;
	/*
	 * The cached reply and length
	 */
	char *cache_reply;
	uint32_t cache_replylen;
	/*
	 * Next node on the list, if there is a collision
	 */
	cache_ptr cache_next;
};

/*
 * The entire cache
 */
struct cl_cache {
	uint32_t uc_size;		/* size of cache */
	cache_ptr *uc_entries;	/* hash table of entries in cache */
	cache_ptr *uc_fifo;	/* fifo list of entries in cache */
	uint32_t uc_nextvictim;	/* points to next victim in fifo list */
	rpcprog_t uc_prog;	/* saved program number */
	rpcvers_t uc_vers;	/* saved version number */
	rpcproc_t uc_proc;	/* saved procedure number */
};


/*
 * the hashing function
 */
#define	CACHE_LOC(transp, xid)	\
	(xid % (SPARSENESS * ((struct cl_cache *) \
		su_data(transp)->su_cache)->uc_size))

extern mutex_t	dupreq_lock;

/*
 * Enable use of the cache. Returns 1 on success, 0 on failure.
 * Note: there is no disable.
 */
static const char cache_enable_str[] = "svc_enablecache: %s %s";
static const char alloc_err[] = "could not allocate cache ";
static const char enable_err[] = "cache already enabled";

int
svc_dg_enablecache(xprt, size)
	SVCXPRT *xprt;
	uint_t size;
{
	SVCXPRT *transp;
	struct svc_dg_data *su;
	struct cl_cache *uc;

/* LINTED pointer alignment */
	if (svc_mt_mode != RPC_SVC_MT_NONE && SVCEXT(xprt)->parent != NULL)
/* LINTED pointer alignment */
		transp = SVCEXT(xprt)->parent;
	else
		transp = xprt;
/* LINTED pointer alignment */
	su = su_data(transp);

	trace2(TR_svc_dg_enablecache, 0, size);
	mutex_lock(&dupreq_lock);
	if (su->su_cache != NULL) {
		(void) syslog(LOG_ERR, cache_enable_str,
				enable_err, " ");
		mutex_unlock(&dupreq_lock);
		trace2(TR_svc_dg_enablecache, 1, size);
		return (0);
	}
	uc = ALLOC(struct cl_cache, 1);
	if (uc == NULL) {
		(void) syslog(LOG_ERR, cache_enable_str,
			alloc_err, " ");
		mutex_unlock(&dupreq_lock);
		trace2(TR_svc_dg_enablecache, 1, size);
		return (0);
	}
	uc->uc_size = size;
	uc->uc_nextvictim = 0;
	uc->uc_entries = ALLOC(cache_ptr, size * SPARSENESS);
	if (uc->uc_entries == NULL) {
		(void) syslog(LOG_ERR, cache_enable_str,
				alloc_err, "data");
		FREE(uc, struct cl_cache, 1);
		mutex_unlock(&dupreq_lock);
		trace2(TR_svc_dg_enablecache, 1, size);
		return (0);
	}
	MEMZERO(uc->uc_entries, cache_ptr, size * SPARSENESS);
	uc->uc_fifo = ALLOC(cache_ptr, size);
	if (uc->uc_fifo == NULL) {
		(void) syslog(LOG_ERR, cache_enable_str,
				alloc_err, "fifo");
		FREE(uc->uc_entries, cache_ptr, size * SPARSENESS);
		FREE(uc, struct cl_cache, 1);
		mutex_unlock(&dupreq_lock);
		trace2(TR_svc_dg_enablecache, 1, size);
		return (0);
	}
	MEMZERO(uc->uc_fifo, cache_ptr, size);
	su->su_cache = (char *)uc;
	mutex_unlock(&dupreq_lock);
	trace2(TR_svc_dg_enablecache, 1, size);
	return (1);
}

/*
 * Set an entry in the cache.  It assumes that the uc entry is set from
 * the earlier call to cache_get() for the same procedure.  This will always
 * happen because cache_get() is calle by svc_dg_recv and cache_set() is called
 * by svc_dg_reply().  All this hoopla because the right RPC parameters are
 * not available at svc_dg_reply time.
 */

static const char cache_set_str[] = "cache_set: %s";
static const char cache_set_err1[] = "victim not found";
static const char cache_set_err2[] = "victim alloc failed";
static const char cache_set_err3[] = "could not allocate new rpc buffer";

static void
cache_set(xprt, replylen)
	SVCXPRT *xprt;
	uint32_t replylen;
{
	SVCXPRT *parent;
	cache_ptr victim;
	cache_ptr *vicp;
	struct svc_dg_data *su;
	struct cl_cache *uc;
	uint_t loc;
	char *newbuf, *newbuf2;
	int my_mallocs = 0;
#ifdef RPC_CACHE_DEBUG
	struct netconfig *nconf;
	char *uaddr;
#endif

/* LINTED pointer alignment */
	if (svc_mt_mode != RPC_SVC_MT_NONE && SVCEXT(xprt)->parent != NULL)
/* LINTED pointer alignment */
		parent = SVCEXT(xprt)->parent;
	else
		parent = xprt;
/* LINTED pointer alignment */
	su = su_data(xprt);
/* LINTED pointer alignment */
	uc = (struct cl_cache *)su_data(parent)->su_cache;

	mutex_lock(&dupreq_lock);
	/*
	 * Find space for the new entry, either by
	 * reusing an old entry, or by mallocing a new one
	 */
	trace2(TR_cache_set, 0, replylen);
	victim = uc->uc_fifo[uc->uc_nextvictim];
	if (victim != NULL) {
/* LINTED pointer alignment */
		loc = CACHE_LOC(parent, victim->cache_xid);
		for (vicp = &uc->uc_entries[loc];
			*vicp != NULL && *vicp != victim;
			vicp = &(*vicp)->cache_next)
			;
		if (*vicp == NULL) {
			(void) syslog(LOG_ERR, cache_set_str, cache_set_err1);
			mutex_unlock(&dupreq_lock);
			trace2(TR_cache_set, 1, replylen);
			return;
		}
		*vicp = victim->cache_next;	/* remove from cache */
		newbuf = victim->cache_reply;
	} else {
		victim = ALLOC(struct cache_node, 1);
		if (victim == NULL) {
			(void) syslog(LOG_ERR, cache_set_str, cache_set_err2);
			mutex_unlock(&dupreq_lock);
			trace2(TR_cache_set, 1, replylen);
			return;
		}
		newbuf = (char *)mem_alloc(su->su_iosz);
		if (newbuf == NULL) {
			(void) syslog(LOG_ERR, cache_set_str, cache_set_err3);
			FREE(victim, struct cache_node, 1);
			mutex_unlock(&dupreq_lock);
			trace2(TR_cache_set, 1, replylen);
			return;
		}
		my_mallocs = 1;
	}

	/*
	 * Store it away
	 */
#ifdef RPC_CACHE_DEBUG
	if (nconf = getnetconfigent(xprt->xp_netid)) {
		uaddr = taddr2uaddr(nconf, &xprt->xp_rtaddr);
		freenetconfigent(nconf);
		printf(
	"cache set for xid= %x prog=%d vers=%d proc=%d for rmtaddr=%s\n",
			su->su_xid, uc->uc_prog, uc->uc_vers,
			uc->uc_proc, uaddr);
		free(uaddr);
	}
#endif
	newbuf2 = ALLOC(char, xprt->xp_rtaddr.len);
	if (newbuf2 == NULL) {
		syslog(LOG_ERR, "cache_set : out of memory");
		if (my_mallocs) {
			FREE(victim, struct cache_node, 1);
			mem_free(newbuf, su->su_iosz);
		}
		mutex_unlock(&dupreq_lock);
		trace2(TR_cache_set, 1, replylen);
		return;
	}
	victim->cache_replylen = replylen;
	victim->cache_reply = rpc_buffer(xprt);
	rpc_buffer(xprt) = newbuf;
	xdrmem_create(&(su->su_xdrs), rpc_buffer(xprt),
			su->su_iosz, XDR_ENCODE);
	su->su_tudata.udata.buf = (char *)rpc_buffer(xprt);
	victim->cache_xid = su->su_xid;
	victim->cache_proc = uc->uc_proc;
	victim->cache_vers = uc->uc_vers;
	victim->cache_prog = uc->uc_prog;
	victim->cache_addr = xprt->xp_rtaddr;
	victim->cache_addr.buf = newbuf2;
	(void) memcpy(victim->cache_addr.buf, xprt->xp_rtaddr.buf,
			(int)xprt->xp_rtaddr.len);
/* LINTED pointer alignment */
	loc = CACHE_LOC(parent, victim->cache_xid);
	victim->cache_next = uc->uc_entries[loc];
	uc->uc_entries[loc] = victim;
	uc->uc_fifo[uc->uc_nextvictim++] = victim;
	uc->uc_nextvictim %= uc->uc_size;
	mutex_unlock(&dupreq_lock);
	trace2(TR_cache_set, 1, replylen);
}

/*
 * Try to get an entry from the cache
 * return 1 if found, 0 if not found and set the stage for cache_set()
 */
static int
cache_get(xprt, msg, replyp, replylenp)
	SVCXPRT *xprt;
	struct rpc_msg *msg;
	char **replyp;
	uint32_t *replylenp;
{
	SVCXPRT *parent;
	uint_t loc;
	cache_ptr ent;
	struct svc_dg_data *su;
	struct cl_cache *uc;
#ifdef RPC_CACHE_DEBUG
	struct netconfig *nconf;
	char *uaddr;
#endif

	trace1(TR_cache_get, 0);

/* LINTED pointer alignment */
	if (svc_mt_mode != RPC_SVC_MT_NONE && SVCEXT(xprt)->parent != NULL)
/* LINTED pointer alignment */
		parent = SVCEXT(xprt)->parent;
	else
		parent = xprt;
/* LINTED pointer alignment */
	su = su_data(xprt);
/* LINTED pointer alignment */
	uc = (struct cl_cache *)su_data(parent)->su_cache;

	mutex_lock(&dupreq_lock);
/* LINTED pointer alignment */
	loc = CACHE_LOC(parent, su->su_xid);
	for (ent = uc->uc_entries[loc]; ent != NULL; ent = ent->cache_next) {
		if (ent->cache_xid == su->su_xid &&
			ent->cache_proc == msg->rm_call.cb_proc &&
			ent->cache_vers == msg->rm_call.cb_vers &&
			ent->cache_prog == msg->rm_call.cb_prog &&
			ent->cache_addr.len == xprt->xp_rtaddr.len &&
			(memcmp(ent->cache_addr.buf, xprt->xp_rtaddr.buf,
				xprt->xp_rtaddr.len) == 0)) {
#ifdef RPC_CACHE_DEBUG
			if (nconf = getnetconfigent(xprt->xp_netid)) {
				uaddr = taddr2uaddr(nconf, &xprt->xp_rtaddr);
				freenetconfigent(nconf);
				printf(
	"cache entry found for xid=%x prog=%d vers=%d proc=%d for rmtaddr=%s\n",
					su->su_xid, msg->rm_call.cb_prog,
					msg->rm_call.cb_vers,
					msg->rm_call.cb_proc, uaddr);
				free(uaddr);
			}
#endif
			*replyp = ent->cache_reply;
			*replylenp = ent->cache_replylen;
			mutex_unlock(&dupreq_lock);
			trace1(TR_cache_get, 1);
			return (1);
		}
	}
	/*
	 * Failed to find entry
	 * Remember a few things so we can do a set later
	 */
	uc->uc_proc = msg->rm_call.cb_proc;
	uc->uc_vers = msg->rm_call.cb_vers;
	uc->uc_prog = msg->rm_call.cb_prog;
	mutex_unlock(&dupreq_lock);
	trace1(TR_cache_get, 1);
	return (0);
}
