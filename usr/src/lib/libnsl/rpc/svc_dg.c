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
 * Copyright 2014 Gary Mills
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
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
 * svc_dg.c, Server side for connectionless RPC.
 *
 * Does some caching in the hopes of achieving execute-at-most-once semantics.
 */

#include "mt.h"
#include "rpc_mt.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <rpc/rpc.h>
#include <rpcsvc/svc_dg_priv.h>
#include <errno.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <ucred.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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
svc_dg_xprtfree(SVCXPRT *xprt)
{
/* LINTED pointer alignment */
	SVCXPRT_EXT		*xt = xprt ? SVCEXT(xprt) : NULL;
/* LINTED pointer alignment */
	struct svc_dg_data	*su = xprt ? get_svc_dg_data(xprt) : NULL;

	if (xprt == NULL)
		return;
	if (xprt->xp_netid)
		free(xprt->xp_netid);
	if (xprt->xp_tp)
		free(xprt->xp_tp);
	if (xt->parent == NULL)
		if (xprt->xp_ltaddr.buf)
			free(xprt->xp_ltaddr.buf);
	if (xprt->xp_rtaddr.buf)
		free(xprt->xp_rtaddr.buf);
	if (su != NULL) {
		XDR_DESTROY(&(su->su_xdrs));
		free(su);
	}
	if (rpc_buffer(xprt))
		free(rpc_buffer(xprt));
	svc_xprt_free(xprt);
}

SVCXPRT *
svc_dg_create_private(int fd, uint_t sendsize, uint_t recvsize)
{
	SVCXPRT *xprt;
	struct svc_dg_data *su = NULL;
	struct t_info tinfo;
	size_t ucred_sz = ucred_size();

	if (RPC_FD_NOTIN_FDSET(fd)) {
		errno = EBADF;
		t_errno = TBADF;
		syslog(LOG_ERR, svc_dg_str, svc_dg_err3);
		return (NULL);
	}

	if (t_getinfo(fd, &tinfo) == -1) {
		syslog(LOG_ERR, svc_dg_str, svc_dg_err1);
		return (NULL);
	}
	/*
	 * Find the receive and the send size
	 */
	sendsize = __rpc_get_t_size((int)sendsize, tinfo.tsdu);
	recvsize = __rpc_get_t_size((int)recvsize, tinfo.tsdu);
	if ((sendsize == 0) || (recvsize == 0)) {
		syslog(LOG_ERR, svc_dg_str, svc_dg_err2);
		return (NULL);
	}

	if ((xprt = svc_xprt_alloc()) == NULL)
		goto freedata;
/* LINTED pointer alignment */
	svc_flags(xprt) |= SVC_DGRAM;

	su = malloc(sizeof (*su) + ucred_sz);
	if (su == NULL)
		goto freedata;
	su->su_iosz = ((MAX(sendsize, recvsize) + 3) / 4) * 4;
	if ((rpc_buffer(xprt) = malloc(su->su_iosz)) == NULL)
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
	su->su_tudata.opt.maxlen = MAX_OPT_WORDS * sizeof (int) + ucred_sz;
/* LINTED pointer alignment */
	SVC_XP_AUTH(xprt).svc_ah_ops = svc_auth_any_ops;
/* LINTED pointer alignment */
	SVC_XP_AUTH(xprt).svc_ah_private = NULL;
	return (xprt);
freedata:
	(void) syslog(LOG_ERR, svc_dg_str, __no_mem_str);
	if (xprt)
		svc_dg_xprtfree(xprt);
	return (NULL);
}

SVCXPRT *
svc_dg_create(const int fd, const uint_t sendsize, const uint_t recvsize)
{
	SVCXPRT *xprt;

	if ((xprt = svc_dg_create_private(fd, sendsize, recvsize)) != NULL)
		xprt_register(xprt);
	return (xprt);
}

SVCXPRT *
svc_dg_xprtcopy(SVCXPRT *parent)
{
	SVCXPRT			*xprt;
	struct svc_dg_data	*su;
	size_t			ucred_sz = ucred_size();

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
	xprt->xp_rtaddr.buf = malloc(xprt->xp_rtaddr.maxlen);
	if (xprt->xp_rtaddr.buf == NULL) {
		svc_dg_xprtfree(xprt);
		return (NULL);
	}
	(void) memcpy(xprt->xp_rtaddr.buf, parent->xp_rtaddr.buf,
	    xprt->xp_rtaddr.maxlen);
	xprt->xp_type = parent->xp_type;

	if ((su = malloc(sizeof (struct svc_dg_data) + ucred_sz)) == NULL) {
		svc_dg_xprtfree(xprt);
		return (NULL);
	}
/* LINTED pointer alignment */
	su->su_iosz = get_svc_dg_data(parent)->su_iosz;
	if ((rpc_buffer(xprt) = malloc(su->su_iosz)) == NULL) {
		svc_dg_xprtfree(xprt);
		free(su);
		return (NULL);
	}
	xdrmem_create(&(su->su_xdrs), rpc_buffer(xprt), su->su_iosz,
	    XDR_DECODE);
	su->su_cache = NULL;
	su->su_tudata.addr.maxlen =  0; /* Fill in later */
	su->su_tudata.udata.buf = (char *)rpc_buffer(xprt);
	su->su_tudata.opt.buf = (char *)su->opts;
	su->su_tudata.udata.maxlen = su->su_iosz;
	su->su_tudata.opt.maxlen = MAX_OPT_WORDS * sizeof (int) + ucred_sz;
	xprt->xp_p2 = (caddr_t)su;	/* get_svc_dg_data(xprt) = su */
	xprt->xp_verf.oa_base = su->su_verfbody;

	return (xprt);
}

/*ARGSUSED*/
static enum xprt_stat
svc_dg_stat(SVCXPRT *xprt)
{
	return (XPRT_IDLE);
}

/*
 * Find the SCM_UCRED in src and place a pointer to that option alone in dest.
 * Note that these two 'netbuf' structures might be the same one, so the code
 * has to be careful about referring to src after changing dest.
 */
static void
extract_cred(const struct netbuf *src, struct netbuf *dest)
{
	char *cp = src->buf;
	unsigned int len = src->len;
	const struct T_opthdr *opt;
	unsigned int olen;

	while (len >= sizeof (*opt)) {
		/* LINTED: pointer alignment */
		opt = (const struct T_opthdr *)cp;
		olen = opt->len;
		if (olen > len || olen < sizeof (*opt) ||
		    !IS_P2ALIGNED(olen, sizeof (t_uscalar_t)))
			break;
		if (opt->level == SOL_SOCKET && opt->name == SCM_UCRED) {
			dest->buf = cp;
			dest->len = olen;
			return;
		}
		cp += olen;
		len -= olen;
	}
	dest->len = 0;
}

/*
 * This routine extracts the destination IP address of the inbound RPC packet
 * and sets that as source IP address for the outbound response.
 */
static void
set_src_addr(SVCXPRT *xprt, struct netbuf *opt)
{
	struct netbuf *nbufp, *ltaddr;
	struct T_opthdr *opthdr;
	in_pktinfo_t *pktinfo;
	struct sockaddr_in *sock = (struct sockaddr_in *)NULL;

	/* extract dest IP of inbound packet */
	/* LINTED pointer alignment */
	nbufp = (struct netbuf *)xprt->xp_p2;
	ltaddr = &xprt->xp_ltaddr;
	if (__rpc_get_ltaddr(nbufp, ltaddr) != 0)
		return;

	/* do nothing for non-IPv4 packet */
	/* LINTED pointer alignment */
	sock = (struct sockaddr_in *)ltaddr->buf;
	if (sock->sin_family != AF_INET)
		return;

	/* set desired option header */
	opthdr = (struct T_opthdr *)memalign(sizeof (int),
	    sizeof (struct T_opthdr) + sizeof (in_pktinfo_t));
	if (opthdr == NULL)
		return;
	opthdr->len = sizeof (struct T_opthdr) + sizeof (in_pktinfo_t);
	opthdr->level = IPPROTO_IP;
	opthdr->name = IP_PKTINFO;

	/*
	 * 1. set source IP of outbound packet
	 * 2. value '0' for index means IP layer uses this as source address
	 */
	pktinfo = (in_pktinfo_t *)(opthdr + 1);
	(void) memset(pktinfo, 0, sizeof (in_pktinfo_t));
	pktinfo->ipi_spec_dst.s_addr = sock->sin_addr.s_addr;
	pktinfo->ipi_ifindex = 0;

	/* copy data into ancillary buffer */
	if (opthdr->len + opt->len <= opt->maxlen) {
		(void) memcpy((void *)(opt->buf+opt->len), (const void *)opthdr,
		    opthdr->len);
		opt->len += opthdr->len;
	}
	free(opthdr);
}

static bool_t
svc_dg_recv(SVCXPRT *xprt, struct rpc_msg *msg)
{
/* LINTED pointer alignment */
	struct svc_dg_data *su = get_svc_dg_data(xprt);
	XDR *xdrs = &(su->su_xdrs);
	struct t_unitdata *tu_data = &(su->su_tudata);
	int moreflag;
	struct netbuf *nbufp;
	struct netconfig *nconf;

	/* XXX: tudata should have been made a part of the server handle */
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
			if ((lookres == T_UDERR) &&
			    (t_rcvuderr(xprt->xp_fd,
				    (struct t_uderr *)0) < 0)) {
				/*EMPTY*/
#ifdef RPC_DEBUG
				syslog(LOG_ERR,
				"svc_dg_recv: t_rcvuderr t_errno = %d\n",
					t_errno);
#endif
			}
			if (lookres == T_DATA)
				goto again;
		} else if ((errno == EINTR) && (t_errno == TSYSERR))
			goto again;
		else {
			return (FALSE);
		}
	}

	if ((moreflag) ||
	    (tu_data->udata.len < 4 * (uint_t)sizeof (uint32_t))) {
		/*
		 * If moreflag is set, drop that data packet. Something wrong
		 */
		return (FALSE);
	}
	su->optbuf = tu_data->opt;
	xprt->xp_rtaddr.len = tu_data->addr.len;
	xdrs->x_op = XDR_DECODE;
	XDR_SETPOS(xdrs, 0);
	if (!xdr_callmsg(xdrs, msg))
		return (FALSE);
	su->su_xid = msg->rm_xid;
	if (su->su_cache != NULL) {
		char *reply;
		uint32_t replylen;

		if (cache_get(xprt, msg, &reply, &replylen)) {
			/* tu_data.addr is already set */
			tu_data->udata.buf = reply;
			tu_data->udata.len = (uint_t)replylen;
			extract_cred(&tu_data->opt, &tu_data->opt);
			set_src_addr(xprt, &tu_data->opt);
			(void) t_sndudata(xprt->xp_fd, tu_data);
			tu_data->udata.buf = (char *)rpc_buffer(xprt);
			tu_data->opt.buf = (char *)su->opts;
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
				/* LINTED pointer cast */
				nbufp = (struct netbuf *)(xprt->xp_p2);
				if (__rpc_get_ltaddr(nbufp,
				    &xprt->xp_ltaddr) < 0) {
					if (strcmp(nconf->nc_protofmly,
					    NC_INET) == 0) {
						syslog(LOG_ERR,
						    "svc_dg_recv: ip(udp), "
						    "t_errno=%d, errno=%d",
						    t_errno, errno);
					}
					if (strcmp(nconf->nc_protofmly,
					    NC_INET6) == 0) {
						syslog(LOG_ERR,
						    "svc_dg_recv: ip (udp6), "
						    "t_errno=%d, errno=%d",
						    t_errno, errno);
					}
					freenetconfigent(nconf);
					return (FALSE);
				}
			}
		}
		freenetconfigent(nconf);
	}
	return (TRUE);
}

static bool_t
svc_dg_reply(SVCXPRT *xprt, struct rpc_msg *msg)
{
/* LINTED pointer alignment */
	struct svc_dg_data *su = get_svc_dg_data(xprt);
	XDR *xdrs = &(su->su_xdrs);
	bool_t stat = FALSE;
	xdrproc_t xdr_results;
	caddr_t xdr_location;
	bool_t has_args;

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
		extract_cred(&su->optbuf, &tu_data->opt);
		set_src_addr(xprt, &tu_data->opt);
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
			    "svc_dg_reply: t_sndudata error t_errno=%d ",
			    "errno=%d\n", t_errno, errno);
		}
		tu_data->opt.buf = (char *)su->opts;
	}
	return (stat);
}

static bool_t
svc_dg_getargs(SVCXPRT *xprt, xdrproc_t xdr_args, caddr_t args_ptr)
{
	if (svc_mt_mode != RPC_SVC_MT_NONE)
		svc_args_done(xprt);
/* LINTED pointer alignment */
	return (SVCAUTH_UNWRAP(&SVC_XP_AUTH(xprt),
	    &(get_svc_dg_data(xprt)->su_xdrs), xdr_args, args_ptr));
}

static bool_t
svc_dg_freeargs(SVCXPRT *xprt, xdrproc_t xdr_args, caddr_t args_ptr)
{
/* LINTED pointer alignment */
	XDR *xdrs = &(get_svc_dg_data(xprt)->su_xdrs);

	xdrs->x_op = XDR_FREE;
	return ((*xdr_args)(xdrs, args_ptr));
}

static void
svc_dg_destroy(SVCXPRT *xprt)
{
	(void) mutex_lock(&svc_mutex);
	_svc_dg_destroy_private(xprt);
	(void) mutex_unlock(&svc_mutex);
}

void
_svc_dg_destroy_private(SVCXPRT *xprt)
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
svc_dg_control(SVCXPRT *xprt, const uint_t rq, void *in)
{
	switch (rq) {
	case SVCGET_XID:
		if (xprt->xp_p2 == NULL)
			return (FALSE);
		/* LINTED pointer alignment */
		*(uint32_t *)in = ((struct svc_dg_data *)(xprt->xp_p2))->su_xid;
		return (TRUE);
	default:
		return (FALSE);
	}
}

static struct xp_ops *
svc_dg_ops(void)
{
	static struct xp_ops ops;
	extern mutex_t ops_lock;

/* VARIABLES PROTECTED BY ops_lock: ops */

	(void) mutex_lock(&ops_lock);
	if (ops.xp_recv == NULL) {
		ops.xp_recv = svc_dg_recv;
		ops.xp_stat = svc_dg_stat;
		ops.xp_getargs = svc_dg_getargs;
		ops.xp_reply = svc_dg_reply;
		ops.xp_freeargs = svc_dg_freeargs;
		ops.xp_destroy = svc_dg_destroy;
		ops.xp_control = svc_dg_control;
	}
	(void) mutex_unlock(&ops_lock);
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
		get_svc_dg_data(transp)->su_cache)->uc_size))

extern mutex_t	dupreq_lock;

/*
 * Enable use of the cache. Returns 1 on success, 0 on failure.
 * Note: there is no disable.
 */
static const char cache_enable_str[] = "svc_enablecache: %s %s";
static const char alloc_err[] = "could not allocate cache ";
static const char enable_err[] = "cache already enabled";

int
svc_dg_enablecache(SVCXPRT *xprt, const uint_t size)
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
	su = get_svc_dg_data(transp);

	(void) mutex_lock(&dupreq_lock);
	if (su->su_cache != NULL) {
		(void) syslog(LOG_ERR, cache_enable_str,
		    enable_err, " ");
		(void) mutex_unlock(&dupreq_lock);
		return (0);
	}
	uc = malloc(sizeof (struct cl_cache));
	if (uc == NULL) {
		(void) syslog(LOG_ERR, cache_enable_str,
		    alloc_err, " ");
		(void) mutex_unlock(&dupreq_lock);
		return (0);
	}
	uc->uc_size = size;
	uc->uc_nextvictim = 0;
	uc->uc_entries = calloc(size * SPARSENESS, sizeof (cache_ptr));
	if (uc->uc_entries == NULL) {
		(void) syslog(LOG_ERR, cache_enable_str, alloc_err, "data");
		free(uc);
		(void) mutex_unlock(&dupreq_lock);
		return (0);
	}
	uc->uc_fifo = calloc(size, sizeof (cache_ptr));
	if (uc->uc_fifo == NULL) {
		(void) syslog(LOG_ERR, cache_enable_str, alloc_err, "fifo");
		free(uc->uc_entries);
		free(uc);
		(void) mutex_unlock(&dupreq_lock);
		return (0);
	}
	su->su_cache = (char *)uc;
	(void) mutex_unlock(&dupreq_lock);
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
cache_set(SVCXPRT *xprt, uint32_t replylen)
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
	su = get_svc_dg_data(xprt);
/* LINTED pointer alignment */
	uc = (struct cl_cache *)get_svc_dg_data(parent)->su_cache;

	(void) mutex_lock(&dupreq_lock);
	/*
	 * Find space for the new entry, either by
	 * reusing an old entry, or by mallocing a new one
	 */
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
			(void) mutex_unlock(&dupreq_lock);
			return;
		}
		*vicp = victim->cache_next;	/* remove from cache */
		newbuf = victim->cache_reply;
	} else {
		victim = malloc(sizeof (struct cache_node));
		if (victim == NULL) {
			(void) syslog(LOG_ERR, cache_set_str, cache_set_err2);
			(void) mutex_unlock(&dupreq_lock);
			return;
		}
		newbuf = malloc(su->su_iosz);
		if (newbuf == NULL) {
			(void) syslog(LOG_ERR, cache_set_str, cache_set_err3);
			free(victim);
			(void) mutex_unlock(&dupreq_lock);
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
		    su->su_xid, uc->uc_prog, uc->uc_vers, uc->uc_proc, uaddr);
		free(uaddr);
	}
#endif
	newbuf2 = malloc(sizeof (char) * xprt->xp_rtaddr.len);
	if (newbuf2 == NULL) {
		syslog(LOG_ERR, "cache_set : out of memory");
		if (my_mallocs) {
			free(victim);
			free(newbuf);
		}
		(void) mutex_unlock(&dupreq_lock);
		return;
	}
	victim->cache_replylen = replylen;
	victim->cache_reply = rpc_buffer(xprt);
	rpc_buffer(xprt) = newbuf;
	xdrmem_create(&(su->su_xdrs), rpc_buffer(xprt), su->su_iosz,
	    XDR_ENCODE);
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
	(void) mutex_unlock(&dupreq_lock);
}

/*
 * Try to get an entry from the cache
 * return 1 if found, 0 if not found and set the stage for cache_set()
 */
static int
cache_get(SVCXPRT *xprt, struct rpc_msg *msg, char **replyp,
							uint32_t *replylenp)
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

/* LINTED pointer alignment */
	if (svc_mt_mode != RPC_SVC_MT_NONE && SVCEXT(xprt)->parent != NULL)
/* LINTED pointer alignment */
		parent = SVCEXT(xprt)->parent;
	else
		parent = xprt;
/* LINTED pointer alignment */
	su = get_svc_dg_data(xprt);
/* LINTED pointer alignment */
	uc = (struct cl_cache *)get_svc_dg_data(parent)->su_cache;

	(void) mutex_lock(&dupreq_lock);
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
			(void) mutex_unlock(&dupreq_lock);
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
	(void) mutex_unlock(&dupreq_lock);
	return (0);
}
