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
 * svc_udp.c,
 * Server side for UDP/IP based RPC.  (Does some caching in the hopes of
 * achieving execute-at-most-once semantics.)
 */

#include <rpc/rpc.h>
#include <rpc/clnt_soc.h>
#include <sys/socket.h>
#include <errno.h>
#include <syslog.h>
#include <malloc.h>
#include <stdio.h>


#define	rpc_buffer(xprt) ((xprt)->xp_p1)

static struct xp_ops *svcudp_ops();

extern int errno;
extern SVCXPRT *svc_xprt_alloc();
extern void svc_xprt_free();
extern int _socket(int, int, int);
extern int _bind(int, const struct sockaddr *, int);
extern int _getsockname(int, struct sockaddr *, int *);
extern int _listen(int, int);
extern int _accept(int, struct sockaddr *, int *);
extern int bindresvport(int, struct sockaddr_in *);
extern int _recvfrom(int, char *, int, int,
		struct sockaddr *, int *);
extern int _sendto(int, const char *, int, int,
		const struct sockaddr *, int);

static int cache_get(SVCXPRT *, struct rpc_msg *,
		char **, uint_t *);
static void cache_set(SVCXPRT *, uint_t);

/*
 * kept in xprt->xp_p2
 */
struct svcudp_data {
	u_int   su_iosz;		/* byte size of send.recv buffer */
	uint32_t su_xid;		/* transaction id */
	XDR	su_xdrs;		/* XDR handle */
	char	su_verfbody[MAX_AUTH_BYTES];	/* verifier body */
	char * 	su_cache;	/* cached data, NULL if no cache */
};
#define	su_data(xprt)	((struct svcudp_data *)(xprt->xp_p2))

/*
 * Usage:
 *	xprt = svcudp_create(sock);
 *
 * If sock<0 then a socket is created, else sock is used.
 * If the socket, sock is not bound to a port then svcudp_create
 * binds it to an arbitrary port.  In any (successful) case,
 * xprt->xp_sock is the registered socket number and xprt->xp_port is the
 * associated port number.
 * Once *xprt is initialized, it is registered as a transporter;
 * see (svc.h, xprt_register).
 * The routines returns NULL if a problem occurred.
 */
SVCXPRT *
svcudp_bufcreate(sock, sendsz, recvsz)
	register int sock;
	u_int sendsz, recvsz;
{
	bool_t madesock = FALSE;
	register SVCXPRT *xprt;
	register struct svcudp_data *su;
	struct sockaddr_in addr;
	int len = sizeof (struct sockaddr_in);

	if (sock == RPC_ANYSOCK) {
		if ((sock = _socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
			(void) syslog(LOG_ERR, "svcudp_create: socket",
				" creation problem: %m");
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
	if (_getsockname(sock, (struct sockaddr *)&addr, &len) != 0) {
		(void) syslog(LOG_ERR, "svcudp_create -",
			" cannot getsockname: %m");
		if (madesock)
			(void) close(sock);
		return ((SVCXPRT *)NULL);
	}
	xprt = svc_xprt_alloc();
	if (xprt == NULL) {
		(void) syslog(LOG_ERR, "svcudp_create: out of memory");
		if (madesock)
			(void) close(sock);
		return ((SVCXPRT *)NULL);
	}
	su = (struct svcudp_data *)mem_alloc(sizeof (*su));
	if (su == NULL) {
		(void) syslog(LOG_ERR, "svcudp_create: out of memory");
		svc_xprt_free(xprt);
		if (madesock)
			(void) close(sock);
		return ((SVCXPRT *)NULL);
	}
	su->su_iosz = ((MAX(sendsz, recvsz) + 3) / 4) * 4;
	if ((rpc_buffer(xprt) = (char *)mem_alloc(su->su_iosz)) == NULL) {
		(void) syslog(LOG_ERR, "svcudp_create: out of memory");
		mem_free((char *) su, sizeof (*su));
		svc_xprt_free(xprt);
		if (madesock)
			(void) close(sock);
		return ((SVCXPRT *)NULL);
	}
	xdrmem_create(
	    &(su->su_xdrs), rpc_buffer(xprt), su->su_iosz, XDR_DECODE);
	su->su_cache = NULL;
	xprt->xp_p2 = (caddr_t)su;
	xprt->xp_netid = NULL;
	xprt->xp_verf.oa_base = su->su_verfbody;
	xprt->xp_ops = svcudp_ops();
	xprt->xp_port = ntohs(addr.sin_port);
	xprt->xp_sock = sock;
	xprt->xp_rtaddr.buf = &xprt->xp_raddr[0];
	xprt_register(xprt);
	return (xprt);
}

SVCXPRT *
svcudp_create(sock)
	int sock;
{

	return (svcudp_bufcreate(sock, UDPMSGSIZE, UDPMSGSIZE));
}

static enum xprt_stat
svcudp_stat(xprt)
	SVCXPRT *xprt;
{

	return (XPRT_IDLE);
}

static bool_t
svcudp_recv(xprt, msg)
	register SVCXPRT *xprt;
	struct rpc_msg *msg;
{
	register struct svcudp_data *su = su_data(xprt);
	register XDR *xdrs = &(su->su_xdrs);
	register int rlen;
	char *reply;
	uint_t replylen;

	again:
	xprt->xp_addrlen = sizeof (struct sockaddr_in);
	rlen = _recvfrom(xprt->xp_sock, rpc_buffer(xprt), (int) su->su_iosz,
	    0, (struct sockaddr *)&(xprt->xp_raddr), &(xprt->xp_addrlen));
	if (rlen == -1 && errno == EINTR)
		goto again;
	if (rlen < 4*sizeof (uint32_t))
		return (FALSE);
	xdrs->x_op = XDR_DECODE;
	XDR_SETPOS(xdrs, 0);
	if (! xdr_callmsg(xdrs, msg))
		return (FALSE);
	su->su_xid = msg->rm_xid;
	if (su->su_cache != NULL) {
		if (cache_get(xprt, msg, &reply, &replylen)) {
			(void) _sendto(xprt->xp_sock, reply, (int) replylen, 0,
				(struct sockaddr *) &xprt->xp_raddr,
				xprt->xp_addrlen);
			return (TRUE);
		}
	}
	return (TRUE);
}

static bool_t
svcudp_reply(xprt, msg)
	register SVCXPRT *xprt;
	struct rpc_msg *msg;
{
	register struct svcudp_data *su = su_data(xprt);
	register XDR *xdrs = &(su->su_xdrs);
	register int slen;
	register bool_t stat = FALSE;

	xdrs->x_op = XDR_ENCODE;
	XDR_SETPOS(xdrs, 0);
	msg->rm_xid = su->su_xid;
	if (xdr_replymsg(xdrs, msg)) {
		slen = (int)XDR_GETPOS(xdrs);
		if (_sendto(xprt->xp_sock, rpc_buffer(xprt), slen, 0,
		    (struct sockaddr *)&(xprt->xp_raddr), xprt->xp_addrlen)
		    == slen) {
			stat = TRUE;
			if (su->su_cache && slen >= 0) {
				(void) cache_set(xprt, (uint_t) slen);
			}
		}
	}
	return (stat);
}

static bool_t
svcudp_getargs(xprt, xdr_args, args_ptr)
	SVCXPRT *xprt;
	xdrproc_t xdr_args;
	caddr_t args_ptr;
{

	return ((*xdr_args)(&(su_data(xprt)->su_xdrs), args_ptr));
}

static bool_t
svcudp_freeargs(xprt, xdr_args, args_ptr)
	SVCXPRT *xprt;
	xdrproc_t xdr_args;
	caddr_t args_ptr;
{
	register XDR *xdrs = &(su_data(xprt)->su_xdrs);

	xdrs->x_op = XDR_FREE;
	return ((*xdr_args)(xdrs, args_ptr));
}

static void
svcudp_destroy(xprt)
	register SVCXPRT *xprt;
{
	register struct svcudp_data *su = su_data(xprt);

	xprt_unregister(xprt);
	(void) close(xprt->xp_sock);
	XDR_DESTROY(&(su->su_xdrs));
	mem_free(rpc_buffer(xprt), su->su_iosz);
	mem_free((caddr_t)su, sizeof (struct svcudp_data));
	svc_xprt_free(xprt);
}


/* **********this could be a separate file********************* */

/*
 * Fifo cache for udp server
 * Copies pointers to reply buffers into fifo cache
 * Buffers are sent again if retransmissions are detected.
 */

#define	SPARSENESS 4	/* 75% sparse */

#define	ALLOC(type, size)	\
	(type *) mem_alloc((unsigned) (sizeof (type) * (size)))

#define	BZERO(addr, type, size)	 \
	memset((char *) (addr), 0, sizeof (type) * (int) (size))

#define	FREE(addr, type, size)	\
	(void) mem_free((char *) (addr), (sizeof (type) * (size)))

/*
 * An entry in the cache
 */
typedef struct cache_node *cache_ptr;
struct cache_node {
	/*
	 * Index into cache is xid, proc, vers, prog and address
	 */
	uint32_t cache_xid;
	uint32_t cache_proc;
	uint32_t cache_vers;
	uint32_t cache_prog;
	struct sockaddr_in cache_addr;
	/*
	 * The cached reply and length
	 */
	char * cache_reply;
	uint32_t cache_replylen;
	/*
	 * Next node on the list, if there is a collision
	 */
	cache_ptr cache_next;
};



/*
 * The entire cache
 */
struct udp_cache {
	uint32_t uc_size;		/* size of cache */
	cache_ptr *uc_entries;	/* hash table of entries in cache */
	cache_ptr *uc_fifo;	/* fifo list of entries in cache */
	uint32_t uc_nextvictim;	/* points to next victim in fifo list */
	uint32_t uc_prog;		/* saved program number */
	uint32_t uc_vers;		/* saved version number */
	uint32_t uc_proc;		/* saved procedure number */
	struct sockaddr_in uc_addr; /* saved caller's address */
};


/*
 * the hashing function
 */
#define	CACHE_LOC(transp, xid)	\
	(xid % (SPARSENESS*((struct udp_cache *) \
	su_data(transp)->su_cache)->uc_size))


/*
 * Enable use of the cache.
 * Note: there is no disable.
 */
int
svcudp_enablecache(transp, size)
	SVCXPRT *transp;
	uint_t size;
{
	struct svcudp_data *su = su_data(transp);
	struct udp_cache *uc;

	if (su->su_cache != NULL) {
		(void) syslog(LOG_ERR, "enablecache: cache already enabled");
		return (0);
	}
	uc = ALLOC(struct udp_cache, 1);
	if (uc == NULL) {
		(void) syslog(LOG_ERR, "enablecache: could not allocate cache");
		return (0);
	}
	uc->uc_size = size;
	uc->uc_nextvictim = 0;
	uc->uc_entries = ALLOC(cache_ptr, size * SPARSENESS);
	if (uc->uc_entries == NULL) {
		(void) syslog(LOG_ERR, "enablecache: could not",
			" allocate cache data");
		FREE(uc, struct udp_cache, 1);
		return (0);
	}
	BZERO(uc->uc_entries, cache_ptr, size * SPARSENESS);
	uc->uc_fifo = ALLOC(cache_ptr, size);
	if (uc->uc_fifo == NULL) {
		(void) syslog(LOG_ERR, "enablecache: could not",
			" allocate cache fifo");
		FREE((char *)uc->uc_entries, cache_ptr, size * SPARSENESS);
		FREE((char *)uc, struct udp_cache, 1);
		return (0);
	}
	BZERO(uc->uc_fifo, cache_ptr, size);
	su->su_cache = (char *) uc;
	return (1);
}


/*
 * Set an entry in the cache
 */
static void
cache_set(xprt, replylen)
	SVCXPRT *xprt;
	uint_t replylen;
{
	register cache_ptr victim;
	register cache_ptr *vicp;
	register struct svcudp_data *su = su_data(xprt);
	struct udp_cache *uc = (struct udp_cache *) su->su_cache;
	u_int loc;
	char *newbuf;

	/*
	 * Find space for the new entry, either by
	 * reusing an old entry, or by mallocing a new one
	 */
	victim = uc->uc_fifo[uc->uc_nextvictim];
	if (victim != NULL) {
		loc = CACHE_LOC(xprt, victim->cache_xid);
		for (vicp = &uc->uc_entries[loc];
			*vicp != NULL && *vicp != victim;
			vicp = &(*vicp)->cache_next)
				;
		if (*vicp == NULL) {
			(void) syslog(LOG_ERR, "cache_set: victim not found");
			return;
		}
		*vicp = victim->cache_next;	/* remote from cache */
		newbuf = victim->cache_reply;
	} else {
		victim = ALLOC(struct cache_node, 1);
		if (victim == NULL) {
			(void) syslog(LOG_ERR, "cache_set: victim alloc",
				" failed");
			return;
		}
		newbuf = (char *)mem_alloc(su->su_iosz);
		if (newbuf == NULL) {
			(void) syslog(LOG_ERR, "cache_set: could not",
				" allocate new rpc_buffer");
			FREE(victim, struct cache_node, 1);
			return;
		}
	}

	/*
	 * Store it away
	 */
	victim->cache_replylen = replylen;
	victim->cache_reply = rpc_buffer(xprt);
	rpc_buffer(xprt) = newbuf;
	xdrmem_create(&(su->su_xdrs), rpc_buffer(xprt),
		su->su_iosz, XDR_ENCODE);
	victim->cache_xid = su->su_xid;
	victim->cache_proc = uc->uc_proc;
	victim->cache_vers = uc->uc_vers;
	victim->cache_prog = uc->uc_prog;
	victim->cache_addr = uc->uc_addr;
	loc = CACHE_LOC(xprt, victim->cache_xid);
	victim->cache_next = uc->uc_entries[loc];
	uc->uc_entries[loc] = victim;
	uc->uc_fifo[uc->uc_nextvictim++] = victim;
	uc->uc_nextvictim %= uc->uc_size;
}

/*
 * Try to get an entry from the cache
 * return 1 if found, 0 if not found
 */
static int
cache_get(xprt, msg, replyp, replylenp)
	SVCXPRT *xprt;
	struct rpc_msg *msg;
	char **replyp;
	uint_t *replylenp;
{
	u_int loc;
	register cache_ptr ent;
	register struct svcudp_data *su = su_data(xprt);
	register struct udp_cache *uc = (struct udp_cache *) su->su_cache;

#define	EQADDR(a1, a2) \
	(memcmp((char *)&a1, (char *)&a2, sizeof (a1)) == 0)

	loc = CACHE_LOC(xprt, su->su_xid);
	for (ent = uc->uc_entries[loc]; ent != NULL; ent = ent->cache_next) {
		if (ent->cache_xid == su->su_xid &&
			ent->cache_proc == uc->uc_proc &&
			ent->cache_vers == uc->uc_vers &&
			ent->cache_prog == uc->uc_prog &&
			EQADDR(ent->cache_addr, uc->uc_addr)) {
			*replyp = ent->cache_reply;
			*replylenp = ent->cache_replylen;
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
	memcpy((char *)&uc->uc_addr, (char *)&xprt->xp_raddr,
		sizeof (struct sockaddr_in));
	return (0);
}

static struct xp_ops *
svcudp_ops()
{
	static struct xp_ops ops;

	if (ops.xp_recv == NULL) {
		ops.xp_recv = svcudp_recv;
		ops.xp_stat = svcudp_stat;
		ops.xp_getargs = svcudp_getargs;
		ops.xp_reply = svcudp_reply;
		ops.xp_freeargs = svcudp_freeargs;
		ops.xp_destroy = svcudp_destroy;
	}
	return (&ops);
}
