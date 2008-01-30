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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * The resolv code was lifted from 4.1.3 ypserv. References to child/pid
 * have been changed to cache/nres to reflect what is really happening.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* ******************** include headers ****************************** */
#include <netdb.h>
#include <ctype.h>
#include <syslog.h>
#include <rpc/rpc.h>
#include <rpcsvc/yp_prot.h>
#include <netdir.h>
#include <stdlib.h>
#include <strings.h>
#include <arpa/inet.h>
#include "../resolv_common.h"
#include "prnt.h"
#include "nres.h"

#define	RESP_NOW	0
#define	RESP_LATER	2

#define	NQTIME		10	/* minutes */
#define	PQTIME		30	/* minutes */

/*
 * Cache entries for storing rpc.nisd req and resolv req info
 */
struct cache_ent {
	struct nres	*nres;
	datum		key;
	datum		val;
	char		*map;
	struct timeval	enqtime;
	int		h_errno;
	SVCXPRT		*xprt;
	struct netbuf	caller;
	char buf[MAX_UADDR];
	unsigned long   xid;
	unsigned long	ttl;
	struct cache_ent   *next_cache_ent;
};


int lookup_AF_type(struct cache_ent *);

/* ******************** static vars and funcs ************************ */
static struct cache_ent *cache_head = NULL;
static ulong_t svc_setxid(SVCXPRT *, ulong_t);
static void my_done(void *, struct hostent *, ulong_t, struct cache_ent *,
		int);
static int yp_matchdns(char *, datum, datum *, unsigned *, SVCXPRT *);
static void free_cache_ent(struct cache_ent *x);

/* ******************** extern vars and funcs ************************ */
extern int verbose;
extern SVCXPRT *reply_xprt4;
extern SVCXPRT *reply_xprt6;

static void
yp_resolv(sa_family_t af, void *req, SVCXPRT *transp)
{
	struct ypresp_val resp;
	int respond = RESP_NOW;
	char tmp[12]; /* max size of 9 rounded up to multiple of 4 bytes */
	char buf[MAX_UADDR];
	struct netbuf *nbuf;
	struct svc_dg_data *bd = NULL;
	struct ypfwdreq_key4 *req4 = (struct ypfwdreq_key4 *)req;
	struct ypfwdreq_key6 *req6 = (struct ypfwdreq_key6 *)req;
	in_port_t port;

	resp.valdat.dptr = NULL;
	resp.valdat.dsize = 0;

	/* Set the reply_xprt: xid and caller here, to fit yp_matchdns() */
	if (af == AF_INET6) {
		(void) inet_ntop(AF_INET6, req6->addr, buf, sizeof (buf));
		port = req6->port;
	} else {
		struct in_addr in4;
		/*
		 * This doesn't make much sense, but the for some reason
		 * the caller converted req->ip to host byte order, and in
		 * the name of backward compatibility...
		 */
		in4.s_addr = htonl(req4->ip);
		(void) strcpy(buf, inet_ntoa(in4));
		port = req4->port;
	}

	(void) snprintf(tmp, sizeof (tmp), ".%u.%u",
		(port>>8) & 0x00ff, port & 0x00ff);
	(void) strcat(buf, tmp);
	if ((nbuf = uaddr2taddr((af == AF_INET6) ? udp_nconf6 : udp_nconf4,
			buf)) == NULL) {
		prnt(P_ERR, "can't get args.\n");
		return;
	}
	if (nbuf->len > MAX_UADDR) { /* added precaution */
		prnt(P_ERR, "uaddr too big for cache.\n");
		netdir_free((void*)nbuf, ND_ADDR);
		return;
	}
	SETCALLER(transp, nbuf);
	/*
	 * Set su_tudata.addr for sendreply() t_sendudata()
	 * since we never did a recv on this unreg'ed xprt.
	 */
	if (!bd) { /* just set maxlen and buf once */
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		bd = get_svc_dg_data(transp);
		bd->su_tudata.addr.maxlen = GETCALLER(transp)->maxlen;
		bd->su_tudata.addr.buf = GETCALLER(transp)->buf;
	}
	bd->su_tudata.addr.len = nbuf->len;
	netdir_free((void*)nbuf, ND_ADDR);
	(void) svc_setxid(transp, (af == AF_INET6) ? req6->xid : req4->xid);

	respond = yp_matchdns((af == AF_INET6) ? req6->map : req4->map,
				(af == AF_INET6) ? req6->keydat : req4->keydat,
				&resp.valdat, &resp.status, transp);

	if (respond == RESP_NOW)
		if (!svc_sendreply(transp,
				(xdrproc_t)xdr_ypresp_val, (char *)&resp)) {
			prnt(P_ERR, "can't respond to rpc request.\n");
		}
}

void
dispatch(rqstp, transp)
	struct svc_req *rqstp;
	SVCXPRT *transp;
{
	struct ypfwdreq_key4 req4;
	struct ypfwdreq_key6 req6;

	switch (rqstp->rq_proc) {
	case NULLPROC:
		if (!svc_sendreply(transp, xdr_void, 0))
			prnt(P_ERR, "can't respond to ping.\n");
		break;
	case YPDNSPROC4:
		req4.map = NULL;
		req4.keydat.dptr = NULL;
		req4.xid = 0;
		req4.ip = 0;
		req4.port = 0;

		if (!svc_getargs(transp, xdr_ypfwdreq_key4, (char *)&req4)) {
			prnt(P_ERR, "can't get args.\n");
			svcerr_decode(transp);
			return;
		}

		/* args were ok: don't wait for resolver */
		if (!svc_sendreply(transp, xdr_void, 0))
			prnt(P_ERR, "can't ack nisd req.\n");

		yp_resolv(AF_INET, &req4, reply_xprt4);

		if (!svc_freeargs(transp, xdr_ypfwdreq_key4, (char *)&req4)) {
			prnt(P_ERR, "can't free args.\n");
			exit(1);
		}

		break;
	case YPDNSPROC6:
		req6.map = NULL;
		req6.keydat.dptr = NULL;
		req6.xid = 0;
		req6.addr = 0;
		req6.port = 0;

		if (!svc_getargs(transp, xdr_ypfwdreq_key6, (char *)&req6)) {
			prnt(P_ERR, "can't get args.\n");
			svcerr_decode(transp);
			return;
		}

		/* args were ok: don't wait for resolver */
		if (!svc_sendreply(transp, xdr_void, 0))
			prnt(P_ERR, "can't ack nisd req.\n");

		yp_resolv(AF_INET6, &req6, reply_xprt6);

		if (!svc_freeargs(transp, xdr_ypfwdreq_key6, (char *)&req6)) {
			prnt(P_ERR, "can't free args.\n");
			exit(1);
		}

		break;
	default:
		prnt(P_ERR, "call to bogus proc.\n");
		svcerr_noproc(transp);
		break;
	}
}

static struct cache_ent *
cache_ent_bykey(map, keydat)
	char *map;
	datum keydat;
{
	struct cache_ent   *chl;
	struct cache_ent   *prev;
	struct timeval  now;
	struct timezone tzp;
	int		secs;
	if (keydat.dptr == NULL)
		return (NULL);
	if (keydat.dsize <= 0)
		return (NULL);
	if (map == NULL)
		return (NULL);
	(void) gettimeofday(&now, &tzp);

	for (prev = cache_head, chl = cache_head; chl; /* */) {
		/* check for expiration */
		if (chl->h_errno == TRY_AGAIN)
			secs = NQTIME * 60;
		else
			secs = chl->ttl;
		if ((chl->nres == 0) &&
				(chl->enqtime.tv_sec + secs) < now.tv_sec) {
			prnt(P_INFO,
				"bykey:stale cache_ent flushed %x.\n", chl);
			/* deleteing the first element is tricky */
			if (chl == cache_head) {
				cache_head = cache_head->next_cache_ent;
				free_cache_ent(chl);
				prev = cache_head;
				chl = cache_head;
				continue;
			} else {
			/* deleteing a middle element */
				prev->next_cache_ent = chl->next_cache_ent;
				free_cache_ent(chl);
				chl = prev->next_cache_ent;
				continue;
			}
		} else if (chl->map)
			if (0 == strcmp(map, chl->map))
				if (chl->key.dptr) {
					/* supress trailing null */
					if (keydat.dptr[keydat.dsize - 1] == 0)
						keydat.dsize--;
					if ((chl->key.dsize == keydat.dsize))
						if (!strncasecmp(chl->key.dptr,
						keydat.dptr, keydat.dsize)) {
							/* move to beginning */
							if (chl != cache_head) {
				prev->next_cache_ent = chl->next_cache_ent;
				chl->next_cache_ent = cache_head;
				cache_head = chl;
							}
							return (chl);
						}
				}
		prev = chl;
		chl = chl->next_cache_ent;
	}
	return (NULL);
}

static struct cache_ent *
new_cache_ent(map, keydat)
	char		*map;
	datum		keydat;
{
	struct cache_ent   *chl;
	struct timezone tzp;

	chl = (struct cache_ent *)calloc(1, sizeof (struct cache_ent));
	if (chl == NULL)
		return (NULL);
	prnt(P_INFO, "cache_ent enqed.\n");
	chl->caller.buf = chl->buf;
	chl->caller.maxlen = sizeof (chl->buf);
	chl->map = (char *)strdup(map);
	if (chl->map == NULL) {
		free(chl);
		return (NULL);
	}
	chl->key.dptr = (char *)malloc(keydat.dsize + 1);
	if (chl->key.dptr == NULL) {
		free(chl->map);
		free(chl);
		return (NULL);
	}
	if (keydat.dptr != NULL)
		/* delete trailing null */
		if (keydat.dptr[keydat.dsize - 1] == 0)
			keydat.dsize = keydat.dsize - 1;
	chl->key.dsize = keydat.dsize;
	chl->key.dptr[keydat.dsize] = '\0';
	chl->val.dptr = 0;
	(void) memcpy(chl->key.dptr, keydat.dptr, keydat.dsize);
	(void) gettimeofday(&(chl->enqtime), &tzp);
	chl->next_cache_ent = cache_head;
	cache_head = chl;
	return (chl);
}

static struct cache_ent *
deq_cache_ent(x)
	struct cache_ent   *x;
{
	struct cache_ent   *chl;
	struct cache_ent   *prev;
	if (x == cache_head) {
		cache_head = cache_head->next_cache_ent;
		x->next_cache_ent = NULL;
		return (x);
	}
	for (chl = cache_head, prev = cache_head; chl;
					chl = chl->next_cache_ent) {
		if (chl == x) {
			/* deq it */
			prev->next_cache_ent = chl->next_cache_ent;
			chl->next_cache_ent = NULL;
			return (chl);
		}
		prev = chl;
	}
	return (NULL);		/* bad */
}

static void
free_cache_ent(x)
	struct cache_ent   *x;
{
	if (x == NULL)
		return;
	if (x->map)
		free(x->map);
	if (x->key.dptr)
		free(x->key.dptr);
	if (x->val.dptr)
		free(x->val.dptr);
	free(x);
}

static ulong_t
svc_setxid(xprt, xid)
	register SVCXPRT *xprt;
	ulong_t xid;
{
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct svc_dg_data *su = get_svc_dg_data(xprt);
	ulong_t old_xid;
	if (su == NULL)
		return (0);
	old_xid = su->su_xid;
	su->su_xid = xid;
	return (old_xid);
}


static int
yp_matchdns(map, keydat, valdatp, statusp, transp)
	char		*map;	/* map name */
	datum		keydat;	/* key to match (e.g. host name) */
	datum		*valdatp; /* returned value if found */
	unsigned	*statusp; /* returns the status */
	SVCXPRT		*transp;
{
	struct nres	*h;
	int		byname, byaddr;
	int		byname_v6, byaddr_v6;
	struct cache_ent   *chl;
	struct timeval  now;
	struct timezone tzp;
	int		try_again;
	int		af_type;

	try_again = 0;
	/*
	 * Skip the domain resolution if: 1. it is not turned on 2. map other
	 * than hosts.byXXX 3. a null string (usingypmap() likes to send
	 * these) 4. a single control character (usingypmap() again)
	 */
	byname = strcmp(map, "hosts.byname") == 0;
	byaddr = strcmp(map, "hosts.byaddr") == 0;
	byname_v6 = strcmp(map, "ipnodes.byname") == 0;
	byaddr_v6 = strcmp(map, "ipnodes.byaddr") == 0;
	if ((!byname && !byaddr && !byname_v6 && !byaddr_v6) ||
			keydat.dsize == 0 || keydat.dptr[0] == '\0' ||
			!isascii(keydat.dptr[0]) || !isgraph(keydat.dptr[0])) {
		*statusp = (unsigned)YP_NOKEY;
		return (RESP_NOW);
	}

	chl = cache_ent_bykey(map, keydat);
	if (chl) {
		(void) gettimeofday(&now, &tzp);
		if (chl->h_errno == TRY_AGAIN)
			try_again = 1;
		else if (chl->nres) {
			/* update xid */
			if (transp) {
				chl->xprt = transp;
				chl->caller.len = transp->xp_rtaddr.len;
				(void) memcpy(chl->caller.buf,
					transp->xp_rtaddr.buf,
					transp->xp_rtaddr.len);
				chl->xid = svc_getxid(transp);
				prnt(P_INFO, "cache_ent %s: xid now %d.\n",
						chl->key.dptr, chl->xid);
			}
			return (RESP_LATER);	/* drop */
		}
		switch (chl->h_errno) {
		case NO_RECOVERY:
#ifndef NO_DATA
#define	NO_DATA	NO_ADDRESS
#endif
		case NO_DATA:
		case HOST_NOT_FOUND:
			prnt(P_INFO, "cache NO_KEY.\n");
			*statusp = (unsigned)YP_NOKEY;
			return (RESP_NOW);

		case TRY_AGAIN:
			prnt(P_INFO, "try_again.\n");
			try_again = 1;
			break;
		case 0:
			prnt(P_INFO, "cache ok.\n");
			if (chl->val.dptr) {
				*valdatp = chl->val;
				*statusp = (unsigned)YP_TRUE;
				return (RESP_NOW);
			}
			break;

		default:
			free_cache_ent(deq_cache_ent(chl));
			chl = NULL;
			break;
		}
	}
	/* have a trier activated -- tell them to try again */
	if (try_again) {
		if (chl->nres) {
			*statusp = (unsigned)YP_NOMORE;
			/* try_again overloaded */
			return (RESP_NOW);
		}
	}
	if (chl) {
		(void) gettimeofday(&(chl->enqtime), &tzp);
	} else
		chl = new_cache_ent(map, keydat);

	if (chl == NULL) {
		perror("new_cache_ent failed");
		*statusp = (unsigned)YP_YPERR;
		return (RESP_NOW);
	}
	if (byname || byname_v6)
		h = nres_gethostbyname(chl->key.dptr, my_done, chl);
	else {
		struct in_addr addr;
		struct in6_addr addr6;
		af_type = (strcmp(chl->map, "ipnodes.byaddr") == 0) ?
			AF_INET6 : AF_INET;
		if (af_type == AF_INET6 || af_type == AF_INET) {
			if (inet_pton(af_type, chl->key.dptr,
			(af_type == AF_INET6) ? (void *)&addr6 : (void *)&addr)
							== -1) {
				*statusp = (unsigned)YP_NOKEY;
				return (RESP_NOW);
			}
			h = nres_gethostbyaddr(
			(af_type == AF_INET6) ? (void *)&addr6 : (void *)&addr,
			(af_type == AF_INET6) ? sizeof (addr6) : sizeof (addr),
			af_type, my_done, chl);
		} else {
			*statusp = (unsigned)YP_NOKEY;
			return (RESP_NOW);
		}
	}
	if (h == 0) {		/* definite immediate reject */
		prnt(P_INFO, "immediate reject.\n");
		free_cache_ent(deq_cache_ent(chl));
		*statusp = (unsigned)YP_NOKEY;
		return (RESP_NOW);
	} else if (h == (struct nres *)-1) {
		perror("nres failed\n");
		*statusp = (unsigned)YP_YPERR;
		return (RESP_NOW);
	} else {
		chl->nres = h;
		/* should stash transport so my_done can answer */
		if (try_again) {
			*statusp = (unsigned)YP_NOMORE;
			/* try_again overloaded */
			return (RESP_NOW);

		}
		chl->xprt = transp;
		if (transp) {
			chl->caller.len = transp->xp_rtaddr.len;
			(void) memcpy(chl->caller.buf, transp->xp_rtaddr.buf,
						transp->xp_rtaddr.len);
			chl->xid = svc_getxid(transp);
		}
		return (RESP_LATER);
	}
}

/* ARGSUSED 4 */
static void
my_done(n, h, ttl, chl, errcode)
	void		*n;	/* opaque */
	struct hostent	*h;
	ulong_t		ttl;
	struct cache_ent	*chl;
	int errcode;
{
	static char	buf[1024];
	char		*endbuf, *tptr;
	datum		valdatp;
	int		i;
	SVCXPRT		*transp;
	unsigned long	xid_hold;
	struct ypresp_val resp;
	struct timezone tzp;
	struct netbuf caller_hold, *addrp;
	char uaddr[sizeof (struct sockaddr_in6)];
	int af_type, bsize;

	prnt(P_INFO, "my_done: %s.\n", chl->key.dptr);
	(void) gettimeofday(&(chl->enqtime), &tzp);
	chl->nres = 0;
	caller_hold.maxlen = sizeof (uaddr);
	caller_hold.buf = uaddr;

	if (h == NULL) {
		chl->h_errno = errcode;
		if (chl->h_errno == TRY_AGAIN)
			resp.status = (unsigned)YP_NOMORE;
		else
			resp.status = (unsigned)YP_NOKEY;
		valdatp.dptr = NULL;
		valdatp.dsize = 0;
	} else {
		chl->h_errno = 0;
		chl->ttl = (ttl != 0 && ttl < PQTIME*60) ? ttl : (PQTIME*60);
		endbuf = buf;
		bsize = sizeof (buf);
		bzero((void *)endbuf, bsize);
		af_type = lookup_AF_type(chl);

		/* build the return list */
		for (i = 0; h->h_addr_list[i]; i++) {
			tptr = endbuf;
			(void *) inet_ntop(af_type,
			    (af_type == AF_INET6) ?
				(void *) (h->h_addr_list[i]) :
				(void *) (h->h_addr_list[i]),
			    endbuf, bsize);
			endbuf = &endbuf[strlen(endbuf)];
			bsize = buf + sizeof (buf) - endbuf;
			(void) snprintf(endbuf, bsize, "\t%s\n", h->h_name);
			endbuf = &endbuf[strlen(endbuf)];
			if ((bsize = buf + sizeof (buf) - endbuf) < 300)
				break;
			prnt(P_INFO, "my_done: bsize=%d str=%s", bsize, tptr);
		}
		valdatp.dptr = buf;
		valdatp.dsize = strlen(buf);
		/* remove trailing newline */
		if (valdatp.dsize) {
			valdatp.dptr[valdatp.dsize-1] = '\0';
			valdatp.dsize -= 1;
		}
		chl->val.dsize = valdatp.dsize;
		chl->val.dptr = (char *)malloc(valdatp.dsize);
		if (chl->val.dptr == NULL) {
			perror("my_done");
			free_cache_ent(deq_cache_ent(chl));
			return;
		}
		(void) memcpy(chl->val.dptr, valdatp.dptr, valdatp.dsize);
		resp.status = (unsigned)YP_TRUE;
	}
	/* try to answer here */

	if (valdatp.dptr)
		prnt(P_INFO, "my_done: return %s.\n", valdatp.dptr);
	transp = chl->xprt;
	if (transp && transp->xp_rtaddr.len <= caller_hold.maxlen) {
		caller_hold.len = transp->xp_rtaddr.len;
		(void) memcpy(caller_hold.buf, transp->xp_rtaddr.buf,
					transp->xp_rtaddr.len);
		xid_hold = svc_setxid(transp, chl->xid);
		addrp = &(chl->caller);
		SETCALLER(transp, addrp);
		resp.valdat = valdatp;
		if (!svc_sendreply(transp, (xdrproc_t)xdr_ypresp_val,
							(char *)&resp)) {
			return;
		}
		addrp = &caller_hold;
		SETCALLER(transp, addrp);
		(void) svc_setxid(transp, xid_hold);
	}
}

/*
 * this routine returns the DNS query type:
 *	T_A: IPv4
 *	T_AAAA: IPv6
 */
int
lookup_T_type(struct cache_ent *chl)
{

	if (strcmp(chl->map, "ipnodes.byname") == 0) {
		prnt(P_INFO, "lookup_T_type: T_AAAA\n");
		return (T_AAAA);
	} else if ((strcmp(chl->map, "hosts.byaddr") == 0) ||
		    (strcmp(chl->map, "ipnodes.byaddr") == 0)) {
		prnt(P_INFO, "lookup_T_type: T_PTR\n");
		return (T_PTR);
	}
	prnt(P_INFO, "lookup_T_type: T_A\n");
	return (T_A);
}


/*
 * this routine returns the AF type for the request:
 *	AF_INET: ipv4
 *	AF_INET6: IPv6
 */
int
lookup_AF_type(struct cache_ent *chl)
{
	if ((strcmp(chl->map, "ipnodes.byname") == 0) ||
	    (strcmp(chl->map, "ipnodes.byaddr") == 0)) {
		prnt(P_INFO, "lookup_AF_type: AF_INET6\n");
		return (AF_INET6);
	}
	prnt(P_INFO, "lookup_AF_type: AF_INET\n");
	return (AF_INET);
}
