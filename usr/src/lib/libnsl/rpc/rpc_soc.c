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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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

#ifdef PORTMAP
/*
 * rpc_soc.c
 *
 * The backward compatibility routines for the earlier implementation
 * of RPC, where the only transports supported were tcp/ip and udp/ip.
 * Based on berkeley socket abstraction, now implemented on the top
 * of TLI/Streams
 */

#include "mt.h"
#include "rpc_mt.h"
#include <stdio.h>
#include <sys/types.h>
#include <rpc/rpc.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netdir.h>
#include <errno.h>
#include <sys/syslog.h>
#include <rpc/pmap_clnt.h>
#include <rpc/pmap_prot.h>
#include <rpc/nettype.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int __rpc_bindresvport(int, struct sockaddr_in *, int *, int);
int __rpc_bindresvport_ipv6(int, struct sockaddr *, int *, int, char *);
void get_myaddress_ipv6(char *, struct sockaddr *);

extern mutex_t	rpcsoc_lock;

/*
 * A common clnt create routine
 */
static CLIENT *
clnt_com_create(struct sockaddr_in *raddr, rpcprog_t prog, rpcvers_t vers,
	int *sockp, uint_t sendsz, uint_t recvsz, char *tp)
{
	CLIENT *cl;
	int madefd = FALSE;
	int fd = *sockp;
	struct t_info tinfo;
	struct netconfig *nconf;
	int port;
	struct netbuf bindaddr;
	bool_t locked = TRUE;

	(void) mutex_lock(&rpcsoc_lock);
	if ((nconf = __rpc_getconfip(tp)) == NULL) {
		rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
		(void) mutex_unlock(&rpcsoc_lock);
		return (NULL);
	}
	if (fd == RPC_ANYSOCK) {
		fd = t_open(nconf->nc_device, O_RDWR, &tinfo);
		if (fd == -1)
			goto syserror;
		RPC_RAISEFD(fd);
		madefd = TRUE;
	} else {
		if (t_getinfo(fd, &tinfo) == -1)
			goto syserror;
	}

	if (raddr->sin_port == 0) {
		uint_t proto;
		ushort_t sport;

		/* pmap_getport is recursive */
		(void) mutex_unlock(&rpcsoc_lock);
		proto = strcmp(tp, "udp") == 0 ? IPPROTO_UDP : IPPROTO_TCP;
		sport = pmap_getport(raddr, prog, vers, proto);
		if (sport == 0) {
			locked = FALSE;
			goto err;
		}
		raddr->sin_port = htons(sport);
		/* pmap_getport is recursive */
		(void) mutex_lock(&rpcsoc_lock);
	}

	/* Transform sockaddr_in to netbuf */
	bindaddr.maxlen = bindaddr.len =  __rpc_get_a_size(tinfo.addr);
	bindaddr.buf = (char *)raddr;

	(void) __rpc_bindresvport(fd, NULL, &port, 0);
	cl = clnt_tli_create(fd, nconf, &bindaddr, prog, vers,
				sendsz, recvsz);
	if (cl) {
		if (madefd == TRUE) {
			/*
			 * The fd should be closed while destroying the handle.
			 */
			(void) CLNT_CONTROL(cl, CLSET_FD_CLOSE, NULL);
			*sockp = fd;
		}
		(void) freenetconfigent(nconf);
		(void) mutex_unlock(&rpcsoc_lock);
		return (cl);
	}
	goto err;

syserror:
	rpc_createerr.cf_stat = RPC_SYSTEMERROR;
	rpc_createerr.cf_error.re_errno = errno;
	rpc_createerr.cf_error.re_terrno = t_errno;

err:	if (madefd == TRUE)
		(void) t_close(fd);
	(void) freenetconfigent(nconf);
	if (locked == TRUE)
		(void) mutex_unlock(&rpcsoc_lock);
	return (NULL);
}

CLIENT *
clntudp_bufcreate(struct sockaddr_in *raddr, rpcprog_t prog, rpcvers_t vers,
	struct timeval wait, int *sockp, uint_t sendsz, uint_t recvsz)
{
	CLIENT *cl;

	cl = clnt_com_create(raddr, prog, vers, sockp, sendsz, recvsz, "udp");
	if (cl == NULL)
		return (NULL);
	(void) CLNT_CONTROL(cl, CLSET_RETRY_TIMEOUT, (char *)&wait);
	return (cl);
}

CLIENT *
clntudp_create(struct sockaddr_in *raddr, rpcprog_t program, rpcvers_t version,
	struct timeval wait, int *sockp)
{
	return (clntudp_bufcreate(raddr, program, version, wait, sockp,
					UDPMSGSIZE, UDPMSGSIZE));
}

CLIENT *
clnttcp_create(struct sockaddr_in *raddr, rpcprog_t prog, rpcvers_t vers,
	int *sockp, uint_t sendsz, uint_t recvsz)
{
	return (clnt_com_create(raddr, prog, vers, sockp, sendsz,
			recvsz, "tcp"));
}

CLIENT *
clntraw_create(rpcprog_t prog, rpcvers_t vers)
{
	return (clnt_raw_create(prog, vers));
}

/*
 * A common server create routine
 */
static SVCXPRT *
svc_com_create(int fd, uint_t sendsize, uint_t recvsize, char *netid)
{
	struct netconfig *nconf;
	SVCXPRT *svc;
	int madefd = FALSE;
	int port;
	int res;

	if ((nconf = __rpc_getconfip(netid)) == NULL) {
		(void) syslog(LOG_ERR, "Could not get %s transport", netid);
		return (NULL);
	}
	if (fd == RPC_ANYSOCK) {
		fd = t_open(nconf->nc_device, O_RDWR, NULL);
		if (fd == -1) {
			char errorstr[100];

			__tli_sys_strerror(errorstr, sizeof (errorstr),
					t_errno, errno);
			(void) syslog(LOG_ERR,
			"svc%s_create: could not open connection : %s", netid,
				    errorstr);
			(void) freenetconfigent(nconf);
			return (NULL);
		}
		madefd = TRUE;
	}

	res = __rpc_bindresvport(fd, NULL, &port, 8);
	svc = svc_tli_create(fd, nconf, NULL,
				sendsize, recvsize);
	(void) freenetconfigent(nconf);
	if (svc == NULL) {
		if (madefd)
			(void) t_close(fd);
		return (NULL);
	}
	if (res == -1)
		/* LINTED pointer cast */
		port = (((struct sockaddr_in *)svc->xp_ltaddr.buf)->sin_port);
	svc->xp_port = ntohs(port);
	return (svc);
}

SVCXPRT *
svctcp_create(int fd, uint_t sendsize, uint_t recvsize)
{
	return (svc_com_create(fd, sendsize, recvsize, "tcp"));
}

SVCXPRT *
svcudp_bufcreate(int fd, uint_t sendsz, uint_t recvsz)
{
	return (svc_com_create(fd, sendsz, recvsz, "udp"));
}

SVCXPRT *
svcfd_create(int fd, uint_t sendsize, uint_t recvsize)
{
	return (svc_fd_create(fd, sendsize, recvsize));
}


SVCXPRT *
svcudp_create(int fd)
{
	return (svc_com_create(fd, UDPMSGSIZE, UDPMSGSIZE, "udp"));
}

SVCXPRT *
svcraw_create(void)
{
	return (svc_raw_create());
}

/*
 * Bind a fd to a privileged IP port.
 * This is slightly different from the code in netdir_options
 * because it has a different interface - main thing is that it
 * needs to know its own address.  We also wanted to set the qlen.
 * t_getname() can be used for those purposes and perhaps job can be done.
 */
int
__rpc_bindresvport_ipv6(int fd, struct sockaddr *sin, int *portp, int qlen,
			char *fmly)
{
	int res;
	static in_port_t port, *sinport;
	struct sockaddr_in6 myaddr;
	int i;
	struct t_bind tbindstr, *tres;
	struct t_info tinfo;
	extern mutex_t portnum_lock;

	/* VARIABLES PROTECTED BY portnum_lock: port */

#define	STARTPORT 600
#define	ENDPORT (IPPORT_RESERVED - 1)
#define	NPORTS	(ENDPORT - STARTPORT + 1)

	if (sin == 0 && fmly == 0) {
		errno = EINVAL;
		return (-1);
	}
	if (geteuid()) {
		errno = EACCES;
		return (-1);
	}
	if ((i = t_getstate(fd)) != T_UNBND) {
		if (t_errno == TBADF)
			errno = EBADF;
		if (i != -1)
			errno = EISCONN;
		return (-1);
	}
	if (sin == 0) {
		sin = (struct sockaddr *)&myaddr;
		get_myaddress_ipv6(fmly, sin);
	}
	if (sin->sa_family == AF_INET) {
		/* LINTED pointer cast */
		sinport = &((struct sockaddr_in *)sin)->sin_port;
	} else if (sin->sa_family == AF_INET6) {
		/* LINTED pointer cast */
		sinport = &((struct sockaddr_in6 *)sin)->sin6_port;
	} else {
		errno = EPFNOSUPPORT;
		return (-1);
	}

	/* Transform sockaddr to netbuf */
	if (t_getinfo(fd, &tinfo) == -1) {
		return (-1);
	}
	/* LINTED pointer cast */
	tres = (struct t_bind *)t_alloc(fd, T_BIND, T_ADDR);
	if (tres == NULL)
		return (-1);

	tbindstr.qlen = qlen;
	tbindstr.addr.buf = (char *)sin;
	tbindstr.addr.len = tbindstr.addr.maxlen = __rpc_get_a_size(tinfo.addr);
	/* LINTED pointer cast */
	sin = (struct sockaddr *)tbindstr.addr.buf;

	res = -1;
	(void) mutex_lock(&portnum_lock);
	if (port == 0)
		port = (getpid() % NPORTS) + STARTPORT;
	for (i = 0; i < NPORTS; i++) {
		*sinport = htons(port++);
		if (port > ENDPORT)
			port = STARTPORT;
		res = t_bind(fd, &tbindstr, tres);
		if (res == 0) {
			if ((tbindstr.addr.len == tres->addr.len) &&
				(memcmp(tbindstr.addr.buf, tres->addr.buf,
					(int)tres->addr.len) == 0))
				break;
			(void) t_unbind(fd);
			res = -1;
		} else if (t_errno != TSYSERR || errno != EADDRINUSE)
			break;
	}
	(void) mutex_unlock(&portnum_lock);

	if ((portp != NULL) && (res == 0))
		*portp = *sinport;
	(void) t_free((char *)tres, T_BIND);
	return (res);
}

int
__rpc_bindresvport(int fd, struct sockaddr_in *sin, int *portp, int qlen)
{
	return (__rpc_bindresvport_ipv6(fd, (struct sockaddr *)sin, portp,
					qlen, NC_INET));
}

/*
 * Get clients IP address.
 * don't use gethostbyname, which would invoke yellow pages
 * Remains only for backward compatibility reasons.
 * Used mainly by the portmapper so that it can register
 * with itself. Also used by pmap*() routines
 */
void
get_myaddress_ipv6(char *fmly, struct sockaddr *addr)
{
	if (fmly != 0 && strcmp(fmly, NC_INET6) == 0) {
		/* LINTED pointer cast */
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
		(void) memset(sin6, 0, sizeof (*sin6));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(PMAPPORT);
		if (__can_use_af(AF_INET6)) {
			/* Local copy of in6addr_any to avoid -lsocket */
			struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
			sin6->sin6_addr = in6addr_any;
		} else {
			struct in_addr in4;
			in4.s_addr = INADDR_ANY;
			IN6_INADDR_TO_V4MAPPED(&in4, &sin6->sin6_addr);
		}
	} else {
		/* LINTED pointer cast */
		struct sockaddr_in	*sin = (struct sockaddr_in *)addr;
		(void) memset(sin, 0, sizeof (*sin));
		sin->sin_family = AF_INET;
		sin->sin_port = htons(PMAPPORT);
		sin->sin_addr.s_addr = INADDR_ANY;
	}
}

void
get_myaddress(struct sockaddr_in *addr)
{
	get_myaddress_ipv6(0, (struct sockaddr *)addr);
}

/*
 * Get port used by specified service on specified host.
 * Exists for source compatibility only.
 * Obsoleted by rpcb_getaddr().
 */
ushort_t
getrpcport(char *host, rpcprog_t prognum, rpcvers_t versnum,
	rpcprot_t proto)
{
	struct sockaddr_in addr;
	struct hostent *hp;

	if ((hp = gethostbyname(host)) == NULL)
		return (0);
	(void) memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
	addr.sin_family = AF_INET;
	addr.sin_port =  0;
	return (pmap_getport(&addr, prognum, versnum, proto));
}

/*
 * For connectionless "udp" transport. Obsoleted by rpc_call().
 */
int
callrpc(char *host, rpcprog_t prognum, rpcvers_t versnum, rpcproc_t procnum,
	xdrproc_t inproc, char *in, xdrproc_t outproc, char *out)
{
	return ((int)rpc_call(host, prognum, versnum, procnum, inproc,
				in, outproc, out, "udp"));
}

/*
 * For connectionless kind of transport. Obsoleted by rpc_reg()
 */
int
registerrpc(rpcprog_t prognum, rpcvers_t versnum, rpcproc_t procnum,
	char *(*progname)(), xdrproc_t inproc, xdrproc_t outproc)
{
	return (rpc_reg(prognum, versnum, procnum, progname, inproc,
				outproc, "udp"));
}

/*
 * All the following clnt_broadcast stuff is convulated; it supports
 * the earlier calling style of the callback function
 */
static pthread_key_t	clnt_broadcast_key = PTHREAD_ONCE_KEY_NP;
static resultproc_t	clnt_broadcast_result_main;

/*
 * Need to translate the netbuf address into sockaddr_in address.
 * Dont care about netid here.
 */
/* ARGSUSED2 */
static bool_t
rpc_wrap_bcast(char *resultp, struct netbuf *addr, struct netconfig *nconf)
{
	resultproc_t clnt_broadcast_result;

	clnt_broadcast_result = thr_main()? clnt_broadcast_result_main :
		(resultproc_t)pthread_getspecific(clnt_broadcast_key);
	return ((*clnt_broadcast_result)(resultp,
				/* LINTED pointer cast */
				(struct sockaddr_in *)addr->buf));
}

/*
 * Broadcasts on UDP transport. Obsoleted by rpc_broadcast().
 */
enum clnt_stat
clnt_broadcast(rpcprog_t prog, rpcvers_t vers, rpcproc_t proc, xdrproc_t xargs,
	caddr_t argsp, xdrproc_t xresults,
	caddr_t resultsp, resultproc_t eachresult)
{
	if (thr_main()) {
		clnt_broadcast_result_main = eachresult;
	} else {
		(void) pthread_key_create_once_np(&clnt_broadcast_key, NULL);
		(void) pthread_setspecific(clnt_broadcast_key,
							(void *)eachresult);
	}
	return (rpc_broadcast(prog, vers, proc, xargs, argsp, xresults,
				resultsp, (resultproc_t)rpc_wrap_bcast, "udp"));
}

/*
 * Create the client des authentication object. Obsoleted by
 * authdes_seccreate().
 */
AUTH *
authdes_create(char *servername, uint_t window, struct sockaddr_in *syncaddr,
	des_block *ckey)
{
	char *hostname = NULL;

	if (syncaddr) {
		/*
		 * Change addr to hostname, because that is the way
		 * new interface takes it.
		 */
		struct netconfig *nconf;
		struct netbuf nb_syncaddr;
		struct nd_hostservlist *hlist;
		AUTH *nauth;
		int fd;
		struct t_info tinfo;

		if ((nconf = __rpc_getconfip("udp")) == NULL &&
		    (nconf = __rpc_getconfip("tcp")) == NULL)
			goto fallback;

		/* Transform sockaddr_in to netbuf */
		if ((fd = t_open(nconf->nc_device, O_RDWR, &tinfo)) == -1) {
			(void) freenetconfigent(nconf);
			goto fallback;
		}
		(void) t_close(fd);
		nb_syncaddr.maxlen = nb_syncaddr.len =
			__rpc_get_a_size(tinfo.addr);
		nb_syncaddr.buf = (char *)syncaddr;
		if (netdir_getbyaddr(nconf, &hlist, &nb_syncaddr)) {
			(void) freenetconfigent(nconf);
			goto fallback;
		}
		if (hlist && hlist->h_cnt > 0 && hlist->h_hostservs)
			hostname = hlist->h_hostservs->h_host;
		nauth = authdes_seccreate(servername, window, hostname, ckey);
		(void) netdir_free((char *)hlist, ND_HOSTSERVLIST);
		(void) freenetconfigent(nconf);
		return (nauth);
	}
fallback:
	return (authdes_seccreate(servername, window, hostname, ckey));
}
#endif /* PORTMAP */
