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
 * Copyright (c) 1993-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <rpc/rpc.h>
#include <syslog.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <errno.h>
#include <sys/systeminfo.h>
#include <netconfig.h>
#include <netdir.h>
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/nis.h>
#include "resolv_common.h"
#include "nis_proc.h"

#define	YPDNSVERS	2L
#define	RESOLV_EXEC_PATH	"/usr/sbin/rpc.nisd_resolv"
#define	RESOLV_EXEC_ERR		"can't exec /usr/sbin/rpc.nisd_resolv: %s\n"

/*
 * Need to protect against inadvertently starting more than one rpc.nis_resolv.
 * Thus, apply this lock before checking if rpc.nisd_resolv is running,
 * and hold it until setup_resolv() (if called) has completed.
 */
DECLMUTEXLOCK(setup_resolv);

extern int verbose;

void
setup_resolv(fwding, child, client, tp_type, prognum)
int	*fwding;
int	*child;
CLIENT	**client;
char	*tp_type;
long	prognum;	/* use transient if this not set */
{
	enum clnt_stat stat;
	struct timeval tv;
	char prog_str[15], fd_str[5];
	SVCXPRT *xprt = NULL;
	char *tp;
	char name[257];
	struct netconfig *nc;
	void *h;

	if (!*fwding)
		return;

	/* try the specified netid (default ticots), then any loopback */
	tp = (tp_type && *tp_type) ? tp_type : "ticots";
	if (!getconf(tp, &h, &nc)) { /* dont forget endnetconfig() */
		syslog(LOG_ERR, "can't get resolv_clnt netconf %s.\n", tp);
		*fwding = FALSE;
		return;
	}
	tp = nc->nc_netid;

	/*
	 * Startup the resolv server: use transient prognum if prognum
	 * isn't set. Using transient means we create mapping then
	 * pass child the fd to use for service.
	 */
	if (!getprognum(&prognum, &xprt, fd_str, prog_str, YPDNSVERS, tp)) {
		syslog(LOG_ERR, "can't create resolv xprt for transient.\n");
		*fwding = FALSE;
		endnetconfig(h);
		return;
	}
	switch (*child = vfork()) {
	case -1: /* error  */
		syslog(LOG_ERR, "can't startup resolv daemon\n");
		endnetconfig(h);
		*fwding = FALSE;
		return;
	case 0:  /* child  */
		/*
		 * if using transient we must maintain fd across
		 * exec cause unset/set on prognum isn't automic.
		 *
		 * if using transient we'll just do svc_tli_create
		 * in child on our bound fd.
		 */
		execlp(RESOLV_EXEC_PATH, "rpc.nisd_resolv",
				"-F",		/* forground  */
				"-C", fd_str,	/* dont close */
				"-p", prog_str,	/* prognum    */
				"-t", tp,	/* tp type    */
				NULL);
		syslog(LOG_ERR, RESOLV_EXEC_ERR, strerror(errno));
		/*
		 * vfork(2) says the forked child should call _exit(),
		 * not exit(), if exec() fails.
		 */
		_exit(1);
	default: /* parent */
		/* close fd, free xprt, but leave mapping */
		if (xprt) svc_destroy(xprt);

		/* let it crank up before we create client */
		sleep(4);
	}
	if (sysinfo(SI_HOSTNAME, name, sizeof (name)-1) == -1) {
		syslog(LOG_ERR, "can't get local hostname.\n");
		(void) kill (*child, SIGINT);
		endnetconfig(h);
		*fwding = FALSE;
		return;
	}
	if ((*client = clnt_tp_create(HOST_SELF_CONNECT, prognum,
			YPDNSVERS, nc)) == NULL) {
		syslog(LOG_ERR, "can't create resolv_clnt\n");
		(void) kill (*child, SIGINT);
		endnetconfig(h);
		*fwding = FALSE;
		return;
	}
	endnetconfig(h);

	/* ping for comfort */
	tv.tv_sec = 10; tv.tv_usec = 0;
	if ((stat = clnt_call(*client, 0, xdr_void, 0,
				xdr_void, 0, tv)) != RPC_SUCCESS) {
		syslog(LOG_ERR, "can't talk with resolv server\n");
		clnt_destroy (*client);
		(void) kill (*child, SIGINT);
		*fwding = FALSE;
		return;
	}

	if (verbose)
		syslog(LOG_INFO, "finished setup for dns fwding.\n");
}

int
getprognum(prognum, xprt, fd_str, prog_str, vers, tp_type)
long *prognum;
SVCXPRT **xprt;
char *fd_str;
char *prog_str;
long vers;
char *tp_type;
{
	static u_long start = 0x40000000;
	int fd;
	struct netconfig *nc;
	struct netbuf *nb;

	/* If prognum specified, use it instead of transient hassel. */
	if (*prognum) {
		*xprt = NULL;
		sprintf(fd_str, "-1"); /* have child close all fds */
		sprintf(prog_str, "%u", *prognum);
		return (TRUE);
	}

	/*
	 * Transient hassel:
	 *	- parent must create mapping since someone else could
	 *	  steal the transient prognum before child created it
	 * 	- pass the child the fd to use for service
	 * 	- close the fd (after exec), free xprt, leave mapping intact
	 */
	/* tp_type is legit: users choice or a loopback netid */
	if ((nc = getnetconfigent(tp_type)) == NULL)
		return (FALSE);
	if ((*xprt = svc_tli_create(RPC_ANYFD, nc, NULL, 0, 0)) == NULL) {
		freenetconfigent(nc);
		return (FALSE);
	}
	nb = &(*xprt)->xp_ltaddr;
	fd = (*xprt)->xp_fd;
	while (!rpcb_set(start, vers, nc, nb))
		start++;
	freenetconfigent(nc);

	*prognum = start;
	sprintf(fd_str, "%u", fd);
	sprintf(prog_str, "%u", *prognum);

	return (TRUE);
}

int
getconf(netid, handle, nconf)
char *netid;
void **handle;
struct netconfig **nconf;
{
	struct netconfig *nc, *save = NULL;

	if ((*handle = setnetconfig()) == NULL)
		return (FALSE);

	while (nc = getnetconfig((void*)*handle)) {
		/* XXX Shouldn't this be strcmp() == 0 ? */
		if (strcmp(nc->nc_netid, netid) != 0) {
			*nconf = nc;
			return (TRUE);
		} else if (!save && strcmp(nc->nc_protofmly, "loopback") != 0)
			save = nc;
	}

	if (save) {
		*nconf = save;
		return (TRUE);
	} else {
		endnetconfig(*handle);
		return (FALSE);
	}
}

int
resolv_req(fwding, client, pid, tp, xprt, req, map)
int *fwding;
CLIENT **client;
int *pid;
char *tp;
SVCXPRT *xprt;
struct ypreq_key *req;
char *map;
{
	enum clnt_stat stat;
	struct timeval tv;
	struct ypfwdreq_key4 fwd_req4;
	struct ypfwdreq_key6 fwd_req6;
	struct in6_addr in6;
	int byname, byaddr;
	int byname6, byaddr6;
	struct netbuf *nb;
	char *cp;
	int i;
	sa_family_t caller_af = AF_UNSPEC;
	struct sockaddr_in *sin4;
	struct sockaddr_in6 *sin6;
	int savepid;

	if (!*fwding)
		return (FALSE);

	byname = strcmp(map, "hosts.byname") == 0;
	byaddr = strcmp(map, "hosts.byaddr") == 0;
	byname6 = strcmp(map, "ipnodes.byname") == 0;
	byaddr6 = strcmp(map, "ipnodes.byaddr") == 0;
	if ((!byname && !byaddr && !byname6 && !byaddr6) ||
				req->keydat.dsize == 0 ||
				req->keydat.dptr[0] == '\0' ||
				!isascii(req->keydat.dptr[0]) ||
				!isgraph(req->keydat.dptr[0])) {
		/* default status is YP_NOKEY */
		return (FALSE);
	}

	/*
	 * In order to tell if we have an IPv4 or IPv6 caller address,
	 * we must know that nb->buf is a (sockaddr_in *) or a
	 * (sockaddr_in6 *). Hence, we might as well dispense with the
	 * conversion to uaddr and parsing of same that this section
	 * of the code previously involved itself in.
	 */
	nb = svc_getrpccaller(xprt);
	if (nb != 0)
		caller_af = ((struct sockaddr_storage *)nb->buf)->ss_family;

	if (caller_af == AF_INET6) {
		fwd_req6.map = map;
		fwd_req6.keydat = req->keydat;
		fwd_req6.xid = svc_getxid(xprt);
		sin6 = (struct sockaddr_in6 *)nb->buf;
		fwd_req6.addr = (uint32_t *)&in6;
		memcpy(fwd_req6.addr, sin6->sin6_addr.s6_addr,
			sizeof (in6));
		fwd_req6.port = sin6->sin6_port;
	} else if (caller_af == AF_INET) {
		fwd_req4.map = map;
		fwd_req4.keydat = req->keydat;
		fwd_req4.xid = svc_getxid(xprt);
		sin4 = (struct sockaddr_in *)nb->buf;
		fwd_req4.ip = ntohl(sin4->sin_addr.s_addr);
		fwd_req4.port = sin4->sin_port;
	} else {
		syslog(LOG_ERR, "unknown caller IP address family %d",
			caller_af);
		return (FALSE);
	}

	/* Restart resolver if it died. (possible overkill) */

	/*
	 * Since we may end up restarting rpc.nisd_resolv, acquire the
	 * lock.
	 */
	MUTEXLOCK(setup_resolv, "resolv_req(setup_resolv)");

	if (kill(*pid, 0)) {
		syslog(LOG_INFO,
		"Restarting resolv server: old one (pid %d) died.\n", *pid);
		clnt_destroy (*client);
		setup_resolv(fwding, pid, client, tp, 0l /* transient p# */);
		if (!*fwding) {
			MUTEXUNLOCK(setup_resolv, "resolv_req(setup_resolv)");
			syslog(LOG_ERR,
			"can't restart resolver: ending resolv service.\n");
			return (FALSE);
		}
	}

	/*
	 * Save pid of rpc.nisd_resolv, so that we can tell if another
	 * thread performed a restart while we weren't holding the lock.
	 */
	savepid = *pid;
	MUTEXUNLOCK(setup_resolv, "resolv_req(setup_resolv)");

	/* may need to up timeout */
	tv.tv_sec = 10; tv.tv_usec = 0;
	if (caller_af == AF_INET6) {
		stat = clnt_call(*client, YPDNSPROC6, xdr_ypfwdreq_key6,
					(char *) &fwd_req6, xdr_void, 0, tv);
	} else {
		stat = clnt_call(*client, YPDNSPROC4, xdr_ypfwdreq_key4,
					(char *) &fwd_req4, xdr_void, 0, tv);
	}
	if (stat == RPC_SUCCESS) /* expected */
		return (TRUE);

	else { /* Over kill error recovery */
		MUTEXLOCK(setup_resolv, "resolv_req(setup_resolv)");
		/*
		 * If the pid of rpc.nisd_resolv has changed, another thread
		 * has already attempted a restart, and there's little point
		 * in our doing the same. Just repeat the clnt_call().
		 */
		if (*pid == savepid) {
			/*
			 * make one attempt to restart service before turning
			 * off
			 */
			syslog(LOG_INFO,
			"Restarting resolv server: old one not responding.\n");

			if (!kill(*pid, 0))
				kill (*pid, SIGINT); /* cleanup old one */

			clnt_destroy (*client);
			setup_resolv(fwding, pid, client, tp,
					0l /* transient p# */);
			if (!*fwding) {
				MUTEXUNLOCK(setup_resolv,
						"resolv_req(setup_resolv)");
				syslog(LOG_ERR,
			"can't restart resolver: ending resolv service.\n");
				return (FALSE);
			}
		}
		MUTEXUNLOCK(setup_resolv, "resolv_req(setup_resolv)");

		if (caller_af == AF_INET6) {
			stat = clnt_call(*client, YPDNSPROC6, xdr_ypfwdreq_key6,
					(char *) &fwd_req6, xdr_void, 0, tv);
		} else {
			stat = clnt_call(*client, YPDNSPROC4, xdr_ypfwdreq_key4,
					(char *) &fwd_req4, xdr_void, 0, tv);
		}
		if (stat == RPC_SUCCESS) /* expected */
			return (TRUE);
		else {
			/* no more restarts */
			clnt_destroy (*client);
			*fwding = FALSE; /* turn off fwd'ing */
			syslog(LOG_ERR,
		"restarted resolver not responding: ending resolv service.\n");
			return (FALSE);
		}
	}
}
