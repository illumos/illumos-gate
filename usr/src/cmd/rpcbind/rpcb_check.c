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
 * Auxiliary routines to shield off random internet hosts and to report
 * service requests (verbose mode only) or violations (always).
 *
 * This code was extensively modifed from a version authored by:
 *
 * Wietse Venema, Eindhoven University of Technology, The Netherlands
 * and distributed as "rpcbind 2.1".
 *
 * Sun was granted permission to use, modify, including make
 * derivatives of, copy, reproduce and distribute this code.c in both
 * binary and source forms, directly and indirectly.
 *
 * Modified for bundling with Solaris and IPv6.
 *
 * Solaris specific modifcations made are:
 *
 *	Double fork() logging replaced with qsyslog();
 *	Connection refusals are flagged with svcerr_auth(); this
 *	aids in quicker diagnosability of misconfigurations and quicker
 *	failures for /net automounts;
 *	Single function for pmap* and rpcb*;
 *	Local transport checks made using localxprt().
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <netconfig.h>
#include <netdb.h>
#include <netdir.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <rpc/rpc.h>
#include <rpc/pmap_prot.h>
#include <rpc/rpcb_prot.h>
#include <thread.h>
#include <synch.h>
#include <tcpd.h>

#include "rpcbind.h"

/*
 * These are globally visible so that they can be modified by the wrapper's
 * language extension routines.
 */
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;

static mutex_t hosts_ctl_lock = DEFAULTMUTEX;

/*
 * "inet_ntoa/inet_pton" for struct sockaddr_gen
 */
static const char *
sgen_toa(struct sockaddr_gen *addr, char *buf, size_t bufsize)
{
	return (inet_ntop(SGFAM(addr), SGADDRP(addr), buf, bufsize));
}

struct proc_map {
	rpcproc_t code;
	const char *proc;
};

static const struct proc_map pmapmap[] = {
	PMAPPROC_CALLIT,	"callit",
	PMAPPROC_DUMP,		"dump",
	PMAPPROC_GETPORT,	"getport",
	PMAPPROC_SET,		"set",
	PMAPPROC_UNSET,		"unset",
	NULLPROC,		"null",
};

static const struct proc_map rpcbmap[] = {
	RPCBPROC_SET,		"set",
	RPCBPROC_UNSET,		"unset",
	RPCBPROC_GETADDR,	"getaddr",
	RPCBPROC_DUMP,		"dump",
	RPCBPROC_CALLIT,	"callit",
	RPCBPROC_GETTIME,	"gettime",
	RPCBPROC_UADDR2TADDR,	"uaddr2taddr",
	RPCBPROC_TADDR2UADDR,	"taddr2uaddr",
	RPCBPROC_GETVERSADDR,	"getversaddr",
	RPCBPROC_INDIRECT,	"indirect",
	RPCBPROC_GETADDRLIST,	"getaddrlist",
	RPCBPROC_GETSTAT,	"getstat",
	NULLPROC,		"null",
};

/*
 * find_procname - map rpcb/pmap procedure number to name
 */
static const char *
find_procname(rpcproc_t procnum, boolean_t pm)
{
	int nitems, i;
	const struct proc_map *procp;

	if (pm) {
		procp = pmapmap;
		nitems = sizeof (pmapmap)/sizeof (struct proc_map);
	} else {
		procp = rpcbmap;
		nitems = sizeof (rpcbmap)/sizeof (struct proc_map);
	}

	for (i = 0; i < nitems; i++) {
		if (procp[i].code == procnum)
			return (procp[i].proc);
	}
	return (NULL);
}

/*
 * rpcb_log - log request for service
 */
void
rpcb_log(boolean_t verdict, SVCXPRT *transp, rpcproc_t proc, rpcprog_t prog,
    boolean_t pm)
{
	struct netconfig *conf;
	const char *client = "unknown";
	char *uaddr;
	char buf[BUFSIZ];
	char toabuf[INET6_ADDRSTRLEN];
	const char *procname;

	/*
	 * Transform the transport address into something printable.
	 */
	if ((conf = rpcbind_get_conf(transp->xp_netid)) == 0) {
		syslog(LOG_WARNING,
		    "unknown transport (rpcbind_get_conf failed)");
	} else if (strcmp(conf->nc_protofmly, "inet") == 0 ||
	    strcmp(conf->nc_protofmly, "inet6") == 0) {
		client = sgen_toa(svc_getgencaller(transp), toabuf,
		    sizeof (toabuf));
	} else if ((uaddr = taddr2uaddr(conf, &(transp->xp_rtaddr))) == NULL) {
		syslog(LOG_WARNING, "unknown address (taddr2uaddr failed)");
	} else {
		(void) snprintf(buf, sizeof (buf), "%s(%s)",
		    conf->nc_protofmly, uaddr);
		free(uaddr);
		client = buf;
	}

	if ((procname = find_procname(proc, pm)) == NULL) {
		qsyslog(verdict ? allow_severity : deny_severity,
		    "%sconnect from %s to %s-%lu(%lu)",
		    verdict ? "" : "refused ", client, pm ? "pmap" : "rpcb",
		    (ulong_t)proc, (ulong_t)prog);
	} else {
		qsyslog(verdict ? allow_severity : deny_severity,
		    "%sconnect from %s to %s(%lu)", verdict ? "" : "refused ",
		    client, procname, (ulong_t)prog);
	}
}

/*
 * rpcb_check; the rpcbind/portmap access check function.
 */
boolean_t
rpcb_check(SVCXPRT *transp, rpcproc_t procnum, boolean_t ispmap)
{
	struct netconfig *conf;
	boolean_t res = B_TRUE;

	if ((conf = rpcbind_get_conf(transp->xp_netid)) == 0) {
		syslog(LOG_ERR,
		    "rpcbind_get_conf failed: no client address checks");
		return (B_TRUE);
	}

	/*
	 * Require IPv4 for pmap calls; they're not defined for anything else.
	 */
	if (ispmap && strcmp(conf->nc_protofmly, "inet") != 0) {
		res = B_FALSE;
	} else if (strcmp(conf->nc_protofmly, "inet") == 0 ||
	    strcmp(conf->nc_protofmly, "inet6") == 0) {
		if (!localxprt(transp, ispmap)) {
			if (local_only) {
				res = B_FALSE;
			} else {
				char buf[INET6_ADDRSTRLEN];
				const char *addr_string =
				    sgen_toa(svc_getgencaller(transp), buf,
				    sizeof (buf));

				(void) mutex_lock(&hosts_ctl_lock);
				if (hosts_ctl("rpcbind", addr_string,
				    addr_string, "") == 0)
					res = B_FALSE;
				(void) mutex_unlock(&hosts_ctl_lock);
			}
		}
	}

	if (!res)
		svcerr_auth(transp, AUTH_FAILED);

	if (verboselog || !res)
		rpcb_log(res, transp, procnum, 0, ispmap);

	return (res);
}
