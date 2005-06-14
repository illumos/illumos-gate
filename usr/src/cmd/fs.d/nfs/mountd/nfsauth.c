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
 *	nfsauth.c
 *
 *	Copyright (c) 1988-1996,1998,1999 by Sun Microsystems, Inc.
 *	All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <rpcsvc/mount.h>
#include <sys/pathconf.h>
#include <sys/systeminfo.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
#include <signal.h>
#include <syslog.h>
#include <locale.h>
#include <unistd.h>
#include <thread.h>
#include <netdir.h>
#include <rpcsvc/nfsauth_prot.h>
#include "../lib/sharetab.h"
#include "mountd.h"

static void nfsauth_access_svc(auth_req *, auth_res *, struct svc_req *);

void
nfsauth_prog(struct svc_req *rqstp, register SVCXPRT *transp)
{
	union {
		auth_req nfsauth_access_arg;
	} argument;
	auth_res  result;

	bool_t (*xdr_argument)();
	bool_t (*xdr_result)();
	void   (*local)();

	switch (rqstp->rq_proc) {
	case NULLPROC:
		(void) svc_sendreply(transp, xdr_void, (char *)NULL);
		return;

	case NFSAUTH_ACCESS:
		xdr_argument = xdr_auth_req;
		xdr_result = xdr_auth_res;
		local = nfsauth_access_svc;
		break;

	default:
		svcerr_noproc(transp);
		return;
	}

	(void) memset((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs(transp, xdr_argument, (caddr_t)&argument)) {
		svcerr_decode(transp);
		return;
	}

	(*local)(&argument, &result, rqstp);

	if (!svc_sendreply(transp, xdr_result, (caddr_t)&result)) {
		svcerr_systemerr(transp);
	}

	if (!svc_freeargs(transp, xdr_argument, (caddr_t)&argument)) {
		syslog(LOG_ERR, "unable to free arguments");
	}
}

/*ARGSUSED*/

static void
nfsauth_access_svc(auth_req *argp, auth_res *result, struct svc_req *rqstp)
{
	struct netconfig *nconf;
	struct nd_hostservlist *clnames = NULL;
	struct netbuf nbuf;
	struct share *sh;
	char tmp[MAXIPADDRLEN];
	char *host = NULL;

	result->auth_perm = NFSAUTH_DENIED;

	/*
	 * Convert the client's address to a hostname
	 */
	nconf = getnetconfigent(argp->req_netid);
	if (nconf == NULL) {
		syslog(LOG_ERR, "No netconfig entry for %s", argp->req_netid);
		return;
	}

	nbuf.len = argp->req_client.n_len;
	nbuf.buf = argp->req_client.n_bytes;

	if (netdir_getbyaddr(nconf, &clnames, &nbuf)) {
		host = &tmp[0];
		if (strcmp(nconf->nc_protofmly, NC_INET) == 0) {
			struct sockaddr_in *sa;

			/* LINTED pointer alignment */
			sa = (struct sockaddr_in *)nbuf.buf;
			(void) inet_ntoa_r(sa->sin_addr, tmp);
		} else if (strcmp(nconf->nc_protofmly, NC_INET6) == 0) {
			struct sockaddr_in6 *sa;
			/* LINTED pointer */
			sa = (struct sockaddr_in6 *)nbuf.buf;
			(void) inet_ntop(AF_INET6, sa->sin6_addr.s6_addr,
				    tmp, INET6_ADDRSTRLEN);
		}
		clnames = anon_client(host);
	}

	/*
	 * Now find the export
	 */
	sh = findentry(argp->req_path);
	if (sh == NULL) {
		syslog(LOG_ERR, "%s not exported", argp->req_path);
		goto done;
	}

	result->auth_perm = check_client(sh, &nbuf, clnames, argp->req_flavor);

	sharefree(sh);

	if (result->auth_perm == NFSAUTH_DENIED) {
		syslog(LOG_ERR, "%s denied access to %s",
			clnames->h_hostservs[0].h_host, argp->req_path);
	}

done:
	freenetconfigent(nconf);
	if (clnames)
		netdir_free(clnames, ND_HOSTSERVLIST);
}
