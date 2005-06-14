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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef lint
static char sccsid[] = "%Z%%M%	%I%	%E% SMI";
#endif
/*
 * YP Version 1 compatibility code added to rpc.nisd.
 *
 * ypserv1.c
 *
 *	Copyright (c) 1993 Sun Microsystems Inc
 *	All rights reserved.
 *
 * This file provides incomplete support for YP Version 1.
 *
 * This addresses bug #1136940.
 *
 * If a NIS+ server running in NIS compat mode does not respond
 * immediately to a NIS version2 call, the 4.X clients fail over to NIS
 * version 1 and then never switches back to version 2. As the rpc.nisd
 * only supports NIS V2 protocol the client process will hang even when
 * rpc.nisd comes up later.
 *
 * The fix (implemented here) is to provide support for NULL, DOMAIN, and
 * DOMAIN_NOACK calls for version 1 YP (in the NIS compatibility case).
 *
 * From the 4.X source: /src/413/lib/libc/yp/yp_match.c,
 * if we provide support for above three procedures, _yp_dobind() returns
 * with binding for version 1, but later (*dofunc) fails because
 * that RPC procedure for version 1 is not supported. As a result, yp_unbind()
 * is called and then __yp_dobind() is again called. This time around,
 * version 2 is tried first and that succeeds (because now hopefully, the NIS+
 * server is up and responding) and then voila! the (*dofunc) succeeds.
 *
 * Please note that there is no need to provide support for other YP version 1
 * procedures such as yp_match or yp_all.
 */

#include <stdio.h>
#include <stdlib.h> /* getenv, exit */
#include <sys/types.h>
#include <memory.h>
#include <stropts.h>
#include <syslog.h>
#include <rpcsvc/yp_prot.h>

typedef char *domainname;

extern int verbose;		/* set by the -v switch */

/*
 * NIS Version 1 (YP) Dispatch table
 */
static void *ypproc_null_1();
extern int *ypproc_domain_svc();
extern int *ypproc_domain_nonack_svc();

static bool_t
xdr_domainname(xdrs, objp)
	register XDR *xdrs;
	domainname *objp;
{
	register long *buf;

	if (!xdr_string(xdrs, objp, YPMAXDOMAIN))
		return (FALSE);
	return (TRUE);
}

void
ypprog_1(rqstp, transp)
	struct svc_req *rqstp;
	register SVCXPRT *transp;
{
	union {
		domainname ypproc_domain_1_arg;
		domainname ypproc_domain_nonack_1_arg;
	} argument;
	char *result;
	bool_t (*xdr_argument)(), (*xdr_result)();
	char *(*local)();

	/*
	 * In the code that follows, we dispatch to the YP Version 2
	 * calls for the DOMAIN and NONACK cases, since there's no
	 * reason to implement those here.
	 */
	switch (rqstp->rq_proc) {
	case YPPROC_NULL:
		xdr_argument = xdr_void;
		xdr_result = xdr_void;
		local = (char *(*)()) ypproc_null_1;
		break;

	case YPPROC_DOMAIN:
		xdr_argument = xdr_domainname;
		xdr_result = xdr_bool;
		local = (char *(*)()) ypproc_domain_svc;
		break;

	case YPPROC_DOMAIN_NONACK:
		xdr_argument = xdr_domainname;
		xdr_result = xdr_bool;
		local = (char *(*)()) ypproc_domain_nonack_svc;
		break;

	default:
		svcerr_noproc(transp);
		return;
	}
	(void) memset((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs(transp, xdr_argument, (caddr_t) &argument)) {
		svcerr_decode(transp);
		return;
	}
	result = (*local)(&argument, rqstp);
	if (result != NULL && !svc_sendreply(transp, xdr_result, result)) {
		svcerr_systemerr(transp);
	}
	if (!svc_freeargs(transp, xdr_argument, (caddr_t) &argument)) {
		syslog(LOG_ERR, "ypserv_v1: unable to free arguments");
		exit(1);
	}
}

static void *
ypproc_null_1()
{
	static char dummy;

	return ((void *) &dummy);
}
