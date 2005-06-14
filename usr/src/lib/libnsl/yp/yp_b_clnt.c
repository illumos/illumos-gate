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
 *
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley
 * under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/rpc.h>
#include <sys/time.h>
#include <sys/types.h>
#include <rpc/trace.h>
#include "yp_b.h"
#define	bzero(a, b) (void) memset(a, 0, b)
#define	YPBIND_ERR_ERR 1		/* Internal error */
#define	YPBIND_ERR_NOSERV 2		/* No bound server for passed domain */
#define	YPBIND_ERR_RESC 3		/* System resource allocation failure */
#define	YPBIND_ERR_NODOMAIN 4		/* Domain doesn't exist */

/* Default timeout can be changed using clnt_control() */
static struct timeval TIMEOUT = { 25, 0 };

void *
ypbindproc_null_3(argp, clnt)
	void *argp;
	CLIENT *clnt;
{
	static char res;

	trace2(TR_ypbindproc_null_3, 0, clnt);
	bzero((char *)&res, sizeof (res));
	if (clnt_call(clnt, YPBINDPROC_NULL, xdr_void,
		argp, xdr_void, &res, TIMEOUT) != RPC_SUCCESS) {
		trace1(TR_ypbindproc_null_3, 1);
		return (NULL);
	}
	trace1(TR_ypbindproc_null_3, 1);
	return ((void *)&res);
}

ypbind_resp *
ypbindproc_domain_3(argp, clnt)
	ypbind_domain *argp;
	CLIENT *clnt;
{
	static ypbind_resp res;

	trace2(TR_ypbindproc_domain_3, 0, clnt);
	bzero((char *)&res, sizeof (res));
	if (clnt_call(clnt, YPBINDPROC_DOMAIN,
		xdr_ypbind_domain, (char *)argp, xdr_ypbind_resp,
		(char *)&res, TIMEOUT) != RPC_SUCCESS) {
		trace1(TR_ypbindproc_domain_3, 1);
		return (NULL);
	}
	trace1(TR_ypbindproc_domain_3, 1);
	return (&res);
}

void *
ypbindproc_setdom_3(argp, clnt)
	ypbind_setdom *argp;
	CLIENT *clnt;
{
	static char res;

	trace2(TR_ypbindproc_setdom_3, 0, clnt);
	bzero((char *)&res, sizeof (res));
	if (clnt_call(clnt, YPBINDPROC_SETDOM,
		xdr_ypbind_setdom, (char *)argp, xdr_void, &res,
		TIMEOUT) != RPC_SUCCESS) {
		trace1(TR_ypbindproc_setdom_3, 1);
		return (NULL);
	}
	trace1(TR_ypbindproc_setdom_3, 1);
	return ((void *)&res);
}
