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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	These functions are documented in the SVID as being part of libnsl.
 *	They are also defined as macros in various RPC header files.  To
 *	ensure that these interfaces exist as functions, we've created this
 *	(we hope unused) file.
 */

#include "mt.h"
#include <rpc/rpc.h>
#include <sys/types.h>
#include <synch.h>

#undef	auth_destroy
#undef	clnt_call
#undef  clnt_send
#undef	clnt_control
#undef	clnt_destroy
#undef	clnt_freeres
#undef	clnt_geterr
#undef	svc_destroy
#undef	svc_freeargs
#undef	svc_getargs
#undef	svc_getrpccaller
#undef	xdr_destroy
#undef	xdr_getpos
#undef	xdr_inline
#undef	xdr_setpos

extern int __svc_versquiet_get();
extern void __svc_versquiet_off();
extern void __svc_versquiet_on();

void
auth_destroy(AUTH *auth)
{
	((*((auth)->ah_ops->ah_destroy))(auth));
}

enum clnt_stat
clnt_call(CLIENT *cl, uint32_t proc, xdrproc_t xargs, caddr_t argsp,
			xdrproc_t xres, caddr_t resp, struct timeval timeout)
{
	return ((*(cl)->cl_ops->cl_call)(cl, proc, xargs, argsp, xres, resp,
		timeout));
}

enum clnt_stat
clnt_send(CLIENT *cl, uint32_t proc, xdrproc_t xargs, caddr_t argsp)
{
	return ((*(cl)->cl_ops->cl_send)(cl, proc, xargs, argsp));
}

bool_t
clnt_control(CLIENT *cl, uint_t rq, char *in)
{
	return ((*(cl)->cl_ops->cl_control)(cl, rq, in));
}

void
clnt_destroy(CLIENT *cl)
{
	((*(cl)->cl_ops->cl_destroy)(cl));
}

bool_t
clnt_freeres(CLIENT *cl, xdrproc_t xres, caddr_t resp)
{
	return ((*(cl)->cl_ops->cl_freeres)(cl, xres, resp));
}

void
clnt_geterr(CLIENT *cl, struct rpc_err *errp)
{
	(*(cl)->cl_ops->cl_geterr)(cl, errp);
}

bool_t
svc_control(SVCXPRT *xprt, const uint_t rq, void *in)
{
	switch (rq) {
	case SVCGET_VERSQUIET:
		*((int *)in) = __svc_versquiet_get(xprt);
		return (TRUE);
	case SVCSET_VERSQUIET:
		if (*((int *)in) == 0)
			__svc_versquiet_off(xprt);
		else
			__svc_versquiet_on(xprt);
		return (TRUE);
	default:
		return ((*(xprt)->xp_ops->xp_control)(xprt, rq, in));
	}
}

void
svc_destroy(SVCXPRT *xprt)
{
	(*(xprt)->xp_ops->xp_destroy)(xprt);
}

bool_t
svc_freeargs(SVCXPRT *xprt, xdrproc_t xargs, char *argsp)
{
	return ((*(xprt)->xp_ops->xp_freeargs)(xprt, xargs, argsp));
}

bool_t
svc_getargs(SVCXPRT *xprt, xdrproc_t xargs, char *argsp)
{
	return ((*(xprt)->xp_ops->xp_getargs)(xprt, xargs, argsp));
}

struct netbuf *
svc_getrpccaller(SVCXPRT *xprt)
{
	return (&(xprt)->xp_rtaddr);
}

void
xdr_destroy(XDR *xdrs)
{
	(*(xdrs)->x_ops->x_destroy)(xdrs);
}

uint_t
xdr_getpos(XDR *xdrs)
{
	return ((*(xdrs)->x_ops->x_getpostn)(xdrs));
}

rpc_inline_t *
xdr_inline(XDR *xdrs, int len)
{
	return ((*(xdrs)->x_ops->x_inline)(xdrs, len));
}

bool_t
xdr_setpos(XDR *xdrs, uint_t pos)
{
	return ((*(xdrs)->x_ops->x_setpostn)(xdrs, pos));
}
